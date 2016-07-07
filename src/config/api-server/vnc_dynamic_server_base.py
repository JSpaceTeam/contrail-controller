__author__ = 'hprakash'
#
# Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
#

import commands
import copy
import functools
import json
import logging
import sys
import threading
import traceback
from io import BytesIO
from lxml.etree import XMLSyntaxError
import cfgm_common
import os
import xmltodict
from app_cfg_server.gen.resource_common import YangSchema
from app_cfg_server.gen.vnc_api_client_gen import SERVICE_PATH
from app_cfg_server.server_core.context import get_request
from app_cfg_server.server_core.vnc_cfg_base_type import Resource
from app_cfg_server.server_core.vnc_server_base import VncApiServerBase
from cfgm_common import utils
from cfgm_common.vnc_extensions import ExtensionManager
from kombu import Exchange, Queue, BrokerConnection
from kombu.connection import Connection
from kombu.mixins import ConsumerMixin
from kombu.pools import producers
from lxml import etree
from oslo_config import cfg
from pysandesh.gen_py.sandesh.ttypes import SandeshLevel

logger = logging.getLogger(__name__)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
ES_FILE = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + "gesm.py"

TEMP_DIR = "/tmp/yangs"
TEMP_ES_DIR = "/tmp/yangs/es"
SCHEMA_OBJ_TYPE = "yang-schema"
SCHEMA_OBJ_MODEL = "yin_schema"
OPERATION = "operation"
META_DATA = "meta-data"
DEVICE = "device"
OC_DEVICE = 'oc-device'
DEVICE_ID = "device-id"
XMLNS_TAG = "@xmlns"

_CREATE_OPERATION = 'create'
_DELETE_OPERATION = 'delete'
_UPDATE_OPERATION = 'update'
_REPLACE_OPERATION = 'replace'
_PATCH_OPERATION = 'patch'

_INSTALL_YANG = 'install-yang'
_ROUTE = 'route'

_WITH_CHILDS = 'children'

_VERTEX_DEPENDENCY = 'vertex_extn'
_DRAFT_DEPENDENCY = 'draft_uuid'
_DB_OBJ_DICT = 'db_obj_dict'
_DB_OBJ_XML = 'db_obj_xml'
_CUR_OBJ_XML = 'cur_obj_xml'
_QUERY_PARAMS = 'query_params'
_REQUEST_TYPE = 'request_type'
_SUBTREE = 'subtree'

_PARENT_TYPE = 'parent_type'
_PARENT_ID = 'parent_id'

# Register RabbitMQ Configuration
route_key = 'dynamic_route'
route_exchange = Exchange('dynamic_route_exchange', type='direct')
route_queue = Queue('dynamic_route_queue', route_exchange, routing_key=route_key)

autogen_props = {'uri', 'parent_uri', 'parent_uuid', 'parent_type', 'uuid', 'perms2', 'id_perms', 'display_name', 'fq_name'}

_FQ_NAME, _UUID, _PARENT_UUID, _TOTAL = 'fq_name', 'uuid', 'parent_uuid', 'total'

# For caching yang schemas elements

YANG_SCHEMAS_OBJS = {}
_XML_PREFIX = ':'
_CSP_PREFIX = '$'


class VncApiDynamicServerBase(VncApiServerBase):
    """
    This is the manager class co-ordinating all dynamic classes present in the package
    """

    def __new__(cls, *args, **kwargs):
        obj = super(VncApiDynamicServerBase, cls).__new__(cls, *args, **kwargs)
        cls._generate_install_yang_method(obj)
        cls._generate_install_yang_uri(obj)
        return obj

    # end __new__

    def __init__(self, args_str=None):  # pragma: no cover
        super(VncApiDynamicServerBase, self).__init__(args_str)
        self._load_dynamic_extensions()
        self._initialize_dynamic_resources_from_db()
        self.routeHandler = DynamicRouteNotificationHandler(self)
        self.routeHandler.start_consumer()

        # Default Zookeeper Node for transaction support
        self._vnc_transaction_path = '/vnc-transaction' + self._db_conn._zk_db._module_path
        if not self.get_vnc_zk_client().exists(self._vnc_transaction_path):
            self.get_vnc_zk_client().create_node(self._vnc_transaction_path)

    # end __init__

    def _initialize_dynamic_resources_from_db(self):
        try:
            (ok, results, total) = self._db_conn.dbe_list(SCHEMA_OBJ_TYPE)
            obj_ids_list = [{'uuid': obj_uuid} for _, obj_uuid in results]
            (ok, results) = self._db_conn.dbe_read_multi(SCHEMA_OBJ_TYPE, obj_ids_list)
            schema_mgr = YangSchemaMgr()
            for result in results:
                route_name = result['module_name']
                self._generate_dynamic_resource_crud_methods(route_name)
                self._generate_dynamic_resource_crud_uri(route_name)
                if 'es_schema' in result and len(result['es_schema']) != 0:
                    self.init_es_schema(route_name, result['es_schema'])
                # Initialize the Resource classes and cache the yang schema element
                yin_schema = result['yin_schema']
                yang_schema = schema_mgr.get_yang_schema(str(yin_schema))
                self.set_dynamic_resource_classes(yang_schema)
        except Exception as e:
            err_msg = cfgm_common.utils.detailed_traceback()
            logger.error(err_msg)
            self.config_log("Exception in adding dynamic routes : %s" % (err_msg),
                            level=SandeshLevel.SYS_ERR)

    @classmethod
    def _generate_install_yang_method(cls, obj):
        obj_type = 'yang'
        install_yang_method = functools.partial(obj.install_yang, obj_type)
        functools.update_wrapper(install_yang_method, obj.install_yang)
        setattr(obj, 'http_install_yang', install_yang_method)

    @classmethod
    def _generate_install_yang_uri(cls, obj):
        obj.route('%s/%s' % (SERVICE_PATH, _INSTALL_YANG), 'POST',
                  getattr(obj, 'http_install_yang'))

    def install_yang(self, resource_type):
        try:
            req = self.get_req_json_obj()
            yang_content = req['yang-content']
            module_name = req['module-name']
            create_routes = 'true'
            if "create-routes" in req:
                create_routes = req['create-routes']
            if not os.path.exists(TEMP_DIR):  # pragma: no cover
                os.makedirs(TEMP_DIR)
            file_name = TEMP_DIR + "/" + module_name
            file_obj = open(file_name, 'w')
            file_obj.write(yang_content)
            file_obj.close()
            # Run the pyang command to generate the yin(xml) format
            pyang_cmd_prefix = "pyang -p " + TEMP_DIR + " -f yin "
            pyang_cmd = pyang_cmd_prefix + file_name
            yin_schema = commands.getoutput(pyang_cmd)
            xml_tree = etree.parse(BytesIO(yin_schema), etree.XMLParser())
            module_element = xml_tree.getroot()
            default_ns = "{" + module_element.nsmap[None] + "}"
            module_name = module_element.get(YangSchemaMgr.NAME_ATTRIB)
            module_name_space = module_element.find(default_ns + YangSchemaMgr.YANG_NAMESPACE).get(
                YangSchemaMgr.URI_ATTRIB)
            module_revision = module_element.find(default_ns + YangSchemaMgr.YANG_REVISION).get(
                YangSchemaMgr.DATE_ATTRIB)
            module_json_schema = json.dumps(xmltodict.parse(yin_schema))
            module_yin_schema = yin_schema

            # Creating Elastic Search Schema
            es_schema = ''

            if self.is_es_enabled() and create_routes == 'true':
                es_schema = self.update_es_schema(module_name, file_name)

            yang_schema = YangSchema(name=module_name, module_name=module_name, version=module_revision,
                                     namespace=module_name_space,
                                     json_schema=module_json_schema, yin_schema=module_yin_schema, es_schema=es_schema)
            schema_dict = dict()
            schema_dict["module_name"] = str(yang_schema.get_module_name())
            schema_dict["revision"] = str(yang_schema.get_revision())
            schema_dict["fq_name"] = yang_schema.get_fq_name()
            schema_dict["namespace"] = str(yang_schema.get_namespace())
            schema_dict["json_schema"] = yang_schema.get_json_schema()
            schema_dict["yin_schema"] = yang_schema.get_yin_schema()
            schema_dict["es_schema"] = yang_schema.get_es_schema()

            uuid = self._get_id_from_fq_name(yang_schema.get_type(), yang_schema.get_fq_name())
            req[yang_schema.get_type()] = schema_dict
            if uuid is not None:
                response = self.http_resource_update(yang_schema.get_type(), uuid)
                logger.info("Yang module got updated successfully with name :" + module_name)
            else:
                response = self.http_resource_create(yang_schema.get_type())
                if create_routes == 'true':
                    self.routeHandler.send_new_route_notification(module_name)
                    response[yang_schema.get_type()]["dynamic-uri"] = SERVICE_PATH + "/" + module_name
                    logger.info("New dynamic uri created for yang module :" + SERVICE_PATH + "/" + module_name)
                else:
                    logger.info("New yang module got installed successfully with name :" + module_name)

            # Initialize the Resource classes and cache the yang schema element
            schema_mgr = YangSchemaMgr()
            yang_schema = schema_mgr.get_yang_schema(str(yin_schema))
            self.set_dynamic_resource_classes(yang_schema)
            return response
        except XMLSyntaxError as ex:
            err_msg = "Error occurred while parsing the Yang Module :" + module_name
            if "<?" in yin_schema:
                yin_schema = yin_schema.split("<?", 1)[0]
            err_msg = err_msg + " " + yin_schema
            raise cfgm_common.exceptions.HttpError(500, err_msg)
        except cfgm_common.exceptions.HttpError as he:
            raise he
        except Exception as e:
            logger.error(traceback.format_exc())
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log("Exception in adding dynamic routes : %s" % (err_msg),
                            level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

    # end install_yang

    def update_es_schema(self, module_name, file_name):
        logger.debug('Create Elastic Search Schema -- input  ' + module_name)

        if not os.path.exists(TEMP_ES_DIR):  # pragma: no cover
            os.makedirs(TEMP_ES_DIR)

        # Copy ES Yang Plugin
        copy_cmd = 'cp %s %s' % (ES_FILE, TEMP_ES_DIR)
        commands.getoutput(copy_cmd)

        pyang_cmd = "pyang  -p " + TEMP_DIR + " --plugindir %s %s -f gesm --gesm-output %s"
        cmd = pyang_cmd % (TEMP_ES_DIR, file_name, TEMP_ES_DIR)

        logger.debug('Command executed ' + cmd)
        commands.getoutput(cmd)

        with open(TEMP_ES_DIR + '/%s.mapping.json' % (module_name)) as file:
            file_content = file.read()

        logger.debug('Elastic Search Schema File Content - ' + file_content)

        self.init_es_schema(module_name, file_content)

        return file_content

    # end update_es_schema

    def is_es_enabled(self):
        return cfg.CONF.elastic_search.search_enabled

    def init_es_schema(self, module_name, es_schema_mapping):

        if self.is_es_enabled():
            es_schema = json.loads(es_schema_mapping)
            logger.debug('es_schema string - ' + str(es_schema))

            if module_name in es_schema:
                mapping = es_schema[module_name]

            _index_client = self._db_conn._search_db._index_client
            _index = self._db_conn._search_db._index

            def _print_mappings(index, doc_type):
                return _index_client.get_mapping(index=_index, doc_type=_doc_type)

            # Exising Mapping for the doc type
            for _doc_type, _mapping in mapping['mappings'].iteritems():
                _doc_type = str(_doc_type)

                logger.debug('Doc Type %s Existing Mapping %s' % (_doc_type, _print_mappings(_index, _doc_type)))

                # Update Mapping
                _index_client.put_mapping(index=_index, doc_type=_doc_type, body=_mapping)

                logger.debug('Doc Type %s Updated Mapping %s' % (_doc_type, _print_mappings(_index, _doc_type)))

                # Update in the HAPI Server Index Map
                self._db_conn._search_db._mapped_doc_types.append(_doc_type)
        else:
            logger.info('Elastic Search is disabled')

            # end init_es_schema

    def get_req_json_obj(self):  # pragma: no cover
        return get_request().json

    def get_req_query_obj(self):  # pragma: no cover
        return get_request().query.dict

    def get_req_method(self):  # pragma: no cover
        return get_request().method

    def apply_to_children(self):
        if _WITH_CHILDS in self.get_req_query_obj():
            children = self.get_req_query_obj()[_WITH_CHILDS]
            if "true" in children:
                return True
        return False

    def _remove_auto_gen_prop(self, obj, r_class):
        for removable_property in autogen_props:
            if removable_property in obj:
                obj.__delitem__(removable_property)
        if YangSchemaMgr.NAME_ATTRIB not in r_class.prop_fields:
            obj.__delitem__(YangSchemaMgr.NAME_ATTRIB)
        self._remove_ref_objs(obj)

    def _remove_ref_objs(self, obj):
        removable_keys = []
        for k, v in obj.iteritems():
            k = str(k)
            if k.endswith('_refs'):
                removable_keys.append(k)

        for prop in removable_keys:
            obj.__delitem__(prop)

    def pre_process_dynamic_service_dependency(func):
        def wrapper(server_obj, resource_type, *args, **kwargs):
            try:
                obj_type = resource_type
                obj_dict = server_obj.get_req_json_obj()
                qry_dict = server_obj.get_req_query_obj()
                uuid = kwargs['id'] if 'id' in kwargs else None

                if _VERTEX_DEPENDENCY not in qry_dict and _DRAFT_DEPENDENCY not in qry_dict:
                    return func(server_obj, resource_type, *args, **kwargs)

                db_obj_dict = None

                if uuid is not None:
                    db_obj_dict = server_obj.http_resource_read(resource_type, uuid)

                    if db_obj_dict is not None:
                        r_class = server_obj.get_resource_class(resource_type)
                        server_obj._remove_auto_gen_prop(db_obj_dict[resource_type], r_class)
                        module_name = obj_type
                        xpath = module_name + '\\' + resource_type
                        new_child_objs = server_obj._read_child_resources(db_obj_dict[resource_type], xpath)
                        # TODO Need to remove this later
                        new_child_objs = json.loads(json.dumps(new_child_objs).replace(_CSP_PREFIX, _XML_PREFIX))
                        db_obj_dict[resource_type].update(new_child_objs)

                if _VERTEX_DEPENDENCY in qry_dict:
                    server_obj._invoke_dynamic_extension("process_vertex_dependency", obj_type, obj_dict,
                                                         db_obj_dict=db_obj_dict, generate_xml=True)

                if _DRAFT_DEPENDENCY in qry_dict:
                    server_obj._invoke_dynamic_extension("process_draft_dependency", obj_type, obj_dict, db_obj_dict=db_obj_dict,
                                                         generate_xml=True)
                else:
                    return func(server_obj, resource_type, *args, **kwargs)
            except Exception as e:
                err_msg = 'Exception while processing dynamic services dependency ' + cfgm_common.utils.detailed_traceback()
                logger.error(err_msg)
                raise cfgm_common.exceptions.HttpError(500, err_msg)

        return wrapper

    @pre_process_dynamic_service_dependency
    def http_dynamic_resource_create(self, resource_type):
        logger.debug('**** Start **** http_dynamic_resource_create method ' + resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_create", obj_type, obj_dict)
        res_obj_dict = dict()
        path_nodes = []
        try:
            # Get the YangElement Object
            yang_element = self.get_yang_element(obj_type, obj_dict)
            # Get the transaction node paths
            path_nodes = self._get_transaction_nodes(resource_type, yang_element)
            # Lock the transaction before creation
            self._lock_transaction(_CREATE_OPERATION, path_nodes)
            # Create the resources recursively
            self._dynamic_resource_create(yang_element)
            # Update Leaf Ref - Objects
            self.update_leaf_ref(yang_element, _CREATE_OPERATION)
            res_obj_dict['uuid'] = yang_element.uuid
            res_obj_dict["uri"] = yang_element.uri
            res_obj_dict["fq_name"] = yang_element.fq_name
            # Unlock the transaction after creation
            self._unlock_transaction(_CREATE_OPERATION, path_nodes)
            logger.debug('**** End **** http_dynamic_resource_create method ' + resource_type)
        except ZNodeLockError as ex:
            logger.error('ZNode lock error', ex.get_message())
            raise cfgm_common.exceptions.HttpError(500, ex.get_message())
        except cfgm_common.exceptions.HttpError as he:
            # Rollback the transaction if any exception happens
            self._rollback_transaction(_CREATE_OPERATION, path_nodes)
            err_msg = cfgm_common.utils.detailed_traceback()
            logger.error(err_msg)
            raise he
        except Exception:
            # Rollback the transaction if any exception happens
            self._rollback_transaction(_CREATE_OPERATION, path_nodes)
            err_msg = 'Error in http_dynamic_resource_create for %s' % (obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            logger.error(err_msg)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

        self._invoke_dynamic_extension("post_dynamic_resource_create", obj_type, obj_dict)
        return {resource_type: res_obj_dict}

    @pre_process_dynamic_service_dependency
    def http_dynamic_resource_update(self, resource_type, id):
        logger.debug('**** Start **** http_dynamic_resource_update method ' + resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_update", obj_type, obj_dict)
        res_obj_dict = dict()
        try:
            # Get the YangElement Object
            yang_element = self.get_yang_element(obj_type, obj_dict)
            # Get the transaction node paths
            path_nodes = self._get_transaction_nodes(resource_type, yang_element)
            # Lock the transaction
            self._lock_transaction(_UPDATE_OPERATION, path_nodes)
            # Update all the resources recursively
            self._dynamic_resource_update(yang_element)
            # Update Leaf Ref - Objects
            self.update_leaf_ref(yang_element, _UPDATE_OPERATION)
            res_obj_dict['uuid'] = yang_element.uuid
            res_obj_dict["uri"] = yang_element.uri
            res_obj_dict["fq_name"] = yang_element.fq_name
            # Unlock the transaction after updating
            self._unlock_transaction(_UPDATE_OPERATION, path_nodes)
            logger.debug('**** End **** http_dynamic_resource_update method ' + resource_type)
        except ZNodeLockError as ex:
            logger.error('ZNode lock error', ex.get_message())
            raise cfgm_common.exceptions.HttpError(500, ex.get_message())
        except cfgm_common.exceptions.HttpError as he:
            self._rollback_transaction(_UPDATE_OPERATION, path_nodes)
            err_msg = cfgm_common.utils.detailed_traceback()
            logger.error(err_msg)
            raise he
        except Exception:
            self._rollback_transaction(_UPDATE_OPERATION, path_nodes)
            err_msg = 'Error in http_dynamic_resource_update for %s' % (obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            logger.error(err_msg)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

        self._invoke_dynamic_extension("post_dynamic_resource_update", obj_type, obj_dict)
        return res_obj_dict

    @pre_process_dynamic_service_dependency
    def http_dynamic_resource_patch(self, resource_type, id):
        logger.debug('**** Start **** http_dynamic_resource_patch method ' + resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_patch", obj_type, obj_dict)
        res_obj_dict = dict()
        try:
            yang_element = self.get_yang_element(obj_type, obj_dict)
            yang_element.uuid = id
            # Get the transaction node paths
            path_nodes = self._get_transaction_nodes(resource_type, yang_element)
            # Lock the transaction
            self._lock_transaction(_PATCH_OPERATION, path_nodes)
            # Apply patch on all the resources recursively
            self._dynamic_resource_patch(yang_element, operation=_UPDATE_OPERATION)
            res_obj_dict['uuid'] = yang_element.uuid
            res_obj_dict["uri"] = yang_element.uri
            res_obj_dict["fq_name"] = yang_element.fq_name
            # Unlock the transaction after updating/patching
            self._unlock_transaction(_PATCH_OPERATION, path_nodes)
            logger.debug('**** End **** http_dynamic_resource_patch method ' + resource_type)
        except ZNodeLockError as ex:
            self.config_log(ex.get_message(), level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, ex.get_message())
        except cfgm_common.exceptions.HttpError as he:
            self._rollback_transaction(_PATCH_OPERATION, path_nodes)
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise he
        except Exception:
            self._rollback_transaction(_PATCH_OPERATION, path_nodes)
            err_msg = 'Error in http_dynamic_resource_patch for %s' % (obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

        self._invoke_dynamic_extension("post_dynamic_resource_patch", obj_type, obj_dict)
        return res_obj_dict

    @pre_process_dynamic_service_dependency
    def http_dynamic_resource_delete(self, resource_type, id):
        logger.debug('**** Start **** http_dynamic_resource_delete method ' + resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        self._invoke_dynamic_extension("pre_dynamic_resource_delete", obj_type, id)
        path_nodes = []
        try:
            res_obj_dict = self.http_resource_read(resource_type, id)
            path_id = ':'.join(res_obj_dict[resource_type]['fq_name'])
            # Lock the transaction before deleting
            self._lock_transaction(_DELETE_OPERATION, [self._vnc_transaction_path + "/" + path_id])
            self._set_transaction_node(_DELETE_OPERATION, resource_type, copy.deepcopy(res_obj_dict))
            # Recursively delete all the children first
            deleted_uuids = self._delete_child_resources(res_obj_dict, obj_type)
            # Now delete the parent
            self.http_resource_delete(resource_type, id)
            deleted_uuids.append(path_id)
            for deleted_uuid in deleted_uuids:
                path_nodes.append(self._vnc_transaction_path + "/" + deleted_uuid)
                # Lock the transaction before deleting
            self._unlock_transaction(_DELETE_OPERATION, path_nodes)
            self._invoke_dynamic_extension("post_dynamic_resource_delete", obj_type, id)
            logger.debug('**** End **** http_dynamic_resource_delete method ' + resource_type)
        except ZNodeLockError as ex:
            self.config_log(ex.get_message(), level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, ex.get_message())
        except cfgm_common.exceptions.HttpError as he:
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            if he.status_code != 404:
                self._rollback_transaction(_DELETE_OPERATION, path_nodes)
            else:
                # Ideally in this case path_nodes should be empty. But still handling corner case where we need to unlock the transaction
                self._unlock_transaction(_DELETE_OPERATION, path_nodes)
            raise he
        except Exception as e:
            self._rollback_transaction(_DELETE_OPERATION, path_nodes)
            err_msg = 'Error in http_dynamic_resource_delete for %s' % id
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

    def http_dynamic_resource_read(self, resource_type, id):
        try:
            logger.debug('**** Start **** http_dynamic_resource_read method ' + resource_type)
            # obj_type = resource_type.replace('-', '_')
            obj_type = resource_type
            self._invoke_dynamic_extension("pre_dynamic_resource_read", obj_type, id)
            # Check for subtree query parameter
            qry_dict = self.get_req_query_obj()
            if _SUBTREE in qry_dict:
                res_obj_dict = self._read_subtree_resources(resource_type, id, qry_dict)
            else:
                res_obj_dict = self.http_resource_read(resource_type, id)
                # If children = true in query parameter, then read all the children
                if self.apply_to_children():
                    # Recursively read all the children
                    module_name = resource_type
                    xpath = module_name + '\\' + resource_type
                    new_child_objs = self._read_child_resources(res_obj_dict[resource_type], xpath)
                    res_obj_dict[resource_type].update(new_child_objs)

            self._invoke_dynamic_extension("post_dynamic_resource_read", obj_type, res_obj_dict)
            logger.debug('**** End **** http_dynamic_resource_read method ' + resource_type)
            res_obj_dict = json.loads(json.dumps(res_obj_dict).replace(_CSP_PREFIX, _XML_PREFIX))
            return res_obj_dict
        except cfgm_common.exceptions.HttpError as he:
            raise he
        except Exception as e:
            err_msg = 'Error in http_dynamic_resource_read for %s' % id
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

    def http_dynamic_resource_list(self, resource_type):
        logger.debug('**** Start ****  http_dynamic_resource_list method ' + resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        res_obj_dict = self.http_resource_list(resource_type)
        res_list = res_obj_dict[resource_type]
        # If children = true in query parameter, then list all the children
        if self.apply_to_children():
            res_new_list = list()
            for res in res_list:
                res_obj = self.http_dynamic_resource_read(resource_type, res["uuid"])
                res_new_list.append(res_obj[resource_type])
            res_obj_dict[resource_type] = res_new_list
        logger.debug('**** End ****  http_dynamic_resource_list method ' + resource_type)
        return res_obj_dict

    def _generate_dynamic_resource_crud_methods(self, resource_type):

        obj_type = resource_type.replace('-', '_')
        create_method = functools.partial(self.http_dynamic_resource_create,
                                          resource_type)
        functools.update_wrapper(create_method, self.http_dynamic_resource_create)
        setattr(self, '%ss_http_post' % (obj_type), create_method)

        read_method = functools.partial(self.http_dynamic_resource_read,
                                        resource_type)
        functools.update_wrapper(read_method, self.http_dynamic_resource_read)
        setattr(self, '%s_http_get' % (obj_type), read_method)

        update_method = functools.partial(self.http_dynamic_resource_update,
                                          resource_type)
        functools.update_wrapper(update_method, self.http_dynamic_resource_update)
        setattr(self, '%s_http_put' % (obj_type), update_method)

        delete_method = functools.partial(self.http_dynamic_resource_delete,
                                          resource_type)
        functools.update_wrapper(delete_method, self.http_dynamic_resource_delete)
        setattr(self, '%s_http_delete' % (obj_type), delete_method)

        list_method = functools.partial(self.http_dynamic_resource_list,
                                        resource_type)
        functools.update_wrapper(list_method, self.http_dynamic_resource_list)
        setattr(self, '%ss_http_get' % (obj_type), list_method)

        patch_method = functools.partial(self.http_dynamic_resource_patch,
                                         resource_type)
        functools.update_wrapper(patch_method, self.http_dynamic_resource_patch)
        setattr(self, '%s_http_patch' % (obj_type), patch_method)

    # end _generate_dynamic_resource_crud_methods

    def _generate_dynamic_resource_crud_uri(self, resource_type):

        obj_type = resource_type.replace('-', '_')
        # leaf resource
        self.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                   'GET',
                   getattr(self, '%s_http_get' % (obj_type)))
        self.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                   'PUT',
                   getattr(self, '%s_http_put' % (obj_type)))
        self.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                   'DELETE',
                   getattr(self, '%s_http_delete' % (obj_type)))
        # collection of leaf
        self.route('%s/%s' % (SERVICE_PATH, resource_type),
                   'POST',
                   getattr(self, '%ss_http_post' % (obj_type)))
        self.route('%s/%s' % (SERVICE_PATH, resource_type),
                   'GET',
                   getattr(self, '%ss_http_get' % (obj_type)))
        self.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                   'PATCH',
                   getattr(self, '%s_http_patch' % (obj_type)))

    # end _generate_dynamic_resource_crud_uri

    def set_dynamic_resource_classes(self, yang_element):
        obj_type = yang_element.get_element_name()
        if yang_element.is_vertex():
            if self.get_resource_class(obj_type) is None:
                camel_name = cfgm_common.utils.CamelCase(obj_type)
                r_class_name = '%sDynamicServer' % (camel_name)
                common_class = yang_element.__class__
                r_class = type(r_class_name, (Resource, common_class, object), {})
            else:
                r_class = self.get_resource_class(obj_type)
            r_class.prop_fields = r_class.prop_fields.union(yang_element.prop_fields)
            r_class.children_fields = r_class.children_fields.union(yang_element.children_fields)
            r_class.ref_fields = r_class.ref_fields.union(yang_element.ref_fields)
            r_class.backref_fields = r_class.backref_fields.union(yang_element.backref_fields)
            r_class.prop_field_types.update(yang_element.prop_field_types)
            r_class.prop_field_metas.update(yang_element.prop_field_metas)
            r_class.children_field_types.update(yang_element.children_field_types)
            r_class.ref_field_types.update(yang_element.ref_field_types)
            r_class.ref_field_metas.update(yang_element.ref_field_metas)
            r_class.backref_field_types.update(yang_element.backref_field_types)
            self.set_resource_class(obj_type, r_class)

        for element in yang_element.get_child_elements():
            self.set_dynamic_resource_classes(element)

    def _load_dynamic_extensions(self):
        try:
            conf_sections = self._args.config_sections
            self._extension_mgrs['dynamicResourceApi'] = ExtensionManager(
                'vnc_cfg_api.dynamicResourceApi',
                propagate_map_exceptions=True,
                api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
        except Exception as e:
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log("Exception in extension load: %s" % (err_msg),
                            level=SandeshLevel.SYS_ERR)

    # end _load_dynamic_extensions

    def _invoke_dynamic_extension(self, method_name, obj_type, obj_dict, db_obj_dict=None, generate_xml=False):
        try:
            params = dict()
            params[_QUERY_PARAMS] = self.get_req_query_obj()
            params[_DB_OBJ_DICT] = db_obj_dict
            params[_REQUEST_TYPE] = self.get_req_method()

            if generate_xml:
                xml_data = self._json_to_xml(obj_dict)
                params[_CUR_OBJ_XML] = xml_data

                if db_obj_dict is not None:
                    # Convert json to xml
                    xml_data = self._json_to_xml(db_obj_dict)
                    params[_DB_OBJ_XML] = xml_data

            self._extension_mgrs['dynamicResourceApi'].map_method(method_name, obj_type, obj_dict, **params)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In %s an extension had error for %s' % (method_name, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

    def _dynamic_resource_create(self, yang_element, parent=None):
        if yang_element.is_vertex():
            self._resource_create(yang_element, parent)
        for child in yang_element.get_child_elements():
            self._dynamic_resource_create(child, yang_element)

    def _dynamic_resource_update(self, yang_element, parent=None):
        if yang_element.is_vertex():
            self._resource_update(yang_element, parent)
        for child in yang_element.get_child_elements():
            self._dynamic_resource_update(child, yang_element)

    def _dynamic_resource_patch(self, yang_element, operation=None, parent=None):
        if not yang_element.is_vertex():
            return
        if operation == _CREATE_OPERATION:
            self._dynamic_resource_create(yang_element, parent)

            # Update leaf ref if any
            self.update_leaf_ref(yang_element, operation)

        if operation == _UPDATE_OPERATION:
            self._resource_update(yang_element, parent)

            # Update leaf ref if any
            self.update_leaf_ref(yang_element, operation, deep_fetch=False)

            for child in yang_element.get_child_elements():
                self._dynamic_resource_patch(child, child.operation_type, yang_element)

        if operation == _DELETE_OPERATION:
            resource_type = yang_element.element_name
            fqn_name = yang_element.get_fq_name_list()
            uuid = self._get_id_from_fq_name(resource_type, fqn_name)
            yang_element.set_uuid(uuid)
            res_obj_dict = self.http_resource_read(resource_type, uuid)
            # Recursively delete all the children first
            self._delete_child_resources(res_obj_dict, resource_type)
            # Now delete the parent
            self.http_resource_delete(resource_type, uuid)

    # End _dynamic_resource_patch

    def update_leaf_ref(self, yang_element, operation, deep_fetch=True):
        try:
            if yang_element.is_leaf_ref():
                self._update_leaf_ref(yang_element, operation)

            if deep_fetch:
                for child in yang_element.get_child_elements():
                    self.update_leaf_ref(child, operation)
            else:
                # PATCH USE CASE - DO FOR ONE LEVEL LOOKUP ONLY - Update happens for every level
                for child in yang_element.get_child_elements():
                    if child.is_leaf_ref():
                        self._update_leaf_ref(child, operation)

        except Exception as e:
            logger.error('Exception while updating leaf ref ', e)

    def _update_leaf_ref(self, yang_element, operation):
        for elt in yang_element.get_parent_elements():
            ref_obj = elt
            break

        for elt in ref_obj.get_parent_elements():
            parent = elt
            break

        self._update_resource_with_leaf_ref(ref_obj, parent)

    def _update_resource_with_leaf_ref(self, element, parent, operation):
        resource_type = element.element_name
        fqn_name = element.get_fq_name_list()
        uuid = self._get_id_from_fq_name(resource_type, fqn_name)
        element.set_uuid(uuid)
        if parent is not None:
            element.parent_uuid = parent.get_uuid()
        json_data = element.get_json(include_leaf_ref=True)
        self.get_req_json_obj()[resource_type] = json_data
        # Setting the transaction state data in Zookeeper.
        self._set_transaction_node(operation, resource_type, {resource_type: uuid})
        content = self.http_resource_update(resource_type, uuid)
        obj_dict = content[resource_type]
        element.uuid = obj_dict['uuid']
        element.uri = obj_dict["uri"]

    def _resource_create(self, element, parent):
        if parent:
            element.parent_uuid = parent.uuid
        json_data = element.get_json()
        resource_type = element.element_name
        self.get_req_json_obj()[resource_type] = json_data
        content = self.http_resource_create(resource_type)
        obj_dict = content[resource_type]
        element.uuid = obj_dict['uuid']
        element.uri = obj_dict["uri"]
        element.fq_name = obj_dict["fq_name"]
        if 'parent_uuid' in obj_dict:
            element.parent_uuid = obj_dict['parent_uuid']
        # Setting the transaction state data in Zookeeper
        self._set_transaction_node(_CREATE_OPERATION, resource_type, {resource_type: element})

    def _resource_update(self, element, parent):
        resource_type = element.element_name
        fqn_name = element.get_fq_name_list()
        uuid = self._get_id_from_fq_name(resource_type, fqn_name)
        element.set_uuid(uuid)
        if parent is not None:
            element.parent_uuid = parent.get_uuid()
        json_data = element.get_json()
        self.get_req_json_obj()[resource_type] = json_data
        # Setting the transaction state data in Zookeeper
        self._set_transaction_node(_UPDATE_OPERATION, resource_type, {resource_type: uuid})
        content = self.http_resource_update(resource_type, uuid)
        obj_dict = content[resource_type]
        element.uuid = obj_dict['uuid']
        element.uri = obj_dict["uri"]

    def _get_id_from_fq_name(self, resource_type, fq_name):
        uuid = None
        try:
            uuid = self._db_conn.fq_name_to_uuid(resource_type, fq_name)
        except Exception:
            logger.error("No uuid was found for given fq_name :" + ':'.join(fq_name))
        return uuid

    def _read_child_resources(self, db_obj, parent_xpath=None, remove_auto_gen_properties=True):
        new_obj = dict()
        for k, v in db_obj.iteritems():
            if isinstance(v, list) and str(k).endswith('s'):
                # Assume given is a list. Remove the last "s" from the child object types
                res_type = str(k)[:str(k).__len__() - 1].replace('_', '-')
                cls = self.get_resource_class(res_type)
                xpath = parent_xpath + '\\' + res_type
                yang_elt = self._get_yang_element_schema(xpath)
                ary = list()
                if cls is not None:
                    for elt in v:
                        if _UUID in elt:
                            child_db_obj = self.http_resource_read(res_type, elt[_UUID])
                            if child_db_obj is not None and res_type in child_db_obj:
                                child_db_obj = child_db_obj[res_type]
                                if remove_auto_gen_properties:
                                    self._remove_auto_gen_prop(child_db_obj, cls)
                                inner_objs = self._read_child_resources(child_db_obj, parent_xpath + '\\' + res_type,
                                                                        remove_auto_gen_properties=remove_auto_gen_properties)
                                child_db_obj.update(inner_objs)
                                ary.append(child_db_obj)

                if yang_elt.get_yang_type() == YangSchemaMgr.YANG_CONTAINER:
                    new_obj[res_type] = ary[0]
                else:
                    new_obj[res_type] = ary  # pragma: no cover

        for k, v in new_obj.iteritems():
            db_obj.__delitem__((str(k) + 's').replace('-', '_'))

        return new_obj

    def _delete_child_resources(self, res_dict, obj_type, deleted_uuids=None, transaction=True):
        if deleted_uuids is None:
            deleted_uuids = []
        res_obj = res_dict[obj_type]
        for k, v in res_obj.iteritems():
            if isinstance(v, list) and str(k).endswith('s'):
                child_obj_type = str(k)
                res_child_objs = res_obj[child_obj_type]
                # Removing the last "s" from the child object types
                child_obj_type = str(k)[:-1]
                for res_child_obj in res_child_objs:
                    child_uuid = res_child_obj["uuid"]
                    child_obj_db = self.http_resource_read(child_obj_type, child_uuid)
                    if child_obj_db is not None:
                        try:
                            self._delete_child_resources(child_obj_db, child_obj_type, deleted_uuids, transaction)
                            node_id = ':'.join(child_obj_db[child_obj_type]['fq_name'])
                            if transaction:
                                self._lock_transaction(_DELETE_OPERATION, [self._vnc_transaction_path + "/" + node_id])
                                self._set_transaction_node(_DELETE_OPERATION, child_obj_type, child_obj_db)
                            self.http_resource_delete(child_obj_type, child_uuid)
                            deleted_uuids.append(node_id)
                        except cfgm_common.exceptions.HttpError as he:
                            # Some stale object if present will get deleted.
                            if he.status_code != 404:
                                raise he
        return deleted_uuids

    def _validate_props_in_request(self, resource_class, obj_dict):
        if resource_class.__name__.endswith("DynamicServer"):
            # TODO validate properties
            return True, ''
        else:
            return super(VncApiDynamicServerBase, self)._validate_props_in_request(resource_class, obj_dict)

    def _validate_refs_in_request(self, r_class, obj_dict):
        if r_class.__name__.endswith("DynamicServer"):
            # TODO validate refs
            return True, ''
        else:
            return super(VncApiDynamicServerBase, self)._validate_refs_in_request(r_class, obj_dict)

    def get_yang_element(self, resource_type, json_data):
        # Convert string object to dict
        if type(json_data) is dict:
            json_data_dict = json_data
        else:
            json_data_dict = json.loads(str(json_data))
        temp_dict = copy.deepcopy(json_data_dict)
        xml_data = self._json_to_xml(temp_dict)
        xml_tree = etree.parse(BytesIO(xml_data), etree.XMLParser())
        module_name = resource_type
        yang_element = YangElement(name=module_name)
        yang_element = self._get_yang_element(module_name, xml_tree.getroot(), yang_element)
        return yang_element

    def _get_yang_element(self, module_name, element, yang_element, parent_element=None):

        e_name = self._get_tag_name(element)
        yang_element.set_element_name(e_name)
        yang_element.set_element_value(element.text)
        yang_element.set_operation_type(element.get(OPERATION))
        yang_element.set_xpath(module_name + "\\" + e_name)
        if parent_element is not None:
            yang_element.add_parent_element(parent_element)
            parent_element.add_child_element(yang_element)
            xpath = parent_element.get_xpath() + "\\" + yang_element.get_element_name()
            yang_element.set_xpath(xpath)

        schema_elt = self._get_yang_element_schema(yang_element.get_xpath())
        yang_element.set_yang_type(schema_elt.get_yang_type())
        yang_element.set_key_names(schema_elt.get_key_names())

        yang_element.set_data_type(schema_elt.get_data_type())
        yang_element.set_leaf_ref_path(schema_elt.get_leaf_ref_path())

        for child in element.getchildren():
            child_tag_name = self._get_tag_name(child)
            child_element = YangElement(name=child_tag_name)
            if child_tag_name == META_DATA:
                self._set_meta_data(child, yang_element)
            elif child_tag_name == OPERATION:
                yang_element.set_operation_type(child.text)
            else:
                self._get_yang_element(module_name, child, child_element, yang_element)

        return yang_element

    def _set_meta_data(self, element, parent_element):
        meta_data = ""
        for child in element.getchildren():
            meta_data = meta_data + ' ' + child.text
        parent_element.set_meta_data(meta_data)

    def _get_yang_schema(self, module_name):
        # TODO to integrate with Schema Manager Service if required
        # module_name = module_name.replace("-", "_")
        obj_type = SCHEMA_OBJ_TYPE
        fq_name = list()
        fq_name.append(module_name)
        id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        r_class = self.get_resource_class(obj_type)
        obj_fields = list(r_class.prop_fields)
        obj_ids = {'uuid': id}
        (ok, result) = self._db_conn.dbe_read(obj_type, obj_ids, obj_fields)
        # This is in YIN (XML) format
        schema_obj = result[SCHEMA_OBJ_MODEL]
        return schema_obj

    def _get_yang_element_schema(self, xpath):
        yang_element_schema = YangSchemaMgr.get_yang_schema_element(xpath)
        if yang_element_schema is not None:
            return yang_element_schema
        else:
            raise AttributeError(
                'Schema element not found for xpath ' + xpath)

    def _get_tag_name(self, element):
        # This is to handle name space
        if "}" in element.tag:
            e_name = element.tag.split("}", 1)[1]
        else:
            e_name = element.tag
        if element.prefix:
            e_name = element.prefix + _CSP_PREFIX + e_name
        return e_name

    def _json_to_xml(self, tree):
        if not tree:
            return ''
        if not isinstance(tree, dict) and not isinstance(tree, list):
            return ''
        result = ''
        for key in tree:
            if key.startswith('@'):
                continue
            value = tree[key]
            if isinstance(value, dict):
                result = self.get_xml_tree(key, value, result)
            elif isinstance(value, list):
                for item in value:
                    result = self.get_xml_tree(key, item, result)
            else:
                s = '<' + key + '>' + value + '</' + key + '>'
                result += s
        return result

    def get_xml_tree(self, element_name, tree, result):
        if not tree:
            return
        if not isinstance(tree, dict) and not isinstance(tree, list):
            s = '<' + element_name + '>' + tree + '</' + element_name + '>'
            result += s
            return
        name_attr = ''
        for key in tree:
            if key.startswith('@'):
                name_attr += ' ' + key[1:] + '="' + tree[key] + '"'
        s = '<' + element_name + name_attr + '>'
        result += s
        for key in tree:
            if key.startswith('@'):
                continue
            value = tree[key]
            if isinstance(value, dict):
                result = self.get_xml_tree(key, value, result)
            elif isinstance(value, list):
                for item in value:
                    result = self.get_xml_tree(key, item, result)
            else:
                s = '<' + key + '>' + value + '</' + key + '>'
                result += s
        s = '</' + element_name + '>'
        result += s
        return result

    def _read_subtree_resources(self, resource_type, uuid, qry_dict):
        res_obj_dict = {}
        subtree_params = qry_dict[_SUBTREE]
        parent_fq_name = str(self._db_conn.uuid_to_fq_name(uuid)[0])
        for xpath in subtree_params:
            xpath = str(xpath)
            # Ex xpath = [configuration/interfaces/interface, configuration/vlans/vlan]
            xpath = xpath[1:len(xpath) - 1]
            paths = xpath.split(',')
            for path in paths:
                path = path.replace(_XML_PREFIX, _CSP_PREFIX)
                res_type_list = [resource_type]
                fqn_name_list = [parent_fq_name]
                path_elem_list = path.split('/')
                for path_elem in path_elem_list:
                    res_type, key = self._get_resource_type_and_key(path_elem)
                    res_type_list.append(res_type)
                    fqn_name_list.append(key)

                # Minimum list size should be always 2 else its a bug, so not checking for size. Need to find if any use case occurs
                parent_type = res_type_list[len(res_type_list) - 2]
                parent_type = parent_type.replace('-', '_')
                res_type = res_type_list[len(res_type_list) - 1]
                res_type = res_type.replace('-', '_')
                fqn_name = fqn_name_list[len(res_type_list) - 1]
                if res_type == fqn_name:
                    # Its a list object
                    qry_dict['detail'] = ['true']
                    if fqn_name_list[1:] != res_type_list[1:]:
                        # This is list object with 'name/key'  in it. Ex [configuration/interfaces/interface[name=irb]/subinterfaces/subinterface
                        parent_fq_name_list = fqn_name_list[0:len(fqn_name_list) - 1]
                        parent_uuid = self._db_conn.fq_name_to_uuid(parent_type, parent_fq_name_list)
                        qry_dict[_PARENT_ID] = [parent_uuid]
                        child_db_objs = self.http_resource_list(res_type)
                    else:
                        # This is list object without any 'name/key' in it. Ex [configuration/interfaces/interface/subinterfaces/subinterface
                        child_db_objs = self.http_resource_list(res_type)
                        # This will give all the object of that type, So need to filter based on parent type
                        # This happens because of duplicate resource types for example "config" , "state" etc
                        child_db_objs_list = []
                        for child_obj in child_db_objs[res_type]:
                            if child_obj[_PARENT_TYPE] == parent_type:
                                child_db_objs_list.append(child_obj)
                        child_db_objs[res_type] = child_db_objs_list
                else:
                    # Its a single object
                    child_uuid = self._db_conn.fq_name_to_uuid(res_type, fqn_name_list)
                    child_db_obj = self.http_resource_read(res_type, str(child_uuid))
                    child_db_objs = {res_type: [child_db_obj[res_type]]}

                if res_type in res_obj_dict:
                    res_obj_dict[res_type] = res_obj_dict[res_type] + child_db_objs[res_type]
                else:
                    res_obj_dict[res_type] = (child_db_objs[res_type])

        return res_obj_dict

    def _get_resource_type_and_key(self, path):
        # Assume input = endpointA or qinq-tags[name=one]
        # If path contains [ then key and resource type both are present else only resource type
        if '[' in path:
            idx = path.index('[')
            resource_type = path[0:idx]
            key = path[idx:len(path) - 1]
            key = key.split('=')[-1]
            return resource_type, key
        else:
            return path, path

    def _lock_transaction(self, operation, paths):
        zk_transaction = self.get_vnc_zk_client().transaction()
        rollback_paths = []
        for path in paths:
            if self.get_vnc_zk_client().exists(path + "/owner"):
                raise ZNodeLockError(operation, path)
            if self.get_vnc_zk_client().exists(path):
                # If path exist that means something went wrong in previous transaction (due to system or connection failure)
                # So previous transaction which is not completed / failed has to be rolled backed or cleaned up
                logger.debug("Rollback needed for the failed transaction for operation " + operation + " and path " + path)
                rollback_paths.append(path)

        # Check if any data has to be rolled back (system or connection failure)
        if len(rollback_paths) > 0:
            self._rollback_transaction(operation, rollback_paths)

        for path in paths:
            value = dict()
            value["operation"] = operation
            value["uuid"] = "None"
            value["snapshot_uuid"] = "None"
            value['resource_type'] = "None"
            zk_transaction.create(path, json.dumps(value))
            ephemeral_owner_node = path + "/owner"
            zk_transaction.create(ephemeral_owner_node, ephemeral=True)

        results = zk_transaction.commit()
        logger.debug("Locking transaction for operation " + operation)
        logger.debug(results)

    def _unlock_transaction(self, operation, paths):
        # zk_transaction = self.get_vnc_zk_client().transaction()
        # zk_cl = ZookeeperClient()
        # td = TransactionRequest()
        for path in paths:
            self.get_vnc_zk_client().delete_node(path, recursive=True)
            # zk_transaction.set_data(path, '')
            # zk_transaction.delete(path)
            # results = zk_transaction.commit()
        logger.debug("Unlocking transaction for operation " + operation)

    def _rollback_transaction(self, operation, paths):
        logger.debug("Rollback transaction called for operation " + operation)
        for path in reversed(paths):
            data = self.get_vnc_zk_client().read_node(path)
            if data is not None and len(data) > 0:
                value = json.loads(data)
                operation = value['operation']
                resource_type = value['resource_type']
                snapshot_uuid = value['snapshot_uuid']
                if resource_type == "None" or snapshot_uuid == "None":
                    # Handling corner case for stale paths or due to system/connection failure.
                    continue
                if operation == _CREATE_OPERATION:
                    # For create the rollback operation is delete
                    try:
                        self.http_resource_delete(resource_type, snapshot_uuid)
                    except cfgm_common.exceptions.HttpError as he:
                        # Corner case. System or connection failure.It may have child objects so delete them first if any
                        if he.status_code == 409:
                            res_obj_dict = self.http_resource_read(resource_type, snapshot_uuid)
                            self._delete_child_resources(res_obj_dict, resource_type, transaction=False)
                            # Now delete the parent
                            self.http_resource_delete(resource_type, snapshot_uuid)
                    logger.debug("Status for rollback in CREATE operation : Success")

                elif operation == _UPDATE_OPERATION:
                    # For update the rollback operation is update with snapshot data
                    if 'data' in value:
                        json_data = value['data']
                        obj_ids = {'uuid': snapshot_uuid}
                        obj_dict = json.loads(json_data)[resource_type]
                        (ok, result) = self._db_conn.dbe_update(resource_type, obj_ids, obj_dict)
                        logger.debug("Status for rollback in UPDATE operation :" + str(ok))

                elif operation == _DELETE_OPERATION:
                    # For delete the rollback operation is create with snapshot data
                    if 'data' in value:
                        json_data = value['data']
                        obj_dict = json.loads(json_data)[resource_type]
                        obj_ids = {'uuid': snapshot_uuid}
                        try:
                            (ok, result) = self._db_conn.dbe_create(resource_type, obj_ids, obj_dict)
                            logger.debug("Status for rollback in DELETE operation :" + str(ok))
                        except cfgm_common.exceptions.HttpError as he:
                            # Corner case. System or connection failure.It may have failed before deleting in DB so create will fail.
                            # So just ignore the exception HttpError 409
                            if he.status_code != 409:
                                raise he

            else:
                logger.debug("Rollback transaction called but no data available for path " + path)

        # After rollback, need to unlock/delete the paths
        self._unlock_transaction(operation, paths)

    def _get_transaction_nodes(self, resource_type, yang_element, paths=None):
        if paths is None:
            paths = list()
        if yang_element.is_vertex():
            path = self._vnc_transaction_path + "/" + yang_element.get_fq_name_string()
            path = path.replace(" ", "_")
            paths.append(path)
        for child in yang_element.get_child_elements():
            self._get_transaction_nodes(resource_type, child, paths)
        return paths

    def _set_transaction_node(self, operation, r_type, data):
        json_data = None
        old_object = None
        if operation == _CREATE_OPERATION:
            # For create data[r_type] is a YangElement object
            yang_element = data[r_type]
            uuid = str(yang_element.get_uuid())
            path = yang_element.get_fq_name_string()
            snapshot_uuid = uuid
        elif operation == _UPDATE_OPERATION:
            # For update data[r_type] is a uuid
            uuid = data[r_type]
            snapshot_uuid = uuid
            old_object = self.http_resource_read(r_type, uuid)
        elif operation == _DELETE_OPERATION:
            # For delete data[r_type] is a Json object (response of a http read operation)
            uuid = data[r_type]["uuid"]
            snapshot_uuid = uuid
            old_object = data

        if old_object is not None:
            # Remove the children list objects as its handled as a separate vertices
            path = ':'.join(old_object[r_type]['fq_name'])
            child_types = []
            for k, v in old_object[r_type].iteritems():
                if isinstance(v, list) and str(k).endswith('s'):
                    child_types.append(k)
            for child_type in child_types:
                old_object[r_type].__delitem__(child_type)
            json_data = json.dumps(old_object)

        # Create the zookeeper node
        self._set_transaction_node_value(operation, path=path, r_type=r_type, uuid=uuid,
                                         snapshot_uuid=snapshot_uuid, data=json_data)

    def _set_transaction_node_value(self, operation, path, r_type, uuid, snapshot_uuid, data=None):
        path = self._vnc_transaction_path + "/" + path
        value = dict()
        value['operation'] = operation
        value['resource_type'] = r_type
        value['uuid'] = uuid
        value['snapshot_uuid'] = snapshot_uuid
        if data is not None:
            value['data'] = data
        self.get_vnc_zk_client().set_node(path, json.dumps(value))


# end class VncApiServer

class DynamicResourceApiGen(object):
    def process_draft_dependency(self, resource_type, resource_dict, **kwargs):
        """
        Method called to process dynamic resource draft
        """
        pass

    # end process_draft_dependency

    def process_vertex_dependency(self, resource_type, resource_dict, **kwargs):
        """
        Method called to process dynamic resource vertex depencies
        """
        pass

    # end process_vertex_dependency


    def pre_dynamic_resource_create(self, resource_type, resource_dict, **kwargs):
        """
        Method called before dynamic resource is created
        """
        pass

    # end pre_dynamic_resource_create

    def post_dynamic_resource_create(self, resource_type, resource_dict, **kwargs):
        """
        Method called after dynamic resource is created
        """
        pass
        # end post_dynamic_resource_create

    def pre_dynamic_resource_update(self, resource_type, resource_dict, **kwargs):
        """
        Method called before dynamic resource is updated
        """
        pass

    # end pre_dynamic_resource_update

    def post_dynamic_resource_update(self, resource_type, resource_dict, **kwargs):
        """
        Method called after dynamic resource is updated
        """
        pass
        # end post_dynamic_resource_update

    def pre_dynamic_resource_read(self, resource_type, resource_dict, **kwargs):
        """
        Method called before dynamic resource is read
        """
        pass

    # end pre_dynamic_resource_read

    def post_dynamic_resource_read(self, resource_type, resource_dict, **kwargs):
        """
        Method called after dynamic resource is read
        """
        pass
        # end post_dynamic_resource_read

    def pre_dynamic_resource_delete(self, resource_type, resource_dict, **kwargs):
        """
        Method called before dynamic resource is delete
        """
        pass

    # end pre_dynamic_resource_delete

    def post_dynamic_resource_delete(self, resource_type, resource_dict, **kwargs):
        """
        Method called after dynamic resource is delete
        """
        pass
        # end post_dynamic_resource_delete


# end class DynamicResourceApiGen


class YangElement(object):
    """
    Represents yang-element configuration representation.

    Properties:
        * name-space (xsd:string type)
        * element-name (xsd:string type)
        * element-value (xsd:string type)
        * xpath (xsd:string type)
        * yang-type (xsd:string type)
        * operation-type (xsd:string type)
        * key-names (xsd:string type)
        * id-perms (:class:`.IdPermsType` type)
        * perms2 (:class:`.PermType2` type)
        * display-name (xsd:string type)

    Children:

    References to:

    Referred by:
    """

    multi_tenancy_rule = {"owner": 1, "owner_access": 7, "share": [], "global_access": 0}
    prop_fields = set([u'id_perms', u'perms2', u'display_name'])
    ref_fields = set([])
    backref_fields = set([])
    children_fields = set([])

    children_elements = set([])
    parent_elements = set([])

    prop_field_types = {}
    prop_field_types['id_perms'] = (False, u'IdPermsType')
    prop_field_types['perms2'] = (False, u'PermType2')
    prop_field_types['display_name'] = (True, u'xsd:string')

    ref_field_types = {}

    backref_field_types = {}
    children_field_types = {}
    parent_types = []

    prop_field_metas = {}
    prop_field_metas['id_perms'] = 'id-perms'
    prop_field_metas['perms2'] = 'perms2'
    prop_field_metas['display_name'] = 'display-name'

    ref_field_metas = {}

    children_field_metas = {}

    prop_list_fields = set([])

    prop_list_field_has_wrappers = {}

    prop_map_fields = set([])

    prop_map_field_has_wrappers = {}

    prop_map_field_key_names = {}

    def __init__(self, name=None, *args, **kwargs):
        # type-independent fields
        self._uuid = None
        self._type = name
        self.name = name
        self.fq_name = [name]

        # set default values to property fields
        self._element_name = None
        self._name_space = None
        self._element_value = None
        self._xpath = None
        self._yang_type = None
        self._operation_type = None
        self._key_names = None
        self._meta_data = None
        self._data_type = None
        self._leaf_ref_path = None

        self.children_elements = set([])
        self.parent_elements = set([])

        self.prop_fields = set([u'id_perms', u'perms2', u'display_name'])
        self.prop_field_types = {}
        self.prop_field_types['id_perms'] = (False, u'IdPermsType')
        self.prop_field_types['perms2'] = (False, u'PermType2')
        self.prop_field_types['display_name'] = (True, u'xsd:string')

        self.prop_field_metas = {}
        self.prop_field_metas['id_perms'] = 'id-perms'
        self.prop_field_metas['perms2'] = 'perms2'
        self.prop_field_metas['display_name'] = 'display-name'

        self.children_fields = set([])
        self.children_fields_types = set([])

        self.ref_fields = set([])
        self.backref_fields = set([])
        self.ref_field_types = {}
        self.backref_field_types = {}
        self.ref_field_metas = {}

    # end __init__

    def get_type(self):
        """Return object type (yang-element)."""
        return self._type

    # end get_type

    def get_fq_name(self):
        """Return FQN of yang-element in list form."""
        return self.fq_name

    # end get_fq_name

    def get_fq_name_str(self):
        """Return FQN of yang-element as colon delimited string."""
        return ':'.join(self.fq_name)

    def get_fq_name_list(self, fq_name_list=None):
        """Return FQN of yang-element in list form."""
        if fq_name_list is None:
            fq_name_list = list()
        for parent in self.get_parent_elements():
            parent.get_fq_name_list(fq_name_list)
        if self.get_yang_type() == YangSchemaMgr.YANG_LIST:
            for child in self.get_child_elements():
                element_name = child.get_element_name()
                if _CSP_PREFIX in element_name:
                    element_name = element_name.split(_CSP_PREFIX)[1]
                if element_name == self.get_key_names():
                    fq_name_list.append(child.get_element_value())
        else:
            fq_name_list.append(self.get_element_name())
        return fq_name_list

    def get_fq_name_string(self):
        """Return FQN of yang-element as colon delimited string."""
        names = self.get_fq_name_list()
        return ':'.join(names)

    # end get_fq_name_str

    @property
    def uuid(self):
        return getattr(self, '_uuid', None)

    # end uuid

    @uuid.setter
    def uuid(self, uuid_val):
        self._uuid = uuid_val

    # end uuid

    def set_uuid(self, uuid_val):
        self.uuid = uuid_val

    # end set_uuid

    def get_uuid(self):
        return self.uuid

    # end get_uuid

    @property
    def uri(self):
        return getattr(self, '_uri', None)

    # end uuid

    @uri.setter
    def uri(self, uri_val):
        self._uri = uri_val

    # end uuid

    def set_uri(self, uri_val):
        self.uri = uri_val

    # end set_uuid

    def get_uri(self):
        return self.uri

    # end get_uuid


    @property
    def name_space(self):
        """Get name-space for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_name_space', None)

    # end name_space

    @name_space.setter
    def name_space(self, name_space):
        """Set name-space for yang-element.

        :param name_space: xsd:string object

        """
        self._name_space = name_space

    # end name_space

    def set_name_space(self, value):
        self.name_space = value

    # end set_name_space

    def get_name_space(self):
        return self.name_space

    # end get_name_space

    @property
    def element_name(self):
        """Get element-name for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_element_name', None)

    # end element_name

    @element_name.setter
    def element_name(self, element_name):
        """Set element-name for yang-element.

        :param element_name: xsd:string object

        """
        self._element_name = element_name

    # end element_name

    def set_element_name(self, value):
        self.element_name = value

    # end set_element_name

    def get_element_name(self):
        return self.element_name.replace(_XML_PREFIX, _CSP_PREFIX)
        # return self.element_name

    # end get_element_name

    @property
    def data_type(self):
        """Get element-name for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_data_type', None)

    # end element_name

    @data_type.setter
    def data_type(self, data_type):
        """Set element-name for yang-element.

        :param element_name: xsd:string object

        """
        self._data_type = data_type

    # end element_name

    def set_data_type(self, value):
        self.data_type = value

    # end set_element_name

    def get_data_type(self):
        return self.data_type

    # end get_element_name

    @property
    def leaf_ref_path(self):
        """Get element-name for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_leaf_ref_path', None)

    # end element_name

    @leaf_ref_path.setter
    def leaf_ref_path(self, path):
        """Set element-name for yang-element.

        :param element_name: xsd:string object

        """
        self._leaf_ref_path = path

    # end element_name

    def set_leaf_ref_path(self, value):
        self.leaf_ref_path = value

    # end set_element_name

    def get_leaf_ref_path(self):
        return self.leaf_ref_path

    # end get_element_name


    @property
    def element_value(self):
        """Get element-value for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_element_value', None)

    # end element_value

    @element_value.setter
    def element_value(self, element_value):
        """Set element-value for yang-element.

        :param element_value: xsd:string object

        """
        self._element_value = element_value

    # end element_value

    def set_element_value(self, value):
        self.element_value = value

    # end set_element_value

    def get_element_value(self):
        return self.element_value

    # end get_element_value

    @property
    def xpath(self):
        """Get xpath for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_xpath', None)

    # end xpath

    @xpath.setter
    def xpath(self, xpath):
        """Set xpath for yang-element.

        :param xpath: xsd:string object

        """
        self._xpath = xpath

    # end xpath

    def set_xpath(self, value):
        self.xpath = value

    # end set_xpath

    def get_xpath(self):
        return self.xpath

    # end get_xpath

    @property
    def yang_type(self):
        """Get yang-type for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_yang_type', None)

    # end yang_type

    @yang_type.setter
    def yang_type(self, yang_type):
        """Set yang-type for yang-element.

        :param yang_type: xsd:string object

        """
        self._yang_type = yang_type

    # end yang_type

    def set_yang_type(self, value):
        self.yang_type = value

    # end set_yang_type

    def get_yang_type(self):
        return self.yang_type

    # end get_yang_type

    @property
    def operation_type(self):
        """Get operation-type for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_operation_type', None)

    # end operation_type

    @operation_type.setter
    def operation_type(self, operation_type):
        """Set operation-type for yang-element.

        :param operation_type: xsd:string object

        """
        self._operation_type = operation_type

    # end operation_type

    def set_operation_type(self, value):
        self.operation_type = value

    # end set_operation_type

    def get_operation_type(self):
        return self.operation_type

    # end get_operation_type

    @property
    def key_names(self):
        """Get key-names for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_key_names', None)

    # end key_names

    @key_names.setter
    def key_names(self, key_names):
        """Set key-names for yang-element.

        :param key_names: xsd:string object

        """
        self._key_names = key_names

    # end key_names

    def set_key_names(self, value):
        self.key_names = value

    # end set_key_names

    def get_key_names(self):
        return self.key_names

    # end get_key_names

    @property
    def meta_data(self):
        """Get meta_data for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_meta_data', None)

    # end meta_data

    @meta_data.setter
    def meta_data(self, meta_data):
        """Set meta-data for yang-element.

        :param meta_data: xsd:string object

        """
        self._meta_data = meta_data

    # end meta_data

    def set_meta_data(self, value):
        self.meta_data = value

    # end set_meta_data

    def get_meta_data(self):
        return self.meta_data

    # end get_meta_data

    @property
    def id_perms(self):
        """Get id-perms for yang-element.

        :returns: IdPermsType object

        """
        return getattr(self, '_id_perms', None)

    # end id_perms

    @id_perms.setter
    def id_perms(self, id_perms):
        """Set id-perms for yang-element.

        :param id_perms: IdPermsType object

        """
        self._id_perms = id_perms

    # end id_perms

    def set_id_perms(self, value):
        self.id_perms = value

    # end set_id_perms

    def get_id_perms(self):
        return self.id_perms

    # end get_id_perms

    @property
    def perms2(self):
        """Get perms2 for yang-element.

        :returns: PermType2 object

        """
        return getattr(self, '_perms2', None)

    # end perms2

    @perms2.setter
    def perms2(self, perms2):
        """Set perms2 for yang-element.

        :param perms2: PermType2 object

        """
        self._perms2 = perms2

    # end perms2

    def set_perms2(self, value):
        self.perms2 = value

    # end set_perms2

    def get_perms2(self):
        return self.perms2

    # end get_perms2

    @property
    def display_name(self):
        """Get display-name for yang-element.

        :returns: xsd:string object

        """
        return getattr(self, '_display_name', None)

    # end display_name

    @display_name.setter
    def display_name(self, display_name):
        """Set display-name for yang-element.

        :param display_name: xsd:string object

        """
        self._display_name = display_name

    # end display_name

    def set_display_name(self, value):
        self.display_name = value

    # end set_display_name

    def get_display_name(self):
        return self.display_name

    # end get_display_name

    def get_child_elements(self):
        return getattr(self, 'children_elements', None)

    # end get_child_elements

    def add_child_element(self, yang_element):
        yang_elements = getattr(self, 'children_elements', None)
        yang_elements.add(yang_element)

    # end add_child_element

    def get_parent_element(self):
        yang_elements = self.get_parent_elements()
        if len(yang_elements) > 0:
            return list(yang_elements)[0]
        return yang_elements

    def get_parent_elements(self):
        yang_elements = getattr(self, 'parent_elements', None)
        return yang_elements

    # end get_parent_elements

    def add_parent_element(self, yang_element):
        yang_elements = getattr(self, 'parent_elements', None)
        if yang_element is not None:
            yang_elements.add(yang_element)

    # end add_parent_element

    def is_choice(self):
        return self.get_yang_type() == YangSchemaMgr.YANG_CHOICE

    def is_leaf(self):
        return self.get_yang_type() == YangSchemaMgr.YANG_LEAF

    def is_vertex(self):
        return self.get_yang_type() == YangSchemaMgr.YANG_CONTAINER or self.get_yang_type() == YangSchemaMgr.YANG_LIST

    def is_leaf_ref(self):
        return self._data_type == YangSchemaMgr.LEAFREF

    def _clone(self):
        clone_element = YangElement(self.name)
        clone_element.set_element_name(self.get_element_name())
        clone_element.set_element_value(self.get_element_value())
        clone_element.set_data_type(self.get_data_type())
        clone_element.set_yang_type(self.get_yang_type())
        clone_element.set_key_names(self.get_key_names())
        clone_element.set_leaf_ref_path(self.get_leaf_ref_path())
        clone_element.set_xpath(self.get_xpath())
        return clone_element

    def get_json(self, include_leaf_ref=False):
        if self.is_leaf() is not True:
            json_data = dict()
            list_fq_names = self.get_fq_name_list()
            for parent in self.get_parent_elements():
                # As of now parent will be always one
                json_data["parent_type"] = parent.get_element_name().replace('-', '_')
            json_data["fq_name"] = list_fq_names
            # json_data["id_perms"] = self.get_id_perms()
            # json_data["perms2"] = self.get_perms2()
            json_data["meta_data"] = self.get_meta_data()
            if self.get_display_name() is None:
                json_data["display_name"] = self.get_fq_name_str()
            else:
                json_data["display_name"] = self.get_display_name()
            json_data["uuid"] = self.get_uuid()

            for child in self.get_child_elements():
                if child.is_leaf():
                    child._set_json_data(json_data, include_leaf_ref)

            return json_data
        else:
            return None

    def _set_json_data(self, json_data, include_leaf_ref):
        if self.get_element_value() is not None:
            json_data[self.get_element_name()] = self.get_element_value()
            if include_leaf_ref:
                self._update_leaf_ref_json(json_data)

    def _update_leaf_ref_json(self, json_data):
        path = self.get_leaf_ref_path()
        level = (len(path) - len(path.replace('..', ''))) / 2
        level_path = path.replace(level * '../', '')
        index = level_path.index('/')
        ref_obj_name = level_path[:index]

        ref_obj = self.get_leaf_ref_object(self, level, ref_obj_name)

        if ref_obj is None:  # Wrong Input - For dynamic services case  # pragma: no cover
            return

        ref_json_data = ref_obj.get_json()

        data = dict()
        data['to'] = ref_json_data['fq_name']
        data['uuid'] = ref_json_data['uuid']

        json_data[ref_obj.element_name + '_refs'] = [data]

    def get_leaf_ref_object(self, yang_schema, level, ref_parent_element_name):
        if level == 0:
            for child in yang_schema.get_child_elements():
                if child.get_element_name() == ref_parent_element_name:
                    return child
            return None

        for parent in yang_schema.get_parent_elements():
            return self.get_leaf_ref_object(parent, level - 1, ref_parent_element_name)

    def trace_json(self, container=None):
        if container is None:
            container = dict()

        if self.is_leaf():
            container[self.get_element_name()] = self.get_element_value()
        else:
            childContainer = dict()
            container[self.get_element_name()] = childContainer
            for child in self.get_child_elements():
                res = child.trace_json(childContainer)
        return container

    def dump(self):  # pragma: no cover
        """Display yang-element object in compact form."""
        print '--------------------------------------------'
        print 'Name = ', self.get_fq_name()
        print 'Fq Name = ', self.get_fq_name_str()
        print 'Uuid = ', self.get_uuid()
        print 'Uri = ', self.get_uri()
        print 'Type = ', self.get_type()
        print 'Namespace = ', self.get_name_space()
        print 'Element Name = ', self.get_element_name()
        print 'Element Value = ', self.get_element_value()
        print 'XPath = ', self.get_xpath()
        print 'Yang Type = ', self.get_yang_type()
        print 'Operation Type = ', self.get_operation_type()
        print 'Key Names = ', self.get_key_names()
        print 'Display Name = ', self.get_display_name()
        print 'Meta Data = ', self.get_meta_data()
        print 'Id Perms = ', self.get_id_perms()
        print 'Perms 2 = ', self.get_perms2()

        for ea in self.get_parent_elements():
            print 'HAS Parent Elements = ', ea.get_fq_name_string()

        for ea in self.get_child_elements():
            print 'HAS Child Elements = ', ea.get_fq_name_string()
            print(ea.dump())


class YangSchemaMgr:
    ROUTE_KEYS = ["list", "container"]
    # RESOURCE_QUALIFIERS = ["module", "list", "container", "leaf", "leaf-list"]
    REPLACE_TYPES = ["uses", "type"]
    NAME_ATTRIB = "name"
    VALUE_ATTRIB = "value"
    URI_ATTRIB = "uri"
    DATE_ATTRIB = "date"

    YANG_NAMESPACE = "namespace"
    YANG_REVISION = "revision"
    YANG_GROUPING = "grouping"
    YANG_MODULE = "module"
    YANG_USES = "uses"
    YANG_LIST = "list"
    YANG_LEAF = "leaf"
    YANG_CHOICE = "choice"
    YANG_CASE = "case"
    YANG_CONTAINER = "container"
    YANG_KEY = "key"
    YANG_TYPEDEF = "typedef"
    YANG_TYPE = "type"
    LEAFREF = "leafref"
    PATH = "path"

    # This Yang Schema is a YangElement object holding the Schema information
    def get_yang_schema(self, yin_schema):
        xml_tree = etree.parse(BytesIO(yin_schema), etree.XMLParser())
        schema_element = xml_tree.getroot()
        default_ns = "{" + schema_element.nsmap[None] + "}"
        # Get elements to be replaced
        replaceable_elements = self._get_replaceable_elements(schema_element, default_ns)
        # Expand / replace the elements
        self._expand_schema(schema_element, replaceable_elements, default_ns)
        # Remove the replaced elements
        self._remove_replaced_elements(schema_element, default_ns)
        yang_schema = self._get_yang_schema(schema_element, default_ns)
        # Set the children fields
        self.set_children_fields(yang_schema)
        # Set the back ref and ref fields
        if yang_schema.get_element_name() != 'oc-device':
            # TODO Need to support leaf ref for dynamic yangs
            self.set_leaf_ref_fields(yang_schema)
        return yang_schema

    def set_children_fields(self, yang_schema):
        if yang_schema.is_vertex():
            for child in yang_schema.get_child_elements():
                if child.is_leaf() or child.is_leaf_ref():
                    yang_schema.prop_fields.add(unicode(child.get_element_name()))
                elif child.is_choice():
                    for sub_child in child.get_child_elements():
                        yang_schema.prop_fields.add(unicode(sub_child.get_element_name()))
                elif child.is_vertex():
                    child_type = (unicode(child.get_element_name()))
                    child_type = child_type.replace('-', '_')
                    child_types = child_type + "s"
                    yang_schema.children_fields.add(child_types)
                    yang_schema.children_field_types[child_types] = (child_type, False)

        for child in yang_schema.get_child_elements():
            self.set_children_fields(child)

    def set_leaf_ref_fields(self, yang_schema):
        if yang_schema.is_leaf_ref():
            path = yang_schema.get_leaf_ref_path()
            level = (len(path) - len(path.replace('..', ''))) / 2
            ref_levels = path.replace(level * '../', '')
            is_same_level_ref = False
            if '/' in ref_levels:
                index = ref_levels.index('/')
                ref_edge_name = ref_levels[:index]
            else:
                ref_edge_name = ref_levels
                is_same_level_ref = True
            back_ref_obj = self.get_ref_obj(yang_schema, level, ref_edge_name)
            # if is_same_level_ref:
            #     back_ref_obj.prop_fields.add(unicode(back_ref_obj.get_element_name()))
            if back_ref_obj is not None:
                ref_obj = None
                for elt in yang_schema.get_parent_elements():
                    ref_obj = elt
                    break
                # Set Dependencies - Set backref in immediate parent and Ref in Parent Element
                back_ref_key = unicode(ref_obj.element_name + '_back_refs')
                back_ref_obj.backref_fields.add(unicode(back_ref_key))
                back_ref_obj.backref_field_types[back_ref_key] = (ref_obj.element_name, 'None', False)
                ref_key = back_ref_obj.element_name + '_refs'
                ref_obj.ref_fields.add(unicode(ref_key))
                ref_obj.ref_field_types[ref_key] = (back_ref_obj.element_name, 'None', False)
                ref_obj.ref_field_metas[ref_key] = ref_obj.element_name + '-' + back_ref_obj.element_name

        for child in yang_schema.get_child_elements():
            self.set_leaf_ref_fields(child)

    def get_ref_obj(self, yang_schema, level, ref_parent_element_name=None):
        if level == 0:
            for child in yang_schema.get_child_elements():
                if child.get_element_name() == ref_parent_element_name:
                    return child
            return None

        for parent in yang_schema.get_parent_elements():
            return self.get_ref_obj(parent, level - 1, ref_parent_element_name)

    def _remove_replaced_elements(self, schema_element, default_ns):
        grouping_elements = schema_element.findall(default_ns + self.YANG_GROUPING)
        typedef_elements = schema_element.findall(default_ns + self.YANG_TYPEDEF)

        for grouping_element in grouping_elements:
            schema_element.remove(grouping_element)

        for typedef_element in typedef_elements:
            schema_element.remove(typedef_element)

    def _expand_schema(self, schema_element, replaceable_elements, default_ns):
        for child_schema in schema_element.getchildren():
            yang_type = child_schema.tag.replace(default_ns, "")
            if yang_type in self.REPLACE_TYPES:
                if yang_type == self.YANG_USES:
                    group_name = child_schema.get(self.NAME_ATTRIB)
                    key_name = self.YANG_GROUPING + group_name
                elif yang_type == self.YANG_TYPE:
                    typedef_name = child_schema.get(self.NAME_ATTRIB)
                    key_name = self.YANG_TYPEDEF + typedef_name

                if key_name in replaceable_elements:
                    child_elements = replaceable_elements[key_name]
                    cloned_elements = copy.deepcopy(child_elements)
                    schema_element.extend(cloned_elements)
                    schema_element.remove(child_schema)

            self._expand_schema(child_schema, replaceable_elements, default_ns)

    def _get_replaceable_elements(self, schema_element, default_ns):
        grouping_elements = schema_element.findall(default_ns + self.YANG_GROUPING)
        typedef_elements = schema_element.findall(default_ns + self.YANG_TYPEDEF)
        replace_dict = dict()
        for grouping_element in grouping_elements:
            group_name = self.YANG_GROUPING + grouping_element.get(self.NAME_ATTRIB)
            replace_dict[group_name] = grouping_element.getchildren()

        for typedef_element in typedef_elements:
            typedef_name = self.YANG_TYPEDEF + typedef_element.get(self.NAME_ATTRIB)
            replace_dict[typedef_name] = typedef_element

        return replace_dict

    def _get_yang_schema(self, schema_element, default_ns, parent_element=None):

        yang_element = YangElement(name=schema_element.tag)
        yang_type = schema_element.tag.replace(default_ns, "")
        yang_element.set_yang_type(yang_type)

        if schema_element.get(self.NAME_ATTRIB) is not None:
            element_name = schema_element.get(self.NAME_ATTRIB)

            if yang_type == self.YANG_LEAF:
                data_type_elt = schema_element.find(default_ns + self.YANG_TYPE)
                yang_element.set_data_type(data_type_elt.get(self.NAME_ATTRIB))

            if yang_element.is_leaf_ref():
                path = schema_element.find(default_ns + self.YANG_TYPE).find(default_ns + self.PATH).get(
                    self.VALUE_ATTRIB)
                yang_element.set_leaf_ref_path(path)

            yang_element.set_element_name(element_name)
            yang_element.set_xpath(element_name)
            yang_element.set_key_names(element_name)

            if parent_element is not None:
                yang_element.add_parent_element(parent_element)
                parent_element.add_child_element(yang_element)
                if parent_element.get_yang_type() == self.YANG_CHOICE:
                    # For choice without case statement, the "choice" element is not included in xpath
                    xpath = parent_element.get_parent_element().get_xpath() + "\\" + yang_element.get_element_name()
                elif parent_element.get_yang_type() == self.YANG_CASE:
                    # For choice with case statement, the "choice" and "case" element both are not included in xpath
                    xpath = parent_element.get_parent_element().get_parent_element().get_xpath() + "\\" + yang_element.get_element_name()
                else:
                    xpath = parent_element.get_xpath() + "\\" + yang_element.get_element_name()
                yang_element.set_xpath(xpath)

            # List has keys
            if yang_type == self.YANG_LIST:
                key = default_ns + self.YANG_KEY
                key_element = schema_element.find(key)
                if key_element is None:
                    logger.error('This list element does not have key ****: ' + element_name + ' **** xpath ' + xpath)
                else:
                    key_names = key_element.get(self.VALUE_ATTRIB)
                    yang_element.set_key_names(key_names)

            # For caching
            YANG_SCHEMAS_OBJS[yang_element.get_xpath()] = yang_element._clone()
            for child_schema in schema_element.getchildren():
                self._get_yang_schema(child_schema, default_ns, yang_element)

        return yang_element

    @staticmethod
    def get_yang_schema_element(xpath):
        if xpath in YANG_SCHEMAS_OBJS:
            return YANG_SCHEMAS_OBJS[xpath]
        else:
            return None


class DynamicRouteNotificationHandler(object):
    def __init__(self, server):
        self.server = server

    def get_ampq_broker_url(self):
        rabbit_user = cfg.CONF.rabbit_user
        rabbit_pwd = cfg.CONF.rabbit_password
        rabbit_host = cfg.CONF.rabbit_server
        rabbit_port = cfg.CONF.rabbit_port

        url = 'amqp://{0}:{1}@{2}//'.format(rabbit_user, rabbit_pwd, rabbit_host) if ':' in rabbit_host \
            else 'amqp://{0}:{1}@{2}:{3}//'.format(rabbit_user, rabbit_pwd, rabbit_host, rabbit_port)

        logger.info('RabbitMQ URL ' + url)
        return url

    def send_new_route_notification(self, route):  # pragma: no cover
        rabbitmq_url = self.get_ampq_broker_url()
        connection = Connection(rabbitmq_url)

        payload = {'route': route}

        with producers[connection].acquire(block=True) as producer:
            producer.publish(payload,
                             exchange=route_exchange,
                             declare=[route_exchange],
                             routing_key=route_key)
        return

    def start_consumer(self):
        class Worker(threading.Thread):
            def run(this):
                url = self.get_ampq_broker_url()
                with BrokerConnection(url) as connection:
                    try:
                        DynamicRouteListener(connection, self.server).run()
                    except Exception as e:
                        logger.error('Stopping Worker Thread for Route Listener ', e)

        Worker().start()


class DynamicRouteListener(ConsumerMixin):
    def __init__(self, connection, server):
        self.connection = connection
        self.server = server

    def get_consumers(self, Consumer, channel):
        return [Consumer(route_queue, callbacks=[self.on_message])]

    def on_message(self, body, message):
        logger.info("RECEIVED MSG - body: %r" % (body,))
        logger.info("RECEIVED MSG - message: %r" % (message,))

        try:
            route = body['route']
            self.server._generate_dynamic_resource_crud_methods(route)
            self.server._generate_dynamic_resource_crud_uri(route)
        except Exception as e:
            logger.error('Exception while installing new routes ', e)

        message.ack()


class ZNodeLockError(Exception):
    def __init__(self, operation, path):
        err_msg = "The current object '" + path + "' is already locked, so requested '" + operation + "' operation can't be performed."
        self.message = err_msg

    def get_message(self):
        return repr(self.message)
