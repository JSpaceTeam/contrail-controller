__author__ = 'hprakash'
#
# Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
#

import logging
from app_cfg_server.server_core.vnc_server_base import VncApiServerBase

logger = logging.getLogger(__name__)
import os
import xmltodict
import commands
import bottle
import functools
from bottle import request
import traceback
from cfgm_common.vnc_extensions import ExtensionManager
import cfgm_common
from pysandesh.gen_py.sandesh.ttypes import SandeshLevel
from app_cfg_server.server_core.context import get_request
import json
import copy
from lxml import etree
from io import BytesIO
from cfgm_common import utils
from app_cfg_server.server_core.vnc_cfg_base_type import Resource
from app_cfg_server.gen.resource_common import YangSchema
from app_cfg_server.gen.vnc_api_client_gen import SERVICE_PATH
from oslo_config import cfg

TEMP_DIR = "/tmp/yangs"
TEMP_ES_DIR = "/tmp/yangs/es"
SCHEMA_OBJ_TYPE = "yang-schema"
SCHEMA_OBJ_MODEL = "yin_schema"
OPERATION = "operation"
META_DATA = "meta-data"
DEVICE = "device"
DEVICE_ID = "device-id"
XMLNS_TAG = "@xmlns"

_CREATE_OPERATION = 'create'
_DELETE_OPERATION = 'delete'
_UPDATE_OPERATION = 'update'
_REPLACE_OPERATION = 'replace'

_INSTALL_YANG = 'install-yang'
_ROUTE = 'route'

_WITH_CHILDS = 'children'


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

    def __init__(self, args_str=None):
        super(VncApiDynamicServerBase, self).__init__(args_str)
        self._load_dynamic_extensions()
        self._initialize_dynamic_resources_from_db()

    # end __init__

    def _initialize_dynamic_resources_from_db(self):
        try:
            (ok, results, total) = self._db_conn.dbe_list(SCHEMA_OBJ_TYPE)
            obj_ids_list = [{'uuid': obj_uuid} for _, obj_uuid in results]
            (ok, results) = self._db_conn.dbe_read_multi(SCHEMA_OBJ_TYPE, obj_ids_list)

            for result in results:
                route_name = result['module_name']
                self._generate_dynamic_resource_crud_methods(route_name)
                self._generate_dynamic_resource_crud_uri(route_name)
                if 'es_schema' in result:
                    es_schema = result['es_schema']
                    self.init_es_schema(route_name, es_schema)
        except Exception as e:
            print(traceback.format_exc())
            err_msg = cfgm_common.utils.detailed_traceback()
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
            # print yang_content
            if not os.path.exists(TEMP_DIR):
                os.makedirs(TEMP_DIR)
            file_name = TEMP_DIR + "/" + module_name
            file_obj = open(file_name, 'w')
            file_obj.write(yang_content)
            file_obj.close()
            # TODO Set the path before compiling
            # prefix = "pyang -p " + yang_dir + " -f yin "
            pyang_cmd_prefix = "pyang -f yin "
            pyang_cmd = pyang_cmd_prefix + file_name
            yin_schema = commands.getoutput(pyang_cmd)
            xml_tree = etree.parse(BytesIO(yin_schema), etree.XMLParser())
            module_element = xml_tree.getroot()
            default_ns = "{" + module_element.nsmap[None] + "}"
            module_name = module_element.get(YangSchemaMgr.NAME_ATTRIB)
            module_name_space = module_element.find(default_ns + YangSchemaMgr.YANG_NAMESPACE).get(YangSchemaMgr.URI_ATTRIB)
            module_revision = module_element.find(default_ns + YangSchemaMgr.YANG_REVISION).get(YangSchemaMgr.DATE_ATTRIB)
            module_json_schema = json.dumps(xmltodict.parse(yin_schema))
            module_yin_schema = yin_schema

            # Creating Elastic Search Schema
            es_schema = ''
            try:
                es_schema = self.update_es_schema(module_name, file_name)
            except Exception as e:
                pass

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

            req[yang_schema.get_type()] = schema_dict
            response = self.http_resource_create(yang_schema.get_type())
            self._generate_dynamic_resource_crud_methods(module_name)
            self._generate_dynamic_resource_crud_uri(module_name)
            response[yang_schema.get_type()]["dynamic-uri"] = SERVICE_PATH + "/" + module_name
            print ("New dynamic uri created ****************:" + SERVICE_PATH + "/" + module_name)
            return response

        except KeyError:
            bottle.abort(400, 'invalid request, key "%s" not found')
        except cfgm_common.exceptions.HttpError as he:
            raise he
        except Exception as e:
            print(traceback.format_exc())
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log("Exception in adding dynamic routes : %s" % (err_msg),
                            level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

    # end install_yang

    def update_es_schema(self, module_name, file_name):
        try:
            print ('Create Elastic Search Schema -- input  ', module_name)

            if not os.path.exists(TEMP_ES_DIR):
                os.makedirs(TEMP_ES_DIR)

            # Copy ES Yang Plugin
            src = os.getcwd() + '/server_core/gesm.py'
            copy_cmd = 'cp %s %s' % (src, TEMP_ES_DIR)
            commands.getoutput(copy_cmd)

            pyang_cmd = "pyang --plugindir %s %s -f gesm --gesm-output %s"
            cmd = pyang_cmd % (TEMP_ES_DIR, file_name, TEMP_ES_DIR)

            print ('Command executed ', cmd)
            commands.getoutput(cmd)

            with open(TEMP_ES_DIR + '/%s.mapping.json' % (module_name)) as file:
                file_content = file.read()

            print ('Elastic Search Schema File Content - ', file_content)

            self.init_es_schema(module_name, file_content)
        except Exception as e:
            print e

        return file_content

    # end update_es_schema

    def is_es_enabled(self):
        return cfg.CONF.elastic_search.search_enabled

    def init_es_schema(self, module_name, es_schema_mapping):
        try:
            if self.is_es_enabled():
                es_schema = json.loads(es_schema_mapping)
                print ('es_schema string - ', str(es_schema))

                if module_name in es_schema:
                    mapping = es_schema[module_name]

                _index_client = self._db_conn._search_db._index_client
                _index = self._db_conn._search_db._index

                def _print_mappings(index, doc_type):
                    return _index_client.get_mapping(index=_index, doc_type=_doc_type)

                # Exising Mapping for the doc type
                for _doc_type, _mapping in mapping['mappings'].iteritems():
                    _doc_type = str(_doc_type)

                    print ('Doc Type %s Existing Mapping %s' % (_doc_type, _print_mappings(_index, _doc_type)))

                    # Update Mapping
                    _index_client.put_mapping(index=_index, doc_type=_doc_type, body=_mapping)

                    print ('Doc Type %s Updated Mapping %s' % (_doc_type, _print_mappings(_index, _doc_type)))

                    # Update in the HAPI Server Index Map
                    self._db_conn._search_db._mapped_doc_types.append(_doc_type)
            else:
                print 'Elastic Search is disabled'
        except Exception as e:
            print e
            # end init_es_schema

    def get_req_json_obj(self):
        return get_request().json

    def get_req_query_obj(self):
        return get_request().query.dict

    def apply_to_children(self):
        if _WITH_CHILDS in self.get_req_query_obj():
            children = self.get_req_query_obj()[_WITH_CHILDS]
            if "true" in children:
                return True
        return False

    def http_dynamic_resource_create(self, resource_type):
        print ('New Route - http_dynamic_resource_create method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        # obj_dict = get_request().json[resource_type]
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_create", obj_type, obj_dict)
        res_obj_dict = dict()
        try:
            # TODO Read from cache (XPATH is causing the issue)
            yang_schema = self.get_yang_schema(obj_type)
            if self.get_resource_class(obj_type) is None:
                self.set_dynamic_resource_classes(yang_schema)

            yang_element = self.get_yang_element(obj_dict, yang_schema)
            self._dynamic_resource_create(yang_element)
            res_obj_dict['uuid'] = yang_element.uuid
            res_obj_dict["uri"] = yang_element.uri
            res_obj_dict["fq_name"] = yang_element.fq_name
        except cfgm_common.exceptions.HttpError as he:
            raise he
        except Exception:
            err_msg = 'Error in http_dynamic_resource_create for %s' % (obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            # print(err_msg)
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)

        self._invoke_dynamic_extension("post_dynamic_resource_create", obj_type, obj_dict)
        return {resource_type: res_obj_dict}

    def http_dynamic_resource_read(self, resource_type, id):
        print ('New Route - http_dynamic_resource_read method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        self._invoke_dynamic_extension("pre_dynamic_resource_read", obj_type, id)
        if self.get_resource_class(obj_type) is None:
            yang_schema = self.get_yang_schema(obj_type)
            self.set_dynamic_resource_classes(yang_schema)

        res_obj_dict = self.http_resource_read(resource_type, id)
        # If children = true in query parameter, then read all the children
        if self.apply_to_children():
            # Recursively read all the children
            res_obj_dict = self._read_child_resources(res_obj_dict, obj_type)
        self._invoke_dynamic_extension("post_dynamic_resource_read", obj_type, res_obj_dict)
        return res_obj_dict

    def http_dynamic_resource_update(self, resource_type, id):
        print ('New Route - http_dynamic_resource_update method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_update", obj_type, obj_dict)
        res_obj_dict = dict()
        try:
            yang_schema = self.get_yang_schema(obj_type)
            if self.get_resource_class(obj_type) is None:
                self.set_dynamic_resource_classes(yang_schema)

            yang_element = self.get_yang_element(obj_dict, yang_schema)
            self._dynamic_resource_update(yang_element)
            res_obj_dict['uuid'] = yang_element.uuid
            res_obj_dict["uri"] = yang_element.uri
        except cfgm_common.exceptions.HttpError as he:
            raise he
        except Exception:
            err_msg = 'Error in http_dynamic_resource_update for %s' % (obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            # print(err_msg)
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
            raise cfgm_common.exceptions.HttpError(500, err_msg)
        self._invoke_dynamic_extension("post_dynamic_resource_update", obj_type, obj_dict)
        return res_obj_dict

    def http_dynamic_resource_patch(self, resource_type, id):
        print ('New Route - http_dynamic_resource_patch method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        obj_dict = self.get_req_json_obj()
        self._invoke_dynamic_extension("pre_dynamic_resource_patch", obj_type, obj_dict)
        if self.get_resource_class(obj_type) is None:
            yang_schema = self.get_yang_schema(obj_type)
            self.set_dynamic_resource_classes(yang_schema)

        # TODO Patch is not yet implemented
        self._invoke_dynamic_extension("post_dynamic_resource_patch", obj_type, obj_dict)

    def http_dynamic_resource_delete(self, resource_type, id):
        print ('New Route - http_dynamic_resource_delete method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        self._invoke_dynamic_extension("pre_dynamic_resource_delete", obj_type, id)
        if self.get_resource_class(obj_type) is None:
            yang_schema = self.get_yang_schema(obj_type)
            self.set_dynamic_resource_classes(yang_schema)
        # If children = true in query parameter, then delete all the children
        if self.apply_to_children():
            res_obj_dict = self.http_resource_read(resource_type, id)
            # Recursively delete all the children first
            self._delete_child_resources(res_obj_dict, obj_type)
        # Now delete the parent
        self.http_resource_delete(resource_type, id)
        self._invoke_dynamic_extension("post_dynamic_resource_delete", obj_type, id)

    def http_dynamic_resource_list(self, resource_type):
        print ('New Route - http_dynamic_resource_list method ', resource_type)
        # obj_type = resource_type.replace('-', '_')
        obj_type = resource_type
        if self.get_resource_class(obj_type) is None:
            yang_schema = self.get_yang_schema(obj_type)
            self.set_dynamic_resource_classes(yang_schema)
        res_obj_dict = self.http_resource_list(resource_type)
        res_list = res_obj_dict[resource_type]
        # If children = true in query parameter, then list all the children
        if self.apply_to_children():
            res_new_list = list()
            for res in res_list:
                res_obj = self.http_dynamic_resource_read(resource_type, res["uuid"])
                res_new_list.append(res_obj[resource_type])
            res_obj_dict[resource_type] = res_new_list
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

    def set_dynamic_resource_classes(self, parent_yang_element):
        obj_type = parent_yang_element.get_element_name()
        if parent_yang_element.is_vertex():
            parent_yang_element.set_all_fields()
            resource_type = parent_yang_element.get_element_name()
            camel_name = cfgm_common.utils.CamelCase(resource_type)
            r_class_name = '%sDynamicServer' % (camel_name)
            common_class = parent_yang_element.__class__
            r_class = type(r_class_name, (Resource, common_class, object), {})
            self.set_resource_class(obj_type, r_class)
        for element in parent_yang_element.get_child_elements():
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

    # end _load_extensions

    def _invoke_dynamic_extension(self, method_name, obj_type, obj_dict):
        try:
            params = dict()
            params['server_obj'] = self
            params['query_params'] = self.get_req_query_obj()
            self._extension_mgrs['dynamicResourceApi'].map_method(method_name, obj_dict, **params)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except cfgm_common.exceptions.HttpError:
            raise
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

    def _dynamic_resource_patch(self, yang_element, operation, parent=None):
        if not yang_element.is_vertex():
            return
        if operation == _DELETE_OPERATION:
            self._resource_delete(yang_element, parent)
            # TODO as of now, returning. When ref-edge support comes, does this need to handle ref-edges?
            return
        if operation == _CREATE_OPERATION:
            self._resource_create(yang_element, parent)
        elif operation == _UPDATE_OPERATION:
            self._resource_update(yang_element, parent)

        for child in yang_element.get_child_elements():
            self._dynamic_resource_update(child, operation if operation == _DELETE_OPERATION else child.operation_type,
                                          yang_element)
            # TODO Add support for ref-edges

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

    def _resource_update(self, element, parent):
        resource_type = element.element_name
        fqn_name = element.get_fq_name_list()
        uuid = self._get_id_from_fq_name(resource_type, fqn_name)
        element.set_uuid(uuid)
        if parent is not None:
            element.parent_uuid = parent.get_uuid()
        json_data = element.get_json()
        self.get_req_json_obj()[resource_type] = json_data
        content = self.http_resource_update(resource_type, uuid)
        obj_dict = content[resource_type]
        element.uuid = obj_dict['uuid']
        element.uri = obj_dict["uri"]

    def _get_id_from_fq_name(self, resource_type, fq_name):
        self.get_req_json_obj()['type'] = resource_type
        self.get_req_json_obj()['fq_name'] = fq_name
        uuid = self.fq_name_to_id_http_post()
        return uuid['uuid']

    def _read_child_resources(self, res_dict, obj_type):
        r_class = self.get_resource_class(obj_type)
        child_fields = r_class.children_fields
        for child_field in child_fields:
            child_obj_type = child_field
            if child_obj_type in res_dict[obj_type]:
                res_child_objs = res_dict[obj_type][child_obj_type]
                for res_child_obj in res_child_objs:
                    child_uuid = res_child_obj["uuid"]
                    # Removing the last "s" from the child object types
                    child_obj_type = child_obj_type[:-1]
                    child_obj_db = self.http_resource_read(child_obj_type, child_uuid)
                    # Remove the below keys as they are not relevant as of now
                    if child_obj_db is not None:
                        child_obj_db_dict = child_obj_db[child_obj_type]
                        child_obj_db_dict.__delitem__("uri")
                        child_obj_db_dict.__delitem__("parent_uri")
                        res_child_obj[child_obj_type] = child_obj_db_dict
                        res_child_obj.__delitem__("uri")
                        res_child_obj.__delitem__("to")
                        res_child_obj.__delitem__("uuid")
                        self._read_child_resources(child_obj_db, child_obj_type)
        return res_dict

    def _delete_child_resources(self, res_dict, obj_type):
        r_class = self.get_resource_class(obj_type)
        child_fields = r_class.children_fields
        for child_field in child_fields:
            child_obj_type = child_field
            if child_obj_type in res_dict[obj_type]:
                res_child_objs = res_dict[obj_type][child_obj_type]
                for res_child_obj in res_child_objs:
                    child_uuid = res_child_obj["uuid"]
                    # Removing the last "s" from the child object types
                    child_obj_type = child_obj_type[:-1]
                    child_obj_db = self.http_resource_read(child_obj_type, child_uuid)
                    if child_obj_db is not None:
                        self._delete_child_resources(child_obj_db, child_obj_type)
                        self.http_resource_delete(child_obj_type, res_child_obj["uuid"])

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

    def get_yang_schema(self, obj_type):
        # TODO Get all the module names once augmentation is supported
        yin_schema = self._get_yang_schema(obj_type)
        schema_mgr = YangSchemaMgr()
        yang_schema = schema_mgr.get_yang_schema(str(yin_schema))
        return yang_schema

    def get_yang_element(self, json_data, yang_schema):
        # Convert string object to dict
        if type(json_data) is dict:
            json_data_dict = json_data
        else:
            json_data_dict = json.loads(str(json_data))
        name_space_dict = self._get_name_space(json_data_dict)
        xml_data = self._json_to_xml(json_data_dict)
        xml_data = self._update_name_space(xml_data, name_space_dict)
        xml_tree = etree.parse(BytesIO(xml_data), etree.XMLParser())
        root_element = xml_tree.getroot()
        module_name = root_element.tag

        yang_element = YangElement(name=root_element.tag)
        yang_element = self._get_yang_element(module_name, yang_schema, xml_tree.getroot(), yang_element)
        return yang_element

    def _get_yang_element(self, module_name, yang_schema, element, yang_element, parent_element=None):

        yang_element.set_element_name(element.tag)
        yang_element.set_element_value(element.text)
        yang_element.set_operation_type(element.get(OPERATION))
        yang_element.set_xpath(module_name + "\\" + element.tag)
        if parent_element is not None:
            yang_element.add_parent_element(parent_element)
            parent_element.add_child_element(yang_element)
            xpath = parent_element.get_xpath() + "\\" + yang_element.get_element_name()
            yang_element.set_xpath(xpath)

        keys, yang_type = self._get_yang_type(yang_element, yang_schema)
        yang_element.set_yang_type(yang_type)
        yang_element.set_key_names(keys)

        for child in element.getchildren():
            child_element = YangElement(name=child.tag)
            if child.tag == META_DATA:
                self._set_vertex_dependency(child, yang_element)
            elif child.tag == OPERATION:
                yang_element.set_operation_type(child.text)
            else:
                self._get_yang_element(module_name, yang_schema, child, child_element, yang_element)

        return yang_element

    def _set_vertex_dependency(self, element, parent_element):
        meta_data = ""
        if element.getchildren() is not None:
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

    def _get_yang_type(self, yang_element, yang_schema):
        xpath = yang_element.get_xpath()
        yang_element_schema = YangSchemaMgr.get_yang_schema_element(xpath, yang_schema)
        if yang_element_schema is not None:
            keys = yang_element_schema.get_key_names()
            yang_type = yang_element_schema.get_yang_type()
            return keys, yang_type
        else:
            raise AttributeError(
                'Schema element not found for ' + yang_element.get_element_name() + ' of ' + xpath)

    def _get_name_space(self, json_data_dict, name_space_dict=None):
        if name_space_dict is None:
            name_space_dict = dict()
        for key in json_data_dict.keys():
            if type(json_data_dict[key]) is dict:
                self._get_name_space(json_data_dict[key], name_space_dict)
            else:
                if key.startswith(XMLNS_TAG):
                    name_space_dict[key] = json_data_dict[key]
                    json_data_dict.__delitem__(key)
        return name_space_dict

    def _update_name_space(self, json_data_xml, name_space_dict):
        # TODO Find a better way to implement this
        ns_list = list()
        for key in name_space_dict.keys():
            value = name_space_dict[key]
            key = key.replace("@", '')
            ns_list.append(key + "=" + "\"" + value + "\"")
        if len(ns_list) > 0:
            ns = ' '.join(ns_list)
            ns = ' ' + ns + ">"
            json_data_xml = json_data_xml.replace(">", ns, 1)
        return str(json_data_xml)

    def _json_to_xml(self, json_obj, line_padding=""):
        result_list = list()
        json_obj_type = type(json_obj)

        if json_obj_type is list:
            for sub_elem in json_obj:
                result_list.append(self._json_to_xml(sub_elem, line_padding))

            return "".join(result_list)

        if json_obj_type is dict:
            for tag_name in json_obj:
                sub_obj = json_obj[tag_name]
                tag_name = tag_name.replace("@", "")
                result_list.append("%s<%s>" % (line_padding, tag_name))
                result_list.append(self._json_to_xml(sub_obj, "" + line_padding))
                result_list.append("%s</%s>" % (line_padding, tag_name))

            return "".join(result_list)

        return "%s%s" % (line_padding, json_obj)


# end class VncApiServer

class DynamicResourceApiGen(object):
    def pre_dynamic_resource_create(self, resource_dict, **kwargs):
        """
        Method called before dynamic resource is created
        """
        pass

    # end pre_dynamic_resource_create

    def post_dynamic_resource_create(self, resource_dict, **kwargs):
        """
        Method called after dynamic resource is created
        """
        pass
        # end post_dynamic_resource_create

    def pre_dynamic_resource_update(self, resource_dict, **kwargs):
        """
        Method called before dynamic resource is updated
        """
        pass

    # end pre_dynamic_resource_update

    def post_dynamic_resource_update(self, resource_dict, **kwargs):
        """
        Method called after dynamic resource is updated
        """
        pass
        # end post_dynamic_resource_update

    def pre_dynamic_resource_read(self, resource_dict, **kwargs):
        """
        Method called before dynamic resource is read
        """
        pass

    # end pre_dynamic_resource_read

    def post_dynamic_resource_read(self, resource_dict, **kwargs):
        """
        Method called after dynamic resource is read
        """
        pass
        # end post_dynamic_resource_read

    def pre_dynamic_resource_delete(self, resource_dict, **kwargs):
        """
        Method called before dynamic resource is delete
        """
        pass

    # end pre_dynamic_resource_delete

    def post_dynamic_resource_delete(self, resource_dict, **kwargs):
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

    def __init__(self, name=None, element_name=None, id_perms=None, perms2=None, parent_obj=None, display_name=None,
                 *args, **kwargs):
        # type-independent fields
        self._type = name
        self._uuid = None
        self.name = name
        self.fq_name = [name]
        # self.children_fields = set([])
        self.children_elements = set([])
        self.parent_elements = set([])
        # self.parent_types = set([])
        # self.prop_fields = set([u'id_perms', u'perms2', u'display_name', u'meta_data'])
        self.add_parent_element(parent_obj)

        # set default values to property fields
        self._element_name = element_name
        self._name_space = None
        self._element_value = None
        self._xpath = None
        self._yang_type = None
        self._operation_type = None
        self._key_names = None
        self._meta_data = None

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
                if child.get_element_name() == self.get_key_names():
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
        return self.element_name

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

    def get_parent_elements(self):
        yang_elements = getattr(self, 'parent_elements', None)
        return yang_elements

    # end get_parent_elements

    def add_parent_element(self, yang_element):
        yang_elements = getattr(self, 'parent_elements', None)
        if yang_element is not None:
            yang_elements.add(yang_element)

    # end add_parent_element

    def is_leaf(self):
        return self.get_yang_type() == YangSchemaMgr.YANG_LEAF

    def is_vertex(self):
        return self.get_yang_type() == YangSchemaMgr.YANG_CONTAINER or self.get_yang_type() == YangSchemaMgr.YANG_LIST

    def get_json(self):
        if self.is_leaf() is not True:
            json_data = dict()
            list_fq_names = self.get_fq_name_list()
            for parent in self.get_parent_elements():
                # As of now parent will be always one
                json_data["parent_type"] = parent.get_element_name().replace('-', '_')
            json_data["fq_name"] = list_fq_names
            # json_data["id_perms"] = self.get_id_perms()
            # json_data["perms2"] = self.get_perms2()
            json_data["meta_data"] = self.get_name_space()
            if self.get_display_name() is None:
                json_data["display_name"] = self.get_fq_name_str()
            else:
                json_data["display_name"] = self.get_display_name()
            json_data["uuid"] = self.get_uuid()
            if self.get_element_value() is not None:
                json_data[self.get_element_name()] = self.get_element_value()
            for child in self.get_child_elements():
                if child.is_leaf() is True:
                    json_data[child.get_element_name()] = child.get_element_value()

            return json_data
        else:
            return None

    def set_all_fields(self):
        for child in self.get_child_elements():
            # TODO set backref fields once ref edge is supported
            if child.is_leaf():
                self.prop_fields.add(unicode(child.get_element_name()))
            elif child.is_vertex():
                child_type = (unicode(child.get_element_name()))
                child_type = child_type.replace('-', '_')
                child_types = child_type + "s"
                self.children_fields.add(child_types)
                self.children_field_types[child_types] = (child_type, False)

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
        print 'Uuid = ', self.uuid
        print 'Namespace = ', self.get_name_space()
        print 'Element Name = ', self.get_element_name()
        print 'Element Value = ', self.get_element_value()
        print 'XPath = ', self.get_xpath()
        print 'Yang Type = ', self.get_yang_type()
        print 'Operation Type = ', self.get_operation_type()
        print 'Key Names = ', self.get_key_names()
        print 'Display Name = ', self.get_display_name()

        for ea in self.get_parent_elements():
            print 'HAS Parent Elements = ', ea.get_fq_name_str()

        for ea in self.get_child_elements():
            print 'HAS Child Elements = ', ea.get_fq_name_str()
            print(ea.dump())


class YangSchemaMgr:
    ROUTE_KEYS = ["list", "container"]
    RESOURCE_QUALIFIERS = ["module", "list", "container", "leaf", "leaf-list"]
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
    YANG_CONTAINER = "container"
    YANG_KEY = "key"
    YANG_TYPEDEF = "typedef"
    YANG_TYPE = "type"

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
        return yang_schema

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

        yang_element = YangElement(schema_element.tag)
        yang_type = schema_element.tag.replace(default_ns, "")
        yang_element.set_yang_type(yang_type)

        if yang_type in self.RESOURCE_QUALIFIERS:
            if schema_element.get(self.NAME_ATTRIB) is not None:
                element_name = schema_element.get(self.NAME_ATTRIB)
                yang_element.set_element_name(element_name)
                yang_element.set_xpath(element_name)
                yang_element.set_key_names(element_name)
                # print "Yang Type :", yang_type
                # print "Element Name :", yang_element.get_element_name()
                if parent_element is not None:
                    yang_element.add_parent_element(parent_element)
                    parent_element.add_child_element(yang_element)
                    xpath = parent_element.get_xpath() + "\\" + yang_element.get_element_name()
                    yang_element.set_xpath(xpath)

                # List has keys
                if yang_type == self.YANG_LIST:
                    key = default_ns + self.YANG_KEY
                    key_element = schema_element.find(key)
                    key_names = key_element.get(self.VALUE_ATTRIB)
                    yang_element.set_key_names(key_names)

                for child_schema in schema_element.getchildren():
                    self._get_yang_schema(child_schema, default_ns, yang_element)

        return yang_element

    @staticmethod
    def get_yang_schema_element(xpath, yang_schema):
        yang_dict = YangSchemaMgr.get_yang_schema_elements([xpath], yang_schema)
        if xpath in yang_dict:
            return yang_dict[xpath]
        else:
            return None

    @staticmethod
    def get_yang_schema_elements(xpaths, yang_schema, yang_dict=None):
        if yang_dict is None:
            yang_dict = dict()
        # Schema xpath starts  with the module name but the data xpath don't have module name
        if yang_schema.get_xpath() in xpaths:
            clone_obj = copy.copy(yang_schema)
            yang_dict[yang_schema.get_xpath()] = clone_obj
        for child_schema in yang_schema.get_child_elements():
            YangSchemaMgr.get_yang_schema_elements(xpaths, child_schema, yang_dict)
        return yang_dict
