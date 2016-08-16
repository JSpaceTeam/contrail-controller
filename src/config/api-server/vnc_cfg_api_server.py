#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#
"""
This is the main module in vnc_cfg_api_server package. It manages interaction
between http/rest, address management, authentication and database interfaces.
"""
from gevent import monkey
monkey.patch_all()
from memoized import memoized
from cfgm_common.stats_collector import collect_stats, construct_stats_collector
from gevent import hub
# from neutron plugin to api server, the request URL could be large. fix the const
# fix the const
import gevent.pywsgi
gevent.pywsgi.MAX_REQUEST_LINE = 65535

import sys
reload(sys)
sys.setdefaultencoding('UTF8')
import functools
import logging
import logging.config
import signal
import os
import re
import socket
from cfgm_common import jsonutils as json
import uuid
import copy
from pprint import pformat
from cStringIO import StringIO
from lxml import etree
from xml.sax.saxutils import quoteattr
from xml.sax.saxutils import escape
from oslo_config import cfg
#import GreenletProfiler
from gen.vnc_api_client_gen import SERVICE_PATH
from decimal import Decimal, InvalidOperation
from oslo_config.cfg import ArgsAlreadyParsedError
from cfgm_common.errorcodes import CommonException
logger = logging.getLogger(__name__)

"""
Following is needed to silence warnings on every request when keystone
    auth_token middleware + Sandesh is used. Keystone or Sandesh alone
    do not produce these warnings.

Exception AttributeError: AttributeError(
    "'_DummyThread' object has no attribute '_Thread__block'",)
    in <module 'threading' from '/usr/lib64/python2.7/threading.pyc'> ignored

See http://stackoverflow.com/questions/13193278/understand-python-threading-bug
for more information.
"""
import threading
threading._DummyThread._Thread__stop = lambda x: 42

CONFIG_VERSION = '1.0'

import bottle
bottle.BaseRequest.MEMFILE_MAX = 1024000

import utils
import context
from context import get_request, get_context, set_context
from context import ApiContext
try:
    import vnc_cfg_types
except:
    pass
from vnc_cfg_ifmap import VncDbClient, SearchUtil

from cfgm_common import ignore_exceptions, imid
from cfgm_common.uve.vnc_api.ttypes import VncApiCommon, VncApiConfigLog,\
    VncApiError
from cfgm_common import illegal_xml_chars_RE
from sandesh_common.vns.ttypes import Module
from sandesh_common.vns.constants import ModuleNames, Module2NodeType,\
    NodeTypeNames, INSTANCE_ID_DEFAULT, API_SERVER_DISCOVERY_SERVICE_NAME,\
    IFMAP_SERVER_DISCOVERY_SERVICE_NAME

from provision_defaults import Provision
from vnc_quota import *
from gen.resource_xsd import *
from gen.resource_common import *
from gen.vnc_api_client_gen import all_resource_type_tuples
import cfgm_common
from cfgm_common.utils import cgitb_hook
from cfgm_common.rest import LinkObject, hdr_server_tenant
from cfgm_common.exceptions import *
from cfgm_common.vnc_extensions import ExtensionManager
import gen.resource_xsd
import vnc_addr_mgmt
import vnc_auth
import vnc_auth_keystone
import vnc_perms
import vnc_rbac
from cfgm_common import vnc_cpu_info
from cfgm_common.vnc_api_stats import log_api_stats

from pysandesh.sandesh_base import *
from pysandesh.gen_py.sandesh.ttypes import SandeshLevel
import discoveryclient.client as client
# from gen_py.vnc_api.ttypes import *
import netifaces
from pysandesh.connection_info import ConnectionState
try:
    from cfgm_common.uve.nodeinfo.ttypes import NodeStatusUVE, \
        NodeStatus
except:
    pass

from sandesh.discovery_client_stats import ttypes as sandesh
from sandesh.traces.ttypes import RestApiTrace
from vnc_bottle import get_bottle_server
from gen.vnc_api_client_gen import get_obj_type_to_db_type
_WEB_HOST = '0.0.0.0'
_WEB_PORT = 8082
_ADMIN_PORT = 8095

_ACTION_RESOURCES = [
    {'uri': '/prop-collection-get', 'link_name': 'prop-collection-get',
     'method': 'GET', 'method_name': 'prop_collection_http_get'},
    {'uri': '/prop-collection-update', 'link_name': 'prop-collection-update',
     'method': 'POST', 'method_name': 'prop_collection_update_http_post'},
    {'uri': '/ref-update', 'link_name': 'ref-update',
     'method': 'POST', 'method_name': 'ref_update_http_post'},
    {'uri': '/ref-relax-for-delete', 'link_name': 'ref-relax-for-delete',
     'method': 'POST', 'method_name': 'ref_relax_for_delete_http_post'},
    {'uri': '/fqname-to-id', 'link_name': 'name-to-id',
     'method': 'POST', 'method_name': 'fq_name_to_id_http_post'},
    {'uri': '/id-to-fqname', 'link_name': 'id-to-name',
     'method': 'POST', 'method_name': 'id_to_fq_name_http_post'},
    # ifmap-to-id only for ifmap subcribers using rest for publish
    {'uri': '/ifmap-to-id', 'link_name': 'ifmap-to-id',
     'method': 'POST', 'method_name': 'ifmap_to_id_http_post'},
    {'uri': '/useragent-kv', 'link_name': 'useragent-keyvalue',
     'method': 'POST', 'method_name': 'useragent_kv_http_post'},
    {'uri': '/db-check', 'link_name': 'database-check',
     'method': 'POST', 'method_name': 'db_check'},
    {'uri': '/fetch-records', 'link_name': 'fetch-records',
     'method': 'POST', 'method_name': 'fetch_records'},
    {'uri': '/start-profile', 'link_name': 'start-profile',
     'method': 'POST', 'method_name': 'start_profile'},
    {'uri': '/stop-profile', 'link_name': 'stop-profile',
     'method': 'POST', 'method_name': 'stop_profile'},
    {'uri': '/list-bulk-collection', 'link_name': 'list-bulk-collection',
     'method': 'POST', 'method_name': 'list_bulk_collection_http_post'},
    {'uri': '/obj-perms', 'link_name': 'obj-perms',
     'method': 'GET', 'method_name': 'obj_perms_http_get'},
    {'uri': '/chown', 'link_name': 'chown',
     'method': 'POST', 'method_name': 'obj_chown_http_post'},
    {'uri': '/chmod', 'link_name': 'chmod',
     'method': 'POST', 'method_name': 'obj_chmod_http_post'},
    {'uri': '/multi-tenancy', 'link_name': 'multi-tenancy',
     'method': 'PUT', 'method_name': 'mt_http_put'},
    {'uri': '/multi-tenancy-with-rbac', 'link_name': 'rbac',
     'method': 'PUT', 'method_name': 'rbac_http_put'},
]


@bottle.error(400)
def error_400(err):
    return err.body
# end error_400


@bottle.error(403)
def error_403(err):
    return err.body
# end error_403


@bottle.error(404)
def error_404(err):
    return err.body
# end error_404


@bottle.error(409)
def error_409(err):
    return err.body
# end error_409

@bottle.error(412)
def error_412(err):
    return err.body
# end error_412

@bottle.error(500)
def error_500(err):
    return err.body
# end error_500


@bottle.error(503)
def error_503(err):
    return err.body
# end error_503


class OWERTYPE(object):
    DEFAULT = 1
    FQ_PROJECT = 2
    CUSTOMIZED = 3

class SHARETYPE(object):
    GLOBAL_SHARED = 1
    FQ_TENANT_SHARED = 2

    @classmethod
    def allowed(cls):
        return [1, 2]

# Parse config for olso configs. Try to move all config parsing to oslo cfg
elastic_search_group = cfg.OptGroup(name='elastic_search', title='ELastic Search Options')
cfg.CONF.register_group(elastic_search_group)
elastic_search_opts = [
    cfg.BoolOpt(name='search_enabled', default=False),
    cfg.ListOpt('server_list',
                item_type=cfg.types.String(),
                default='127.0.0.1:9200',
                help="Multiple servers option"),
    cfg.BoolOpt(name='enable_sniffing', default=False,
                help="Enable connection sniffing for elastic search driver"),

    cfg.ListOpt('log_server_list',
                item_type=cfg.types.String(),
                default='127.0.0.1:9200',
                help="Multiple servers option for es log servers"),
    cfg.IntOpt(name='timeout', default=5, help="Default timeout in seconds for elastic search operations"),
    cfg.StrOpt(name='search_client', default=None, help="VncDBSearch client implementation"),
    cfg.StrOpt(name='update', choices=["partial", "script"], default="script", help="update type for elastic search"),
    cfg.IntOpt(name='number_of_shards', default=2),
    cfg.IntOpt(name='number_of_replicas', default=1)
]

for opt in elastic_search_opts:
    try:
        cfg.CONF.register_cli_opt(opt, group=elastic_search_group)
    except ArgsAlreadyParsedError:
        pass


class VncApiServer(object):
    """
    This is the manager class co-ordinating all classes present in the package
    """
    _INVALID_NAME_CHARS = set(':')
    _GENERATE_DEFAULT_INSTANCE = [
        'namespace',
        'project',
        'virtual_network', 'virtual-network',
        'network_ipam', 'network-ipam',
    ]
    def __new__(cls, *args, **kwargs):
        obj = super(VncApiServer, cls).__new__(cls, *args, **kwargs)
        if SERVICE_PATH:
            bottle.route('%s' % SERVICE_PATH, 'GET', obj.homepage_http_get)
        else:
            bottle.route('/', 'GET', obj.homepage_http_get)

        cls._generate_resource_crud_methods(obj)
        cls._generate_resource_crud_uri(obj)
        for act_res in _ACTION_RESOURCES:
            http_method = act_res.get('method', 'POST')
            method_name = getattr(obj, act_res['method_name'])
            uri = act_res['uri']
            if SERVICE_PATH:
                uri = '%s%s' % (SERVICE_PATH, uri)
            obj.route(uri, http_method, method_name)
        return obj
    # end __new__

    @classmethod
    def _validate_complex_type(cls, dict_cls, dict_body, is_update = False):
        if dict_body is None:
            return

        for key, value in dict_body.items():
            if key not in dict_cls.attr_fields:
                raise ValueError('class %s does not have field %s' % (
                                  str(dict_cls), key))
            attr_type_vals = dict_cls.attr_field_type_vals[key]
            attr_type = attr_type_vals['attr_type']
            restrictions = attr_type_vals['restrictions']
            is_array = attr_type_vals.get('is_array', False)
            optional = attr_type_vals['optional']
            if value is None:
                continue
            if is_array:
                if not isinstance(value, list):
                    raise ValueError('Field %s must be a list. Received value: %s'
                                     % (key, str(value)))
                values = value
            else:
                values = [value]
            if attr_type_vals['is_complex']:
                attr_cls = cfgm_common.utils.str_to_class(attr_type, __name__)
                key_set = set()
                for item in values:
                    if is_array and attr_cls.key_field is not 'None':
                        if attr_cls.key_field not in item:
                            raise ValueError("key '%s' is expected"%(attr_cls.key_field))
                        else:
                            value = item[attr_cls.key_field]
                            if value in key_set:
                                raise ValueError("key '%s' not unique"%(value))
                            else:
                                key_set.add(value)
                    cls._validate_complex_type(attr_cls, item, is_update)
            else:
                simple_type = attr_type_vals['simple_type']
                for item in values:
                    cls._validate_simple_type(key, attr_type, item, optional, restrictions, is_update)
    # end _validate_complex_type

    @staticmethod
    @memoized
    def _pattern_validator(pattern):
        # static method one arg memomization is fast with no additional function call other than dict lookup if key is available
        doc = StringIO(
            '<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">'\
            '  <xsd:element name="a" type="x"/>'\
            '    <xsd:simpleType name="x">'\
            '      <xsd:restriction base="xsd:string">'\
            '        <xsd:pattern value=%s/>'\
            '      </xsd:restriction>'\
            '     </xsd:simpleType>'\
            '   </xsd:schema>' % quoteattr(pattern))
        try:
            sch = etree.XMLSchema(etree.parse(doc))
            return sch
        except etree.XMLSchemaParseError as v:
            logging.warn("Failed to parse pattern validation %s  %v", pattern, v)
            return None

    @classmethod
    def _validate_pattern(cls, pattern, value):
        #idea from pyang
        rex = cls._pattern_validator(pattern)
        if not rex:
            return False
        doc = StringIO('<a>%s</a>' % escape(value))
        return rex.validate(etree.parse(doc))


    @classmethod
    def _validate_simple_type(cls, type_name, xsd_type, value, optional, restrictions=None, is_update=False):
        error_msg="Value '%s' is not facet-valid with respect to %s '%s' for type '%s'"
        if value is None:
            if is_update or optional:
                return
            else:
                raise ValueError('%s is expected' %(type_name))
        elif xsd_type in ('byte', 'short', 'int', 'long', 'unsignedByte', 'unsignedShort', 'unsignedInt',
                          'unsignedLong', 'integer'):
            if not isinstance(value, (int, long)):
                raise ValueError('%s: %s value expected instead of %s' %(
                    type_name, xsd_type, value))
            if xsd_type == 'byte':
                if not (-128 <= value <= 127):
                    raise ValueError('%s is derived from int8, value must between -128 and 127' %(
                                type_name))
            elif xsd_type == 'short':
                if not (-32768 <= value <= 32767):
                    raise ValueError('%s is derived from int16, value must between -32768 and 32767' %(
                                type_name))
            elif xsd_type == 'int':
                if not (-2147483648 <= value <= 2147483647):
                    raise ValueError('%s is derived from int32, value must between -2147483648 and 2147483647' %(
                                type_name))
            elif xsd_type == 'long':
                if not (-9223372036854775808 <= value <= 9223372036854775807):
                    raise ValueError('%s is derived from int64, value must between -9223372036854775808 and 9223372036854775807' %(
                                type_name))
            elif xsd_type == 'unsignedByte':
                if not (0 <= value <= 255):
                    raise ValueError('%s is derived from uint8, value must between 0 and 255' %(
                                type_name))
            elif xsd_type == 'unsignedShort':
                if not (0 <= value <= 65535):
                    raise ValueError('%s is derived from uint16, value must between 0 and 65535' %(
                                type_name))
            elif xsd_type == 'unsignedInt':
                if not (0 <= value <= 4294967295):
                    raise ValueError('%s is derived from uint32, value must between 0 and 4294967295' %(
                                type_name))
            elif xsd_type == 'unsignedLong':
                if not (0 <= value <= 18446744073709551615):
                    raise ValueError('%s is derived from uint64, value must between 0 and 18446744073709551615' %(
                                type_name))
            if restrictions:
                for restriction in restrictions:
                    for (k,v) in restriction.items():
                        if 'max-inclusive' == k:
                            if not (long(v) >= value):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'min-inclusive' == k:
                            if not (long(v) <= value):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'max-exclusive' == k:
                            if not (long(v) > value):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'min-exclusive' == k:
                            if not (long(v) < value):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'union' == k:
                            match = False
                            for restr in v:
                                if not match:
                                    try:
                                        cls._validate_simple_type(type_name, xsd_type, value, optional, restr, is_update)
                                        match = True
                                    except Exception as e:
                                        err_msg = 'Error ' + str(e)
                            if not match:
                                raise ValueError('%s: value must be one of %s'%(type_name,str(v)))
        elif xsd_type == 'boolean':
            if not isinstance(value, bool):
                raise ValueError('%s: true/false expected instead of %s' %(
                    type_name, value))
        elif xsd_type == 'decimal':
            try:
                Decimal(value)
            except (TypeError, InvalidOperation):
                raise ValueError('%s: decimal value expected instead of %s' %(
                    type_name, value))
        elif xsd_type == "any": #anyxml
            pass
        elif xsd_type == 'string' and simple_type == 'CommunityAttribute':
            cls._validate_communityattribute_type(value)
        else:
            if not isinstance(value, basestring):
                raise ValueError('%s: string value expected instead of %s' %(
                    type_name, value))
            if restrictions:
                for restriction in restrictions:
                    for (k,v) in restriction.items():
                        if 'enumeration' == k:
                            if len(v)>0 and value not in v:
                                raise ValueError('%s: value must be one of %s' % (
                                    type_name, str(restrictions)))
                        if 'min-length' == k:
                            if not (long(v) <= len(value)):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'max-length' == k:
                            if not (long(v) >= len(value)):
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'pattern' == k:
                            match = cls._validate_pattern(v, value)
                            if not match:
                                raise ValueError(error_msg%(value, k, v, type_name))
                        if 'union' == k:
                            match = False
                            for restr in v:
                                if not match:
                                    try:
                                        cls._validate_simple_type(type_name, xsd_type, value, optional, restr, is_update)
                                        match = True
                                    except Exception as e:
                                        err_msg = 'Error ' + str(e)
                            if not match:
                                raise ValueError("%s: value must be one of %s"%(type_name,str(v)))
    # end _validate_simple_type

    def _validate_props_in_request(self, resource_class, obj_dict, is_update=False):
        if self._args.disable_validation:
            return True, ''
        for prop_name in resource_class.prop_fields:
            prop_field_types = resource_class.prop_field_types[prop_name]
            is_simple = not prop_field_types['is_complex']
            prop_type = prop_field_types['xsd_type']
            restrictions = prop_field_types['restrictions']
            optional = prop_field_types['optional']
            simple_type = prop_field_types['simple_type']
            is_list_prop = prop_name in resource_class.prop_list_fields
            is_map_prop = prop_name in resource_class.prop_map_fields

            if is_simple and (not is_list_prop) and (not is_map_prop):
                try:
                   self._validate_simple_type(prop_name, prop_type,obj_dict.get(prop_name), optional, restrictions, is_update)
                   continue
                except Exception as e:
                   err_msg = 'Error validating property. '+str(e)
                   return False, err_msg

            prop_value = obj_dict.get(prop_name)
            if not prop_value:
                continue

            prop_cls = cfgm_common.utils.str_to_class(prop_type, __name__)
            if isinstance(prop_value, dict):
                try:
                    self._validate_complex_type(prop_cls, prop_value, is_update)
                except Exception as e:
                    err_msg = 'Error validating property %s value %s. ' %(
                        prop_name, prop_value)
                    err_msg += str(e)
                    return False, err_msg
            elif isinstance(prop_value, list):
                key_set = set()
                for elem in prop_value:
                    try:
                        if is_simple:
                            self._validate_simple_type(prop_name, prop_type,
                                                       elem, optional, restrictions, is_update)
                        else:
                            if prop_cls.key_field is not None and prop_cls.key_field not in elem:
                                raise ValueError("key '%s' is expected"%(prop_cls.key_field))
                            else:
                                value = elem[prop_cls.key_field]
                                if value in key_set:
                                    raise ValueError("Key '%s' is not unique"%(value))
                                else:
                                    key_set.add(value)
                            self._validate_complex_type(prop_cls, elem, is_update)
                    except Exception as e:
                        err_msg = 'Error validating property %s elem %s. ' %(
                            prop_name, elem)
                        err_msg += str(e)
                        return False, err_msg
            else: # complex-type + value isn't dict or wrapped in list or map
                err_msg = 'Error in property %s type %s value of %s ' %(
                    prop_name, prop_cls, prop_value)
                return False, err_msg
        # end for all properties

        return True, ''
    # end _validate_props_in_request

    def _validate_refs_in_request(self, resource_class, obj_dict):
        for ref_name in resource_class.ref_fields:
            ref_fld_types_list = list(resource_class.ref_field_types[ref_name])
            ref_link_type = ref_fld_types_list[1]
            if ref_link_type == 'None':
                continue
            for ref_dict in obj_dict.get(ref_name) or []:
                buf = cStringIO.StringIO()
                attr_cls = cfgm_common.utils.str_to_class(ref_link_type, __name__)
                tmp_attr = attr_cls(**ref_dict['attr'])
                tmp_attr.export(buf)
                tmp_attr = attr_cls()
                node = etree.fromstring(buf.getvalue())
                try:
                    tmp_attr.build(node)
                except Exception as e:
                    err_msg = 'Error validating reference %s value %s ' \
                              %(ref_name, ref_dict)
                    err_msg += str(e)
                    return False, err_msg

        return True, ''
    # end _validate_refs_in_request

    def _validate_perms_in_request(self, resource_class, obj_type, obj_dict):
        for ref_name in resource_class.ref_fields:
            for ref in obj_dict.get(ref_name) or []:
                ref_uuid = self._db_conn.fq_name_to_uuid(ref_name[:-5],
                                                         ref['to'])
                (ok, status) = self._permissions.check_perms_link(
                    get_request(), ref_uuid)
                if not ok:
                    (code, err_msg) = status
                    raise cfgm_common.exceptions.HttpError(code, err_msg, "10003")
    # end _validate_perms_in_request

    def _validate_resource_type(self, type):
        try:
            resource_class = self.get_resource_class(type)
        except TypeError:
            return False, (404, "Resouce type '%s' not found" % type)
        return True, resource_class.resource_type

    # http_resource_<oper> - handlers invoked from
    # a. bottle route (on-the-wire) OR
    # b. internal requests
    # using normalized get_request() from ApiContext
    @log_api_stats
    def http_resource_create(self, obj_type):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type
        obj_dict = get_request().json[resource_type]

        self._post_validate(obj_type, obj_dict=obj_dict)
        fq_name = obj_dict['fq_name']

        try:
            self._extension_mgrs['resourceApi'].map_method(
                 'pre_%s_create' %(obj_type), obj_dict)
        except RuntimeError as e:
            # lack of registered extension leads to RuntimeError
            pass
        except HttpError:
            raise
        except Exception as e:
            err_msg = 'In pre_%s_create an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        # properties validator
        ok, result = self._validate_props_in_request(r_class, obj_dict, is_update=False)
        if not ok:
            result = 'Bad property in create: ' + result
            raise cfgm_common.exceptions.HttpError(400, result, "40001")

        # references validator
        ok, result = self._validate_refs_in_request(r_class, obj_dict)
        if not ok:
            result = 'Bad reference in create: ' + result
            raise cfgm_common.exceptions.HttpError(400, result, "40001")

        # parent check
        if r_class.parent_types and 'parent_type' not in obj_dict:
            raise cfgm_common.exceptions.HttpError(400, 'No parent_type attribute', "40001")

        if r_class.parent_types and obj_dict.get('parent_type') not in r_class.parent_types:
            err_msg = "parent_type is invalid.Valid parent type(s): %s" % ",".join(r_class.parent_types)
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40001")


        # common handling for all resource create
        (ok, result) = self._post_common(get_request(), obj_type,
                                         obj_dict)
        if not ok:
            (code, msg) = result
            fq_name_str = ':'.join(obj_dict.get('fq_name', []))
            self.config_object_error(None, fq_name_str, obj_type, 'http_post', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40001")

        uuid_in_req = result
        name = obj_dict['fq_name'][-1]
        fq_name = obj_dict['fq_name']

        db_conn = self._db_conn

        # if client gave parent_type of config-root, ignore and remove
        if 'parent_type' in obj_dict and obj_dict['parent_type'] == 'config-root':
            del obj_dict['parent_type']

        parent_class = None
        if 'parent_type' in obj_dict:
            # non config-root child, verify parent exists
            parent_class = self.get_resource_class(obj_dict['parent_type'])
            parent_obj_type = parent_class.object_type
            parent_res_type = parent_class.resource_type
            parent_fq_name = obj_dict['fq_name'][:-1]
            try:
                parent_uuid = self._db_conn.fq_name_to_uuid(parent_obj_type, parent_fq_name)

                (ok, status) = self._permissions.check_perms_write(
                    get_request(), parent_uuid)
                if not ok:
                    (code, err_msg) = status
                    raise cfgm_common.exceptions.HttpError(code, err_msg, "40005")
                self._permissions.set_user_role(get_request(), obj_dict)
            except NoIdError:
                err_msg = 'Parent %s type %s does not exist' % (
                    pformat(parent_fq_name), parent_res_type)
                fq_name_str = ':'.join(parent_fq_name)
                self.config_object_error(None, fq_name_str, obj_type, 'http_post', err_msg)
                raise cfgm_common.exceptions.HttpError(400, err_msg, "40001")

        # Validate perms on references
        try:
            self._validate_perms_in_request(r_class, obj_type, obj_dict)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                400, 'Unknown reference in resource create %s.' %(obj_dict), "40014")

        # State modification starts from here. Ensure that cleanup is done for all state changes
        cleanup_on_failure = []
        obj_ids = {}
        def undo_create(result):
            (code, msg) = result
            get_context().invoke_undo(code, msg, self.config_log)
            failed_stage = get_context().get_state()
            fq_name_str = ':'.join(fq_name)
            self.config_object_error(
                None, fq_name_str, obj_type, failed_stage, msg)
        # end undo_create

        def stateful_create():
            # Alloc and Store id-mappings before creating entry on pubsub store.
            # Else a subscriber can ask for an id mapping before we have stored it
            (ok, result) = db_conn.dbe_alloc(obj_type, obj_dict,
                                             uuid_in_req)
            if not ok:
                return (ok, result)
            get_context().push_undo(db_conn.dbe_release, obj_type, fq_name)

            obj_ids.update(result)

            env = get_request().headers.environ
            tenant_name = env.get(hdr_server_tenant(), 'default-project')

            get_context().set_state('PRE_DBE_CREATE')
            # type-specific hook
            (ok, result) = r_class.pre_dbe_create(tenant_name, obj_dict,
                                                  db_conn)
            if not ok:
                return (ok, result)
            callable = getattr(r_class, 'http_post_collection_fail', None)
            if callable:
                cleanup_on_failure.append((callable, [tenant_name, obj_dict, db_conn]))

            get_context().set_state('DBE_CREATE')
            (ok, result) = db_conn.dbe_create(obj_type, obj_ids,
                                              obj_dict)
            if not ok:
                return (ok, result)

            get_context().set_state('POST_DBE_CREATE')
            # type-specific hook
            try:
                ok, err_msg = r_class.post_dbe_create(tenant_name, obj_dict, db_conn)
            except Exception as e:
                ok = False
                err_msg = '%s:%s post_dbe_create had an exception: %s' %(
                    obj_type, obj_ids['uuid'], str(e))
                err_msg += cfgm_common.utils.detailed_traceback()

            if not ok:
                # Create is done, log to system, no point in informing user
                self.config_log(err_msg, level=SandeshLevel.SYS_ERR)

            return True, ''
        # end stateful_create

        try:
            ok, result = stateful_create()
        except Exception as e:
            ok = False
            err_msg = cfgm_common.utils.detailed_traceback()
            result = (500, err_msg)
        if not ok:
            undo_create(result)
            code, msg = result
            raise cfgm_common.exceptions.HttpError(code, msg, "50006")

        rsp_body = {}
        rsp_body['name'] = name
        rsp_body['fq_name'] = fq_name
        rsp_body['uuid'] = obj_ids['uuid']
        rsp_body['href'] = self.generate_url(resource_type, obj_ids['uuid'])
        if parent_class:
            # non config-root child, send back parent uuid/href
            rsp_body['parent_uuid'] = parent_uuid
            rsp_body['parent_href'] = self.generate_url(parent_res_type,
                                                        parent_uuid)

        try:
            self._extension_mgrs['resourceApi'].map_method(
                'post_%s_create' %(obj_type), obj_dict)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except OperationRollBackException:
            raise
        except Exception as e:
            err_msg = 'In post_%s_create an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        if self.is_multi_tenancy_with_rbac_set(): # updating perms2 for share relation
            try:
                self._update_refs_perms2(obj_type, obj_dict, 'ADD')
            except Exception as e:
                logger.error("Failed updating share-relation: %s", e.message)

        return {resource_type: rsp_body}
    # end http_resource_create

    @log_api_stats
    def http_resource_read(self, obj_type, id):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type
        try:
            self._extension_mgrs['resourceApi'].map_method(
                'pre_%s_read' %(obj_type), id)
        except HttpError:
            raise
        except Exception as e:
            pass

        etag = get_request().headers.get('If-None-Match')
        db_conn = self._db_conn
        try:
            req_obj_type = db_conn.uuid_to_obj_type(id)
            if req_obj_type != obj_type:
                raise cfgm_common.exceptions.HttpError(
                    404, 'No %s object found for id %s' %(resource_type, id), "40002")
            fq_name = db_conn.uuid_to_fq_name(id)
        except NoIdError as e:
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")

        # common handling for all resource get
        (ok, result) = self._get_common(get_request(), id)
        if not ok:
            (code, msg) = result
            self.config_object_error(
                id, None, obj_type, 'http_get', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40015")

        db_conn = self._db_conn
        if etag:
            obj_ids = {'uuid': id}
            (ok, result) = db_conn.dbe_is_latest(obj_ids, etag.strip('"'))
            if not ok:
                # Not present in DB
                self.config_object_error(
                    id, None, obj_type, 'http_get', result)
                raise cfgm_common.exceptions.HttpError(404, result, "40015")

            is_latest = result
            if is_latest:
                # send Not-Modified, caches use this for read optimization
                bottle.response.status = 304
                return
        #end if etag

        obj_ids = {'uuid': id}

        # Generate field list for db layer
        obj_fields = r_class.prop_fields | r_class.ref_fields
        if 'fields' in get_request().query:
            obj_fields |= set(get_request().query.fields.split(','))
        else: # default props + children + refs + backrefs
            if 'exclude_back_refs' not in get_request().query:
                obj_fields |= r_class.backref_fields
            if 'exclude_children' not in get_request().query:
                obj_fields |= r_class.children_fields

        try:
            (ok, result) = db_conn.dbe_read(obj_type, obj_ids,
                                            list(obj_fields))
            if not ok:
                self.config_object_error(id, None, obj_type, 'http_get', result)
        except NoIdError as e:
            # Not present in DB
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")
        if not ok:
            raise cfgm_common.exceptions.HttpError(500, result, "40015")

        # check visibility
        if (not result['id_perms'].get('user_visible', True) and
            not self.is_admin_request()):
            result = 'This object is not visible by users: %s' % id
            self.config_object_error(id, None, obj_type, 'http_get', result)
            raise cfgm_common.exceptions.HttpError(404, result, "40005")

        rsp_body = {}
        rsp_body['uuid'] = id
        rsp_body['uri'] = self.generate_uri(resource_type, id)
        rsp_body['name'] = result['fq_name'][-1]
        rsp_body.update(result)
        id_perms = result['id_perms']
        bottle.response.set_header('ETag', '"' + id_perms['last_modified'] + '"')
        try:
            self._extension_mgrs['resourceApi'].map_method(
                'post_%s_read' %(obj_type), id, rsp_body)
        except HttpError:
            raise
        except Exception as e:
            pass

        return {resource_type: rsp_body}
    # end http_resource_read

    @log_api_stats
    def http_resource_update(self, obj_type, id):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type

        # Early return if there is no body or an empty body
        request = get_request()
        if (not hasattr(request, 'json') or
            not request.json or
            not request.json[resource_type]):
            return

        obj_dict = get_request().json[resource_type]
        try:
            self._extension_mgrs['resourceApi'].map_method(
                'pre_%s_update' %(obj_type), id, obj_dict)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except HttpError:
            raise
        except Exception as e:
            err_msg = 'In pre_%s_update an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        db_conn = self._db_conn
        try:
            req_obj_type = db_conn.uuid_to_obj_type(id)
            if req_obj_type != obj_type:
                raise cfgm_common.exceptions.HttpError(
                    404, 'No %s object found for id %s' %(resource_type, id), "40002")
            obj_ids = {'uuid': id}
            (read_ok, read_result) = db_conn.dbe_read(obj_type, obj_ids)
            if not read_ok:
                bottle.abort(
                    404, 'No %s object found for id %s' %(resource_type, id))
            fq_name = read_result['fq_name']
        except NoIdError as e:
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")

        # properties validator
        ok, result = self._validate_props_in_request(r_class, obj_dict, is_update=True)
        if not ok:
            result = 'Bad property in update: ' + result
            raise cfgm_common.exceptions.HttpError(400, result, "40001")

        # references validator
        ok, result = self._validate_refs_in_request(r_class, obj_dict)
        if not ok:
            result = 'Bad reference in update: ' + result
            raise cfgm_common.exceptions.HttpError(400, result, "40014")

        # common handling for all resource put
        (ok, result) = self._put_common(
            get_request(), obj_type, id, fq_name, obj_dict)
        if not ok:
            (code, msg) = result
            self.config_object_error(id, None, obj_type, 'http_put', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40016")

        # Validate perms on references
        try:
            self._validate_perms_in_request(r_class, obj_type, obj_dict)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(400,
                'Unknown reference in resource update %s %s.'
                %(obj_type, obj_dict), "40014")

        # State modification starts from here. Ensure that cleanup is done for all state changes
        cleanup_on_failure = []
        obj_ids = {'uuid': id}
        def undo_update(result):
            (code, msg) = result
            get_context().invoke_undo(code, msg, self.config_log)
            failed_stage = get_context().get_state()
            self.config_object_error(
                id, None, obj_type, failed_stage, msg)
        # end undo_update

        def stateful_update():
            get_context().set_state('PRE_DBE_UPDATE')
            # type-specific hook
            (ok, result) = r_class.pre_dbe_update(
                id, fq_name, obj_dict, self._db_conn)
            if not ok:
                return (ok, result)

            get_context().set_state('DBE_UPDATE')
            (ok, result) = db_conn.dbe_update(obj_type, obj_ids,
                                              obj_dict)
            if not ok:
                return (ok, result)

            get_context().set_state('POST_DBE_UPDATE')
            # type-specific hook
            (ok, result) = r_class.post_dbe_update(id, fq_name, obj_dict, self._db_conn)
            if not ok:
                return (ok, result)

            return (ok, result)
        # end stateful_update

        try:
            ok, result = stateful_update()
        except Exception as e:
            ok = False
            err_msg = cfgm_common.utils.detailed_traceback()
            result = (500, err_msg)
        if not ok:
            undo_update(result)
            code, msg = result
            raise cfgm_common.exceptions.HttpError(code, msg, "40016")

        rsp_body = {}
        rsp_body['uuid'] = id
        rsp_body['uri'] = self.generate_uri(resource_type, id)

        try:
            self._extension_mgrs['resourceApi'].map_method(
                'post_%s_update' %(obj_type), id, obj_dict, read_result)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except OperationRollBackException:
            raise
        except Exception as e:
            err_msg = 'In post_%s_update an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        if self.is_multi_tenancy_with_rbac_set():
            try:
                refs_add, refs_del = self._refs_diff(obj_type, read_result, obj_dict)
                self._update_refs_perms2(obj_type, refs_add, 'ADD')
                self._update_refs_perms2(obj_type, refs_del, 'DELETE')
            except Exception as e:
                logger.error("Failed updating share-relation: %s", e.message)

        return {resource_type: rsp_body}
    # end http_resource_update

    @log_api_stats
    def http_resource_delete(self, obj_type, id):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type

        db_conn = self._db_conn
        # if obj doesn't exist return early
        try:
            req_obj_type = db_conn.uuid_to_obj_type(id)
            if req_obj_type != obj_type:
                raise cfgm_common.exceptions.HttpError(
                    404, 'No %s object found for id %s' %(resource_type, id), "40002")
            _ = db_conn.uuid_to_fq_name(id)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'ID %s does not exist' %(id), "40002")


        try:
            self._extension_mgrs['resourceApi'].map_method(
                'pre_%s_delete' %(obj_type), id)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except HttpError:
            raise
        except Exception as e:
            err_msg = 'In pre_%s_delete an extension had error for %s' \
                      %(obj_type, id)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        # read in obj from db (accepting error) to get details of it
        obj_ids = {'uuid': id}
        try:
            (read_ok, read_result) = db_conn.dbe_read(obj_type, obj_ids)
        except NoIdError as e:
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")
        if not read_ok:
            self.config_object_error(
                id, None, obj_type, 'http_delete', read_result)
            # proceed down to delete the resource

        pj_id = None
        if self.is_multi_tenancy_with_rbac_set() and read_ok:
            try:
                pj_id = self._db_conn.fq_name_to_uuid('project', read_result.get('fq_name')[:2]).replace('-', '')
            except cfgm_common.exceptions.NoIdError:
                logger.warn("No uuid for project based on fq_name %s[:2] of %s", read_result.get('fq_name'), obj_type)
            except Exception as e:
                logger.warn("Cannot get project info for obj (%s): %s", read_result.get('fq_name'), e.message)

        # common handling for all resource delete
        parent_obj_type = read_result.get('parent_type')
        (ok, del_result) = self._delete_common(
            get_request(), obj_type, id, parent_obj_type)
        if not ok:
            (code, msg) = del_result
            self.config_object_error(id, None, obj_type, 'http_delete', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40017")

        fq_name = read_result['fq_name']
        ifmap_id = imid.get_ifmap_id_from_fq_name(resource_type, fq_name)
        obj_ids['imid'] = ifmap_id
        if parent_obj_type:
            parent_res_type = \
                self.get_resource_class(parent_obj_type).resource_type
            parent_imid = cfgm_common.imid.get_ifmap_id_from_fq_name(
                parent_res_type, fq_name[:-1])
            obj_ids['parent_imid'] = parent_imid

        # type-specific hook
        r_class = self.get_resource_class(obj_type)
        # fail if non-default children or non-derived backrefs exist
        default_names = {}
        for child_field in r_class.children_fields:
            child_type, is_derived = r_class.children_field_types[child_field]
            if is_derived:
                continue
            child_cls = self.get_resource_class(child_type)
            default_child_name = 'default-%s' %(
                child_cls(parent_type=obj_type).get_type())
            default_names[child_type] = default_child_name
            exist_hrefs = []
            for child in read_result.get(child_field, []):
                if child['to'][-1] == default_child_name:
                    continue
                exist_hrefs.append(child['uri'])
            if exist_hrefs:
                err_msg = 'Delete when children still present: %s' %(
                    exist_hrefs)
                self.config_object_error(
                    id, None, obj_type, 'http_delete', err_msg)
                raise cfgm_common.exceptions.HttpError(409, err_msg, "40006")

        relaxed_refs = set(db_conn.dbe_get_relaxed_refs(id))
        for backref_field in r_class.backref_fields:
            _, _, is_derived = r_class.backref_field_types[backref_field]
            if is_derived:
                continue
            exist_hrefs = [backref['uri']
                           for backref in read_result.get(backref_field, [])
                               if backref['uuid'] not in relaxed_refs]
            if exist_hrefs:
                err_msg = 'Delete when resource still referred: %s' %(
                    exist_hrefs)
                self.config_object_error(
                    id, None, obj_type, 'http_delete', err_msg)
                raise cfgm_common.exceptions.HttpError(409, err_msg, "40006")

        # State modification starts from here. Ensure that cleanup is done for all state changes
        cleanup_on_failure = []

        def undo_delete(result):
            (code, msg) = result
            get_context().invoke_undo(code, msg, self.config_log)
            failed_stage = get_context().get_state()
            self.config_object_error(
                id, None, obj_type, failed_stage, msg)
        # end undo_delete

        def stateful_delete():
            get_context().set_state('PRE_DBE_DELETE')
            (ok, del_result) = r_class.pre_dbe_delete(id, read_result, db_conn)
            if not ok:
                return (ok, del_result)
            # Delete default children first
            for child_field in r_class.children_fields:
                child_type, is_derived = r_class.children_field_types[child_field]
                if is_derived:
                    continue
                if child_field in self._GENERATE_DEFAULT_INSTANCE:
                    self.delete_default_children(child_type, read_result)

            callable = getattr(r_class, 'http_delete_fail', None)
            if callable:
                cleanup_on_failure.append((callable, [id, read_result, db_conn]))

            get_context().set_state('DBE_DELETE')
            (ok, del_result) = db_conn.dbe_delete(
                obj_type, obj_ids, read_result)
            if not ok:
                return (ok, del_result)

            # type-specific hook
            get_context().set_state('POST_DBE_DELETE')
            try:
                ok, err_msg = r_class.post_dbe_delete(id, read_result, db_conn)
            except Exception as e:
                ok = False
                err_msg = '%s:%s post_dbe_delete had an exception: ' \
                          %(obj_type, id)
                err_msg += cfgm_common.utils.detailed_traceback()

            if not ok:
                # Delete is done, log to system, no point in informing user
                self.config_log(err_msg, level=SandeshLevel.SYS_ERR)

            return (True, '')
        # end stateful_delete

        try:
            ok, result = stateful_delete()
        except NoIdError as e:
            raise cfgm_common.exceptions.HttpError(
                404, 'No %s object found for id %s' %(resource_type, id), "40002")
        except Exception as e:
            ok = False
            err_msg = cfgm_common.utils.detailed_traceback()
            result = (500, err_msg)
        if not ok:
            undo_delete(result)
            code, msg = result
            raise cfgm_common.exceptions.HttpError(code, msg, "40017")

        try:
            self._extension_mgrs['resourceApi'].map_method(
                'post_%s_delete' %(obj_type), id, read_result)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In pre_%s_delete an extension had error for %s' \
                      %(obj_type, id)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        if self.is_multi_tenancy_with_rbac_set():
            try:
                self._update_refs_perms2(obj_type, read_result, 'DELETE', pj_id)
            except Exception as e:
                logger.error("Failed updating share-relation: %s", e.message)
    # end http_resource_delete


    @collect_stats
    def http_resource_list(self, obj_type):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type
        db_conn = self._db_conn
        env = get_request().headers.environ
        tenant_name = env.get(hdr_server_tenant(), 'default-project')
        parent_uuids = None
        back_ref_uuids = None
        obj_uuids = None
        if 'fq_name_str' in get_request().query:
            obj_fq_name = get_request().query.fq_name_str.split(':')
            try:
                obj_uuids = [self._db_conn.fq_name_to_uuid(resource_type, obj_fq_name)]
            except NoIdError:
                raise cfgm_common.exceptions.HttpError(
                    404, 'Name ' + pformat(obj_fq_name) + ' not found', "40002")
        else:
            if (('parent_fq_name_str' in get_request().query) and
                ('parent_type' in get_request().query)):
                parent_fq_name = get_request().query.parent_fq_name_str.split(':')
                parent_res_type = get_request().query.parent_type
                parent_class = self.get_resource_class(parent_res_type)
                parent_type = parent_class.object_type
                parent_uuids = [self._db_conn.fq_name_to_uuid(parent_type, parent_fq_name)]
            elif 'parent_id' in get_request().query:
                parent_uuids = get_request().query.parent_id.split(',')
            if 'back_ref_id' in get_request().query:
                back_ref_uuids = get_request().query.back_ref_id.split(',')
            if 'obj_uuids' in get_request().query:
                obj_uuids = get_request().query.obj_uuids.split(',')

        # common handling for all resource get
        (ok, result) = self._get_common(get_request(), parent_uuids)
        if not ok:
            (code, msg) = result
            self.config_object_error(
                None, None, '%ss' %(resource_type), 'http_get_collection', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40018")

        if 'count' in get_request().query:
            is_count = 'true' in get_request().query.count.lower()
        else:
            is_count = False

        if 'detail' in get_request().query:
            is_detail = 'true' in get_request().query.detail.lower()
        else:
            is_detail = False

        if 'fields' in get_request().query:
            req_fields = get_request().query.fields.split(',')
        else:
            req_fields = []

        try:
            filters = utils.get_filters(get_request().query.filters)
        except Exception as e:
            raise cfgm_common.exceptions.HttpError(
                400, 'Invalid filter ' + get_request().query.filters)
        params=get_request().query
        return self._list_collection(obj_type, parent_uuids, back_ref_uuids,
                                     obj_uuids, is_count, is_detail, filters,
                                     req_fields,params=params)
    # end http_resource_list

    # internal_request_<oper> - handlers of internally generated requests
    # that save-ctx, generate-ctx and restore-ctx
    def internal_request_create(self, resource_type, obj_json):
        object_type = self.get_resource_class(resource_type).object_type
        try:
            orig_context = get_context()
            orig_request = get_request()
            b_req = bottle.BaseRequest(
                {'PATH_INFO': '/%ss' %(resource_type),
                 'bottle.app': orig_request.environ['bottle.app'],
                 'HTTP_X_USER': 'contrail-api',
                 'HTTP_X_ROLE': self.cloud_admin_role})
            json_as_dict = {'%s' %(resource_type): obj_json}
            i_req = context.ApiInternalRequest(
                b_req.url, b_req.urlparts, b_req.environ, b_req.headers,
                json_as_dict, None)
            set_context(context.ApiContext(internal_req=i_req))
            self.http_resource_create(object_type)
            return True, ""
        finally:
            set_context(orig_context)
    # end internal_request_create

    def internal_request_update(self, resource_type, obj_uuid, obj_json):
        object_type = self.get_resource_class(resource_type).object_type
        try:
            orig_context = get_context()
            orig_request = get_request()
            b_req = bottle.BaseRequest(
                {'PATH_INFO': '/%ss' %(resource_type),
                 'bottle.app': orig_request.environ['bottle.app'],
                 'HTTP_X_USER': 'contrail-api',
                 'HTTP_X_ROLE': self.cloud_admin_role})
            json_as_dict = {'%s' %(resource_type): obj_json}
            i_req = context.ApiInternalRequest(
                b_req.url, b_req.urlparts, b_req.environ, b_req.headers,
                json_as_dict, None)
            set_context(context.ApiContext(internal_req=i_req))
            self.http_resource_update(object_type, obj_uuid)
            return True, ""
        finally:
            set_context(orig_context)
    # end internal_request_update

    def internal_request_delete(self, resource_type, obj_uuid):
        object_type = self.get_resource_class(resource_type).object_type
        try:
            orig_context = get_context()
            orig_request = get_request()
            b_req = bottle.BaseRequest(
                {'PATH_INFO': '/%s/%s' %(resource_type, obj_uuid),
                 'bottle.app': orig_request.environ['bottle.app'],
                 'HTTP_X_USER': 'contrail-api',
                 'HTTP_X_ROLE': self.cloud_admin_role})
            i_req = context.ApiInternalRequest(
                b_req.url, b_req.urlparts, b_req.environ, b_req.headers,
                None, None)
            set_context(context.ApiContext(internal_req=i_req))
            self.http_resource_delete(object_type, obj_uuid)
            return True, ""
        finally:
            set_context(orig_context)
    # end internal_request_delete

    def internal_request_ref_update(self,
        res_type, obj_uuid, operation, ref_res_type, ref_uuid, attr=None):
        req_dict = {'type': res_type,
                    'uuid': obj_uuid,
                    'operation': operation,
                    'ref-type': ref_res_type,
                    'ref-uuid': ref_uuid,
                    'attr': attr}
        try:
            orig_context = get_context()
            orig_request = get_request()
            b_req = bottle.BaseRequest(
                {'PATH_INFO': '/ref-update',
                 'bottle.app': orig_request.environ['bottle.app'],
                 'HTTP_X_USER': 'contrail-api',
                 'HTTP_X_ROLE': self.cloud_admin_role})
            i_req = context.ApiInternalRequest(
                b_req.url, b_req.urlparts, b_req.environ, b_req.headers,
                req_dict, None)
            set_context(context.ApiContext(internal_req=i_req))
            self.ref_update_http_post()
            return True, ""
        finally:
            set_context(orig_context)
    # end internal_request_ref_update

    def create_default_children(self, object_type, parent_obj):
        r_class = self.get_resource_class(object_type)
        for child_fields in r_class.children_fields:
            # Create a default child only if provisioned for
            child_res_type, is_derived =\
                r_class.children_field_types[child_fields]
            if is_derived:
                continue
            if child_res_type not in self._GENERATE_DEFAULT_INSTANCE:
                continue
            child_cls = self.get_resource_class(child_res_type)
            child_obj_type = child_cls.object_type
            child_obj = child_cls(parent_obj=parent_obj)
            child_dict = child_obj.__dict__
            child_dict['id_perms'] = self._get_default_id_perms()
            child_dict['perms2'] = self._get_default_perms2()
            (ok, result) = self._db_conn.dbe_alloc(child_obj_type, child_dict)
            if not ok:
                return (ok, result)
            obj_ids = result

            # For virtual networks, allocate an ID
            if child_obj_type == 'virtual_network':
                child_dict['virtual_network_network_id'] =\
                    self._db_conn._zk_db.alloc_vn_id(
                        child_obj.get_fq_name_str())

            (ok, result) = self._db_conn.dbe_create(child_obj_type, obj_ids,
                                                    child_dict)
            if not ok:

                # DB Create failed, log and stop further child creation.
                err_msg = "DB Create failed creating %s" % child_res_type
                self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
                return (ok, result)

            # recurse down type hierarchy
            self.create_default_children(child_obj_type, child_obj)
    # end create_default_children

    def delete_default_children(self, resource_type, parent_dict):
        r_class = self.get_resource_class(resource_type)
        for child_field in r_class.children_fields:
            # Delete a default child only if provisioned for
            child_type, is_derived = r_class.children_field_types[child_field]
            if child_type not in self._GENERATE_DEFAULT_INSTANCE:
               continue
            child_cls = self.get_resource_class(child_type)
            # first locate default child then delete it")
            default_child_name = 'default-%s' %(child_type)
            child_infos = parent_dict.get(child_field, [])
            for child_info in child_infos:
                if child_info['to'][-1] == default_child_name:
                    default_child_id = has_info['uri'].split('/')[-1]
                    self.http_resource_delete(child_type, default_child_id)
                    break
    # end delete_default_children

    @classmethod
    def _generate_resource_crud_methods(cls, obj):
        for object_type, _ in all_resource_type_tuples:
            create_method = functools.partial(obj.http_resource_create,
                                              object_type)
            functools.update_wrapper(create_method, obj.http_resource_create)
            setattr(obj, '%ss_http_post' %(object_type), create_method)

            read_method = functools.partial(obj.http_resource_read,
                                            object_type)
            functools.update_wrapper(read_method, obj.http_resource_read)
            setattr(obj, '%s_http_get' %(object_type), read_method)

            update_method = functools.partial(obj.http_resource_update,
                                              object_type)
            functools.update_wrapper(update_method, obj.http_resource_update)
            setattr(obj, '%s_http_put' %(object_type), update_method)

            delete_method = functools.partial(obj.http_resource_delete,
                                              object_type)
            functools.update_wrapper(delete_method, obj.http_resource_delete)
            setattr(obj, '%s_http_delete' %(object_type), delete_method)

            list_method = functools.partial(obj.http_resource_list,
                                            object_type)
            functools.update_wrapper(list_method, obj.http_resource_list)
            setattr(obj, '%ss_http_get' %(object_type), list_method)
    # end _generate_resource_crud_methods

    @classmethod
    def _generate_resource_crud_uri(cls, obj):
        for object_type, resource_type in all_resource_type_tuples:
            # CRUD + list URIs of the form
            # obj.route('/virtual-network/<id>', 'GET', obj.virtual_network_http_get)
            # obj.route('/virtual-network/<id>', 'PUT', obj.virtual_network_http_put)
            # obj.route('/virtual-network/<id>', 'DELETE', obj.virtual_network_http_delete)
            # obj.route('/virtual-networks', 'POST', obj.virtual_networks_http_post)
            # obj.route('/virtual-networks', 'GET', obj.virtual_networks_http_get)

            # leaf resource
            obj.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                      'GET',
                      getattr(obj, '%s_http_get' % object_type))
            obj.route('%s/%s/<id>' % (SERVICE_PATH, resource_type),
                      'PUT',
                      getattr(obj, '%s_http_put' % object_type))
            obj.route('%s/%s<id>' % (SERVICE_PATH, resource_type),
                      'DELETE',
                      getattr(obj, '%s_http_delete' % object_type))
            # collection of leaf
            obj.route('%s/%s' % (SERVICE_PATH, resource_type),
                      'POST',
                      getattr(obj, '%ss_http_post' % object_type))
            obj.route('%s/%s' % (SERVICE_PATH, resource_type),
                      'GET',
                      getattr(obj, '%ss_http_get' % object_type))
    # end _generate_resource_crud_uri

    def __init__(self, args_str=None):
        self._db_conn = None
        self._get_common = None
        self._post_common = None
        self._resource_classes = {}
        self._args = None
        if not args_str:
            args_str = ' '.join(sys.argv[1:])
        self._parse_args(args_str)

        # set python logging level from logging_level cmdline arg
        if not self._args.logging_conf:
            logging.basicConfig(level = getattr(logging, self._args.logging_level))

        self._base_url = "http://%s:%s" % (self._args.listen_ip_addr,
                                           self._args.listen_port)

        # Generate LinkObjects for all entities
        links = []
        # Link for root
        links.append(LinkObject('root', self._base_url , '/config-root',
                                'config-root'))

        for _, resource_type in all_resource_type_tuples:
            link = LinkObject('collection',
                           self._base_url , '/%s' %(resource_type),
                           '%s' %(resource_type))

            links.append(link)

        for _, resource_type in all_resource_type_tuples:
            link = LinkObject('resource-base',
                              self._base_url , '/%s' %(resource_type),
                              '%s' %(resource_type))
            links.append(link)

        self._homepage_links = links

        self._pipe_start_app = None

        #GreenletProfiler.set_clock_type('wall')
        self._profile_info = None

        # REST interface initialization
        self._get_common = self._http_get_common
        self._put_common = self._http_put_common
        self._delete_common = self._http_delete_common
        self._post_validate = self._http_post_validate
        self._post_common = self._http_post_common

        for act_res in _ACTION_RESOURCES:
            uri = act_res['uri']
            if SERVICE_PATH:
                uri = '%s%s' % (SERVICE_PATH, uri)
            link = LinkObject('action', self._base_url, uri,
                              act_res['link_name'], act_res['method'])
            self._homepage_links.append(link)

        # Register for VN delete request. Disallow delete of system default VN
        self.route('/virtual-network/<id>', 'DELETE', self.virtual_network_http_delete)

        self.route('/documentation/<filename:path>',
                     'GET', self.documentation_http_get)
        self._homepage_links.insert(
            0, LinkObject('documentation', self._base_url,
                          '/documentation/index.html',
                          'documentation', 'GET'))

        # APIs to reserve/free block of IP address from a VN/Subnet
        self.route('/virtual-network/<id>/ip-alloc',
                     'POST', self.vn_ip_alloc_http_post)
        self._homepage_links.append(
            LinkObject('action', self._base_url,
                       '/virtual-network/%s/ip-alloc',
                       'virtual-network-ip-alloc', 'POST'))

        self.route('/virtual-network/<id>/ip-free',
                     'POST', self.vn_ip_free_http_post)
        self._homepage_links.append(
            LinkObject('action', self._base_url,
                       '/virtual-network/%s/ip-free',
                       'virtual-network-ip-free', 'POST'))

        # APIs to find out number of ip instances from given VN subnet
        self.route('/virtual-network/<id>/subnet-ip-count',
                     'POST', self.vn_subnet_ip_count_http_post)
        self._homepage_links.append(
            LinkObject('action', self._base_url,
                       '/virtual-network/%s/subnet-ip-count',
                       'virtual-network-subnet-ip-count', 'POST'))

        # Enable/Disable multi tenancy
        self.route('/multi-tenancy', 'GET', self.mt_http_get)
        self.route('/multi-tenancy', 'PUT', self.mt_http_put)
        self.route('/multi-tenancy-with-rbac', 'GET', self.rbac_http_get)
        self.route('/multi-tenancy-with-rbac', 'PUT', self.rbac_http_put)

        # Initialize discovery client
        self._disc = None
        if self._args.disc_server_ip and self._args.disc_server_port:
            self._disc = client.DiscoveryClient(self._args.disc_server_ip,
                                                self._args.disc_server_port,
                                                ModuleNames[Module.API_SERVER])

        # sandesh init
        self._sandesh = Sandesh()
        # Reset the sandesh send rate limit  value
        if self._args.sandesh_send_rate_limit is not None:
            SandeshSystem.set_sandesh_send_rate_limit(
                self._args.sandesh_send_rate_limit)
        sandesh.DiscoveryClientStatsReq.handle_request = self.sandesh_disc_client_stats_handle_request
        sandesh.DiscoveryClientSubscribeInfoReq.handle_request = self.sandesh_disc_client_subinfo_handle_request
        sandesh.DiscoveryClientPublishInfoReq.handle_request = self.sandesh_disc_client_pubinfo_handle_request
        module = Module.API_SERVER
        module_name = ModuleNames[Module.API_SERVER]
        node_type = Module2NodeType[module]
        node_type_name = NodeTypeNames[node_type]
        self.table = "ObjectConfigNode"
        if self._args.worker_id:
            instance_id = self._args.worker_id
        else:
            instance_id = INSTANCE_ID_DEFAULT
        hostname = socket.gethostname()
        self._sandesh.init_generator(module_name, hostname,
                                     node_type_name, instance_id,
                                     self._args.collectors,
                                     'vnc_api_server_context',
                                     int(self._args.http_server_port),
                                     ['cfgm_common', 'vnc_cfg_api_server.sandesh'], self._disc,
                                     logger_class=self._args.logger_class,
                                     logger_config_file=self._args.logging_conf)
        self._sandesh.trace_buffer_create(name="VncCfgTraceBuf", size=1000)
        self._sandesh.trace_buffer_create(name="RestApiTraceBuf", size=1000)
        self._sandesh.trace_buffer_create(name="DBRequestTraceBuf", size=1000)
        self._sandesh.trace_buffer_create(name="DBUVERequestTraceBuf", size=1000)
        self._sandesh.trace_buffer_create(name="MessageBusNotifyTraceBuf",
                                          size=1000)
        self._sandesh.trace_buffer_create(name="IfmapTraceBuf", size=1000)

        self._sandesh.set_logging_params(
            enable_local_log=self._args.log_local,
            category=self._args.log_category,
            level=self._args.log_level,
            file=self._args.log_file,
            enable_syslog=self._args.use_syslog,
            syslog_facility=self._args.syslog_facility)

        ConnectionState.init(self._sandesh, hostname, module_name,
                instance_id,
                staticmethod(ConnectionState.get_process_state_cb),
                NodeStatusUVE, NodeStatus, self.table)

        # Address Management interface
        addr_mgmt = vnc_addr_mgmt.AddrMgmt(self)
        vnc_cfg_types.LogicalRouterServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.SecurityGroupServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.VirtualMachineInterfaceServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.FloatingIpServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.AliasIpServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.InstanceIpServer.addr_mgmt = addr_mgmt
        vnc_cfg_types.VirtualNetworkServer.addr_mgmt = addr_mgmt
        self._addr_mgmt = addr_mgmt

        # DB interface initialization
        if self._args.wipe_config:
            self._db_connect(True)
        else:
            self._db_connect(self._args.reset_config)
            self._db_init_entries()

        # API/Permissions check
        # after db init (uses db_conn)
        self._rbac = vnc_rbac.VncRbac(self, self._db_conn)
        self._permissions = vnc_perms.VncPermissions(self, self._args)
        if self._args.multi_tenancy_with_rbac:
            self._create_default_rbac_rule()

        # Cpuinfo interface
        sysinfo_req = True
        config_node_ip = self.get_server_ip()
        cpu_info = vnc_cpu_info.CpuInfo(
            self._sandesh.module(), self._sandesh.instance_id(), sysinfo_req,
            self._sandesh, 60, config_node_ip)
        self._cpu_info = cpu_info

        self.re_uuid = re.compile('^[0-9A-F]{8}-?[0-9A-F]{4}-?4[0-9A-F]{3}-?[89AB][0-9A-F]{3}-?[0-9A-F]{12}$',
                                  re.IGNORECASE)

        # VncZkClient client assignment
        vnc_cfg_types.Resource.vnc_zk_client = self._db_conn._zk_db

        # Load extensions
        self._extension_mgrs = {}
        self._load_extensions()

        # Authn/z interface
        if self._args.auth == 'keystone':
            auth_svc = vnc_auth_keystone.AuthServiceKeystone(self, self._args)
        else:
            auth_svc = vnc_auth.AuthService(self, self._args)

        self._pipe_start_app = auth_svc.get_middleware_app()
        self._auth_svc = auth_svc

        try:
            self._extension_mgrs['resync'].map(self._resync_domains_projects)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_ERR)
    # end __init__

    def sandesh_disc_client_subinfo_handle_request(self, req):
        stats = self._disc.get_stats()
        resp = sandesh.DiscoveryClientSubscribeInfoResp(Subscribe=[])

        for sub in stats['subs']:
            info = sandesh.SubscribeInfo(service_type=sub['service_type'])
            info.instances   = sub['instances']
            info.ttl         = sub['ttl']
            info.blob        = sub['blob']
            resp.Subscribe.append(info)

        resp.response(req.context())
    # end

    def sandesh_disc_client_pubinfo_handle_request(self, req):
        stats = self._disc.get_stats()
        resp = sandesh.DiscoveryClientPublishInfoResp(Publish=[])

        for service_type, pub in stats['pubs'].items():
            info = sandesh.PublishInfo(service_type=service_type)
            info.blob        = pub['blob']
            resp.Publish.append(info)

        resp.response(req.context())
    # end

    # Return discovery client stats
    def sandesh_disc_client_stats_handle_request(self, req):
        stats = self._disc.get_stats()
        resp = sandesh.DiscoveryClientStatsResp(Subscribe=[], Publish=[])

        # pub stats
        for service_type, pub in stats['pubs'].items():
            pub_stats = sandesh.PublisherStats(service_type=service_type)
            pub_stats.Request     = pub['request']
            pub_stats.Response     = pub['response']
            pub_stats.ConnError   = pub['conn_error']
            pub_stats.Timeout   = pub['timeout']
            pub_stats.unknown_exceptions = pub['exc_unknown']
            pub_stats.exception_info    = pub['exc_info']
            xxx = ['%s:%d' % (k[3:], v) for k, v in pub.items() if 'sc_' in k]
            pub_stats.HttpError = ", ".join(xxx)
            resp.Publish.append(pub_stats)

        # sub stats
        for sub in stats['subs']:
            sub_stats = sandesh.SubscriberStats(service_type=sub['service_type'])
            sub_stats.Request   = sub['request']
            sub_stats.Response   = sub['response']
            sub_stats.ConnError   = sub['conn_error']
            sub_stats.Timeout   = sub['timeout']
            sub_stats.unknown_exceptions = sub['exc_unknown']
            sub_stats.exception_info    = sub['exc_info']
            xxx = ['%s:%d' % (k[3:], v) for k, v in sub.items() if 'sc_' in k]
            sub_stats.HttpError = ", ".join(xxx)
            resp.Subscribe.append(sub_stats)

        resp.response(req.context())
    # end sandesh_disc_client_stats_handle_request

    def _extensions_transform_request(self, request):
        extensions = self._extension_mgrs.get('resourceApi')
        if not extensions or not extensions.names():
            return None
        return extensions.map_method(
                    'transform_request', request)
    # end _extensions_transform_request

    def _extensions_validate_request(self, request):
        extensions = self._extension_mgrs.get('resourceApi')
        if not extensions or not extensions.names():
            return None
        return extensions.map_method(
                    'validate_request', request)
    # end _extensions_validate_request

    def _extensions_transform_response(self, request, response):
        extensions = self._extension_mgrs.get('resourceApi')
        if not extensions or not extensions.names():
            return None
        return extensions.map_method(
                    'transform_response', request, response)
    # end _extensions_transform_response

    @ignore_exceptions
    def _generate_rest_api_request_trace(self):
        method = get_request().method.upper()
        if method == 'GET':
            return None

        req_id = get_request().headers.get('X-Request-Id',
                                            'req-%s' %(str(uuid.uuid4())))
        gevent.getcurrent().trace_request_id = req_id
        url = get_request().url
        if method == 'DELETE':
            req_data = ''
        else:
            try:
                req_data = json.dumps(get_request().json)
            except Exception as e:
                req_data = '%s: Invalid request body' %(e)
        rest_trace = RestApiTrace(request_id=req_id)
        rest_trace.url = url
        rest_trace.method = method
        rest_trace.request_data = req_data
        return rest_trace
    # end _generate_rest_api_request_trace

    @ignore_exceptions
    def _generate_rest_api_response_trace(self, rest_trace, response):
        if not rest_trace:
            return

        rest_trace.status = bottle.response.status
        rest_trace.response_body = json.dumps(response)
        rest_trace.trace_msg(name='RestApiTraceBuf', sandesh=self._sandesh)
    # end _generate_rest_api_response_trace

    # Public Methods
    def route(self, uri, method, handler):
        def handler_trap_exception(*args, **kwargs):
            stats = construct_stats_collector(stats_enabled=self._args.enable_stats)
            gevent.getcurrent().stats = stats
            stats.start("route")
            set_context(ApiContext(external_req=bottle.request))
            trace = None
            try:
                self._extensions_transform_request(get_request())
                self._extensions_validate_request(get_request())

                trace = self._generate_rest_api_request_trace()

                (ok, status) = self._rbac.validate_request(get_request())
                if not ok:
                    (code, err_msg) = status
                    raise cfgm_common.exceptions.HttpError(code, err_msg, "40005")
                response = handler(*args, **kwargs)
                self._generate_rest_api_response_trace(trace, response)

                self._extensions_transform_response(get_request(), response)

                return response
            except Exception as e:
                if trace:
                    trace.trace_msg(name='RestApiTraceBuf',
                        sandesh=self._sandesh)
                #Add extra error definition attributes to the exception object
                #This will add any available extra attributes to all exception objects, however,
                #only the HttpError type exceptions will show those extra attributes in the response
                #because of the if-else block below.
                #For all non HttpError types, the response is 500, Internal Server Error from bottle.py
                #A possibility to report the error with some details is to check for any content in the exception
                #object and in case it has some content, then abort with 500 and the content as message.

                if hasattr(self, 'handle_error_code'):
                    self.handle_error_code(e)

                # don't log details of cfgm_common.exceptions.HttpError i.e handled error cases
                if isinstance(e, cfgm_common.exceptions.HttpError) \
                        or ((isinstance(e, VncError) or isinstance(e, CommonException)) and hasattr(e, 'status_code') and hasattr(e, 'content')):
                    bottle.abort(e.status_code, e.content)
                else:
                    string_buf = StringIO()
                    cgitb_hook(file=string_buf, format="text")
                    err_msg = string_buf.getvalue()
                    self.config_log(err_msg, level=SandeshLevel.SYS_ERR)

                    #if exception has some non empty content
                    if hasattr(e, 'content'):
                        msg = getattr(e, 'content')
                        if msg and msg.strip:
                            bottle.abort(500, msg)

                    raise
            finally:
                stats.end("route")
                gevent.getcurrent().stats.print_stats()
                gevent.getcurrent().stats = None
        print "ADD ROUTE: %s %s" % (uri, method)
        bottle.route(uri, method, handler_trap_exception)
    # end route

    def get_args(self):
        return self._args
    # end get_args

    def get_server_ip(self):
        ip_list = []
        for i in netifaces.interfaces():
            try:
                if netifaces.AF_INET in netifaces.ifaddresses(i):
                    addr = netifaces.ifaddresses(i)[netifaces.AF_INET][0][
                        'addr']
                    if addr != '127.0.0.1' and addr not in ip_list:
                        ip_list.append(addr)
            except ValueError, e:
                self.config_log("Skipping interface %s" % i,
                                level=SandeshLevel.SYS_DEBUG)
        return ip_list
    # end get_server_ip

    def get_listen_ip(self):
        return self._args.listen_ip_addr
    # end get_listen_ip

    def get_server_port(self):
        return self._args.listen_port
    # end get_server_port

    def get_pipe_start_app(self):
        return self._pipe_start_app
    # end get_pipe_start_app

    def get_ifmap_health_check_interval(self):
        return float(self._args.ifmap_health_check_interval)
    # end get_ifmap_health_check_interval

    def is_auth_disabled(self):
        return self._args.auth is None

    def is_admin_request(self):
        if not self.is_multi_tenancy_set():
            return True

        env = bottle.request.headers.environ
        for field in ('HTTP_X_API_ROLE', 'HTTP_X_ROLE'):
            if field in env:
                roles = env[field].split(',')
                return self.cloud_admin_role in [x.lower() for x in roles]
        return False

    # Check for the system created VN. Disallow such VN delete
    def virtual_network_http_delete(self, id):
        db_conn = self._db_conn
        # if obj doesn't exist return early
        try:
            obj_type = db_conn.uuid_to_obj_type(id)
            if obj_type != 'virtual_network':
                raise cfgm_common.exceptions.HttpError(
                    404, 'No virtual-network object found for id %s' %(id), "40002")
            vn_name = db_conn.uuid_to_fq_name(id)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'ID %s does not exist' %(id), "40002")
        if (vn_name == cfgm_common.IP_FABRIC_VN_FQ_NAME or
            vn_name == cfgm_common.LINK_LOCAL_VN_FQ_NAME):
            raise cfgm_common.exceptions.HttpError(
                409,
                'Can not delete system created default virtual-network '+id, "40019")
        super(VncApiServer, self).virtual_network_http_delete(id)
   # end

    def homepage_http_get(self):
        set_context(ApiContext(external_req=bottle.request))
        json_body = {}
        json_links = []
        # strip trailing '/' in url
        url = get_request().url.rstrip('/').rstrip(SERVICE_PATH)
        for link in self._homepage_links:
            # strip trailing '/' in url
            json_links.append(
                {'link': link.to_dict(with_url=url)}
            )
        json_body = {"uri": SERVICE_PATH, "links": json_links}
        #json_body = {"url": SERVICE_PATH, "links": json_links}
        return json_body
    # end homepage_http_get

    def documentation_http_get(self, filename):
        # ubuntu packaged path
        doc_root = '/usr/share/doc/contrail-config/doc/contrail-config/html/'
        if not os.path.exists(doc_root):
            # centos packaged path
            doc_root='/usr/share/doc/python-vnc_cfg_api_server/contrial-config/html/'

        return bottle.static_file(
                filename,
                root=doc_root)
    # end documentation_http_get

    def obj_perms_http_get(self):
        if 'token' not in get_request().query:
            raise cfgm_common.exceptions.HttpError(
                400, 'User token needed for validation', "40020")
        if 'uuid' not in get_request().query:
            raise cfgm_common.exceptions.HttpError(
                400, 'Object uuid needed for validation', "40021")
        obj_uuid = get_request().query.uuid
        user_token = get_request().query.token

        result = {'permissions' : ''}

        # get permissions in internal context
        try:
            orig_context = get_context()
            orig_request = get_request()
            b_req = bottle.BaseRequest(
                {
                 'HTTP_X_AUTH_TOKEN':  user_token,
                 'REQUEST_METHOD'   : 'GET',
                 'bottle.app': orig_request.environ['bottle.app'],
                })
            i_req = context.ApiInternalRequest(
                b_req.url, b_req.urlparts, b_req.environ, b_req.headers, None, None)
            set_context(context.ApiContext(internal_req=i_req))
            token_info = self._auth_svc.validate_user_token(get_request())
        finally:
            set_context(orig_context)

        # roles in result['token_info']['access']['user']['roles']
        if token_info:
            result = {'token_info' : token_info}
            if 'uuid' in get_request().query:
                obj_uuid = get_request().query.uuid
                result['permissions'] = self._permissions.obj_perms(get_request(), obj_uuid)
        else:
            raise cfgm_common.exceptions.HttpError(403, " Permission denied")
        return result
    #end check_obj_perms_http_get

    def invalid_uuid(self, uuid):
        return self.re_uuid.match(uuid) == None
    def invalid_access(self, access):
        return type(access) is not int or access not in range(0,8)

    # change ownership of an object
    def obj_chown_http_post(self):
        self._post_common(get_request(), None, None)

        try:
            obj_uuid = get_request().json['uuid']
            owner = get_request().json['owner']
        except Exception as e:
            raise cfgm_common.exceptions.HttpError(400, str(e))
        if self.invalid_uuid(obj_uuid) or self.invalid_uuid(owner):
            raise cfgm_common.exceptions.HttpError(
                400, "Bad Request, invalid object or owner id")

        try:
            obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(400, 'Invalid object id')

        # ensure user has RW permissions to object
        perms = self._permissions.obj_perms(get_request(), obj_uuid)
        if not 'RW' in perms:
            raise cfgm_common.exceptions.HttpError(403, " Permission denied")

        (ok, obj_dict) = self._db_conn.dbe_read(obj_type, {'uuid':obj_uuid},
                             obj_fields=['perms2'])
        obj_dict['perms2']['owner'] = owner
        self._db_conn.dbe_update(obj_type, {'uuid': obj_uuid}, obj_dict)

        msg = "chown: %s owner set to %s" % (obj_uuid, owner)
        self.config_log(msg, level=SandeshLevel.SYS_NOTICE)

        return {}
    #end obj_chown_http_post

    # chmod for an object
    def obj_chmod_http_post(self):
        self._post_common(get_request(), None, None)

        try:
            obj_uuid = get_request().json['uuid']
        except Exception as e:
            raise cfgm_common.exceptions.HttpError(400, str(e))
        if self.invalid_uuid(obj_uuid):
            raise cfgm_common.exceptions.HttpError(
                400, "Bad Request, invalid object id")

        try:
            obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(400, 'Invalid object id')

        # ensure user has RW permissions to object
        perms = self._permissions.obj_perms(get_request(), obj_uuid)
        if not 'RW' in perms:
            raise cfgm_common.exceptions.HttpError(403, " Permission denied")

        request_params = get_request().json
        owner         = request_params.get('owner')
        share         = request_params.get('share')
        owner_access  = request_params.get('owner_access')
        global_access = request_params.get('global_access')

        (ok, obj_dict) = self._db_conn.dbe_read(obj_type, {'uuid':obj_uuid},
                             obj_fields=['perms2'])
        obj_perms = obj_dict['perms2']
        old_perms = '%s/%d %d %s' % (obj_perms['owner'],
            obj_perms['owner_access'], obj_perms['global_access'],
            ['%s:%d' % (item['tenant'], item['tenant_access']) for item in obj_perms['share']])

        if owner:
            if self.invalid_uuid(owner):
                raise cfgm_common.exceptions.HttpError(
                    400, "Bad Request, invalid owner")
            obj_perms['owner'] = owner.replace('-','')
        if owner_access is not None:
            if self.invalid_access(owner_access):
                raise cfgm_common.exceptions.HttpError(
                    400, "Bad Request, invalid owner_access value")
            obj_perms['owner_access'] = owner_access
        if share is not None:
            try:
                for item in share:
                    if self.invalid_uuid(item['tenant']) or self.invalid_access(item['tenant_access']):
                        raise cfgm_common.exceptions.HttpError(
                            400, "Bad Request, invalid share list")
            except Exception as e:
                raise cfgm_common.exceptions.HttpError(400, str(e))
            obj_perms['share'] = share
        if global_access is not None:
            if self.invalid_access(global_access):
                raise cfgm_common.exceptions.HttpError(
                    400, "Bad Request, invalid global_access value")
            obj_perms['global_access'] = global_access

        new_perms = '%s/%d %d %s' % (obj_perms['owner'],
            obj_perms['owner_access'], obj_perms['global_access'],
            ['%s:%d' % (item['tenant'], item['tenant_access']) for item in obj_perms['share']])

        self._db_conn.dbe_update(obj_type, {'uuid': obj_uuid}, obj_dict)
        msg = "chmod: %s perms old=%s, new=%s" % (obj_uuid, old_perms, new_perms)
        self.config_log(msg, level=SandeshLevel.SYS_NOTICE)

        return {}
    #end obj_chmod_http_post

    def prop_collection_http_get(self):
        if 'uuid' not in get_request().query:
            raise cfgm_common.exceptions.HttpError(
                400, 'Object uuid needed for property collection get', "40021")
        obj_uuid = get_request().query.uuid

        if 'fields' not in get_request().query:
            raise cfgm_common.exceptions.HttpError(
                400, 'Object fields needed for property collection get', "40022")
        obj_fields = get_request().query.fields.split(',')

        if 'position' in get_request().query:
            fields_position = get_request().query.position
        else:
            fields_position = None

        try:
            obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Object Not Found: ' + obj_uuid, "40002")
        resource_class = self.get_resource_class(obj_type)

        for obj_field in obj_fields:
            if ((obj_field not in resource_class.prop_list_fields) and
                (obj_field not in resource_class.prop_map_fields)):
                err_msg = '%s neither "ListProperty" nor "MapProperty"' %(
                    obj_field)
                raise cfgm_common.exceptions.HttpError(400, err_msg, "40023")
        # request validations over

        # common handling for all resource get
        (ok, result) = self._get_common(get_request(), obj_uuid)
        if not ok:
            (code, msg) = result
            self.config_object_error(
                obj_uuid, None, None, 'prop_collection_http_get', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40018")

        try:
            ok, result = self._db_conn.prop_collection_get(
                obj_type, obj_uuid, obj_fields, fields_position)
            if not ok:
                self.config_object_error(
                    obj_uuid, None, None, 'prop_collection_http_get', result)
        except NoIdError as e:
            # Not present in DB
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")
        if not ok:
            raise cfgm_common.exceptions.HttpError(500, result, "50006")

        # check visibility
        if (not result['id_perms'].get('user_visible', True) and
            not self.is_admin_request()):
            result = 'This object is not visible by users: %s' % id
            self.config_object_error(
                id, None, None, 'prop_collection_http_get', result)
            raise cfgm_common.exceptions.HttpError(404, result, "40018")

        # Prepare response
        del result['id_perms']

        return result
    # end prop_collection_http_get

    def prop_collection_update_http_post(self):
        self._post_common(get_request(), None, None)

        request_params = get_request().json
        # validate each requested operation
        obj_uuid = request_params.get('uuid')
        if not obj_uuid:
            err_msg = 'Error: prop_collection_update needs obj_uuid'
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40021")

        try:
            obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Object Not Found: ' + obj_uuid, "40002")
        resource_class = self.get_resource_class(obj_type)

        for req_param in request_params.get('updates') or []:
            obj_field = req_param.get('field')
            if obj_field in resource_class.prop_list_fields:
                prop_coll_type = 'list'
            elif obj_field in resource_class.prop_map_fields:
                prop_coll_type = 'map'
            else:
                err_msg = '%s neither "ListProperty" nor "MapProperty"' %(
                    obj_field)
                raise cfgm_common.exceptions.HttpError(400, err_msg, "40023")

            req_oper = req_param.get('operation').lower()
            field_val = req_param.get('value')
            field_pos = str(req_param.get('position'))
            if prop_coll_type == 'list':
                if req_oper not in ('add', 'modify', 'delete'):
                    err_msg = 'Unsupported operation %s in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40025")
                if ((req_oper == 'add') and field_val is None):
                    err_msg = 'Add needs field value in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40022")
                elif ((req_oper == 'modify') and
                    None in (field_val, field_pos)):
                    err_msg = 'Modify needs field value and position in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40023")
                elif ((req_oper == 'delete') and field_pos is None):
                    err_msg = 'Delete needs field position in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40022")
            elif prop_coll_type == 'map':
                if req_oper not in ('set', 'delete'):
                    err_msg = 'Unsupported operation %s in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40025")
                if ((req_oper == 'set') and field_val is None):
                    err_msg = 'Set needs field value in request %s' %(
                        req_oper, json.dumps(req_param))
                elif ((req_oper == 'delete') and field_pos is None):
                    err_msg = 'Delete needs field position in request %s' %(
                        req_oper, json.dumps(req_param))
                    raise cfgm_common.exceptions.HttpError(400, err_msg, "40022")

        # Validations over. Invoke type specific hook and extension manager
        try:
            fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
            (read_ok, read_result) = self._db_conn.dbe_read(
                                         obj_type, {'uuid':obj_uuid})
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Object Not Found: '+obj_uuid, "40002")
        except Exception as e:
            read_ok = False
            read_result = cfgm_common.utils.detailed_traceback()

        if not read_ok:
            self.config_object_error(
                obj_uuid, None, obj_type, 'prop_collection_update', read_result)
            raise cfgm_common.exceptions.HttpError(500, read_result, "40018")

        # invoke the extension
        try:
            pre_func = 'pre_'+obj_type+'_update'
            self._extension_mgrs['resourceApi'].map_method(pre_func, obj_uuid, {},
                prop_collection_updates=request_params.get('updates'))
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In pre_%s_update an extension had error for %s' \
                      %(obj_type, request_params)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        # type-specific hook
        r_class = self.get_resource_class(obj_type)
        get_context().set_state('PRE_DBE_UPDATE')
        (ok, pre_update_result) = r_class.pre_dbe_update(
            obj_uuid, fq_name, {}, self._db_conn,
            prop_collection_updates=request_params.get('updates'))
        if not ok:
            (code, msg) = pre_update_result
            self.config_object_error(
                obj_uuid, None, obj_type, 'prop_collection_update', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40024")

        # the actual db update
        try:
            get_context().set_state('DBE_UPDATE')
            ok, update_result = self._db_conn.prop_collection_update(
                obj_type, obj_uuid, request_params.get('updates'))
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'uuid ' + obj_uuid + ' not found', "40002")
        if not ok:
            (code, msg) = update_result
            self.config_object_error(
                obj_uuid, None, obj_type, 'prop_collection_update', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40024")

        # type-specific hook
        get_context().set_state('POST_DBE_UPDATE')
        (ok, post_update_result) = r_class.post_dbe_update(
            obj_uuid, fq_name, {}, self._db_conn,
            prop_collection_updates=request_params.get('updates'))
        if not ok:
            (code, msg) = pre_update_result
            self.config_object_error(
                obj_uuid, None, obj_type, 'prop_collection_update', msg)
            raise cfgm_common.exceptions.HttpError(code, msg, "40024")

        # invoke the extension
        try:
            post_func = 'post_'+obj_type+'_update'
            self._extension_mgrs['resourceApi'].map_method(
                post_func, obj_uuid, {}, read_result,
                prop_collection_updates=request_params.get('updates'))
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In post_%s_update an extension had error for %s' \
                      %(obj_type, request_params)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type
        apiConfig.identifier_name=':'.join(fq_name)
        apiConfig.identifier_uuid = obj_uuid
        apiConfig.operation = 'prop-collection-update'
        try:
            body = json.dumps(get_request().json)
        except:
            body = str(get_request().json)
        apiConfig.body = body

        self._set_api_audit_info(apiConfig)
        self.vnc_api_config_log(apiConfig)

    # end prop_collection_update_http_post

    def ref_update_http_post(self):
        self._post_common(get_request(), None, None)
        # grab fields
        type = get_request().json.get('type')
        ok, result = self._validate_resource_type(type)
        if not ok:
            raise cfgm_common.exceptions.HttpError(result[0], result[1])
        res_type = result
        res_class = self.get_resource_class(res_type)
        obj_uuid = get_request().json.get('uuid')
        ref_type = get_request().json.get('ref-type')
        ok, result = self._validate_resource_type(ref_type)
        if not ok:
            raise cfgm_common.exceptions.HttpError(result[0], result[1])
        ref_res_type = result
        ref_class = self.get_resource_class(ref_res_type)
        operation = get_request().json.get('operation')
        ref_uuid = get_request().json.get('ref-uuid')
        ref_fq_name = get_request().json.get('ref-fq-name')
        attr = get_request().json.get('attr')

        # validate fields
        if None in (res_type, obj_uuid, ref_res_type, operation):
            err_msg = 'Bad Request: type/uuid/ref-type/operation is null: '
            err_msg += '%s, %s, %s, %s.' \
                        %(obj_type, obj_uuid, ref_type, operation)
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40025")


        operation = operation.upper()
        if operation not in ['ADD', 'DELETE']:
            err_msg = 'Bad Request: operation should be add or delete: %s' \
                      %(operation)
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40025")

        if not ref_uuid and not ref_fq_name:
            err_msg = 'Bad Request: ref-uuid or ref-fq-name must be specified'
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40021")

        obj_type = res_class.object_type
        ref_obj_type = ref_class.object_type
        if not ref_uuid:
            try:
                ref_uuid = self._db_conn.fq_name_to_uuid(ref_obj_type, ref_fq_name)
            except NoIdError:
                raise cfgm_common.exceptions.HttpError(
                    404, 'Name ' + pformat(ref_fq_name) + ' not found', "40002")

        # To verify existence of the reference being added
        if operation == 'ADD':
            try:
                (read_ok, read_result) = self._db_conn.dbe_read(
                    ref_obj_type, {'uuid': ref_uuid}, obj_fields=['fq_name'])
            except NoIdError:
                raise cfgm_common.exceptions.HttpError(
                    404, 'Object Not Found: ' + ref_uuid, "40002")
            except Exception as e:
                read_ok = False
                read_result = cfgm_common.utils.detailed_traceback()

        # To invoke type specific hook and extension manager
        try:
            (read_ok, read_result) = self._db_conn.dbe_read(
                                         obj_type, get_request().json)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Object Not Found: '+obj_uuid, "40002")
        except Exception as e:
            read_ok = False
            read_result = cfgm_common.utils.detailed_traceback()

        if not read_ok:
            self.config_object_error(obj_uuid, None, obj_type, 'ref_update', read_result)
            raise cfgm_common.exceptions.HttpError(500, read_result, "40015")

        obj_dict = copy.deepcopy(read_result)

        # invoke the extension
        try:
            pre_func = 'pre_' + obj_type + '_update'
            self._extension_mgrs['resourceApi'].map_method(pre_func, obj_uuid, obj_dict)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In pre_%s_update an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        # type-specific hook
        if res_class:
            try:
                fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
            except NoIdError:
                raise cfgm_common.exceptions.HttpError(
                    404, 'UUID ' + obj_uuid + ' not found', "40021")

            if operation == 'ADD':
                if ref_obj_type+'_refs' not in obj_dict:
                    obj_dict[ref_obj_type+'_refs'] = []
                obj_dict[ref_obj_type+'_refs'].append(
                    {'to':ref_fq_name, 'uuid': ref_uuid, 'attr':attr})
            elif operation == 'DELETE':
                for old_ref in obj_dict.get(ref_obj_type+'_refs', []):
                    if old_ref['to'] == ref_fq_name or old_ref['uuid'] == ref_uuid:
                        obj_dict[ref_obj_type+'_refs'].remove(old_ref)
                        break

            (ok, put_result) = res_class.pre_dbe_update(
                obj_uuid, fq_name, obj_dict, self._db_conn)
            if not ok:
                (code, msg) = put_result
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', msg)
                raise cfgm_common.exceptions.HttpError(code, msg, "40016")
        # end if r_class


        try:
            self._db_conn.ref_update(obj_type, obj_uuid, ref_obj_type,
                                     ref_uuid, {'attr': attr}, operation)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'uuid ' + obj_uuid + ' not found', "40002")

        # invoke the extension
        try:
            post_func = 'post_' + obj_type + '_update'
            self._extension_mgrs['resourceApi'].map_method(post_func, obj_uuid, obj_dict, read_result)
        except RuntimeError:
            # lack of registered extension leads to RuntimeError
            pass
        except Exception as e:
            err_msg = 'In post_%s_update an extension had error for %s' \
                      %(obj_type, obj_dict)
            err_msg += cfgm_common.utils.detailed_traceback()
            self.config_log(err_msg, level=SandeshLevel.SYS_NOTICE)

        if self.is_multi_tenancy_with_rbac_set():
            try:
                self._update_ref_perms2(obj_type, obj_dict, ref_type.replace('_', '-'), ref_uuid, operation.upper())
            except Exception as e:
                logger.error("Failed updating share-relation: %s", e.message)

        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type
        fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
        apiConfig.identifier_name=':'.join(fq_name)
        apiConfig.identifier_uuid = obj_uuid
        apiConfig.operation = 'ref-update'
        try:
            body = json.dumps(get_request().json)
        except:
            body = str(get_request().json)
        apiConfig.body = body

        self._set_api_audit_info(apiConfig)
        self.vnc_api_config_log(apiConfig)
        return {'uuid': obj_uuid}
    # end ref_update_http_post

    def ref_relax_for_delete_http_post(self):
        self._post_common(get_request(), None, None)
        # grab fields
        obj_uuid = get_request().json.get('uuid')
        ref_uuid = get_request().json.get('ref-uuid')

        # validate fields
        if None in (obj_uuid, ref_uuid):
            err_msg = 'Bad Request: Both uuid and ref-uuid should be specified: '
            err_msg += '%s, %s.' %(obj_uuid, ref_uuid)
            raise cfgm_common.exceptions.HttpError(400, err_msg, "40021")

        try:
            obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
            self._db_conn.ref_relax_for_delete(obj_uuid, ref_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'uuid ' + obj_uuid + ' not found', "40002")

        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type
        fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
        apiConfig.identifier_name=':'.join(fq_name)
        apiConfig.identifier_uuid = obj_uuid
        apiConfig.operation = 'ref-relax-for-delete'
        try:
            body = json.dumps(get_request().json)
        except:
            body = str(get_request().json)
        apiConfig.body = body

        self._set_api_audit_info(apiConfig)
        self.vnc_api_config_log(apiConfig)

        return {'uuid': obj_uuid}
    # end ref_relax_for_delete_http_post

    def fq_name_to_id_http_post(self):
        self._post_common(get_request(), None, None)
        type = get_request().json.get('type')
        ok, result = self._validate_resource_type(type)
        if not ok:
            raise cfgm_common.exceptions.HttpError(result[0], result[1])
        res_type = result
        r_class = self.get_resource_class(res_type)
        obj_type = r_class.object_type
        fq_name = get_request().json['fq_name']

        try:
            id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Name ' + pformat(fq_name) + ' not found', "40002")

        # ensure user has access to this id
        ok, result = self._permissions.check_perms_read(bottle.request, id)
        if not ok:
            err_code, err_msg = result
            raise cfgm_common.exceptions.HttpError(err_code, err_msg, "40005")

        return {'uuid': id}
    # end fq_name_to_id_http_post

    def id_to_fq_name_http_post(self):
        self._post_common(get_request(), None, None)
        obj_uuid = get_request().json['uuid']

        # ensure user has access to this id
        ok, result = self._permissions.check_perms_read(get_request(), obj_uuid)
        if not ok:
            err_code, err_msg = result
            raise cfgm_common.exceptions.HttpError(err_code, err_msg, "40005")

        try:
            fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
               404, 'UUID ' + obj_uuid + ' not found', "40002")

        obj_type = self._db_conn.uuid_to_obj_type(obj_uuid)
        res_type = self.get_resource_class(obj_type).resource_type
        return {'fq_name': fq_name, 'type': res_type}
    # end id_to_fq_name_http_post

    def ifmap_to_id_http_post(self):
        self._post_common(get_request(), None, None)
        uuid = self._db_conn.ifmap_id_to_uuid(get_request().json['ifmap_id'])
        return {'uuid': uuid}
    # end ifmap_to_id_http_post

    # Enables a user-agent to store and retrieve key-val pair
    # TODO this should be done only for special/quantum plugin
    def useragent_kv_http_post(self):
        self._post_common(get_request(), None, None)

        oper = get_request().json['operation']
        key = get_request().json['key']
        val = get_request().json.get('value', '')

        # TODO move values to common
        if oper == 'STORE':
            self._db_conn.useragent_kv_store(key, val)
        elif oper == 'RETRIEVE':
            try:
                result = self._db_conn.useragent_kv_retrieve(key)
                return {'value': result}
            except NoUserAgentKey:
                raise cfgm_common.exceptions.HttpError(
                    404, "Unknown User-Agent key " + key, "40008")
        elif oper == 'DELETE':
            result = self._db_conn.useragent_kv_delete(key)
        else:
            raise cfgm_common.exceptions.HttpError(
                404, "Invalid Operation " + oper, "40025")

    # end useragent_kv_http_post

    def db_check(self):
        """ Check database for inconsistencies. No update to database """
        check_result = self._db_conn.db_check()

        return {'results': check_result}
    # end db_check

    def fetch_records(self):
        """ Retrieve and return all records """
        result = self._db_conn.db_read()
        return {'results': result}
    # end fetch_records

    def start_profile(self):
        #GreenletProfiler.start()
        pass
    # end start_profile

    def stop_profile(self):
        pass
        #GreenletProfiler.stop()
        #stats = GreenletProfiler.get_func_stats()
        #self._profile_info = stats.print_all()

        #return self._profile_info
    # end stop_profile

    def get_profile_info(self):
        return self._profile_info
    # end get_profile_info

    def get_resource_class(self, type_str):
        if type_str in self._resource_classes:
            return self._resource_classes[type_str]

        common_name = cfgm_common.utils.CamelCase(type_str)
        server_name = '%sServer' % common_name
        try:
            resource_class = getattr(vnc_cfg_types, server_name)
        except AttributeError:
            common_class = cfgm_common.utils.str_to_class(common_name,
                                                          __name__)
            # Create Placeholder classes derived from Resource, <Type> so
            # resource_class methods can be invoked in CRUD methods without
            # checking for None
            resource_class = type(
                str(server_name),
                (vnc_cfg_types.Resource, common_class, object),
                {})
        resource_class.server = self
        self._resource_classes[resource_class.object_type] = resource_class
        self._resource_classes[resource_class.resource_type] = resource_class
        return resource_class
    # end get_resource_class

    def get_resource_xsd_class(self, resource_type):
        return cfgm_common.utils.str_to_class(resource_type, __name__)
    # end get_resource_xsd_class

    def _get_obj_type_to_db_type(self, resource_type):
        return get_obj_type_to_db_type(resource_type)
    # end get_obj_type_to_db_type

    def list_bulk_collection_http_post(self):
        """ List collection when requested ids don't fit in query params."""
        type = get_request().json.get('type') # e.g. virtual-network
        ok, result = self._validate_resource_type(type)
        if not ok:
            raise cfgm_common.exceptions.HttpError(400, "Bad Request, no 'type' in POST body", "40004")
        resource_type = result
        return self._http_post_filter(resource_type)

    def _http_post_filter(self, resource_type):
        r_class = self.get_resource_class(resource_type)
        if not r_class:
            raise cfgm_common.exceptions.HttpError(400,
                                                   "Bad Request, Unknown type %s in POST body" % (resource_type))
        body = get_request().json
        try:
            parent_uuids = get_request().json['parent_id'].split(',')
            del body['parent_id']
        except KeyError:
            parent_uuids = None

        try:
            back_ref_uuids = get_request().json['back_ref_id'].split(',')
            del body['back_ref_id']
        except KeyError:
            back_ref_uuids = None
                
        try:
            obj_uuids = get_request().json['obj_uuids'].split(',')
            del body['obj_uuids']
        except KeyError:
            obj_uuids = None

        is_count = get_request().json.get('count', False)
        is_detail = get_request().json.get('detail', False)
                
        try:
            filters = utils.get_filters(get_request().json.get('filters'))
        except Exception as e:
            raise cfgm_common.exceptions.HttpError(
                                                   400, 'Invalid filter ' + get_request().json.get('filters'))
                
        req_fields = get_request().json.get('fields', [])
        if req_fields:
            req_fields = req_fields.split(',')
        if 'count' in body:
            del body['count']
        if 'detail' in body:
            del body['detail']
        if 'fields' in body:
            del body['fields']
        if 'filters' in body:
            del body['filters']
        if 'type' in body:
            del body['type']
        params=get_request().query

        return self._list_collection(r_class.object_type, parent_uuids,
                                     back_ref_uuids, obj_uuids, is_count,
                                     is_detail,  filters=filters,
                                     body=body, req_fields=req_fields, params=params)


    # Private Methods
    def _parse_args(self, args_str):
	'''
        Eg. python vnc_cfg_api_server.py --ifmap_server_ip 192.168.1.17
                                         --ifmap_server_port 8443
                                         --ifmap_username test
                                         --ifmap_password test
                                         --cassandra_server_list
                                             10.1.2.3:9160 10.1.2.4:9160
                                         --redis_server_ip 127.0.0.1
                                         --redis_server_port 6382
                                         --collectors 127.0.0.1:8086
                                         --http_server_port 8090
                                         --listen_ip_addr 127.0.0.1
                                         --listen_port 8082
                                         --admin_port 8095
                                         --region_name RegionOne
                                         --log_local
                                         --log_level SYS_DEBUG
                                         --logging_level DEBUG
                                         --logging_conf <logger-conf-file>
                                         --log_category test
                                         --log_file <stdout>
                                         --trace_file /var/log/contrail/vnc_openstack.err
                                         --use_syslog
                                         --syslog_facility LOG_USER
                                         --disc_server_ip 127.0.0.1
                                         --disc_server_port 5998
                                         --worker_id 1
                                         --rabbit_max_pending_updates 4096
                                         --cluster_id <testbed-name>
                                         [--auth keystone]
                                         [--ifmap_server_loc
                                          /home/contrail/source/ifmap-server/]
                                         [--default_encoding ascii ]
                                         --ifmap_health_check_interval 60
        '''
        self._args, _ = utils.parse_args(args_str)
    # end _parse_args

    # sigchld handler is currently not engaged. See comment @sigchld
    def sigchld_handler(self):
        # DB interface initialization
        self._db_connect(reset_config=False)
        self._db_init_entries()
    # end sigchld_handler

    def sigterm_handler(self):
        exit()

    def _load_extensions(self):
        try:
            conf_sections = self._args.config_sections
            self._extension_mgrs['resync'] = ExtensionManager(
                'vnc_cfg_api.resync', api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
            self._extension_mgrs['resourceApi'] = ExtensionManager(
                'vnc_cfg_api.resourceApi',
                propagate_map_exceptions=True,
                api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
            self._extension_mgrs['neutronApi'] = ExtensionManager(
                'vnc_cfg_api.neutronApi',
                api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
        except Exception as e:
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log("Exception in extension load: %s" %(err_msg),
                level=SandeshLevel.SYS_ERR)
    # end _load_extensions

    def _db_connect(self, reset_config):
        ifmap_ip = self._args.ifmap_server_ip
        ifmap_port = self._args.ifmap_server_port
        user = self._args.ifmap_username
        passwd = self._args.ifmap_password
        cass_server_list = self._args.cassandra_server_list
        redis_server_ip = self._args.redis_server_ip
        redis_server_port = self._args.redis_server_port
        zk_server = self._args.zk_server_ip
        rabbit_servers = self._args.rabbit_server
        rabbit_port = self._args.rabbit_port
        rabbit_user = self._args.rabbit_user
        rabbit_password = self._args.rabbit_password
        rabbit_vhost = self._args.rabbit_vhost
        rabbit_ha_mode = self._args.rabbit_ha_mode
        cassandra_user = self._args.cassandra_user
        cassandra_password = self._args.cassandra_password
        cred = None
        if cassandra_user is not None and cassandra_password is not None:
            cred = {'username':cassandra_user,'password':cassandra_password}
        cassandra_pool = {
                'max_overflow': self._args.cassandra_max_overflow,
                'pool_size': self._args.cassandra_pool_size
                }
        self._db_conn = VncDbClient(self, ifmap_ip, ifmap_port, user, passwd,
                              cass_server_list, rabbit_servers, rabbit_port,
                              rabbit_user, rabbit_password, rabbit_vhost,
                              rabbit_ha_mode, reset_config,
                              zk_server, self._args.cluster_id,
                              cassandra_credential=cred, ifmap_disable=self._args.disable_ifmap,
                              cassandra_pool=cassandra_pool,rabbit_use_ssl=self._args.rabbit_use_ssl,
                              kombu_ssl_version=self._args.kombu_ssl_version,
                              kombu_ssl_keyfile= self._args.kombu_ssl_keyfile,
                              kombu_ssl_certfile=self._args.kombu_ssl_certfile,
                              kombu_ssl_ca_certs=self._args.kombu_ssl_ca_certs)
    # end _db_connect

    def get_vnc_zk_client(self):
        return self._db_conn.get_zk_db_client()
    # end get_vnc_zk_client

    def _ensure_id_perms_present(self, obj_uuid, obj_dict):
        """
        Called at resource creation to ensure that id_perms is present in obj
        """
        # retrieve object and permissions
        id_perms = self._get_default_id_perms()

        if (('id_perms' not in obj_dict) or
                (obj_dict['id_perms'] is None)):
            # Resource creation
            if obj_uuid is None:
                obj_dict['id_perms'] = id_perms
                return

            return

        # retrieve the previous version of the id_perms
        # from the database and update the id_perms with
        # them.
        if obj_uuid is not None:
            try:
                old_id_perms = self._db_conn.uuid_to_obj_perms(obj_uuid)
                for field, value in old_id_perms.items():
                    if value is not None:
                        id_perms[field] = value
            except NoIdError:
                pass

        # not all fields can be updated
        if obj_uuid:
            field_list = ['enable', 'description']
        else:
            field_list = ['enable', 'description', 'user_visible', 'creator']

        # Start from default and update from obj_dict
        req_id_perms = obj_dict['id_perms']
        for key in field_list:
            if key in req_id_perms:
                id_perms[key] = req_id_perms[key]
        # TODO handle perms present in req_id_perms

        obj_dict['id_perms'] = id_perms
    # end _ensure_id_perms_present

    def _get_default_id_perms(self):
        id_perms = copy.deepcopy(Provision.defaults.perms)
        id_perms_json = json.dumps(id_perms, default=lambda o: dict((k, v)
                                   for k, v in o.__dict__.iteritems()))
        id_perms_dict = json.loads(id_perms_json)
        return id_perms_dict
    # end _get_default_id_perms

    def _ensure_perms2_present(self, obj_type, obj_uuid, obj_dict,
                               project_id=None):
        """
        Called at resource creation to ensure that id_perms is present in obj
        """
        # retrieve object and permissions
        perms2 = self._get_default_perms2()

        # set ownership of object to creator tenant
        if obj_type == 'project' and 'uuid' in obj_dict:
            perms2['owner'] = str(obj_dict['uuid']).replace('-','')
        elif project_id:
            perms2['owner'] = project_id

        if (('perms2' not in obj_dict) or
                (obj_dict['perms2'] is None)):
            # Resource creation
            if obj_uuid is None:
                obj_dict['perms2'] = perms2
                return
            # Resource already exist
            try:
                obj_dict['perms2'] = self._db_conn.uuid_to_obj_perms2(obj_uuid)
            except NoIdError:
                obj_dict['perms2'] = perms2

            return

        # retrieve the previous version of the perms2
        # from the database and update the perms2 with
        # them.
        if obj_uuid is not None:
            try:
                old_perms2 = self._db_conn.uuid_to_obj_perms2(obj_uuid)
                for field, value in old_perms2.items():
                    if value is not None:
                        perms2[field] = value
            except NoIdError:
                pass

        # Start from default and update from obj_dict
        req_perms2 = obj_dict['perms2']
        for key in req_perms2:
            perms2[key] = req_perms2[key]
        # TODO handle perms2 present in req_perms2

        obj_dict['perms2'] = perms2
    # end _ensure_perms2_present

    def _get_default_perms2(self):
        perms2 = copy.deepcopy(Provision.defaults.perms2)
        perms2_json = json.dumps(perms2, default=lambda o: dict((k, v)
                                   for k, v in o.__dict__.iteritems()))
        perms2_dict = json.loads(perms2_json)
        return perms2_dict
    # end _get_default_perms2

    def _db_init_entries(self):
        # create singleton defaults if they don't exist already in db
        glb_sys_cfg = self._create_singleton_entry(
            GlobalSystemConfig(autonomous_system=64512,
                               config_version=CONFIG_VERSION))
        def_domain = self._create_singleton_entry(Domain())
        ip_fab_vn = self._create_singleton_entry(
            VirtualNetwork(cfgm_common.IP_FABRIC_VN_FQ_NAME[-1]))
        self._create_singleton_entry(
            RoutingInstance('__default__', ip_fab_vn,
                routing_instance_is_default=True))
        link_local_vn = self._create_singleton_entry(
            VirtualNetwork(cfgm_common.LINK_LOCAL_VN_FQ_NAME[-1]))
        self._create_singleton_entry(
            RoutingInstance('__link_local__', link_local_vn,
                routing_instance_is_default=True))
        try:
            self._create_singleton_entry(
                RoutingInstance('default-virtual-network',
                    routing_instance_is_default=True))
        except Exception as e:
            self.config_log('error while creating primary routing instance for'
                            'default-virtual-network: ' + str(e),
                            level=SandeshLevel.SYS_NOTICE)

        self._create_singleton_entry(DiscoveryServiceAssignment())
        self._create_singleton_entry(GlobalQosConfig())

        self._db_conn.db_resync()
    # end _db_init_entries

    # generate default rbac group rule, merge it with the already existing ones
    def _create_default_rbac_rule(self, fq_name=None):
        obj_type = 'api-access-list'
        rule_list = []
        if not fq_name:
            fq_name = ['default-domain', 'default-api-access-list']
        try:
            id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
            return
        except NoIdError:
            self._create_singleton_entry(ApiAccessList(parent_type='domain', fq_name=fq_name))
            id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        (ok, obj_dict) = self._db_conn.dbe_read(obj_type, {'uuid': id})
        if 'api_access_list_entries' in obj_dict:
           api_access_list_entries = obj_dict['api_access_list_entries']
           if 'rbac_rule' in api_access_list_entries:
              if (api_access_list_entries['rbac_rule'])[0]:
                 rule_list.extend(api_access_list_entries['rbac_rule'])

        # allow full access to cloud admin
        rbac_rules = [
            {
                'rule_object':'fqname-to-id',
                'rule_field': '',
                'rule_perms': [{'role_name':'*', 'role_crud':'CRUD'}]
            },
            {
                'rule_object':'id-to-fqname',
                'rule_field': '',
                'rule_perms': [{'role_name':'*', 'role_crud':'CRUD'}]
            },
            {
                'rule_object':'documentation',
                'rule_field': '',
                'rule_perms': [{'role_name':'*', 'role_crud':'R'}]
            },
        ]
        rule_list.extend(rbac_rules)
        updated_rbac_rule = self._merge_rbac_rule(rule_list)
        obj_dict['api_access_list_entries'] = {'rbac_rule' : updated_rbac_rule}
        self._db_conn.dbe_update(obj_type, {'uuid': id}, obj_dict)
    # end _create_default_rbac_rule

    def _merge_rbac_rule(self, rbac_rule):
        rule_dict = {}
        for rule in rbac_rule[:]:
            o = rule['rule_object']
            f = rule['rule_field']
            p = rule['rule_perms']
            o_f = "%s.%s" % (o,f) if f else o
            if o_f not in rule_dict:
                rule_dict[o_f] = rule
            else:
                role_to_crud_dict = {rp['role_name']:rp['role_crud'] for rp in rule_dict[o_f]['rule_perms']}
                for role in rule['rule_perms']:
                    role_name = role['role_name']
                    role_crud = role['role_crud']
                    if role_name in role_to_crud_dict:
                        x = set(list(role_to_crud_dict[role_name])) | set(list(role_crud))
                        role_to_crud_dict[role_name] = ''.join(x)
                    else:
                        role_to_crud_dict[role_name] = role_crud
                # update perms in existing rule
                rule_dict[o_f]['rule_perms'] = [{'role_crud': rc, 'role_name':rn} for rn,rc in role_to_crud_dict.items()]
                # remove duplicate rule from list
                rbac_rule.remove(rule)

        return rbac_rule
    # end _merge_rbac_rule
    
    def _resync_domains_projects(self, ext):
        if hasattr(ext.obj, 'resync_domains_projects'):
            ext.obj.resync_domains_projects()
    # end _resync_domains_projects

    def _create_singleton_entry(self, singleton_obj):
        s_obj = singleton_obj
        obj_type = s_obj.object_type
        fq_name = s_obj.get_fq_name()

        # TODO remove backward compat create mapping in zk
        # for singleton START
        try:
            cass_uuid = self._db_conn._cassandra_db.fq_name_to_uuid(obj_type, fq_name)
            try:
                zk_uuid = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
            except NoIdError:
                # doesn't exist in zookeeper but does so in cassandra,
                # migrate this info to zookeeper
                self._db_conn._zk_db.create_fq_name_to_uuid_mapping(obj_type, fq_name, str(cass_uuid))
        except NoIdError:
            # doesn't exist in cassandra as well as zookeeper, proceed normal
            pass
        # TODO backward compat END


        # create if it doesn't exist yet
        try:
            id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        except NoIdError:
            obj_dict = s_obj.serialize_to_json()
            obj_dict['id_perms'] = self._get_default_id_perms()
            obj_dict['perms2'] = self._get_default_perms2()
            (ok, result) = self._db_conn.dbe_alloc(obj_type, obj_dict)
            obj_ids = result
            # For virtual networks, allocate an ID
            if obj_type == 'virtual_network':
                vn_id = self._db_conn._zk_db.alloc_vn_id(
                    s_obj.get_fq_name_str())
                obj_dict['virtual_network_network_id'] = vn_id
            self._db_conn.dbe_create(obj_type, obj_ids, obj_dict)
            self.create_default_children(obj_type, s_obj)

        return s_obj
    # end _create_singleton_entry
    @collect_stats
    def _list_collection(self, obj_type, parent_uuids=None,
                         back_ref_uuids=None, obj_uuids=None,
                         is_count=False, is_detail=False, filters=None,
                         req_fields=None, body=None, params=None):
        r_class = self.get_resource_class(obj_type)
        resource_type = r_class.resource_type
        # include objects shared with tenant
        env = get_request().headers.environ
        tenant_name = env.get(hdr_server_tenant(), 'default-project')
        tenant_fq_name = ['default-domain', tenant_name]
        tenant = None
        try:
            tenant_uuid = self._db_conn.fq_name_to_uuid('project', tenant_fq_name)
            if self.is_multi_tenancy_set() and not self.is_admin_request():
                tenant = tenant_uuid.replace('-','')
            shares = self._db_conn.get_shared_objects(obj_type, tenant_uuid)
        except NoIdError:
            shares = []
        if obj_uuids or back_ref_uuids or parent_uuids:
            # Disable shares when using id filters TODO: Later need to handle query filters as well
            shares = []

        if cfg.CONF.elastic_search.search_enabled:
            body = SearchUtil.convert_to_es_query_dsl(body, params, tenant)
            self.config_log('search body: %s ' % (json.dumps(body)), level=SandeshLevel.SYS_INFO)

        (ok, result, total) = self._db_conn.dbe_list(obj_type,
                             parent_uuids, back_ref_uuids, obj_uuids, is_count, shared_uuids=None,
                             filters=filters, body=body, params=params)
        if not ok:
            self.config_object_error(None, None, '%ss' %(obj_type),
                                     'dbe_list', result)
            raise cfgm_common.exceptions.HttpError(404, result, "40002")

        # If only counting, return early
        if is_count:
            return {'%s' %(resource_type): {'count': total}}


        owned_objs = set([obj_uuid for (fq_name, obj_uuid) in result])

        # include objects shared with tenant
        for (obj_uuid, obj_perm) in shares:
            # skip owned objects already included in results
            if obj_uuid in owned_objs:
                continue
            try:
                fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
                result.append((fq_name, obj_uuid))
                total += 1
            except NoIdError:
                # uuid no longer valid. Delete?
                pass
        fq_names_uuids = result
        obj_dicts = []
        if not is_detail:
            if not self.is_admin_request():
                obj_ids_list = [{'uuid': obj_uuid}
                                for _, obj_uuid in fq_names_uuids]
                obj_fields = [u'id_perms']
                if req_fields:
                    obj_fields = obj_fields + req_fields
                (ok, result) = self._db_conn.dbe_read_multi(
                                    obj_type, obj_ids_list, obj_fields)
                if not ok:
                    raise cfgm_common.exceptions.HttpError(404, result, "40002")
                for obj_result in result:
                    if obj_result['id_perms'].get('user_visible', True):
                        # skip items not authorized
                        (ok, status) = self._permissions.check_perms_read(
                                get_request(), obj_result['uuid'],
                                obj_result['id_perms'], obj_result.get('fq_name')[-1],
                                obj_type, obj_result.get('perms2'))
                        if not ok and status[0] == 403:
                            total -= 1
                            continue
                        obj_dict = {}
                        obj_dict['uuid'] = obj_result['uuid']
                        obj_dict['uri'] = self.generate_uri(resource_type,
                                                         obj_result['uuid'])

                        obj_dict['fq_name'] = obj_result['fq_name']
                        for field in req_fields:
                            try:
                                obj_dict[field] = obj_result[field]
                            except KeyError:
                                pass
                        obj_dicts.append(obj_dict)
            else: # admin
                obj_results = {}
                if req_fields:
                    obj_ids_list = [{'uuid': obj_uuid}
                                    for _, obj_uuid in fq_names_uuids]
                    (ok, result) = self._db_conn.dbe_read_multi(
                        obj_type, obj_ids_list, req_fields)
                    if ok:
                        obj_results = dict((elem['uuid'], elem)
                                           for elem in result)
                for fq_name, obj_uuid in fq_names_uuids:
                    obj_dict = {}
                    obj_dict['uuid'] = obj_uuid
                    obj_dict['uri'] = self.generate_uri(resource_type,
                                                         obj_uuid)
                    obj_dict['fq_name'] = fq_name
                    for field in req_fields or []:
                       try:
                           obj_dict[field] = obj_results[obj_uuid][field]
                       except KeyError:
                           pass
                    obj_dicts.append(obj_dict)
        else: #detail
            obj_ids_list = [{'uuid': obj_uuid}
                            for _, obj_uuid in fq_names_uuids]

            obj_class = self.get_resource_class(obj_type)
            obj_fields = list(obj_class.prop_fields) + \
                         list(obj_class.ref_fields)
            if req_fields:
                obj_fields.extend(req_fields)
            (ok, result) = self._db_conn.dbe_read_multi(
                                obj_type, obj_ids_list, obj_fields)

            if not ok:
                raise cfgm_common.exceptions.HttpError(404, result, "40002")

            for obj_result in result:
                obj_dict = {}
                obj_dict['name'] = obj_result['fq_name'][-1]
                obj_dict['uri'] = self.generate_url(resource_type,
                                                     obj_result['uuid'])
                obj_dict.update(obj_result)
                if 'id_perms' not in obj_dict:
                    # It is possible that the object was deleted, but received
                    # an update after that. We need to ignore it for now. In
                    # future, we should clean up such stale objects
                    continue
                if (obj_dict['id_perms'].get('user_visible', True) or
                    self.is_admin_request()):
                    # skip items not authorized
                    (ok, status) = self._permissions.check_perms_read(
                            get_request(), obj_result['uuid'],
                            obj_result['id_perms'], obj_result.get('fq_name')[-1],
                            obj_type, obj_result.get('perms2'))
                    if not ok and status[0] == 403:
                        total -= 1
                        continue
                    obj_dicts.append(obj_dict)

        return {'total': total, resource_type: obj_dicts}
    # end _list_collection

    def get_db_connection(self):
        return self._db_conn
    # end get_db_connection

    def generate_uri(self,resource_type, obj_uuid):
        if resource_type in gen.vnc_api_client_gen.all_resource_types:
            obj_uri_type = '/' + resource_type
        else:
            obj_uri_type = '/' + resource_type
        return '%s%s/%s' % (SERVICE_PATH, obj_uri_type, obj_uuid)



    def generate_url(self, resource_type, obj_uuid):
        try:
            url_parts = get_request().urlparts
            return '%s://%s/%s/%s'\
                % (url_parts.scheme, url_parts.netloc, resource_type, obj_uuid)
        except Exception as e:
            return '%s/%s/%s' % (self._base_url, resource_type, obj_uuid)
    # end generate_url

    def config_object_error(self, id, fq_name_str, obj_type,
                            operation, err_str):
        apiConfig = VncApiCommon()
        if obj_type is not None:
            apiConfig.object_type = obj_type
        apiConfig.identifier_name = fq_name_str
        apiConfig.identifier_uuid = id
        apiConfig.operation = operation
        if err_str:
            apiConfig.error = "%s:%s" % (obj_type, err_str)
        self._set_api_audit_info(apiConfig)

        self.vnc_api_config_log(apiConfig)
    # end config_object_error

    def config_log(self, err_str, level=SandeshLevel.SYS_INFO):
        VncApiError(api_error_msg=err_str, level=level, sandesh=self._sandesh).send(
            sandesh=self._sandesh)
    # end config_log

    def _set_api_audit_info(self, apiConfig):
        apiConfig.url = get_request().url
        apiConfig.remote_ip = get_request().headers.get('Host')
        useragent = get_request().headers.get('X-Contrail-Useragent')
        if not useragent:
            useragent = get_request().headers.get('User-Agent')
        apiConfig.useragent = useragent
        apiConfig.user = get_request().headers.get('X-User-Name')
        apiConfig.project = get_request().headers.get('X-Project-Name')
        apiConfig.domain = get_request().headers.get('X-Domain-Name', 'None')
        if apiConfig.domain.lower() == 'none':
            apiConfig.domain = 'default-domain'
        if int(get_request().headers.get('Content-Length', 0)) > 0:
            try:
                body = json.dumps(get_request().json)
            except:
                body = str(get_request().json)
            apiConfig.body = body
    # end _set_api_audit_info

    # uuid is parent's for collections
    @collect_stats
    def _http_get_common(self, request, uuid=None):
        # TODO check api + resource perms etc.
        if self.is_multi_tenancy_set() and uuid:
            if isinstance(uuid, list):
                for u_id in uuid:
                    ok, result = self._permissions.check_perms_read(request,
                                                                    u_id)
                    if not ok:
                        return ok, result
            else:
                return self._permissions.check_perms_read(request, uuid)

        return (True, '')
    # end _http_get_common

    def _http_put_common(self, request, obj_type, obj_uuid, obj_fq_name,
                         obj_dict):
        # If not connected to zookeeper do not allow operations that
        # causes the state change
        if not self._db_conn._zk_db.is_connected():
            return (False,
                    (503, "Not connected to zookeeper. Not able to perform requested action"))

        # If there are too many pending updates to rabbit, do not allow
        # operations that cause state change
        npending = self._db_conn.dbe_oper_publish_pending()
        if (npending >= int(self._args.rabbit_max_pending_updates)):
            err_str = str(MaxRabbitPendingError(npending))
            return (False, (500, err_str))

        if obj_dict:
            fq_name_str = ":".join(obj_fq_name)

            # TODO keep _id_perms.uuid_xxlong immutable in future
            # dsetia - check with ajay regarding comment above
            # if 'id_perms' in obj_dict:
            #    del obj_dict['id_perms']
            if 'id_perms' in obj_dict and obj_dict['id_perms']['uuid']:
                if not self._db_conn.match_uuid(obj_dict, obj_uuid):
                    log_msg = 'UUID mismatch from %s:%s' \
                        % (request.environ['REMOTE_ADDR'],
                           request.environ['HTTP_USER_AGENT'])
                    self.config_object_error(
                        obj_uuid, fq_name_str, obj_type, 'put', log_msg)
                    self._db_conn.set_uuid(obj_type, obj_dict,
                                           uuid.UUID(obj_uuid),
                                           do_lock=False)

            # TODO remove this when the generator will be adapted to
            # be consistent with the post method

            # Ensure object has at least default permissions set
            self._ensure_id_perms_present(obj_uuid, obj_dict)

            apiConfig = VncApiCommon()
            apiConfig.object_type = obj_type
            apiConfig.identifier_name = fq_name_str
            apiConfig.identifier_uuid = obj_uuid
            apiConfig.operation = 'put'
            self._set_api_audit_info(apiConfig)
            self.vnc_api_config_log(apiConfig)
        # TODO check api + resource perms etc.
        if self.is_multi_tenancy_set():
            return self._permissions.check_perms_write(request, obj_uuid)

        return (True, '')
    # end _http_put_common

    # parent_type needed for perms check. None for derived objects (eg.
    # routing-instance)
    def _http_delete_common(self, request, obj_type, uuid, parent_type):
        # If not connected to zookeeper do not allow operations that
        # causes the state change
        if not self._db_conn._zk_db.is_connected():
            return (False,
                    (503, "Not connected to zookeeper. Not able to perform requested action"))

        # If there are too many pending updates to rabbit, do not allow
        # operations that cause state change
        npending = self._db_conn.dbe_oper_publish_pending()
        if (npending >= int(self._args.rabbit_max_pending_updates)):
            err_str = str(MaxRabbitPendingError(npending))
            return (False, (500, err_str))

        fq_name = self._db_conn.uuid_to_fq_name(uuid)
        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type
        apiConfig.identifier_name=':'.join(fq_name)
        apiConfig.identifier_uuid = uuid
        apiConfig.operation = 'delete'
        self._set_api_audit_info(apiConfig)
        self.vnc_api_config_log(apiConfig)
        # TODO check api + resource perms etc.
        if not self.is_multi_tenancy_set() or not parent_type:
            return (True, '')

        """
        Validate parent allows write access. Implicitly trust
        parent info in the object since coming from our DB.
        """
        parent_fq_name = fq_name[:-1]
        try:
            parent_uuid = self._db_conn.fq_name_to_uuid(
                parent_type, parent_fq_name)
        except NoIdError:
            # parent uuid could be null for derived resources such as
            # routing-instance
            return (True, '')
        return self._permissions.check_perms_write(request, parent_uuid)
    # end _http_delete_common

    def _http_post_validate(self, obj_type=None, obj_dict=None):
        if not obj_dict:
            return

        def _check_field_present(fname):
            fval = obj_dict.get(fname)
            if not fval:
                raise cfgm_common.exceptions.HttpError(
                    400, "Bad Request, no %s in POST body" %(fname), "40023")
            name = fval[-1]
            if not name:
                raise cfgm_common.exceptions.HttpError(
                    400, "Bad Request, fq_name cannot be empty", "40023")
            return fval
        fq_name = _check_field_present('fq_name')

        # well-formed name checks
        if illegal_xml_chars_RE.search(fq_name[-1]):
            raise cfgm_common.exceptions.HttpError(400,
                "Bad Request, name has illegal xml characters", "40001")
        if obj_type[:].replace('-','_') == 'route_target':
            invalid_chars = self._INVALID_NAME_CHARS - set(':')
        else:
            invalid_chars = self._INVALID_NAME_CHARS
        if any((c in invalid_chars) for c in fq_name[-1]):
            raise cfgm_common.exceptions.HttpError(400,
                "Bad Request, name has one of invalid chars %s"
                %(invalid_chars), "40001")
    # end _http_post_validate

    def _update_perms2_ownership(self, request, obj_type, obj_dict, multi_tenancy_owner):
        if multi_tenancy_owner == OWERTYPE.CUSTOMIZED:
            return obj_dict

        multi_tenancy_rule = self.get_resource_class(obj_type).multi_tenancy_rule
        multi_tenancy_owner = multi_tenancy_rule.get('owner', 1)
        multi_tenancy_owner_access = multi_tenancy_rule.get('owner_access', 7)
        multi_tenancy_global_access = multi_tenancy_rule.get('global_access', 0)

        obj_dict['perms2']['owner_access'] = multi_tenancy_owner_access
        obj_dict['perms2']['global_access'] = multi_tenancy_global_access

        if multi_tenancy_owner == OWERTYPE.FQ_PROJECT:
            try:
                owner = self._db_conn.fq_name_to_uuid('project', obj_dict['fq_name'][:2]).replace('-', '')
            except Exception as ex:
                owner = None
                logger.warn("Cannot set owner to fq_name project id, exception caught %s", ex.message)
            obj_dict['perms2']['owner'] = owner
        else:  # if owner type is default or invalid type value, use default token pj id
            # set ownership of object to creator tenant
            owner = request.headers.environ.get('HTTP_X_PROJECT_ID', None)
            obj_dict['perms2']['owner'] = owner
        return obj_dict

    def _get_share_rules(self, obj_type, ref_type):
        multi_tenancy_rule = self.get_resource_class(ref_type).multi_tenancy_rule
        ok, rules = True, None
        try:
            share_type = multi_tenancy_rule.get('share').get(obj_type)[0]
            share_access = multi_tenancy_rule.get('share').get(obj_type)[1]
            global_access = multi_tenancy_rule.get('global_access')
            ok = True if share_type in SHARETYPE.allowed() else False
            if ok:
                rules = {'share_type': share_type, 'share_access': share_access, 'global_access': global_access}
        except Exception:
            ok = False
        return ok, rules

    def _refs_diff(self, obj_type, old_obj, new_obj):
        ref_add_dict, ref_del_dict = copy.deepcopy(old_obj), copy.deepcopy(old_obj)
        for ref_name in self.get_resource_class(obj_type).ref_fields:
            refs_in_old, refs_in_new = old_obj.get(ref_name), new_obj.get(ref_name)
            if refs_in_new is None:
                ref_add_dict[ref_name], ref_del_dict[ref_name] = [], []
            elif not refs_in_old:
                ref_add_dict[ref_name], ref_del_dict[ref_name] = refs_in_new, []
            elif refs_in_old and isinstance(refs_in_new, list) and len(refs_in_new) == 0:
                ref_add_dict[ref_name], ref_del_dict[ref_name] = [], refs_in_old
            else:
                try:
                    old_dict = {k.get("uuid"): k for k in refs_in_old}
                    new_dict = {k.get("uuid"): k for k in refs_in_new}
                    refs_del, refs_add = [], []
                    for k in old_dict.keys():
                        if new_dict.get(k):
                            refs_add.append(new_dict.get(k))
                            new_dict.pop(k, None)
                        else:
                            refs_del.append(old_dict.get(k))
                    ref_add_dict[ref_name], ref_del_dict[ref_name] = refs_add, refs_del
                    for k in new_dict.keys():
                        ref_add_dict.get(ref_name).append(new_dict.get(k))
                except Exception: # input format has exception, no change
                    ref_add_dict[ref_name], ref_del_dict[ref_name] = [], []
        return ref_add_dict, ref_del_dict

    def _update_refs_perms2(self, obj_type, obj_dict, operation, project_id=None):
        for ref_name in self.get_resource_class(obj_type).ref_fields:
            ref_type = ref_name.replace('_refs', '').replace('_', '-')
            obj_type = obj_type.replace('_', '-')
            has_share_rule, share_rules = self._get_share_rules(obj_type, ref_type)
            if not has_share_rule:
                continue
            for ref_dict in obj_dict.get(ref_name) or []:
                ref_uuid = ref_dict.get('uuid')
                try:
                    self._update_refs_perms2_common(obj_dict, ref_type, ref_uuid, operation, share_rules, project_id)
                except Exception as e:
                    logger.error("Caught exception when updating %s with uuid %s: %s", ref_type, ref_uuid, e.message)

    def _update_ref_perms2(self, obj_type, obj_dict, ref_type, ref_uuid, operation):
        obj_type = obj_type.replace('_', '-')
        has_share_rule, share_rules = self._get_share_rules(obj_type, ref_type)
        if not has_share_rule:
            return
        try:
            self._update_refs_perms2_common(obj_dict, ref_type, ref_uuid, operation, share_rules)
        except Exception as e:
            logger.error("Caught exception when updating %s with uuid %s: %s", ref_type, ref_uuid, e.message)

    def _update_refs_perms2_common(self, obj_dict, ref_type, ref_uuid, operation, share_rules, project_id=None):
        logger.info("Updating refs perms2: ref_type=%s ref_uuid=%s operation=%s share_rules=%s",
                    ref_type, ref_uuid, operation, str(share_rules))
        share_type = share_rules.get('share_type')
        share_access = share_rules.get('share_access')
        global_access = share_rules.get('global_access')
        ref_ok = False
        try:
            (ref_ok, ref_result) = self._db_conn.dbe_read(ref_type, {"uuid": ref_uuid})
        except cfgm_common.exceptions.NoIdError:
            logger.error("No uuid %s for %s", ref_uuid, ref_type)
        except Exception as e:
            logger.error("Cannot read %s with uuid %s: %s", ref_type, ref_uuid, e.message)
        if not ref_ok:
            return False
        ref_dict = copy.deepcopy(ref_result)
        if share_type == SHARETYPE.GLOBAL_SHARED:
            if operation == 'ADD':
                ref_dict.get('perms2')['global_access'] = share_access
            elif operation == 'DELETE':
                ref_dict.get('perms2')['global_access'] = global_access
        elif share_type == SHARETYPE.FQ_TENANT_SHARED:
            share_list, tenant_id = ref_dict.get('perms2').get('share'), None
            tmp_dict = {k.get("tenant"): k for k in share_list}
            try:
                tenant_id = project_id if project_id else \
                    self._db_conn.fq_name_to_uuid('project', obj_dict['fq_name'][:2]).replace('-', '')
            except cfgm_common.exceptions.NoIdError:
                logger.error("No uuid for project %s", obj_dict['fq_name'][:2])
            except Exception as e:
                logger.error("Cannot get project info for obj (%s): %s", obj_dict.get('fq_name'), e.message)
            if not tenant_id:
                return False
            if operation == 'ADD':
                tmp_dict[tenant_id] = {"tenant": tenant_id, "tenant_access": share_access}
            elif operation == 'DELETE':
                tmp_dict.pop(tenant_id, None)
            ref_dict.get('perms2')['share'] = tmp_dict.values()
        try:
            self._db_conn.dbe_update(ref_type, {"uuid": ref_uuid}, ref_dict)
        except cfgm_common.exceptions.NoIdError:
            logger.error("No uuid %s for %s", ref_uuid, ref_type)
            return False
        except Exception as e:
            logger.error("Cannot update %s with uuid %s: %s", ref_type, ref_uuid, e.message)
            return False
        logger.info("Updating share relation in perms2 successful for %s with uuid %s", ref_type, ref_uuid)
        return True

    def _http_post_common(self, request, obj_type, obj_dict):
        # If not connected to zookeeper do not allow operations that
        # causes the state change
        if not self._db_conn._zk_db.is_connected():
            return (False,
                    (503, "Not connected to zookeeper. Not able to perform requested action"))
        if not obj_dict:
            # TODO check api + resource perms etc.
            return (True, None)

        # If there are too many pending updates to rabbit, do not allow
        # operations that cause state change
        npending = self._db_conn.dbe_oper_publish_pending()
        if (npending >= int(self._args.rabbit_max_pending_updates)):
            err_str = str(MaxRabbitPendingError(npending))
            return (False, (500, err_str))

        # Fail if object exists already
        try:
            obj_uuid = self._db_conn.fq_name_to_uuid(
                obj_type, obj_dict['fq_name'])
            raise cfgm_common.exceptions.HttpError(
                409, '' + pformat(obj_dict['fq_name']) +
                ' already exists with uuid: ' + obj_uuid, "40003")
        except NoIdError:
            pass

        multi_tenancy_owner = OWERTYPE.DEFAULT

        if 'perms2' in obj_dict:
            multi_tenancy_owner = OWERTYPE.CUSTOMIZED  # if input has perms2, leaving the input intact
            logger.info("Input contains perms2")

        # Ensure object has at least default permissions set
        self._ensure_id_perms_present(None, obj_dict)
        self._ensure_perms2_present(obj_type, None, obj_dict,
                                    request.headers.environ.get('HTTP_X_PROJECT_ID', None))

        if not self.is_multi_tenancy_with_rbac_set():
            # set ownership of object to creator tenant
            owner = request.headers.environ.get('HTTP_X_PROJECT_ID', None)
            obj_dict['perms2']['owner'] = owner
        else:
            obj_dict = self._update_perms2_ownership(request, obj_type, obj_dict, multi_tenancy_owner)


        # TODO check api + resource perms etc.

        uuid_in_req = obj_dict.get('uuid', None)

        # Set the display name
        if (('display_name' not in obj_dict) or
            (obj_dict['display_name'] is None)):
            obj_dict['display_name'] = obj_dict['fq_name'][-1]

        fq_name_str = ":".join(obj_dict['fq_name'])
        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type
        apiConfig.identifier_name=fq_name_str
        apiConfig.identifier_uuid = uuid_in_req
        apiConfig.operation = 'post'
        try:
            body = json.dumps(request.json)
        except:
            body = str(request.json)
        apiConfig.body = body
        if uuid_in_req:
            if uuid_in_req != str(uuid.UUID(uuid_in_req)):
                bottle.abort(400, 'Invalid UUID format: ' + uuid_in_req)
            try:
                fq_name = self._db_conn.uuid_to_fq_name(uuid_in_req)
                raise cfgm_common.exceptions.HttpError(
                    409, uuid_in_req + ' already exists with fq_name: ' +
                    pformat(fq_name), "40003")
            except NoIdError:
                pass
            apiConfig.identifier_uuid = uuid_in_req

        self._set_api_audit_info(apiConfig)
        self.vnc_api_config_log(apiConfig)

        return (True, uuid_in_req)
    # end _http_post_common


    def vnc_api_config_log(self, apiConfig):
        log = VncApiConfigLog(api_log=apiConfig, sandesh=self._sandesh)
        log.send(sandesh=self._sandesh)

    def cleanup(self):
        # TODO cleanup sandesh context
        pass
    # end cleanup

    def reset(self):
        # cleanup internal state/in-flight operations
        if self._db_conn:
            self._db_conn.reset()
    # end reset

    # allocate block of IP addresses from VN. Subnet info expected in request
    # body
    def vn_ip_alloc_http_post(self, id):
        try:
            vn_fq_name = self._db_conn.uuid_to_fq_name(id)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Virtual Network ' + id + ' not found!', "40002")

        # expected format {"subnet_list" : "2.1.1.0/24", "count" : 4}
        req_dict = get_request().json
        count = req_dict.get('count', 1)
        subnet = req_dict.get('subnet')
        family = req_dict.get('family')
        try:
            result = vnc_cfg_types.VirtualNetworkServer.ip_alloc(
                vn_fq_name, subnet, count, family)
        except vnc_addr_mgmt.AddrMgmtSubnetUndefined as e:
            raise cfgm_common.exceptions.HttpError(404, str(e), "20003")
        except vnc_addr_mgmt.AddrMgmtSubnetExhausted as e:
            raise cfgm_common.exceptions.HttpError(409, str(e), "20004")

        return result
    # end vn_ip_alloc_http_post

    # free block of ip addresses to subnet
    def vn_ip_free_http_post(self, id):
        try:
            vn_fq_name = self._db_conn.uuid_to_fq_name(id)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Virtual Network ' + id + ' not found!', "40002")

        """
          {
            "subnet" : "2.1.1.0/24",
            "ip_addr": [ "2.1.1.239", "2.1.1.238", "2.1.1.237", "2.1.1.236" ]
          }
        """

        req_dict = get_request().json
        ip_list = req_dict['ip_addr'] if 'ip_addr' in req_dict else []
        subnet = req_dict['subnet'] if 'subnet' in req_dict else None
        result = vnc_cfg_types.VirtualNetworkServer.ip_free(
            vn_fq_name, subnet, ip_list)
        return result
    # end vn_ip_free_http_post

    # return no. of  IP addresses from VN/Subnet
    def vn_subnet_ip_count_http_post(self, id):
        try:
            vn_fq_name = self._db_conn.uuid_to_fq_name(id)
        except NoIdError:
            raise cfgm_common.exceptions.HttpError(
                404, 'Virtual Network ' + id + ' not found!', "40002")

        # expected format {"subnet_list" : ["2.1.1.0/24", "1.1.1.0/24"]
        req_dict = get_request().json
        try:
            (ok, result) = self._db_conn.dbe_read('virtual_network', {'uuid': id})
        except NoIdError as e:
            raise cfgm_common.exceptions.HttpError(404, str(e), "40002")
        except Exception as e:
            ok = False
            result = cfgm_common.utils.detailed_traceback()
        if not ok:
            raise cfgm_common.exceptions.HttpError(500, result, "40015")

        obj_dict = result
        subnet_list = req_dict[
            'subnet_list'] if 'subnet_list' in req_dict else []
        result = vnc_cfg_types.VirtualNetworkServer.subnet_ip_count(
            vn_fq_name, subnet_list)
        return result
    # end vn_subnet_ip_count_http_post

    def set_mt(self, multi_tenancy):
        pipe_start_app = self.get_pipe_start_app()
        try:
            pipe_start_app.set_mt(multi_tenancy)
        except AttributeError:
            pass
        self._args.multi_tenancy = multi_tenancy
    # end

    def is_multi_tenancy_set(self):
        return self._args.multi_tenancy or self._args.multi_tenancy_with_rbac

    def is_multi_tenancy_with_rbac_set(self):
        return self._args.multi_tenancy_with_rbac

    def set_multi_tenancy_with_rbac(self, rbac_flag):
        self._args.multi_tenancy_with_rbac = rbac_flag
    # end

    def mt_http_get(self):
        pipe_start_app = self.get_pipe_start_app()
        mt = False
        try:
            mt = pipe_start_app.get_mt()
        except AttributeError:
            pass
        return {'enabled': mt}
    # end

    def mt_http_put(self):
        multi_tenancy = get_request().json['enabled']
        user_token = get_request().get_header('X-Auth-Token')
        if user_token is None:
            raise cfgm_common.exceptions.HttpError(403, " Permission denied", "40020")

        data = self._auth_svc.verify_signed_token(user_token)
        if data is None:
            raise cfgm_common.exceptions.HttpError(403, " Permission denied", "40020")

        self.set_mt(multi_tenancy)
        return {'enabled': self.is_multi_tenancy_set()}
    # end

    # indication if multi tenancy with rbac is enabled or disabled
    def rbac_http_get(self):
        return {'enabled': self._args.multi_tenancy_with_rbac}

    def rbac_http_put(self):
        multi_tenancy_with_rbac = get_request().json['enabled']
        if not self._auth_svc.validate_user_token(get_request()):
            raise cfgm_common.exceptions.HttpError(403, " Permission denied")
        if not self.is_admin_request():
            raise cfgm_common.exceptions.HttpError(403, " Permission denied")

        self.set_multi_tenancy_with_rbac(multi_tenancy_with_rbac)
        return {'enabled': self.is_multi_tenancy_with_rbac_set()}
    # end

    @property
    def cloud_admin_role(self):
        return self._args.cloud_admin_role

    def publish_self_to_discovery(self):
        # publish API server
        data = {
            'ip-address': self._args.ifmap_server_ip,
            'port': self._args.listen_port,
        }
        if self._disc:
            self.api_server_task = self._disc.publish(
                API_SERVER_DISCOVERY_SERVICE_NAME, data)

    def publish_ifmap_to_discovery(self, state = 'up', msg = ''):
        # publish ifmap server
        data = {
            'ip-address': self._args.ifmap_server_ip,
            'port': self._args.ifmap_server_port,
        }
        if self._disc:
            self.ifmap_task = self._disc.publish(
                                  IFMAP_SERVER_DISCOVERY_SERVICE_NAME,
                                  data, state, msg)
    # end publish_ifmap_to_discovery

    def un_publish_self_to_discovery(self):
        # un publish api server
        data = {
            'ip-address': self._args.ifmap_server_ip,
            'port': self._args.listen_port,
        }
        if self._disc:
            self._disc.un_publish(API_SERVER_DISCOVERY_SERVICE_NAME, data)

    def un_publish_ifmap_to_discovery(self):
        # un publish ifmap server
        data = {
            'ip-address': self._args.ifmap_server_ip,
            'port': self._args.ifmap_server_port,
        }
        if self._disc:
            self._disc.un_publish(IFMAP_SERVER_DISCOVERY_SERVICE_NAME, data)
    # end un_publish_ifmap_to_discovery
    def get_service_module(self):
        if SERVICE_PATH:
            return SERVICE_PATH.split('/')[1]
        else:
            return None


server = None
def main(args_str=None):
    vnc_api_server = VncApiServer(args_str)
    # set module var for uses with import e.g unit test
    global server
    server = vnc_api_server

    pipe_start_app = vnc_api_server.get_pipe_start_app()

    server_ip = vnc_api_server.get_listen_ip()
    server_port = vnc_api_server.get_server_port()

    # Advertise services
    if (vnc_api_server._args.disc_server_ip and
            vnc_api_server._args.disc_server_port):
        vnc_api_server.publish_self_to_discovery()

    """ @sigchld
    Disable handling of SIG_CHLD for now as every keystone request to validate
    token sends SIG_CHLD signal to API server.
    """
    #hub.signal(signal.SIGCHLD, vnc_api_server.sigchld_handler)
    hub.signal(signal.SIGTERM, vnc_api_server.sigterm_handler)

    try:
        bottle.run(app=pipe_start_app, host=server_ip, port=server_port,
                   server=get_bottle_server(server._args.max_requests))
    except KeyboardInterrupt:
        # quietly handle Ctrl-C
        pass
    except:
        # dump stack on all other exceptions
        raise
    finally:
        # always cleanup gracefully
        vnc_api_server.reset()

# end main

def server_main(args_str=None):
    import cgitb
    cgitb.enable(format='text')

    main()
#server_main

if __name__ == "__main__":
    server_main()
