import ConfigParser
import abc
from cStringIO import StringIO
import cgitb
import copy
import json
from pprint import pformat
import uuid
from oslo_config import cfg
import re
import sys
import logging
import logging.config
import argparse
from cfgm_common import illegal_xml_chars_RE, ignore_exceptions
from cfgm_common.exceptions import MaxRabbitPendingError, NoIdError
from cfgm_common.rest import LinkObject
from cfgm_common.uve.vnc_api.ttypes import VncApiCommon
import netifaces
from cfgm_common.vnc_extensions import ExtensionManager
from csp.csp_api_context import APIContext
from pysandesh.gen_py.sandesh.ttypes import SandeshLevel
from pysandesh.sandesh_base import Sandesh
import gen
from gen.vnc_api_server_gen import VncApiServerGen, SERVICE_PATH
from gevent import monkey
from provision_defaults import Provision
import vnc_auth
import vnc_auth_keystone
from vnc_cfg_ifmap import VncDbClient
import vnc_perms
from vnc_quota import QuotaHelper
from oslo_utils import importutils
from vnc_bottle import get_bottle_server


monkey.patch_all()
from gevent import hub

"""
Following is needed to silence warnings on every request when keystone\
    auth_token middleware + Sandesh is used. Keystone or Sandesh alone\
    do not produce these warnings.

Exception AttributeError: AttributeError(
    "'_DummyThread' object has no attribute '_Thread__block'",)
    in <module 'threading' from '/usr/lib64/python2.7/threading.pyc'> ignored

See http://stackoverflow.com/questions/13193278/understand-python-threading-bug
for more information.
"""
import threading

threading._DummyThread._Thread__stop = lambda x: 42

# from neutron plugin to api server, the request URL could be large. fix the const
import gevent.pywsgi

gevent.pywsgi.MAX_REQUEST_LINE = 65535

import bottle

bottle.BaseRequest.MEMFILE_MAX = 1024000

import sys

reload(sys)
sys.setdefaultencoding('UTF8')


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


@bottle.error(500)
def error_500(err):
    return err.body


# end error_500


@bottle.error(503)
def error_503(err):
    return err.body


from sandesh.traces.ttypes import RestApiTrace

_WEB_HOST = '0.0.0.0'
_WEB_PORT = 8082
_ADMIN_PORT = 8095


sandesh_to_log_level = {
        SandeshLevel.SYS_EMERG : logging.FATAL,
        SandeshLevel.SYS_CRIT : logging.CRITICAL,
        SandeshLevel.SYS_ALERT : logging.INFO,
        SandeshLevel.SYS_NOTICE : logging.INFO,
        SandeshLevel.SYS_INFO : logging.INFO,
        SandeshLevel.SYS_WARN : logging.WARN,
        SandeshLevel.SYS_DEBUG : logging.DEBUG,
        SandeshLevel.SYS_ERR : logging.ERROR
}


_ACTION_RESOURCES = [
    {'uri': '%s/ref-update'%(SERVICE_PATH), 'link_name': 'ref-update',
     'method_name': 'ref_update_http_post'},
    {'uri': '%s/fqname-to-id' % (SERVICE_PATH), 'link_name': 'name-to-id',
     'method_name': 'fq_name_to_id_http_post'},
    {'uri': '%s/id-to-fqname' % (SERVICE_PATH), 'link_name': 'id-to-name',
     'method_name': 'id_to_fq_name_http_post'},
    # ifmap-to-id only for ifmap subcribers using rest for publish
    {'uri': '%s/ifmap-to-id' % (SERVICE_PATH), 'link_name': 'ifmap-to-id',
     'method_name': 'ifmap_to_id_http_post'},
    {'uri': '%s/db-check' % (SERVICE_PATH), 'link_name': 'database-check',
     'method_name': 'db_check'},
    {'uri': '%s/fetch-records' % (SERVICE_PATH), 'link_name': 'fetch-records',
     'method_name': 'fetch_records'},
    {'uri': '%s/start-profile' % (SERVICE_PATH), 'link_name': 'start-profile',
     'method_name': 'start_profile'},
    {'uri': '%s/stop-profile' % (SERVICE_PATH), 'link_name': 'stop-profile',
     'method_name': 'stop_profile'},
    {'uri': '%s/list-bulk-collection' % (SERVICE_PATH), 'link_name': 'list-bulk-collection',
     'method_name': 'list_bulk_collection_http_post'},
]


# Masking of password from openstack/common/log.py
_SANITIZE_KEYS = ['adminPass', 'admin_pass', 'password', 'admin_password']

# NOTE(ldbragst): Let's build a list of regex objects using the list of
# _SANITIZE_KEYS we already have. This way, we only have to add the new key
# to the list of _SANITIZE_KEYS and we can generate regular expressions
# for XML and JSON automatically.
_SANITIZE_PATTERNS = []
_FORMAT_PATTERNS = [r'(%(key)s\s*[=]\s*[\"\']).*?([\"\'])',
                    r'(<%(key)s>).*?(</%(key)s>)',
                    r'([\"\']%(key)s[\"\']\s*:\s*[\"\']).*?([\"\'])',
                    r'([\'"].*?%(key)s[\'"]\s*:\s*u?[\'"]).*?([\'"])']

for key in _SANITIZE_KEYS:
    for pattern in _FORMAT_PATTERNS:
        reg_ex = re.compile(pattern % {'key': key}, re.DOTALL)
        _SANITIZE_PATTERNS.append(reg_ex)


def mask_password(message, secret="***"):
    """Replace password with 'secret' in message.
    :param message: The string which includes security information.
    :param secret: value with which to replace passwords.
    :returns: The unicode value of message with the password fields masked.

    For example:

    >>> mask_password("'adminPass' : 'aaaaa'")
    "'adminPass' : '***'"
    >>> mask_password("'admin_pass' : 'aaaaa'")
    "'admin_pass' : '***'"
    >>> mask_password('"password" : "aaaaa"')
    '"password" : "***"'
    >>> mask_password("'original_password' : 'aaaaa'")
    "'original_password' : '***'"
    >>> mask_password("u'original_password' :   u'aaaaa'")
    "u'original_password' :   u'***'"
    """
    if not any(key in message for key in _SANITIZE_KEYS):
        return message

    secret = r'\g<1>' + secret + r'\g<2>'
    for pattern in _SANITIZE_PATTERNS:
        message = re.sub(pattern, secret, message)
    return message

#Parse config for olso configs. Try to move all config parsing to oslo cfg
elastic_search_group = cfg.OptGroup(name='elastic_search', title='ELastic Search Options')
cfg.CONF.register_cli_opt(cfg.BoolOpt(name='search_enabled', default=False),
                              group=elastic_search_group)
cfg.CONF.register_cli_opt(cfg.ListOpt('server_list',
                                          item_type=cfg.types.String(),
                                          default='127.0.0.1:9200',
                                          help="Multiple servers option"), group=elastic_search_group)
cfg.CONF.register_cli_opt(cfg.BoolOpt(name='enable_sniffing',default=False,
                                          help="Enable connection sniffing for elastic search driver")
                              ,group=elastic_search_group)

cfg.CONF.register_cli_opt(cfg.IntOpt(name='timeout', default=2, help="Default timeout in seconds for elastic search operations"),
                          group=elastic_search_group)

class VncApiServerBase(VncApiServerGen):
    """
    This is the manager class co-ordinating all classes present in the package
    """
    __metaclass__ = abc.ABCMeta

    _INVALID_NAME_CHARS = set(':')

    def __new__(cls, *args, **kwargs):
        obj = super(VncApiServerBase, cls).__new__(cls, *args, **kwargs)
        bottle.route('/', 'GET', obj.homepage_http_get)
        for act_res in _ACTION_RESOURCES:
            method = getattr(obj, act_res['method_name'])
            obj.route(act_res['uri'], 'POST', method)
        return obj

    # end __new__

    def __init__(self, args_str=None):
        self._args = None
        if not args_str:
            args_str = ' '.join(sys.argv[1:])
        self._parse_args(args_str)

        self._settings = vars(self._args)

        # set python logging level from logging_level cmdline arg
        if not self._args.logging_conf:
            logging.basicConfig(level=getattr(logging, self._args.logging_level))
        else:
            logging.config.fileConfig(self._args.logging_conf)

        self._base_url = "http://%s:%s" % (self._args.listen_ip_addr,
                                           self._args.listen_port)
        super(VncApiServerBase, self).__init__()
        self._pipe_start_app = None

        # GreenletProfiler.set_clock_type('wall')
        self._profile_info = None
        self._sandesh = None
        self.csp_logger_init(self._settings)
        self._csp_logger = self.get_default_logger()


        # REST interface initialization
        self._get_common = self._http_get_common
        self._put_common = self._http_put_common
        self._delete_common = self._http_delete_common
        self._post_validate = self._http_post_validate
        self._post_common = self._http_post_common
        for act_res in _ACTION_RESOURCES:
            link = LinkObject('action', self._base_url, act_res['uri'],
                              act_res['link_name'])
            self._homepage_links.append(link)
        # Enable/Disable multi tenancy
        bottle.route('/multi-tenancy', 'GET', self.mt_http_get)
        bottle.route('/multi-tenancy', 'PUT', self.mt_http_put)


        # Initialize discovery client
        self._disc = None
        # Load extensions
        self._extension_mgrs = {}
        self._load_extensions()

        # Authn/z interface
        if self._args.auth == 'keystone':
            auth_svc = vnc_auth_keystone.AuthServiceKeystone(self, self._args)
        else:
            auth_svc = vnc_auth.AuthService(self, self._args)

        self._pipe_start_app = auth_svc.get_middleware_app()


        if not self._pipe_start_app:
            self._pipe_start_app = bottle.app()
            # When the multi tenancy is disable, add 'admin' role into the
            # header for all requests to see all resources
            @self._pipe_start_app.hook('before_request')
            @bottle.hook('before_request')
            def set_admin_role(*args, **kwargs):
                bottle.request.environ['HTTP_X_ROLE'] = 'admin'
        self.__load_middleware()
        self._auth_svc = auth_svc

        # API/Permissions check
        self._permissions = vnc_perms.VncPermissions(self, self._args)

        # DB interface initialization
        if self._args.wipe_config:
            self._db_connect(True)
        else:
            self._db_connect(self._args.reset_config)
            self._db_init_entries()


    def homepage_http_get(self):
        json_body = {}
        json_links = []
        # strip trailing '/' in url
        url = bottle.request.url[:-1]
        for link in self._homepage_links:
            # strip trailing '/' in url
            json_links.append(
                {'link': link.to_dict(with_url=url)}
            )

        json_body = \
            {"href": url,
             "links": json_links
             }

        return json_body

    # end homepage_http_get

    def get_default_logger(self):
        from csp.csp_log_writer import CSPSandeshLogger
        return CSPSandeshLogger().get_csp_logger()  # CSP Logger

    def __add_middleware(self,name, module):
        mod, func = module.split(':')
        try:
            middleware_module = importutils.import_module(mod)
            entry_func = getattr(middleware_module, func)
            if entry_func:
                self._pipe_start_app = entry_func(self._pipe_start_app, self._settings)
            logging.warn("Successfully loaded middleware {}".format(name))
        except ImportError as e:
            logging.error("Failed to load middleware module {}".format(name))

    def __load_middleware(self):
        middlewares = self.get_pipeline()
        if middlewares:
            for k, v in middlewares.iteritems():
                self.__add_middleware(k,v)


    @abc.abstractmethod
    def get_pipeline(self):
        pass


    @ignore_exceptions
    def _generate_rest_api_request_trace(self):
        method = bottle.request.method.upper()
        if method == 'GET':
            return None

        req_id = bottle.request.headers.get('X-Request-Id',
                                            'req-%s' % (str(uuid.uuid4())))
        gevent.getcurrent().trace_request_id = req_id
        url = bottle.request.url
        if method == 'DELETE':
            req_data = ''
        else:
            try:
                req_data = json.dumps(bottle.request.json)
            except Exception as e:
                req_data = '%s: Invalid request body' % (e)
        # rest_trace = RestApiTrace(request_id=req_id)
        # rest_trace.url = url
        # rest_trace.method = method
        # rest_trace.request_data = req_data
        return None

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
            trace = self._generate_rest_api_request_trace()
            try:
                response = handler(*args, **kwargs)
                return response
            except Exception as e:
                if trace:
                    # CSP Logger?
                    pass
                # don't log details of bottle.abort i.e handled error cases
                if not isinstance(e, bottle.HTTPError):
                    string_buf = StringIO()
                    cgitb.Hook(
                        file=string_buf,
                        format="text",
                    ).handle(sys.exc_info())
                    err_msg = mask_password(string_buf.getvalue())
                    self.config_log(err_msg, level=SandeshLevel.SYS_ERR)

                raise

        bottle.route(uri, method, handler_trap_exception)

    # end route

    def config_log(self, err_str, level=SandeshLevel.SYS_INFO):
        log_level = logging.WARN
        if level in sandesh_to_log_level:
          log_level=sandesh_to_log_level[level]
        logging.log(log_level, err_str)
    # end config_log



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

    @abc.abstractmethod
    def _db_init_entries(self):
        pass

    def get_db_connection(self):
        return self._db_conn

    # end get_db_connection
    def _db_connect(self, reset_config):
        ifmap_ip = self._args.ifmap_server_ip
        ifmap_port = self._args.ifmap_server_port
        user = self._args.ifmap_username
        passwd = self._args.ifmap_password
        cass_server_list = self._args.cassandra_server_list
        redis_server_ip = self._args.redis_server_ip
        redis_server_port = self._args.redis_server_port
        ifmap_loc = self._args.ifmap_server_loc
        zk_server = self._args.zk_server_ip
        rabbit_server = self._args.rabbit_server
        rabbit_port = self._args.rabbit_port
        rabbit_user = self._args.rabbit_user
        rabbit_password = self._args.rabbit_password
        rabbit_vhost = self._args.rabbit_vhost


        db_conn = VncDbClient(self, ifmap_ip, ifmap_port, user, passwd,
                              cass_server_list, rabbit_server, rabbit_port,
                              rabbit_user, rabbit_password, rabbit_vhost,
                              reset_config, ifmap_loc, zk_server, self._args.cluster_id, ifmap_disable=self._args.disable_ifmap)

        self._db_conn = db_conn

    def _ensure_id_perms_present(self, obj_type, obj_uuid, obj_dict):
        """
        Called at resource creation to ensure that id_perms is present in obj
        """
        # retrieve object and permissions
        id_perms = self._get_default_id_perms(obj_type)

        if (('id_perms' not in obj_dict) or
                (obj_dict['id_perms'] is None)):
            # Resource creation
            if obj_uuid is None:
                obj_dict['id_perms'] = id_perms
                return
            # Resource already exist
            try:
                obj_dict['id_perms'] = self._db_conn.uuid_to_obj_perms(obj_uuid)
            except NoIdError:
                obj_dict['id_perms'] = id_perms

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

    def _get_default_id_perms(self, obj_type):
        id_perms = copy.deepcopy(Provision.defaults.perms[obj_type])
        id_perms_json = json.dumps(id_perms, default=lambda o: dict((k, v)
                                                                    for k, v in o.__dict__.iteritems()))
        id_perms_dict = json.loads(id_perms_json)
        return id_perms_dict

    # end _get_default_id_perms



    def config_object_error(self, id, fq_name_str, obj_type,
                            operation, err_str):
        error_msg = "ConfigError id: %s, fq_name:%s, type: %s, operation:%s, error:%s" % (id, fq_name_str,
                                                                                          obj_type, operation, err_str)
        self.config_log(err_str, level=SandeshLevel.SYS_ERR)
    # end config_object_error

    # uuid is parent's for collections
    def _http_get_common(self, request, uuid=None):
        # TODO check api + resource perms etc.
        if self._args.multi_tenancy and uuid:
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
                                           persist=False)

            # TODO remove this when the generator will be adapted to
            # be consistent with the post method
            obj_type = obj_type.replace('_', '-')

            # Ensure object has at least default permissions set
            self._ensure_id_perms_present(obj_type, obj_uuid, obj_dict)
            # Fix ME CSP Audit logger??
            # Fixme CSP Logger

        # TODO check api + resource perms etc.
        if self._args.multi_tenancy:
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


        # TODO check api + resource perms etc.
        if not self._args.multi_tenancy or not parent_type:
            return (True, '')

        """
        Validate parent allows write access. Implicitly trust
        parent info in the object since coming from our DB.
        """
        obj_dict = self._db_conn.uuid_to_obj_dict(uuid)
        parent_fq_name = json.loads(obj_dict['fq_name'])[:-1]
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
                bottle.abort(400, "Bad Request, no %s in POST body" % (fname))
            return fval

        fq_name = _check_field_present('fq_name')

        # well-formed name checks
        if illegal_xml_chars_RE.search(fq_name[-1]):
            bottle.abort(400,
                         "Bad Request, name has illegal xml characters")
        if obj_type[:].replace('-', '_') == 'route_target':
            invalid_chars = self._INVALID_NAME_CHARS - set(':')
        else:
            invalid_chars = self._INVALID_NAME_CHARS
        if any((c in invalid_chars) for c in fq_name[-1]):
            bottle.abort(400,
                         "Bad Request, name has one of invalid chars %s"
                         % (invalid_chars))

    # end _http_post_validate

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
            bottle.abort(
                409, '' + pformat(obj_dict['fq_name']) +
                     ' already exists with uuid: ' + obj_uuid)
        except NoIdError:
            pass

        # Ensure object has at least default permissions set
        self._ensure_id_perms_present(obj_type, None, obj_dict)

        # TODO check api + resource perms etc.

        uuid_in_req = obj_dict.get('uuid', None)

        # Set the display name
        if (('display_name' not in obj_dict) or
                (obj_dict['display_name'] is None)):
            obj_dict['display_name'] = obj_dict['fq_name'][-1]

        fq_name_str = ":".join(obj_dict['fq_name'])
        if uuid_in_req:
            try:
                fq_name = self._db_conn.uuid_to_fq_name(uuid_in_req)
                bottle.abort(
                    409, uuid_in_req + ' already exists with fq_name: ' +
                         pformat(fq_name))
            except NoIdError:
                pass
        return (True, uuid_in_req)

    # end _http_post_common


    # sigchld handler is currently not engaged. See comment @sigchld
    def sigchld_handler(self):
        # DB interface initialization
        self._db_connect(reset_config=False)
        self._db_init_entries()

    # end sigchld_handler

    def sigterm_handler(self):
        self.cleanup()
        exit()

    def cleanup(self):
        pass

    def _load_extensions(self):
        try:
            conf_sections = self._args.config_sections
            self._extension_mgrs['resync'] = ExtensionManager(
                'vnc_cfg_api.resync', api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
            self._extension_mgrs['resourceApi'] = ExtensionManager(
                'vnc_cfg_api.resourceApi',
                api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
            self._extension_mgrs['rpcApi'] = ExtensionManager(
                'vnc_cfg_api.rpcApi', api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh, propogate_map_exceptions=True)
            self._extension_mgrs['neutronApi'] = ExtensionManager(
                'vnc_cfg_api.neutronApi',
                api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh)
        except Exception as e:
            # csp Log
            pass

    # end _load_extensions


    def _create_singleton_entry(self, singleton_obj):
        s_obj = singleton_obj
        obj_type = s_obj.get_type()
        method_name = obj_type.replace('-', '_')
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
            obj_dict['id_perms'] = self._get_default_id_perms(obj_type)
            (ok, result) = self._db_conn.dbe_alloc(obj_type, obj_dict)
            obj_ids = result
            self._db_conn.dbe_create(obj_type, obj_ids, obj_dict)
            method = '_%s_create_default_children' % (method_name)
            def_children_method = getattr(self, method)
            def_children_method(s_obj)

        return s_obj

    def list_bulk_collection_http_post(self):
        """ List collection when requested ids don't fit in query params."""

        obj_type = bottle.request.json.get('type')  # e.g. virtual-network
        if not obj_type:
            bottle.abort(400, "Bad Request, no 'type' in POST body")

        obj_class = self._resource_classes.get(obj_type)
        if not obj_class:
            bottle.abort(400,
                         "Bad Request, Unknown type %s in POST body" % (obj_type))

        try:
            parent_ids = bottle.request.json['parent_id'].split(',')
            parent_uuids = [str(uuid.UUID(p_uuid)) for p_uuid in parent_ids]
        except KeyError:
            parent_uuids = None

        try:
            back_ref_ids = bottle.request.json['back_ref_id'].split(',')
            back_ref_uuids = [str(uuid.UUID(b_uuid)) for b_uuid in back_ref_ids]
        except KeyError:
            back_ref_uuids = None

        try:
            obj_ids = bottle.request.json['obj_uuids'].split(',')
            obj_uuids = [str(uuid.UUID(b_uuid)) for b_uuid in obj_ids]
        except KeyError:
            obj_uuids = None

        try:
            is_count = bottle.request.json['count']
        except KeyError:
            is_count = False

        try:
            is_detail = bottle.request.json['detail']
        except KeyError:
            is_detail = False

        return self._list_collection(obj_type, parent_uuids, back_ref_uuids,
                                     obj_uuids, is_count, is_detail)

    # end list_bulk_collection_http_post


    def _list_collection(self, obj_type, parent_uuids=None,
                         back_ref_uuids=None, obj_uuids=None,
                         is_count=False, is_detail=False):
        method_name = obj_type.replace('-', '_')  # e.g. virtual_network

        (ok, result, total) = self._db_conn.dbe_list(obj_type,
                                              parent_uuids, back_ref_uuids, obj_uuids, is_count)
        if not ok:
            self.config_object_error(None, None, '%ss' % (method_name),
                                     'dbe_list', result)
            bottle.abort(404, result)

        # If only counting, return early
        if is_count:
            return {'%ss' % (obj_type): {'count': total}}

        fq_names_uuids = result
        obj_dicts = []
        if not is_detail:
            if not self.is_admin_request():
                obj_ids_list = [{'uuid': obj_uuid}
                                for _, obj_uuid in fq_names_uuids]
                obj_fields = [u'id_perms']
                (ok, result) = self._db_conn.dbe_read_multi(
                    obj_type, obj_ids_list, obj_fields)
                if not ok:
                    bottle.abort(404, result)
                for obj_result in result:
                    if obj_result['id_perms'].get('user_visible', True):
                        obj_dict = {}
                        obj_dict['uuid'] = obj_result['uuid']
                        obj_dict['href'] = self.generate_url(obj_type,
                                                             obj_result['uuid'])
                        obj_dict['fq_name'] = obj_result['fq_name']
                        obj_dicts.append(obj_dict)
            else:  # admin
                for fq_name, obj_uuid in fq_names_uuids:
                    obj_dict = {}
                    obj_dict['uuid'] = obj_uuid
                    obj_dict['href'] = self.generate_url(obj_type, obj_uuid)
                    obj_dict['fq_name'] = fq_name
                    obj_dicts.append(obj_dict)
        else:  # detail
            obj_ids_list = [{'uuid': obj_uuid}
                            for _, obj_uuid in fq_names_uuids]

            obj_class = self._resource_classes[obj_type]
            obj_fields = list(obj_class.prop_fields) + \
                         list(obj_class.ref_fields)
            if 'fields' in bottle.request.query:
                obj_fields.extend(bottle.request.query.fields.split(','))
            (ok, result) = self._db_conn.dbe_read_multi(
                obj_type, obj_ids_list, obj_fields)

            if not ok:
                bottle.abort(404, result)

            for obj_result in result:
                obj_dict = {}
                obj_dict['name'] = obj_result['fq_name'][-1]
                obj_dict['href'] = self.generate_url(
                    obj_type, obj_result['uuid'])
                obj_dict.update(obj_result)
                if (obj_dict['id_perms'].get('user_visible', True) or
                        self.is_admin_request()):
                    obj_dicts.append({obj_type: obj_dict})

        return {'%ss' % (obj_type): obj_dicts}

    # end _list_collection

    def generate_url(self, obj_type, obj_uuid):
        obj_uri_type = '/' + obj_type.replace('_', '-')
        try:
            url_parts = bottle.request.urlparts
            return '%s://%s%s%s/%s' \
                   % (url_parts.scheme, url_parts.netloc, SERVICE_PATH, obj_uri_type, obj_uuid)
        except Exception as e:
            return '%s/%s/%s' % (self._base_url, obj_uri_type, obj_uuid)

    # end generate_url

    def ref_update_http_post(self):
        self._post_common(bottle.request, None, None)
        obj_type = bottle.request.json['type']
        obj_uuid = bottle.request.json['uuid']
        ref_type = bottle.request.json['ref-type'].replace('-', '_')
        operation = bottle.request.json['operation']
        ref_uuid = bottle.request.json.get('ref-uuid')
        ref_fq_name = bottle.request.json.get('ref-fq-name')
        attr = bottle.request.json.get('attr')

        if not ref_uuid and not ref_fq_name:
            bottle.abort(404, 'Either ref-uuid or ref-fq-name must be specified')

        if not ref_uuid:
            try:
                ref_uuid = self._db_conn.fq_name_to_uuid(ref_type, ref_fq_name)
            except NoIdError:
                bottle.abort(404, 'Name ' + pformat(ref_fq_name) + ' not found')

        # type-specific hook
        r_class = self._resource_classes.get(obj_type)
        if r_class:
            try:
                fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
            except NoIdError:
                bottle.abort(404, 'UUID ' + obj_uuid + ' not found')
            (read_ok, read_result) = self._db_conn.dbe_read(
                obj_type, bottle.request.json)
            if not read_ok:
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', read_result)
                bottle.abort(404, read_result)

            obj_dict = read_result
            if operation == 'ADD':
                if ref_type + '_refs' not in obj_dict:
                    obj_dict[ref_type + '_refs'] = []
                obj_dict[ref_type + '_refs'].append({'to': ref_fq_name, 'uuid': ref_uuid, 'attr': attr})
            elif operation == 'DELETE':
                for old_ref in obj_dict.get(ref_type + '_refs', []):
                    if old_ref['to'] == ref_fq_name or old_ref['uuid'] == ref_uuid:
                        obj_dict[ref_type + '_refs'].remove(old_ref)
                        break
            else:
                msg = 'Unknown operation ' + operation
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', msg)
                bottle.abort(409, msg)

            (ok, put_result) = r_class.http_put(obj_uuid, fq_name, obj_dict, self._db_conn)
            if not ok:
                (code, msg) = put_result
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', msg)
                bottle.abort(code, msg)
        obj_type = obj_type.replace('-', '_')
        try:
            id = self._db_conn.ref_update(obj_type, obj_uuid, ref_type, ref_uuid, {'attr': attr}, operation)
        except NoIdError:
            bottle.abort(404, 'uuid ' + obj_uuid + ' not found')
        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type.replace('-', '_')
        fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
        apiConfig.identifier_name = ':'.join(fq_name)
        return {'uuid': id}

    # end ref_update_id_http_post

    def id_to_fq_name_http_post(self):
        self._post_common(bottle.request, None, None)
        obj_type = bottle.request.json['type']
        obj_uuid = bottle.request.json['uuid']
        ref_type = bottle.request.json['ref-type'].replace('-', '_')
        operation = bottle.request.json['operation']
        ref_uuid = bottle.request.json.get('ref-uuid')
        ref_fq_name = bottle.request.json.get('ref-fq-name')
        attr = bottle.request.json.get('attr')

        if not ref_uuid and not ref_fq_name:
            bottle.abort(404, 'Either ref-uuid or ref-fq-name must be specified')

        if not ref_uuid:
            try:
                ref_uuid = self._db_conn.fq_name_to_uuid(ref_type, ref_fq_name)
            except NoIdError:
                bottle.abort(404, 'Name ' + pformat(ref_fq_name) + ' not found')

        # type-specific hook
        r_class = self._resource_classes.get(obj_type)
        if r_class:
            try:
                fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
            except NoIdError:
                bottle.abort(404, 'UUID ' + obj_uuid + ' not found')
            (read_ok, read_result) = self._db_conn.dbe_read(
                obj_type, bottle.request.json)
            if not read_ok:
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', read_result)
                bottle.abort(404, read_result)

            obj_dict = read_result
            if operation == 'ADD':
                if ref_type + '_refs' not in obj_dict:
                    obj_dict[ref_type + '_refs'] = []
                obj_dict[ref_type + '_refs'].append({'to': ref_fq_name, 'uuid': ref_uuid, 'attr': attr})
            elif operation == 'DELETE':
                for old_ref in obj_dict.get(ref_type + '_refs', []):
                    if old_ref['to'] == ref_fq_name or old_ref['uuid'] == ref_uuid:
                        obj_dict[ref_type + '_refs'].remove(old_ref)
                        break
            else:
                msg = 'Unknown operation ' + operation
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', msg)
                bottle.abort(409, msg)

            (ok, put_result) = r_class.http_put(obj_uuid, fq_name, obj_dict, self._db_conn)
            if not ok:
                (code, msg) = put_result
                self.config_object_error(obj_uuid, None, obj_type, 'ref_update', msg)
                bottle.abort(code, msg)
        obj_type = obj_type.replace('-', '_')
        try:
            id = self._db_conn.ref_update(obj_type, obj_uuid, ref_type, ref_uuid, {'attr': attr}, operation)
        except NoIdError:
            bottle.abort(404, 'uuid ' + obj_uuid + ' not found')
        apiConfig = VncApiCommon()
        apiConfig.object_type = obj_type.replace('-', '_')
        fq_name = self._db_conn.uuid_to_fq_name(obj_uuid)
        return {'uuid': id}

    # end ref_update_id_http_post

    def fq_name_to_id_http_post(self):
        self._post_common(bottle.request, None, None)
        obj_type = bottle.request.json['type'].replace('-', '_')
        fq_name = bottle.request.json['fq_name']

        try:
            id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        except NoIdError:
            bottle.abort(404, 'Name ' + pformat(fq_name) + ' not found')

        return {'uuid': id}

    # end fq_name_to_id_http_post

    def ifmap_to_id_http_post(self):
        self._post_common(bottle.request, None, None)
        uuid = self._db_conn.ifmap_id_to_uuid(bottle.request.json['ifmap_id'])
        return {'uuid': uuid}

    # end ifmap_to_id_http_post

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
        # GreenletProfiler.start()
        pass

    # end start_profile

    def stop_profile(self):
        pass
        # GreenletProfiler.stop()
        # stats = GreenletProfiler.get_func_stats()
        # self._profile_info = stats.print_all()

        # return self._profile_info

    # end stop_profile
    def mt_http_get(self):
        pipe_start_app = self.get_pipe_start_app()
        mt = False
        try:
            mt = pipe_start_app.get_mt()
        except AttributeError:
            pass
        return {'enabled': mt}

    # end

	def get_profile_info(self):
            return self._profile_info
    # end get_profile_info

    def get_resource_class(self, resource_type):
        if resource_type in self._resource_classes:
            return self._resource_classes[resource_type]

        return None
    # end get_resource_class

    def set_resource_class(self, resource_type, resource_class):
        obj_type = resource_type.replace('-', '_')
        self._resource_classes[obj_type]  = resource_class
    # end set_resource_class



    def mt_http_put(self):
        multi_tenancy = bottle.request.json['enabled']
        user_token = bottle.request.get_header('X-Auth-Token')
        if user_token is None:
            bottle.abort(403, " Permission denied")

        data = self._auth_svc.verify_signed_token(user_token)
        if data is None:
            bottle.abort(403, " Permission denied")

        pipe_start_app = self.get_pipe_start_app()
        try:
            pipe_start_app.set_mt(multi_tenancy)
        except AttributeError:
            pass
        self._args.multi_tenancy = multi_tenancy
        return {}

    # end


    # The following method could reside in csp-logger for better maintenance
    def csp_logger_init(self, settings):
        if not settings.get('contrail_analytics_server'):
            raise Exception('Missing contrail_analytics_server configuration.')
        contrail_analytics_server = settings['contrail_analytics_server']

        if not settings.get('application_name'):
            raise Exception('Missing application name.')
        app_name = settings['application_name']

        contrail_discovery_port = '5998'
        if settings.get('contrail_discovery_port'):
            contrail_discovery_port = settings['contrail_discovery_port']

        log_level = 'ERROR'
        if settings.get('log_level'):
            log_level = settings['log_level']

        # if file location is configured, get it
        file_location = '/tmp/'
        if settings.get('log_location'):
            file_location = settings.get('log_location')
        # if local_log_enabled if configured, take it; otherwise log will be sent to analytics server
        local_log_enabled = False
        if settings.get('local_log_enabled') and \
                        settings.get('local_log_enabled').lower() in ["true", "yes"]:
            local_log_enabled = True

        APIContext().set_csp_logger(
            contrail_analytics_server,
            contrail_discovery_port,
            app_name,
            log_level,
            file_location=file_location,
            local_log_enabled=local_log_enabled)

        # end
        # Private Methods

    def _parse_args(self, args_str):
        '''
        Eg. python vnc_cfg_api_server.py --ifmap_server_ip 192.168.1.17
                                         --ifmap_server_port 8443
                                         --ifmap_username test
                                         --ifmap_password test
                                         --cassandra_server_list\
                                             10.1.2.3:9160 10.1.2.4:9160
                                         --redis_server_ip 127.0.0.1
                                         --redis_server_port 6382
                                         --collectors 127.0.0.1:8086
                                         --http_server_port 8090
                                         --listen_ip_addr 127.0.0.1
                                         --listen_port 8082
                                         --admin_port 8095
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
        '''

        # Source any specified config/ini file
        # Turn off help, so we print all options in response to -h
        conf_parser = argparse.ArgumentParser(add_help=False)

        conf_parser.add_argument("-c", "--conf_file", action='append',
                                 help="Specify config file", metavar="FILE")

        args, remaining_argv = conf_parser.parse_known_args(args_str.split())

        defaults = {
            'reset_config': False,
            'wipe_config': False,
            'listen_ip_addr': _WEB_HOST,
            'listen_port': _WEB_PORT,
            'admin_port': _ADMIN_PORT,
            'ifmap_server_ip': '127.0.0.1',
            'ifmap_server_port': "8443",
            'collectors': None,
            'http_server_port': '8084',
            'log_local': True,
            'log_level': SandeshLevel.SYS_NOTICE,
            'log_category': '',
            'log_file': Sandesh._DEFAULT_LOG_FILE,
            'trace_file': '/var/log/contrail/vnc_openstack.err',
            'use_syslog': False,
            'syslog_facility': Sandesh._DEFAULT_SYSLOG_FACILITY,
            'logging_level': 'WARN',
            'logging_conf': '',
            'multi_tenancy': True,
            'disc_server_ip': None,
            'disc_server_port': '5998',
            'zk_server_ip': '127.0.0.1:2181',
            'worker_id': '0',
            'rabbit_server': 'localhost',
            'rabbit_port': '5672',
            'rabbit_user': 'guest',
            'rabbit_password': 'guest',
            'rabbit_vhost': None,
            'rabbit_max_pending_updates': '4096',
            'cluster_id': '',
            'disable_ifmap': False,
            'max_requests': 1024
        }
        # ssl options
        secopts = {
            'use_certs': False,
            'keyfile': '',
            'certfile': '',
            'ca_certs': '',
            'ifmap_certauth_port': "8444",
        }
        # keystone options
        ksopts = {
            'auth_host': '127.0.0.1',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'admin_user': '',
            'admin_password': '',
            'admin_tenant_name': '',
            'insecure': True
        }

        config = None
        if args.conf_file:
            config = ConfigParser.SafeConfigParser({'admin_token': None})
            config.read(args.conf_file)
            defaults.update(dict(config.items("DEFAULT")))
            if 'multi_tenancy' in config.defaults():
                defaults['multi_tenancy'] = config.getboolean(
                    'DEFAULT', 'multi_tenancy')
            if 'SECURITY' in config.sections() and \
                            'use_certs' in config.options('SECURITY'):
                if config.getboolean('SECURITY', 'use_certs'):
                    secopts.update(dict(config.items("SECURITY")))
            if 'KEYSTONE' in config.sections():
                ksopts.update(dict(config.items("KEYSTONE")))
            if 'QUOTA' in config.sections():
                for (k, v) in config.items("QUOTA"):
                    try:
                        if str(k) != 'admin_token':
                            QuotaHelper.default_quota[str(k)] = int(v)
                    except ValueError:
                        pass
            if 'default_encoding' in config.defaults():
                default_encoding = config.get('DEFAULT', 'default_encoding')
                gen.resource_xsd.ExternalEncoding = default_encoding

        # Override with CLI options
        # Don't surpress add_help here so it will handle -h
        parser = argparse.ArgumentParser(
            # Inherit options from config_parser
            parents=[conf_parser],
            # print script description with -h/--help
            description=__doc__,
            # Don't mess with format of description
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        defaults.update(secopts)
        defaults.update(ksopts)
        parser.set_defaults(**defaults)

        parser.add_argument(
            "--ifmap_server_ip", help="IP address of ifmap server")
        parser.add_argument(
            "--ifmap_server_port", help="Port of ifmap server")

        # TODO should be from certificate
        parser.add_argument(
            "--ifmap_username",
            help="Username known to ifmap server")
        parser.add_argument(
            "--ifmap_password",
            help="Password known to ifmap server")
        parser.add_argument(
            "--cassandra_server_list",
            help="List of cassandra servers in IP Address:Port format",
            nargs='+')
        parser.add_argument(
            "--redis_server_ip",
            help="IP address of redis server")
        parser.add_argument(
            "--redis_server_port",
            help="Port of redis server")
        parser.add_argument(
            "--auth", choices=['keystone'],
            help="Type of authentication for user-requests")
        parser.add_argument(
            "--reset_config", action="store_true",
            help="Warning! Destroy previous configuration and start clean")
        parser.add_argument(
            "--wipe_config", action="store_true",
            help="Warning! Destroy previous configuration")
        parser.add_argument(
            "--listen_ip_addr",
            help="IP address to provide service on, default %s" % (_WEB_HOST))
        parser.add_argument(
            "--listen_port",
            help="Port to provide service on, default %s" % (_WEB_PORT))
        parser.add_argument(
            "--admin_port",
            help="Port with local auth for admin access, default %s"
                 % (_ADMIN_PORT))
        parser.add_argument(
            "--collectors",
            help="List of VNC collectors in ip:port format",
            nargs="+")
        parser.add_argument(
            "--http_server_port",
            help="Port of local HTTP server")
        parser.add_argument(
            "--ifmap_server_loc",
            help="Location of IFMAP server")
        parser.add_argument(
            "--log_local", action="store_true",
            help="Enable local logging of sandesh messages")
        parser.add_argument(
            "--log_level",
            help="Severity level for local logging of sandesh messages")
        parser.add_argument(
            "--logging_level",
            help=("Log level for python logging: DEBUG, INFO, WARN, ERROR default: %s"
                  % defaults['logging_level']))
        parser.add_argument(
            "--logging_conf",
            help=("Optional logging configuration file, default: None"))
        parser.add_argument(
            "--log_category",
            help="Category filter for local logging of sandesh messages")
        parser.add_argument(
            "--log_file",
            help="Filename for the logs to be written to")
        parser.add_argument(
            "--trace_file",
            help="Filename for the errors backtraces to be written to")
        parser.add_argument("--use_syslog",
                            action="store_true",
                            help="Use syslog for logging")
        parser.add_argument("--syslog_facility",
                            help="Syslog facility to receive log lines")
        parser.add_argument(
            "--multi_tenancy", action="store_true",
            help="Validate resource permissions (implies token validation)")
        parser.add_argument(
            "--worker_id",
            help="Worker Id")
        parser.add_argument(
            "--zk_server_ip",
            help="Ip address:port of zookeeper server")
        parser.add_argument(
            "--rabbit_server",
            help="Rabbitmq server address")
        parser.add_argument(
            "--rabbit_port",
            help="Rabbitmq server port")
        parser.add_argument(
            "--rabbit_user",
            help="Username for rabbit")
        parser.add_argument(
            "--rabbit_vhost",
            help="vhost for rabbit")
        parser.add_argument(
            "--rabbit_password",
            help="password for rabbit")
        parser.add_argument(
            "--rabbit_max_pending_updates",
            help="Max updates before stateful changes disallowed")
        parser.add_argument(
            "--cluster_id",
            help="Used for database keyspace separation")
        parser.add_argument(
            "--disable_ifmap",
            action= "store_true",
            help= "disable ip map publish"
        )
        parser.add_argument(
            "--max_requests", type=int,
            help="Maximum number of concurrent requests served by api server")
        self._args = parser.parse_args(remaining_argv)
        self._args.config_sections = config
        if type(self._args.cassandra_server_list) is str:
            self._args.cassandra_server_list = \
                self._args.cassandra_server_list.split()
        if type(self._args.collectors) is str:
            self._args.collectors = self._args.collectors.split()

        config_args = []
        config_args.append("--config-dir")
        cfg_dir = str(args.conf_file[0]).rsplit("/", 1)[0]
        config_args.append(cfg_dir)
        cfg.CONF(args=config_args, default_config_files = args.conf_file)

    # end _parse_args

    def start_server(self):
        import cgitb
        cgitb.enable(format='text')
        '''
        Start server
        :param server_ip:
        :param server_port:
        :param pipe_start_app:
        :return:
        '''
        try:
            pipe_start_app = self.get_pipe_start_app()
            server_ip = self.get_listen_ip()
            server_port = self.get_server_port()
            print ("BOTTLE RUN {} {} ".format(server_ip, server_port))
            bottle.run(app=pipe_start_app, host=server_ip, port=server_port,
                       server=get_bottle_server(self._args.max_requests))
        except KeyboardInterrupt:
            # quietly handle Ctrl-C
            pass
        except:
            # dump stack on all other exceptions
            raise
        finally:
            # always cleanup gracefully
            self.cleanup()
