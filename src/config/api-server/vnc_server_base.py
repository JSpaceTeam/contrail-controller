from gevent import monkey

monkey.patch_all()
from gevent import hub
import abc

"""
Overriding the base api_stats logger to do nothing
"""


def log_api_stats(func):
    def wrapper(api_server_obj, resource_type, *args, **kwargs):
        return func(api_server_obj, resource_type, *args, **kwargs)

    return wrapper


from csp.csp_api_context import APIContext
from oslo_utils import importutils
from cfgm_common import vnc_api_stats

vnc_api_stats.log_api_stats = log_api_stats
from server_core import vnc_cfg_base_type
from vnc_cfg_api_server import *
from vnc_cfg_api_server import _ACTION_RESOURCES
from bottle import request
from gen.resource_xsd import *
from cfgm_common.vnc_extensions import ExtensionManager, ApiHookManager

# Parse config for olso configs. Try to move all config parsing to oslo cfg
elastic_search_group = cfg.OptGroup(name='elastic_search', title='ELastic Search Options')
cfg.CONF.register_cli_opt(cfg.BoolOpt(name='search_enabled', default=False),
                          group=elastic_search_group)
cfg.CONF.register_cli_opt(cfg.ListOpt('server_list',
                                      item_type=cfg.types.String(),
                                      default='127.0.0.1:9200',
                                      help="Multiple servers option"), group=elastic_search_group)
cfg.CONF.register_cli_opt(cfg.BoolOpt(name='enable_sniffing', default=False,
                                      help="Enable connection sniffing for elastic search driver")
                          , group=elastic_search_group)

cfg.CONF.register_cli_opt(
    cfg.IntOpt(name='timeout', default=2, help="Default timeout in seconds for elastic search operations"),
    group=elastic_search_group)

sandesh_to_log_level = {
    SandeshLevel.SYS_EMERG: logging.FATAL,
    SandeshLevel.SYS_CRIT: logging.CRITICAL,
    SandeshLevel.SYS_ALERT: logging.INFO,
    SandeshLevel.SYS_NOTICE: logging.INFO,
    SandeshLevel.SYS_INFO: logging.INFO,
    SandeshLevel.SYS_WARN: logging.WARN,
    SandeshLevel.SYS_DEBUG: logging.DEBUG,
    SandeshLevel.SYS_ERR: logging.ERROR
}


class VncApiServerBase(VncApiServer):
    __metaclass__ = abc.ABCMeta

    def __new__(cls, *args, **kwargs):
        obj = super(VncApiServerBase, cls).__new__(cls, *args, **kwargs)
        cls._generate_rpc_methods(obj)
        cls._generate_rpc_uri(obj)
        return obj

    def __init__(self, args_str=None):
        self._db_conn = None
        self._get_common = None
        self._post_common = None
        self._resource_classes = {}
        self._rpc_input_types = {}
        for resource_type in gen.vnc_api_server_gen.all_resource_types:
            camel_name = cfgm_common.utils.CamelCase(resource_type)
            r_class_name = '%sServer' % (camel_name)
            common_class = cfgm_common.utils.str_to_class(camel_name, __name__)
            # Create Placeholder classes derived from Resource, <Type> so
            # r_class methods can be invoked in CRUD methods without
            # checking for None
            r_class = type(r_class_name,
                           (vnc_cfg_base_type.Resource, common_class, object), {})
            self.set_resource_class(resource_type, r_class)

        for rpc_input in gen.vnc_api_server_gen.all_rpc_input_types:
            camel_name = cfgm_common.utils.CamelCase(rpc_input)
            rpc_input_type = '%s_InputType' % (camel_name)
            self._rpc_input_types[rpc_input] = rpc_input_type

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
        # Generate LinkObjects for all entities
        links = []
        for resource_type in gen.vnc_api_server_gen.all_resource_types:
            link = LinkObject('collection',
                              self._base_url, '%s/%s' % (SERVICE_PATH, resource_type),
                              '%s' % (resource_type))
            links.append(link)

        for resource_type in gen.vnc_api_server_gen.all_resource_types:
            link = LinkObject('resource-base',
                              self._base_url, '%s/%s' % (SERVICE_PATH, resource_type),
                              '%s' % (resource_type))
            links.append(link)

        for rpc in gen.vnc_api_server_gen.all_rpc_input_types:
            link = LinkObject('rpc',
                              self._base_url, '%s/%s' % (SERVICE_PATH, rpc),
                              '%s' % (rpc))
            links.append(link)

        self._homepage_links = links

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

    @classmethod
    def _generate_rpc_uri(cls, obj):
        for resource_type in gen.vnc_api_server_gen.all_rpc_input_types:
            # RPC /rpc
            obj_type = resource_type.replace('-', '_')
            # leaf resource
            obj.route('%s/%s' % (SERVICE_PATH, obj_type),
                      'POST',
                      getattr(obj, '%s_rpc_http_post' % (obj_type)))

    # end _generate_resource_crud_uri

    @classmethod
    def _generate_rpc_methods(cls, obj):
        for resource_type in gen.vnc_api_server_gen.all_rpc_input_types:
            obj_type = resource_type.replace('-', '_')
            rpc_method = functools.partial(obj.http_rpc_post,
                                           resource_type)
            functools.update_wrapper(rpc_method, obj.http_rpc_post)
            setattr(obj, '%s_rpc_http_post' % (obj_type), rpc_method)

    # end _generate_rpc_methods

    def get_rpc_input_type(self, rpc):
        if rpc in self._rpc_input_types:
            return self._rpc_input_types[rpc]
        return None

    # end get_rpc_input_type

    @abc.abstractmethod
    def get_pipeline(self):
        pass

    def vnc_api_config_log(self, apiConfig):
        pass

    def http_rpc_post(self, resource_type):
        _key = 'input'
        try:
            obj_dict = request.json[_key]
        except KeyError:
            bottle.abort(400, 'invalid request, key "%s" not found' % _key)
        obj_dict = {_key: obj_dict}

        prop_dict = obj_dict.get('input')
        prop_type = self.get_rpc_input_type(resource_type)
        if prop_type:
            buf = cStringIO.StringIO()
            prop_cls = cfgm_common.utils.str_to_class(prop_type, __name__)
            try:
                tmp_prop = prop_cls(**prop_dict)
                tmp_prop.export(buf)
                node = etree.fromstring(buf.getvalue())
                tmp_prop = prop_cls()
                tmp_prop.build(node)
            except Exception as e:
                err_msg = 'Error validating property %s value %s ' \
                          % (prop_type, prop_dict)
                err_msg += str(e)
                return False, err_msg
        env = request.headers.environ
        tenant_name = env.get(hdr_server_tenant(), 'default-project')

        # State modification starts from here. Ensure that cleanup is done for all state changes
        cleanup_on_failure = []
        # type-specific hook
        r_class = self.get_resource_class(resource_type)
        if r_class:
            (ok, result) = r_class.http_post(tenant_name, obj_dict)
            if not ok:
                for fail_cleanup_callable, cleanup_args in cleanup_on_failure:
                    fail_cleanup_callable(*cleanup_args)
                (code, msg) = result
                self.config_object_error(None, resource_type, '%s_execute' % (resource_type), 'http_post', msg)
                bottle.abort(code, msg)
        callable = getattr(r_class, 'http_post_collection_fail', None)
        if callable:
            cleanup_on_failure.append((callable, [tenant_name, obj_dict]))

        # call RPC implementation
        ok = True
        try:
            rsp_body = self._extension_mgrs['rpcApi'].map_method('%s_execute' % resource_type, obj_dict)
        except KeyError as e:
            ok = False
            result = 'RPC not implemented'

        except Exception as e:
            ok = False
            result = str(e)

        if not ok:
            for fail_cleanup_callable, cleanup_args in cleanup_on_failure:
                fail_cleanup_callable(*cleanup_args)
            self.config_object_error(None, resource_type, '%s_execute' % resource_type, 'http_post', result)
            bottle.abort(404, result)

        return rsp_body
    # end http_rpc_post

    # Override Route
    def route(self, uri, method, handler):
        print("Add route: %s " % uri)

        def handler_trap_exception(*args, **kwargs):
            set_context(ApiContext(external_req=bottle.request))
            trace = None
            try:
                self._extensions_transform_request(get_request())
                self._extensions_validate_request(get_request())

                trace = self._generate_rest_api_request_trace()
                # (ok, status) = self._rbac.validate_request(get_request())
                # if not ok:
                #     (code, err_msg) = status
                #     raise cfgm_common.exceptions.HttpError(code, err_msg)
                response = handler(*args, **kwargs)
                self._generate_rest_api_response_trace(trace, response)

                self._extensions_transform_response(get_request(), response)

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
            log_level = sandesh_to_log_level[level]
        logging.log(log_level, err_str)

    # end config_log

    def get_default_logger(self):
        from csp.csp_log_writer import CSPSandeshLogger
        return CSPSandeshLogger().get_csp_logger()  # CSP Logger

    def __add_middleware(self, name, module):
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
                self.__add_middleware(k, v)




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
                conf_sections=conf_sections, sandesh=self._sandesh, propagate_map_exceptions=True)
        except Exception as e:
            # csp Log
            pass

    # end _load_extensions


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
