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


from oslo_utils import importutils
from cfgm_common import vnc_api_stats

vnc_api_stats.log_api_stats = log_api_stats
from server_core import vnc_cfg_base_type
from vnc_cfg_api_server import *
from vnc_cfg_api_server import _ACTION_RESOURCES
from bottle import request
from gen.resource_xsd import *
from cfgm_common.vnc_extensions import ExtensionManager, ApiHookManager
from pysandesh.sandesh_base_logger import SandeshBaseLogger
from csp_services_common import cfg

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


RBAC_RULE = 'rbac_rule'
MULTI_TENANCY = 'multi_tenancy'


class Policy(object):
    """An object to hold rbac and multi tenancy policy"""

    def __init__(self, filename):
        with open(filename) as policy_file:
            self.policy_json = json.loads(policy_file.read())

    def get_default_rbac_rule(self):
        return self.policy_json.get(RBAC_RULE).get('default')

    def get_multi_tenancy_rule(self):
        return self.policy_json.get(MULTI_TENANCY)


class VncApiServerBase(VncApiServer):
    __metaclass__ = abc.ABCMeta

    def __new__(cls, *args, **kwargs):
        obj = super(VncApiServerBase, cls).__new__(cls, *args, **kwargs)
        cls._generate_rpc_methods(obj)
        cls._generate_rpc_uri(obj)
        cls._generate_search_methods(obj)
        cls._generate_search_uri(obj)
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

        # REST interface initialization
        self._get_common = self._http_get_common
        self._put_common = self._http_put_common
        self._delete_common = self._http_delete_common
        self._post_validate = self._http_post_validate
        self._post_common = self._http_post_common

        self.get_resource_class('api-access-list').generate_default_instance = False


        for act_res in _ACTION_RESOURCES:
            uri = act_res['uri']
            if SERVICE_PATH:
                uri = '%s%s' % (SERVICE_PATH, uri)
            link = LinkObject('action', self._base_url, uri,
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
            policy = None
            try:
                policy = Policy("policy/policy.json")
            except Exception:
                logger.warn("Cannot load policy file, apply default policy")
            if policy:
                self._update_default_rbac_rule(policy.get_default_rbac_rule())
                self._update_multi_tenancy_rule(policy.get_multi_tenancy_rule())

        @bottle.hook('before_request')
        def strip_path(): # pylint: disable=W0612
            bottle.request.environ['PATH_INFO'] = bottle.request.\
                    environ['PATH_INFO'].rstrip('/')

    @classmethod
    def _generate_rpc_uri(cls, obj):
        for resource_type in gen.vnc_api_server_gen.all_rpc_input_types:
            # RPC /rpc
            obj_type = resource_type.replace('-', '_')
            # leaf resource
            obj.route('%s/%s' % (SERVICE_PATH, resource_type),
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

    def _update_default_rbac_rule(self, rbac_rule):
        obj_type = 'api-access-list'
        fq_name = ['default-domain', 'default-api-access-list']
        id = self._db_conn.fq_name_to_uuid(obj_type, fq_name)
        (ok, obj_dict) = self._db_conn.dbe_read(obj_type, {'uuid': id})
        obj_dict['api_access_list_entries'] = {'rbac_rule': rbac_rule}
        self._db_conn.dbe_update(obj_type, {'uuid': id}, obj_dict)
        logger.info("Updated default rbac rule")

    # end _update_default_rbac_rule

    def _update_multi_tenancy_rule(self, multi_tenancy_rule):
        for resource in multi_tenancy_rule.keys():
            if not resource.startswith('r:'):
                rule = multi_tenancy_rule.get(resource)
                self.get_resource_class(resource).multi_tenancy_rule = multi_tenancy_rule.get(rule)
        logger.info("Updated multi-tenancy rule")

    # end _update_multi_tenancy_rule

    #Override trace since we are using logger middleware
    def _generate_rest_api_request_trace(self):
        return None

    @classmethod
    def _generate_search_methods(cls, obj):
        for resource_type in gen.vnc_api_server_gen.all_resource_types:
            obj_type = resource_type.replace('-', '_')

            filter_method = functools.partial(obj._http_post_filter, resource_type)
            functools.update_wrapper(filter_method, obj._http_post_filter)
            setattr(obj, '%s_http_post_filter' % obj_type, filter_method)

            search_method = functools.partial(obj._http_post_search, resource_type)
            functools.update_wrapper(search_method, obj._http_post_search)
            setattr(obj, '%s_http_post_search' % obj_type, search_method)

            index_method = functools.partial(obj.http_resource_index, resource_type)
            functools.update_wrapper(index_method, obj.http_resource_index)
            setattr(obj, '%s_http_post_index' % obj_type, index_method)

    # end _generate_search_methods

    @classmethod
    def _generate_search_uri(cls, obj):
        for resource_type in gen.vnc_api_server_gen.all_resource_types:
            obj_type = resource_type.replace('-', '_')
            obj.route('%s/%s/_filter'%(SERVICE_PATH, resource_type),
                      'POST',
                      getattr(obj, '%s_http_post_filter' % obj_type))
            obj.route('%s/%s/_search'%(SERVICE_PATH, resource_type),
                      'POST',
                      getattr(obj, '%s_http_post_search' % obj_type))
            obj.route('%s/%s/_index' % (SERVICE_PATH, resource_type),
                      'POST',
                      getattr(obj, '%s_http_post_index' % obj_type))
        #Module level routes for search
        obj.route('%s/_search'%(SERVICE_PATH),
                      'POST',
                      obj.search_execute)
        obj.route('%s/_suggest'%(SERVICE_PATH),
                      'POST',
                      obj.suggest_execute)

    @abc.abstractmethod
    def get_pipeline(self):
        pass

    def vnc_api_config_log(self, apiConfig):
        # we already fo API logging through the logging middleware.
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
            method_name = resource_type.replace('-','_')
            rsp_body = self._extension_mgrs['rpcApi'].map_method('%s_execute' % method_name, obj_dict)
        except KeyError as e:
            ok = False
            result = HttpError(404, "RPC not available")

        except Exception as e:
            ok = False
            result = e
        if not ok:
            for fail_cleanup_callable, cleanup_args in cleanup_on_failure:
                fail_cleanup_callable(*cleanup_args)
            self.config_object_error(None, resource_type, '%s_execute' % resource_type, 'http_post', str(result))
            if isinstance(result, cfgm_common.exceptions.HttpError):
                raise result
            if hasattr(result, 'status_code') and hasattr(result, 'content'):
                raise HttpError(getattr(result, 'status_code'), getattr(result, 'content'))
            raise result

        return rsp_body
    # end http_rpc_post

    def _http_post_search(self, resource_type):
        db_conn = self._db_conn
        if request.json is not None:
            body = request.json
        else:
            raise cfgm_common.exceptions.HttpError(400, 'invalid request, search body not found')
        result = db_conn.search(resource_type, body)
        return result
    #end _http_post_search

    def suggest_execute(self):
        db_conn = self._db_conn
        if request.json is not None:
            body = request.json
        else:
           raise cfgm_common.exceptions.HttpError(400, 'invalid request, search body not found')
        result = db_conn.suggest(body)
        return result
    #end suggest_execute

    def search_execute(self):
        db_conn = self._db_conn
        if request.json is not None:
            body = request.json
        else:
            raise cfgm_common.exceptions.HttpError(400, 'invalid request, search body not found')
        result = db_conn.search(None, body)
        return result
    #end search_execute

    def http_resource_index(self, resource_type):
        obj_type = resource_type.replace('-', '_')

        env = get_request().headers.environ
        tenant_name = env.get(hdr_server_tenant(), 'default-project')
        parent_uuids = None
        back_ref_uuids = None
        obj_uuids = None
        if (('parent_fq_name_str' in get_request().query) and
            ('parent_type' in get_request().query)):
            parent_fq_name = get_request().query.parent_fq_name_str.split(':')
            parent_type = get_request().query.parent_type
            parent_uuids = [self._db_conn.fq_name_to_uuid(parent_type, parent_fq_name)]
        elif 'parent_id' in get_request().query:
            parent_ids = get_request().query.parent_id.split(',')
            parent_uuids = [str(uuid.UUID(p_uuid)) for p_uuid in parent_ids]
        if 'back_ref_id' in get_request().query:
            back_ref_ids = get_request().query.back_ref_id.split(',')
            back_ref_uuids = [str(uuid.UUID(b_uuid)) for b_uuid in back_ref_ids]
        if 'obj_uuids' in get_request().query:
            obj_uuids = get_request().query.obj_uuids.split(',')

        if 'fields' in get_request().query:
            req_fields = get_request().query.fields.split(',')
        else:
            req_fields = []
        (ok, result, total) = self._db_conn.dbe_only_list(obj_type,
                             parent_uuids, back_ref_uuids, obj_uuids,count=False,
                             filters=None)
        if not ok:
            self.config_object_error(None, None, '%ss' %(obj_type),
                                     'dbe_list', result)
            raise cfgm_common.exceptions.HttpError(404, result)
        obj_ids_list = [{'uuid': obj_uuid}
                            for _, obj_uuid in result]

        obj_class = self.get_resource_class(obj_type)
        obj_fields = list(obj_class.prop_fields)
        if req_fields:
            obj_fields.extend(req_fields)
        (ok, result) = self._db_conn.dbe_read_multi(
                                obj_type, obj_ids_list, obj_fields)

        if not ok:
                raise cfgm_common.exceptions.HttpError(404, result)
        for obj_result in result:
                obj_dict = {}
                obj_dict['name'] = obj_result['fq_name'][-1]
                obj_dict.update(obj_result)
                obj_ids = {'uuid': obj_dict['uuid']}
                self._db_conn.dbe_search_update(obj_type, obj_ids, obj_dict)
                gevent.sleep(0)
        return bottle.HTTPResponse(status=200)




    def config_log(self, err_str, level=SandeshLevel.SYS_INFO):
        logging.log(SandeshBaseLogger.get_py_logger_level(level), err_str)

    # end config_log


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
                propagate_map_exceptions=True,
                conf_sections=conf_sections, sandesh=self._sandesh)
            self._extension_mgrs['rpcApi'] = ExtensionManager(
                'vnc_cfg_api.rpcApi', api_server_ip=self._args.listen_ip_addr,
                api_server_port=self._args.listen_port,
                conf_sections=conf_sections, sandesh=self._sandesh, propagate_map_exceptions=True)
        except Exception as e:
            err_msg = cfgm_common.utils.detailed_traceback()
            self.config_log("Exception in extension load: %s" %(err_msg),
                level=SandeshLevel.SYS_ERR)

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
