import gevent
from pysandesh.gen_py.sandesh.ttypes import SandeshLevel
import cfgm_common

class ApiInternalRequest(object):
    def __init__(self, url, urlparts, environ, headers, json_as_dict, query):
        self.url = url
        self.urlparts = urlparts
        self.environ = environ
        self.headers = headers
        self.json = json_as_dict
        self.query = query
    # end __init__
# end class ApiInternalRequest

class ApiContext(object):
    """
    An object holding request-specific context. Holds a reference
    to external(bottle) request or internal(follow-up) request
    """
    states = {
        'INIT': 'Initializing',

        'PRE_DBE_CREATE': 'Before DB Entry Creation',
        'DBE_CREATE': 'DB Entry Creation',
        'POST_DBE_CREATE': 'After DB Entry Creation',

        'PRE_DBE_UPDATE': 'Before DB Entry Update',
        'DBE_UPDATE': 'DB Entry Update',
        'POST_DBE_UPDATE': 'After DB Entry Update',

        'PRE_DBE_DELETE': 'Before DB Entry Delete',
        'DBE_DELETE': 'DB Entry Delete',
        'POST_DBE_DELETE': 'After DB Entry Delete',
    }

    def __init__(self, external_req=None, internal_req=None):
        self.external_req = external_req
        self.internal_req = internal_req
        self.proc_state = self.states['INIT']
        self.undo_callables_with_args = []
    # end __init__

    @property
    def request(self):
        if self.internal_req:
            return self.internal_req
        return self.external_req
    # end request

    def set_state(self, state):
        # set to enumerated or if no mapping, user-passed state-str
        self.proc_state = self.states.get(state, state)
    # end state

    def get_state(self):
        # return enumerated or if no-mapping actual state val
        return self.states.get(self.proc_state, self.proc_state)
    # end get_state

    def push_undo(self, undo_callable, *args, **kwargs):
        self.undo_callables_with_args.append(
            (undo_callable, (args, kwargs)))
    # end push_undo

    def invoke_undo(self, failure_code, failure_msg, logger):
        for undo_callable, (args, kwargs) in self.undo_callables_with_args:
            try:
                undo_callable(*args, **kwargs)
            except Exception as e:
                err_msg = cfgm_common.utils.detailed_traceback()
                logger(err_msg, level=SandeshLevel.SYS_ERR)
    # end invoke_undo
# end class ApiContext



def get_request():
    return gevent.getcurrent().api_context.request

def get_context():
    return gevent.getcurrent().api_context

def set_context(api_ctx):
    gevent.getcurrent().api_context = api_ctx




class RequestContext(object):
    '''
     This hold request context that can be propgated to RPC calls
    '''
    def __init__(self, auth_token=None, username=None, password=None,
                 tenant=None, tenant_id=None, auth_url=None, roles=None, is_admin=None,
                 request_id=None, **kwargs):
        self.auth_token = auth_token
        self.user = username
        self.tenant = tenant
        self.is_admin = is_admin
        self.request_id = request_id
        self.username = username
        self.password = password
        self.tenant_id = tenant_id
        self.auth_url = auth_url
        # One of Invalid, Confirmed, None
        self.auth_status = kwargs['auth_status']
        # Domain to which the tenant belongs; today derived from user
        self.domain = kwargs['domain']
        # Domain_id as uuid except for default domain
        self.domain_id = kwargs['domain_id']
        # user is passing a domain-scoped token, i.e domain owner
        self.is_domain_scoped = kwargs['is_domain_scoped']
        self.roles = roles or []

    def to_dict(self):
        return {'auth_token': self.auth_token,
                'username': self.username,
                'password': self.password,
                'tenant': self.tenant,
                'tenant_id': self.tenant_id,
                'auth_url': self.auth_url,
                'auth_status': self.auth_status,
                'domain': self.domain,
                'domain_id': self.domain_id,
                'is_domain_scoped': self.is_domain_scoped,
                'roles': self.roles,
                'is_admin': self.is_admin,
                'user': self.user,
                'request_id': self.request_id}

    @classmethod
    def from_dict(cls, values):
        return cls(**values)
# end RequestContext

def create_request_context(context):
    if context:
        request = context.request
        username = request.get_header('X-User-Name')
        token = request.get_header('X-Auth-Token')
        auth_status = request.get_header('X-Identity-Status')
        auth_url = request.get_header('X-Auth-Url')
        tenant = request.get_header('X-Project-Name')
        domain = request.get_header('X-User-Domain-Name')
        is_domain_scoped = False
        if request.get_header('X-Domain-Id') is not None:
            is_domain_scoped = True
        domain_id = request.get_header('X-User-Domain-Id')
        tenant_id = request.get_header('X-Tenant-Id')

        if not domain_id:
            domain_id = "00000000000000000000000000000000"
        if not tenant_id:
            tenant_id = "00000000000000000000000000000000"

        roles = request.get_header('X-Roles')
        if roles is not None:
            roles = roles.split(',')

        return RequestContext(auth_token=token,
            tenant=tenant,
            tenant_id=tenant_id,
            domain=domain,
            domain_id=domain_id,
            auth_status=auth_status,
            username=username,
            auth_url=auth_url,
            roles=roles,
            is_domain_scoped=is_domain_scoped)
    return None
# end create_request_context