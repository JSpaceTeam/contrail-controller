#
# Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
#
#
import eventlet
import kazoo.client
import kazoo.exceptions
import kazoo.handlers.eventlet
import kazoo.recipe.election
from cfgm_common.zkclient import ZookeeperClient
import logging

LOG = logging.getLogger()


class ZookeeperEventletClient(ZookeeperClient):
    '''
     Eventlet based zk client
    '''

    def __init__(self, module, server_list, logging_fn=None):
        super(ZookeeperEventletClient, self). \
            __init__(module, server_list, logging_fn=logging_fn,
                     client_handler=kazoo.handlers.eventlet.SequentialEventletHandler(),
                     sleep_func=kazoo.handlers.eventlet.SequentialEventletHandler.sleep_func,
                     timeout_exception_cls=eventlet.Timeout)

    # end __init__

    # start


    def _sandesh_connection_info_update(self, status, message):
        '''
        Override to not use sandesh
        Args:
            status:
            message:

        Returns:

        '''
        new_conn_state = getattr(ConnectionStatus, status)
        if self._conn_state and self._conn_state != ConnectionStatus.DOWN \
                and new_conn_state == ConnectionStatus.DOWN:
            msg = 'Connection to Zookeeper down: %s' % (message)
            self.log(msg, level=logging.FATAL)
        if self._conn_state and self._conn_state != new_conn_state \
                and new_conn_state == ConnectionStatus.UP:
            msg = 'Connection to Zookeeper ESTABLISHED'
            self.log(msg, level=logging.WARN)

        self._conn_state = new_conn_state
        # end _sandesh_connection_info_update

    def get_zk_client(self):
        return self._zk_client
    # end

# end class ZookeeperClient

class ConnectionStatus(object):
    INIT = 0
    DOWN = 1
    UP = 2

    _VALUES_TO_NAMES = {
        0: "INIT",
        1: "DOWN",
        2: "UP",
    }

    _NAMES_TO_VALUES = {
        "INIT": 0,
        "DOWN": 1,
        "UP": 2,
    }
