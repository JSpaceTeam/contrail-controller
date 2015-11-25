from pysandesh.gen_py.sandesh.ttypes import SandeshLevel
from cfgm_common.exceptions import SearchServiceError

SEARCH_ERROR = 0
DB_ERROR = 1
OP_CREATE = 'create'
OP_UPDATE = 'update'
OP_DELETE = 'delete'
OP_REINDEX = 'reindex'

class VncDBRollBackHandler(object):
    """
    This class handles roll back logic for DB changes
    """

    def __init__(self, application_mgr, msg_bus, db_mgr, search_mgr):
        self._application_mgr = application_mgr
        self._msg_bus = msg_bus
        self._search_mgr = search_mgr
    # end __init__

    def handle_error(self, error_type, error_exception, operation, obj_type, object_ids, object_dict=None):
        if error_type is SEARCH_ERROR:
            do_raise = self.__handler_search_error(operation, obj_type, object_ids, object_dict)
            raise SearchServiceError(str(error_exception)) if do_raise else None
        if error_type is DB_ERROR:
            do_raise = self.__handle_db_error(operation, obj_type, object_ids, object_dict)
            raise error_exception if do_raise else None
        else:
            raise NotImplementedError

    # end handle_error

    def config_log(self, msg, level = SandeshLevel.SYS_NOTICE):
        self._application_mgr.config_log(msg, level=level)

    # end config_log

    def __handle_db_error(self, operation, obj_type, object_ids, object_dict=None):
        return self.__rollback_action_on_db_failure(operation, obj_type, object_ids, object_dict)

    # end  __handle_db_error

    def __handler_search_error(self, operation, obj_type, object_ids, object_dict=None):
        try:
            return self.__rollback_action_on_es_failure(operation, obj_type, object_ids, object_dict)
        except Exception as e:
            raise SearchServiceError(str(e))

    # end __handler_search_error

    def __rollback_action_on_db_failure(self, operation, obj_type, obj_ids, obj_dict):
        """
        Rollback operation if DB reports failures
        :param operation:
        :param obj_type:
        :param obj_ids:
        :param obj_dict:
        :return:
        """
        raise_exception = False
        if operation == OP_CREATE:
            try:
                self._search_mgr.search_delete(obj_type, obj_ids)
            except Exception as e:
                #Swallow any exception and re raise root exception
                self.config_log("Failed to delete object from es")
            finally:
                self.__reconcile_delete(obj_type, obj_ids)
            raise_exception = True
        if operation == OP_UPDATE:
            # Reindex object
            self.__rollback_es_update(obj_type, obj_ids)
            raise_exception = True
        if operation == OP_DELETE:
            # raise exception up but do nothing since DB delete failed no rollback needed
            raise_exception = True

        return raise_exception

    # end rollback_on_db_failure

    def __rollback_action_on_es_failure(self, operation, obj_type, obj_ids, obj_dict):
        """
        Rollback operation failures and decide if exception needs to be raised up
        :param operation:
        :param obj_type:
        :param obj_ids:
        :param obj_dict:
        :return: boolean
        """
        if self._search_mgr.is_doc_type_mapped(obj_type):
            if operation == OP_CREATE:
                # No OP just raise exception and send error to user
                return True
            if operation == OP_UPDATE:
                # No OP on Update failure send user error
                return True
            if operation == OP_DELETE:
                # reconcile don't raise
                self.__reconcile_delete(obj_type, obj_ids)
                return False

    # end __rollback_es_failure

    def __rollback_es_delete(self, obj_type, obj_ids):
        #put to GC queue
        message = self.__reconciliation_message(OP_REINDEX, obj_type, obj_ids)
        self._msg_bus.search_rc_publish(message)
    # end __rollback_delete

    def __rollback_es_update(self, obj_type, obj_ids):
        #put to GC queue
        message = self.__reconciliation_message(OP_REINDEX, obj_type, obj_ids)
        self._msg_bus.search_rc_publish(message)

    # end __rollback_es_failure

    def __reconcile_delete(self, obj_type, obj_ids):
        # put to GC queue
        message = self.__reconciliation_message(OP_DELETE, obj_type, obj_ids)
        self._msg_bus.search_rc_publish(message)
    # end __reconcile_delete

    def __reconciliation_message(self, op, obj_type, obj_ids):
        message = {'reconcile': op, 'index': self._search_mgr.index}
        message.update(obj_ids)
        message.update({'type': obj_type})
        return message
        # end __reconciliation_message
