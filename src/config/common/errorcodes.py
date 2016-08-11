from cfgm_common import jsonutils as json
import logging
import copy
import os

logger = logging.getLogger(__name__)


def isNotBlank (myString):
    return (myString and myString.strip())

# End Util Methods

class ErrorCodes(object):
    '''
    This class will provide the error details for an error code.
    This should be instantiated and initialized once and the same instance should be used thereafter (singleton).
    The ms_error_codes_file path should be passed during instantiation.
    '''
    ERROR_CODE = "error_code"
    STATUS_CODE = "status_code"
    ERROR_TAG = "error_tag"
    ERROR_MESSAGE = "error_message"
    ERROR_DIAG = "error_diag"
    ERROR_APP_MESSAGE = "error_app_message"
    CAUSE = "cause"

    CONTENT = "content"
    FORMAT_ARGS = "format_args"
    FORMAT_KWARGS = "format_kwargs"

    def __init__(self, common_errors_filePath, ms_errors_filePath=None):
        self.__error_codes = self.__read_from_file(common_errors_filePath)

        if ms_errors_filePath is not None and os.path.exists(ms_errors_filePath):
            self.__append_to_error_codes(ms_errors_filePath)
        else:
            logmsg = 'ms_errors_filePath is None' if ms_errors_filePath is None else 'ms_errors_filePath does not exist'
            logger.warning(logmsg)



    def get_error_code_details(self, error_code, *args, **kwargs):
        '''
        This method returns the error code details in a dict object
        :param error_code: The error_code whose details should be returned
        :return: dict of the error code detials
        :rtype: dict
        '''
        if error_code is not None and isNotBlank(error_code):
            for key in self.__error_codes.keys():
                error_code_dict = self.__error_codes.get(key)
                if (error_code_dict.has_key(error_code)):
                    #always return a copy so that the original dict object doesn't get modified
                    error_code_details = copy.deepcopy(error_code_dict[error_code])
                    if (args is not None and len(args) > 0) or (kwargs is not None and len(kwargs) > 0):
                        #format the error_message
                        try:
                            self.__format_error_message(error_code_details, args, kwargs)
                        except Exception as e:
                            logger.exception("Exception while formatting error_message - " + e.__str__())
                            raise e

                    return error_code_details

        return None


    def get_error_code_data(self, error_code, *args, **kwargs):
        '''
        This method returns a dictionary object with the error code details nested one level inside a dict object,
        the key value being "error_data"
        :param error_code: The error_code whose details should be returned
        :return: dict with one member: key value being "error_data" and the value being the error_code details.
        :rtype: dict
        '''
        error_code_details = self.get_error_code_details(error_code, *args, **kwargs)
        if error_code_details is None:
            return None
        error_code_data = dict()
        error_code_data['error_data'] = error_code_details

        return error_code_data



    def __format_error_message(self, error_details_dict, args, kwargs):
        if error_details_dict is None:
            return

        if error_details_dict.has_key(ErrorCodes.ERROR_MESSAGE):
            error_msg = error_details_dict[ErrorCodes.ERROR_MESSAGE]
            if kwargs is not None and len(kwargs) > 0 and args is not None and len(args) > 0:
                error_msg = error_msg.format(*args, **kwargs)
            elif kwargs is not None and len(kwargs) > 0:
                error_msg = error_msg.format(**kwargs)
            elif args is not None and len(args) > 0:
                error_msg = error_msg.format(*args)

            error_details_dict[ErrorCodes.ERROR_MESSAGE] = error_msg



    def __read_from_file(self, filePath):
        """
        This method reads the error codes from the passed error codes definition file
        :rtype: dict
        """
        logger.info('Reading error code definition file - %s' % filePath)
        try:
            with open(filePath, 'r') as f:
                text = f.read()
                data = json.loads(text)
                return data

        except Exception as e:
            raise RuntimeError("Error while loading error codes definition file [" + filePath + "] - " + e.__str__())



    def __append_to_error_codes(self, ms_errors_filePath):
        '''
        This method appends the additional error codes from the passed file to the self.error_codes dict
        :param ms_errors_filePath:
        :return:
        '''
        data = self.__read_from_file(ms_errors_filePath)
        if data is not None:
            keys = data.keys()
            if len(keys) > 0:
                dict_name = keys[0]
                dict_val = data.get(dict_name)
                self.__error_codes[dict_name] = dict_val
                logger.info('Added dict [%s] to error_codes'% dict_name)

        else:
            logger.info('data is None from file - %s' % ms_errors_filePath)



    def get_error_json(self, exceptionObj):

        '''
        This method returns a json representation of the error / exception object
        :param exceptionObj: The exception object for which the json representation is required
        :return: JSON string representation of the exception object
        :rtype: str
        '''

        error_json_dict = self.__get_error_json_dict(exceptionObj)
        #Convert to json string now
        jsonStr = json.dumps(error_json_dict, indent=5)

        return jsonStr



    def __get_error_json_dict(self, exceptionObj):

        '''
        This method returns a json representation of the error / exception object
        :param exceptionObj: The exception object for which the json representation is required
        :return: JSON (dict) representation of the exception object
        '''

        error_json = dict()

        if exceptionObj is not None:
            if hasattr(exceptionObj, ErrorCodes.ERROR_CODE):
                error_code = getattr(exceptionObj, ErrorCodes.ERROR_CODE)
                error_json[ErrorCodes.ERROR_CODE] = error_code

                error_code_details = self.__get_error_code_details_formatted(exceptionObj, str(error_code))

                #add defaults from the error definition
                if error_code_details is not None:
                    for attribute in [ErrorCodes.STATUS_CODE, ErrorCodes.ERROR_TAG, ErrorCodes.ERROR_MESSAGE, ErrorCodes.ERROR_DIAG]:
                        if error_code_details.has_key(attribute):
                            error_json[attribute] = error_code_details.get(attribute)
                else:
                    logger.warning('No details found for error_code ['+ str(error_code) + ']. Possibly invalid error_code in exception.')
                    #return empty dict in this case
                    return dict()

            #override defaults from exceptionObj
            for attribute in [ErrorCodes.STATUS_CODE, ErrorCodes.ERROR_TAG, ErrorCodes.ERROR_APP_MESSAGE, ErrorCodes.ERROR_MESSAGE, ErrorCodes.ERROR_DIAG]:
                if hasattr(exceptionObj, attribute):
                    val = getattr(exceptionObj, attribute)
                    if isinstance(val, int):
                        error_json[attribute] = str(val)
                    else:
                        strval = str(val)
                        if isNotBlank(strval):
                            error_json[attribute] = strval

            #override error_app_message with content
            if hasattr(exceptionObj, ErrorCodes.CONTENT):
                content = getattr(exceptionObj, ErrorCodes.CONTENT)
                error_json[ErrorCodes.ERROR_APP_MESSAGE] = content

            #still no error_app_message, then set it to exception string
            if not error_json.has_key(ErrorCodes.ERROR_APP_MESSAGE):
                ex_msg = str(exceptionObj)
                #truncate very long strings
                if len(ex_msg) > 1000:
                    ex_msg = ex_msg[0:1000]
                error_json[ErrorCodes.ERROR_APP_MESSAGE] = ex_msg

            if hasattr(exceptionObj, ErrorCodes.CAUSE):
                cause = getattr(exceptionObj, ErrorCodes.CAUSE)
                #check for cause to be an exception type and then only proceed further with nesting the error json.
                if cause is not None and isinstance(cause, Exception):
                    error_json[ErrorCodes.CAUSE] = self.__get_error_json_dict(cause)

        return error_json


    def __get_error_code_details_formatted(self, exceptionObj, error_code):
        error_code_details = None
        if hasattr(exceptionObj, ErrorCodes.FORMAT_ARGS) and hasattr(exceptionObj, ErrorCodes.FORMAT_KWARGS):
            f_args = getattr(exceptionObj, ErrorCodes.FORMAT_ARGS)
            f_kwargs = getattr(exceptionObj, ErrorCodes.FORMAT_KWARGS)
            error_code_details = self.get_error_code_details(error_code, *f_args, **f_kwargs)
        elif hasattr(exceptionObj, ErrorCodes.FORMAT_KWARGS):
            f_kwargs = getattr(exceptionObj, ErrorCodes.FORMAT_KWARGS)
            error_code_details = self.get_error_code_details(error_code, **f_kwargs)
        elif hasattr(exceptionObj, ErrorCodes.FORMAT_ARGS):
            f_args = getattr(exceptionObj, ErrorCodes.FORMAT_ARGS)
            error_code_details = self.get_error_code_details(error_code, *f_args)
        else:
            error_code_details = self.get_error_code_details(error_code)
        return error_code_details

#end class ErrorCodes


class CommonException(Exception):
    '''
        This class represents a generic exception which can be used for all purposes. This exception class can be used as
        a wrapper exception to encapsulate an error-code and can be converted into a json representaion which will
        contain error-code attributes which can provide detailed information about an exception instance.

        An error code definition can have an error_message defined as a formatted string with place holders that can be
        dynamically populated. An object of CommonException can then be instantiated along with the placeholder arguments
        passed into the constructor. The placeholder arguments can be positional arguments or keyword arguments or a
        mix of both depending upon the formatted string in the error_message of the error_code definition.
    '''

    def __init__(self, error_code, error_app_message=None, *args, **kwargs):
        self.error_code = error_code
        if (error_app_message is not None):
            self.error_app_message = error_app_message
        if len(args) > 0:
            self.format_args = args
        if len(kwargs) > 0:
            self.format_kwargs = kwargs

# end class CommonException


