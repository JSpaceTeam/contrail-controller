from cfgm_common import jsonutils as json
import logging

logger = logging.getLogger(__name__)

def isBlank (myString):
    return not (myString and myString.strip())

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

    def __init__(self, common_errors_filePath, ms_errors_filePath=None):
        self.__error_codes = self.__read_from_file(common_errors_filePath)

        if ms_errors_filePath is not None:
            self.__append_to_error_codes(ms_errors_filePath)
        else:
            logger.warning('ms_errors_filePath is None')
            


    def get_error_code_details(self, error_code):
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
                    return error_code_dict[error_code]

        return None


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

                error_code_details = self.get_error_code_details(error_code)
                #add defaults from the error definition
                if error_code_details is not None:
                    for attribute in [ErrorCodes.STATUS_CODE, ErrorCodes.ERROR_TAG, ErrorCodes.ERROR_MESSAGE, ErrorCodes.ERROR_DIAG]:
                        if error_code_details.has_key(attribute):
                            error_json[attribute] = error_code_details.get(attribute)


            #override defaults from exceptionObj
            for attribute in [ErrorCodes.STATUS_CODE, ErrorCodes.ERROR_TAG, ErrorCodes.ERROR_APP_MESSAGE, ErrorCodes.ERROR_MESSAGE, ErrorCodes.ERROR_DIAG]:
                if hasattr(exceptionObj, attribute):
                    val = getattr(exceptionObj, attribute)
                    if isinstance(val, int):
                        error_json[attribute] = str(val)
                        #error_json[attribute] = val
                    elif isinstance(val, str) and isNotBlank(val):
                        error_json[attribute] = val

            #override error_app_message with content
            if hasattr(exceptionObj, ErrorCodes.CONTENT):
                content = getattr(exceptionObj, ErrorCodes.CONTENT)
                error_json[ErrorCodes.ERROR_APP_MESSAGE] = content

            #still no error_app_message, then get exception toString
            if not error_json.has_key(ErrorCodes.ERROR_APP_MESSAGE):
                error_json[ErrorCodes.ERROR_APP_MESSAGE] = str(exceptionObj)

            if hasattr(exceptionObj, ErrorCodes.CAUSE):
                cause = getattr(exceptionObj, ErrorCodes.CAUSE)
                #check for cause to be an exception type and then only proceed further with nesting the error json.
                if cause is not None and isinstance(cause, Exception):
                    error_json[ErrorCodes.CAUSE] = self.__get_error_json_dict(cause)

        return error_json

#end class ErrorCodes



