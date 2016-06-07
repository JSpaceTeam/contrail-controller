
import unittest
import tempfile
import json
import os

from cfgm_common.errorcodes import ErrorCodes, CommonException

common_error_codes_json = '''
{
            "common_error_codes" : {

                "70001" : {
			            "status_code" : "404",
                        "error_tag" : "Not Found",
                        "error_message" : "The requested {resourceType} with id {resourceID} was not found. ",
                        "error_diag" : "This error occurs when a resource is not found. "
                },
                "70002" : {
			            "status_code" : "404",
                        "error_tag" : "Not Found",
                        "error_message" : "The requested {} with id {} was not found. ",
                        "error_diag" : "This error occurs when a resource is not found. "
                },
                "70003" : {
			            "status_code" : "400",
                        "error_tag" : "Bad Request",
                        "error_message" : "The requested {} with id {} was not found. Please provide a valid {resourceType} id",
                        "error_diag" : "This error occurs when a resource is not found. "
                },
                "70004" : {
			            "status_code" : "500",
                        "error_tag" : "Internal Server Error",
                        "error_message" : "This is a hard coded error message without any placeholders",
                        "error_diag" : "This error occurs when a resource is not found. "
                },
                "70005" : {
			            "status_code" : "403",
                        "error_tag" : "Forbidden",
                        "error_message" : "The request to {} resource with id {} cannot be processed. Please provide a valid {resourceType} id with valid {}",
                        "error_diag" : "This error occurs when there is no permission. "
                },
                "100001" : null
            }
}
'''

ms_error_codes_json = '''
{
            "ms_error_codes" : {

            }
}
'''

invalid_json = '''
{
            "common_error_codes" : {

                "70011" : {
			            "status_code" : "404",
                        "error_tag" : "Not Found",
                        "error_message : "The requested {resourceType} with id {resourceID} was not found. ",
                        "error_diag" : "This error occurs when a resource is not found. "
                }
            }
}
'''


class ErrorCodesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # create the json files for error codes
        cls.common_error_codes_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False)
        cls.ms_error_codes_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False)
        cls.invalid_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False)
        cls.blank_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False)

        with open(cls.common_error_codes_json_file.name, 'wt') as f:
            f.write(common_error_codes_json)

        with open(cls.ms_error_codes_json_file.name, 'wt') as f:
            f.write(ms_error_codes_json)

        with open(cls.invalid_json_file.name, 'wt') as f:
            f.write(invalid_json)

        with open(cls.blank_file.name, 'wt') as f:
            f.write('null')



    @classmethod
    def tearDownClass(cls):
        if cls.common_error_codes_json_file is not None and os.path.exists(cls.common_error_codes_json_file.name):
            os.remove(cls.common_error_codes_json_file.name)

        if cls.ms_error_codes_json_file is not None and os.path.exists(cls.ms_error_codes_json_file.name):
            os.remove(cls.ms_error_codes_json_file.name)

        if cls.invalid_json_file is not None and os.path.exists(cls.invalid_json_file.name):
            os.remove(cls.invalid_json_file.name)

        if cls.blank_file is not None and os.path.exists(cls.blank_file.name):
            os.remove(cls.blank_file.name)


    def setUp(self):
        #print "------------------------------------------ Set Up ------------------------------------------------------"
        self.common_error_codes_json_file_path = self.__class__.common_error_codes_json_file.name
        self.ms_error_codes_json_file_path = self.__class__.ms_error_codes_json_file.name
        self.invalid_json_file_path = self.__class__.invalid_json_file.name
        self.blank_file_path = self.__class__.blank_file.name


    def tearDown(self):
        #print "------------------------------------------ Tear Down ----------------------------------------------------"
        pass


    def is_valid_json(self, json_string):
        try:
            json_object = json.loads(json_string)
        except ValueError, e:
            return False
        return True


    def get_dict_from_json(self, json_string):
        json_object = None
        try:
            json_object = json.loads(json_string)
        except ValueError, e:
            pass

        return json_object


    def test_create_valid_ErrorCodes(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        self.assertIsNotNone(error_codes)
        self.assertIsInstance(error_codes, ErrorCodes)


    def test_create_ErrorCodes_without_ms_err_codes(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path)
        self.assertIsNotNone(error_codes)
        self.assertIsInstance(error_codes, ErrorCodes)


    def test_create_ErrorCodes_with_invalid_err_codes(self):
        with self.assertRaises(RuntimeError):
            error_codes = ErrorCodes(self.invalid_json_file_path)


    def test_create_ErrorCodes_with_ms_err_code_file_with_null_data(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.blank_file_path)
        self.assertIsNotNone(error_codes)
        self.assertIsInstance(error_codes, ErrorCodes)


    def test_get_Valid_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70004')
        self.assertIsNotNone(error_code_details, 'error_code_details should not be None')
        self.assertIsInstance(error_code_details, dict)


    def test_get_Correct_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70004')
        expected_val_dict = {
            "status_code" : "500",
            "error_tag" : "Internal Server Error",
            "error_message" : "This is a hard coded error message without any placeholders",
            "error_diag" : "This error occurs when a resource is not found. "
        }
        self.assertDictEqual(error_code_details, expected_val_dict)


    def test_get_None_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details(None)
        self.assertIsNone(error_code_details, 'error_code_details should be None for None argument')


    def test_get_Blank_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('')
        self.assertIsNone(error_code_details, 'error_code_details should be None for blank argument')


    def test_get_Blank2_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('   ')
        self.assertIsNone(error_code_details, 'error_code_details should be None for blank space argument')


    def test_get_Non_Existent_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('90000')
        self.assertIsNone(error_code_details, 'error_code_details should be None for non existent error_code')


    def test_get_Garbage_error_code_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details(' ye707*% (09 ')
        self.assertIsNone(error_code_details, 'error_code_details should be None for garbage error_code')


    def test_get_error_code_details_formatted_with_kwargs(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70001', resourceType="Device", resourceID="Dev001")
        expected_formatted_val_dict = {
            "status_code" : "404",
            "error_tag" : "Not Found",
            "error_message" : "The requested Device with id Dev001 was not found. ",
            "error_diag" : "This error occurs when a resource is not found. "
        }
        self.assertDictEqual(error_code_details, expected_formatted_val_dict)


    def test_get_error_code_details_formatted_test_original_formatter_is_not_modified(self):
        '''
        This test checks whether the original formatter string with placeholder in the dict does not get
        modified with a previous formatting
        :return:
        '''
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details1 = error_codes.get_error_code_details('70001', resourceType="Device", resourceID="Dev001")
        error_code_details2 = error_codes.get_error_code_details('70001', resourceType="Box", resourceID="Box001")
        expected_formatted_val_dict = {
            "status_code" : "404",
            "error_tag" : "Not Found",
            "error_message" : "The requested Box with id Box001 was not found. ",
            "error_diag" : "This error occurs when a resource is not found. "
        }
        self.assertDictEqual(error_code_details2, expected_formatted_val_dict)


    def test_get_error_code_details_formatted_with_args(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70002', 'Device', 'Dev001')
        expected_formatted_val_dict = {
            "status_code" : "404",
            "error_tag" : "Not Found",
            "error_message" : "The requested Device with id Dev001 was not found. ",
            "error_diag" : "This error occurs when a resource is not found. "
        }
        self.assertDictEqual(error_code_details, expected_formatted_val_dict)


    def test_get_error_code_details_formatted_valid_with_both_args_and_kwargs(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70003', 'Device', 'Dev001', resourceType="Device")
        expected_formatted_val_dict = {
            "status_code" : "400",
            "error_tag" : "Bad Request",
            "error_message" : "The requested Device with id Dev001 was not found. Please provide a valid Device id",
            "error_diag" : "This error occurs when a resource is not found. "
        }
        self.assertDictEqual(error_code_details, expected_formatted_val_dict)


    def test_get_error_code_details_formatted_valid_with_mixed_args_and_kwargs(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        error_code_details = error_codes.get_error_code_details('70005', 'create', 'Dev001', 'credentials', resourceType="Device")
        expected_formatted_val_dict = {
            "status_code" : "403",
            "error_tag" : "Forbidden",
            "error_message" : "The request to create resource with id Dev001 cannot be processed. Please provide a valid Device id with valid credentials",
            "error_diag" : "This error occurs when there is no permission. "
        }
        self.assertDictEqual(error_code_details, expected_formatted_val_dict)


    def test_get_error_code_details_formatted_with_invalid_number_of_args(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        with self.assertRaises(IndexError):
            error_code_details = error_codes.get_error_code_details('70002', 'Device')


    def test_get_error_code_details_formatted_with_invalid_number_of_kwargs(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        with self.assertRaises(KeyError):
            error_code_details = error_codes.get_error_code_details('70001', resourceID="Dev001")


    def test_get_error_json_from_exception_with_valid_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        someException = Exception()
        setattr(someException, 'error_code', '70004')
        error_json_str = error_codes.get_error_json(someException)
        self.assertIsInstance(error_json_str, str)
        self.assertTrue(self.is_valid_json(error_json_str))


    def test_get_error_json_from_exception_with_invalid_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        someException = Exception()
        setattr(someException, 'error_code', '90004')
        error_json_str = error_codes.get_error_json(someException)
        self.assertIsInstance(error_json_str, str)
        self.assertTrue(self.is_valid_json(error_json_str))
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')


    def test_get_error_json_from_exception_with_valid_error_code_with_formatted_message(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        someException = Exception()
        setattr(someException, 'error_code', '70003')
        f_args = ('box', 'box001')
        f_kwargs = {'resourceType':'box'}
        setattr(someException, 'format_args', f_args)
        setattr(someException, 'format_kwargs', f_kwargs)
        error_json_str = error_codes.get_error_json(someException)

        expected_formatted_val_dict = {
             "status_code": "400",
             "error_tag": "Bad Request",
             "error_message": "The requested box with id box001 was not found. Please provide a valid box id",
             "error_app_message": "",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70003"
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_exception_with_valid_error_code_with_cause_with_formatted_message(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        mainException = Exception()
        setattr(mainException, 'error_code', '70003')
        f_args = ('box-part', 'box-part1001')
        f_kwargs = {'resourceType':'box'}
        setattr(mainException, 'format_args', f_args)
        setattr(mainException, 'format_kwargs', f_kwargs)

        causeException = Exception()
        setattr(causeException, 'error_code', '70002')
        f_args = ('box', 'box001')
        setattr(causeException, 'format_args', f_args)

        #set the cause in the mainException
        setattr(mainException, 'cause', causeException)

        error_json_str = error_codes.get_error_json(mainException)
        expected_formatted_val_dict = {
             "status_code": "400",
             "error_tag": "Bad Request",
             "error_message": "The requested box-part with id box-part1001 was not found. Please provide a valid box id",
             "error_app_message": "",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70003",
             "cause": {
                      "status_code": "404",
                      "error_tag": "Not Found",
                      "error_message": "The requested box with id box001 was not found. ",
                      "error_app_message": "",
                      "error_diag": "This error occurs when a resource is not found. ",
                      "error_code": "70002"
             }
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_exception_with_valid_error_code_override_status_code_and_content(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        someException = Exception()
        setattr(someException, 'error_code', '70004')
        setattr(someException, 'status_code', 501)
        setattr(someException, 'content', 'This is some content')
        error_json_str = error_codes.get_error_json(someException)
        expected_val_dict = {
             "status_code": "501",
             "error_tag": "Internal Server Error",
             "error_message": "This is a hard coded error message without any placeholders",
             "error_app_message": "This is some content",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70004"
        }
        self.assertDictEqual(expected_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_valid_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70004')
        error_json_str = error_codes.get_error_json(commonException)
        self.assertIsInstance(error_json_str, str)
        self.assertTrue(self.is_valid_json(error_json_str))


    def test_get_error_json_from_CommonException_with_invalid_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('90004')
        error_json_str = error_codes.get_error_json(commonException)
        self.assertIsInstance(error_json_str, str)
        self.assertTrue(self.is_valid_json(error_json_str))
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')


    def test_get_error_json_from_CommonException_with_valid_error_code_with_kwargs(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70001', resourceType="Group", resourceID="GRP001")
        error_json_str = error_codes.get_error_json(commonException)
        expected_formatted_val_dict = {
             "status_code": "404",
             "error_tag": "Not Found",
             "error_message": "The requested Group with id GRP001 was not found. ",
             "error_app_message": "",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70001"
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_valid_error_code_with_mixed_args(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70003', None, 'box', 'box001', resourceType='box')
        error_json_str = error_codes.get_error_json(commonException)
        expected_formatted_val_dict = {
             "status_code": "400",
             "error_tag": "Bad Request",
             "error_message": "The requested box with id box001 was not found. Please provide a valid box id",
             "error_app_message": "",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70003"
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_valid_error_code_with_cause_with_formatted_message(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        mainException = CommonException('70003', None, 'box-part', 'box-part1001', resourceType='box')
        causeException = CommonException('70002', None, 'box', 'box001')

        #set the cause in the mainException
        setattr(mainException, 'cause', causeException)

        error_json_str = error_codes.get_error_json(mainException)
        expected_formatted_val_dict = {
             "status_code": "400",
             "error_tag": "Bad Request",
             "error_message": "The requested box-part with id box-part1001 was not found. Please provide a valid box id",
             "error_app_message": "",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70003",
             "cause": {
                      "status_code": "404",
                      "error_tag": "Not Found",
                      "error_message": "The requested box with id box001 was not found. ",
                      "error_app_message": "",
                      "error_diag": "This error occurs when a resource is not found. ",
                      "error_code": "70002"
             }
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_valid_error_code_override_status_code_and_content(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70004')
        setattr(commonException, 'status_code', 501)
        setattr(commonException, 'content', 'This is some content')
        error_json_str = error_codes.get_error_json(commonException)
        expected_val_dict = {
             "status_code": "501",
             "error_tag": "Internal Server Error",
             "error_message": "This is a hard coded error message without any placeholders",
             "error_app_message": "This is some content",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70004"
        }
        self.assertDictEqual(expected_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_invalid_args_list(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70002', 'box', 'box001')
        with self.assertRaises(IndexError):
            error_json_str = error_codes.get_error_json(commonException)


    def test_get_error_json_from_CommonException_with_errorcode_having_null_details(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('100001', None, 'box', 'box001')
        error_json_str = error_codes.get_error_json(commonException)
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')


    def test_get_error_json_from_CommonException_with_nonexistent_errorcode(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('90007', None, 'box', 'box001')
        error_json_str = error_codes.get_error_json(commonException)
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')


    def test_get_error_json_from_CommonException_with_app_message(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException('70003', 'This is context message', 'box', 'box001', resourceType='box')
        error_json_str = error_codes.get_error_json(commonException)
        expected_formatted_val_dict = {
             "status_code": "400",
             "error_tag": "Bad Request",
             "error_message": "The requested box with id box001 was not found. Please provide a valid box id",
             "error_app_message": "This is context message",
             "error_diag": "This error occurs when a resource is not found. ",
             "error_code": "70003"
        }
        self.assertDictEqual(expected_formatted_val_dict, self.get_dict_from_json(error_json_str))


    def test_get_error_json_from_CommonException_with_None_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException(None)
        error_json_str = error_codes.get_error_json(commonException)
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')


    def test_get_error_json_from_CommonException_with_GarbageObj_error_code(self):
        error_codes = ErrorCodes(self.common_error_codes_json_file_path, self.ms_error_codes_json_file_path)
        commonException = CommonException(None)
        commonException.error_code = Exception()
        error_json_str = error_codes.get_error_json(commonException)
        empty = dict()
        self.assertDictEqual(empty, self.get_dict_from_json(error_json_str), 'must return empty json')

