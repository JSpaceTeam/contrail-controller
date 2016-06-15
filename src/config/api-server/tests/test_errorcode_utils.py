
import unittest
import tempfile
import os
from contextlib import contextmanager

from oslo_config import cfg
from oslo_config.cfg import ArgsAlreadyParsedError

from cfgm_common.errorcodes import ErrorCodes
from cfgm_common.errorcode_utils import ErrorCodeRepo

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
                }
            }
}
'''

ms_error_codes_json = '''
{
            "ms_error_codes" : {

            }
}
'''

@contextmanager
def ignore_already_parsed_error():
    try:
        yield
    except ArgsAlreadyParsedError:
        pass


class ErrorCodeUtilsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # create the json files for error codes
        cls.common_error_codes_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False, suffix='_en_US.json')
        cls.ms_error_codes_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False, suffix='_en_US.json')
        cls.invalid_json_file = tempfile.NamedTemporaryFile(mode='w+t', delete=False)

        with open(cls.common_error_codes_json_file.name, 'wt') as f:
            f.write(common_error_codes_json)

        with open(cls.ms_error_codes_json_file.name, 'wt') as f:
            f.write(ms_error_codes_json)

        cls.common_error_codes_json_path_tuple = os.path.split(cls.common_error_codes_json_file.name)
        cls.ms_error_codes_json_path_tuple = os.path.split(cls.ms_error_codes_json_file.name)

        default_conf = [
            cfg.StrOpt(name='default_locale', default='en_US'),
            cfg.BoolOpt(name='use_locales', default=True)
        ]

        errorcodes = cfg.OptGroup(name='ERROR_CODES')
        cfg.CONF.register_group(errorcodes)

        errorcodes_args = [
            cfg.StrOpt(name='common_error_codes_dir', default=cls.common_error_codes_json_path_tuple[0]),
            cfg.StrOpt(name='ms_error_codes_dir', default=cls.ms_error_codes_json_path_tuple[0]),
            cfg.StrOpt(name='common_error_codes_file', default=cls.common_error_codes_json_path_tuple[1].replace('en_US', '{locale}')),
            cfg.StrOpt(name='ms_error_codes_file', default=cls.ms_error_codes_json_path_tuple[1].replace('en_US', '{locale}'))
        ]


        for conf in default_conf:
            with ignore_already_parsed_error():
                cfg.CONF.register_cli_opt(conf)

        for err_conf in errorcodes_args:
            with ignore_already_parsed_error():
                cfg.CONF.register_cli_opt(err_conf, group=errorcodes)

        cls.conf = cfg.CONF


    @classmethod
    def tearDownClass(cls):
        if cls.common_error_codes_json_file is not None and os.path.exists(cls.common_error_codes_json_file.name):
            os.remove(cls.common_error_codes_json_file.name)

        if cls.ms_error_codes_json_file is not None and os.path.exists(cls.ms_error_codes_json_file.name):
            os.remove(cls.ms_error_codes_json_file.name)



    def setUp(self):
        #print "------------------------------------------ Set Up ------------------------------------------------------"
        pass


    def tearDown(self):
        #print "------------------------------------------ Tear Down ----------------------------------------------------"
        pass

    def test_1_create_valid_ErrorCodeRepo_and_ErrorCodes(self):
        error_codes_repo = ErrorCodeRepo(self.__class__.conf)
        self.assertIsNotNone(error_codes_repo)
        self.assertIsInstance(error_codes_repo, ErrorCodeRepo)

        error_codes = error_codes_repo.getErrorCodes()
        self.assertIsNotNone(error_codes)
        self.assertIsInstance(error_codes, ErrorCodes)


    def test_2_reuse_existing_ErrorCodeRepo_and_ErrorCodes(self):
        error_codes_repo_ORIG = ErrorCodeRepo(self.__class__.conf)
        error_codes_repo_REUSED = ErrorCodeRepo.getInstance()

        self.assertIsNotNone(error_codes_repo_ORIG)
        self.assertIsNotNone(error_codes_repo_REUSED)
        self.assertIs(error_codes_repo_REUSED, error_codes_repo_ORIG, "error code repo object must be reused and not created again")

        error_codes_ORIG = error_codes_repo_ORIG.getErrorCodes()
        error_codes_REUSED = error_codes_repo_REUSED.getErrorCodes()
        self.assertIs(error_codes_REUSED, error_codes_ORIG, "error_code from repo must be same")


    def test_3_create_ErrorCodeRepo_with_invalid_conf_input(self):
        with self.assertRaises(ValueError):
            error_codes_repo = ErrorCodeRepo(dict())




