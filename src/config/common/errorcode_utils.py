import cfgm_common.utils
from cfgm_common.errorcodes import ErrorCodes
import logging
import locale
from oslo_config.cfg import ConfigOpts

logger = logging.getLogger(__name__)


class Singleton(object):
    """ A Pythonic Singleton for ErrorCodeRepo """

    def __new__(cls, *args, **kwargs):
        if '_inst' not in vars(cls):
            cls._inst = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._inst


class ErrorCodeRepo(Singleton):

    def __init__(self, conf):
        if (conf is None or not isinstance(conf, ConfigOpts)):
            raise ValueError("Illegal Argument: conf must be a valid instance of ConfigOpts")

        self.__errorCodes = self.__load_error_codes(conf)

    @classmethod
    def getInstance(cls):
        return cls._inst

    def getErrorCodes(self):
        return self.__errorCodes


    def __load_error_codes(self, CONF):
        try:
            common_errcodes_dir = CONF.ERROR_CODES.common_error_codes_dir
            ms_errcodes_dir = CONF.ERROR_CODES.ms_error_codes_dir
            if not common_errcodes_dir.endswith("/"):
                common_errcodes_dir = common_errcodes_dir + "/"
            if not ms_errcodes_dir.endswith("/"):
                ms_errcodes_dir = ms_errcodes_dir + "/"

            common_errcodes_file = CONF.ERROR_CODES.common_error_codes_file
            ms_errcodes_file = CONF.ERROR_CODES.ms_error_codes_file
            locale_name = self.__get_locale_name(CONF)

            common_errcodes_file_name = self.__get_error_code_locale_file_name(common_errcodes_file, locale_name)
            ms_errcodes_file_name = self.__get_error_code_locale_file_name(ms_errcodes_file, locale_name)

            err_codes = ErrorCodes(common_errcodes_dir + common_errcodes_file_name, ms_errcodes_dir + ms_errcodes_file_name)
            return err_codes

        except Exception as e:  # pragma: no cover
            err_msg = cfgm_common.utils.detailed_traceback()
            logger.exception("Exception in error_codes loading: %s" % (err_msg))
            raise

    #end _load_error_codes

    def __get_locale_name(self, CONF):
        use_localization = CONF.use_locales
        locale_name = CONF.default_locale
        if use_localization:
            locale_tup = locale.getlocale(locale.LC_ALL)
            if locale_tup is not None and locale_tup[0] is not None:        # pragma: no cover
                locale_name = locale_tup[0]
            else:
                locale_tup = locale.getdefaultlocale()
                if locale_tup[0] is not None:                           # pragma: no cover
                    locale_name = locale_tup[0]

        return locale_name

    #end _get_locale_name

    def __get_error_code_locale_file_name(self, errcodes_file, locale_name):
        errcodes_file_name = errcodes_file
        try:
            if errcodes_file is not None and locale_name is not None:
                errcodes_file_name = errcodes_file.format(locale=locale_name)
        except Exception as e:      # pragma: no cover
            err_msg = cfgm_common.utils.detailed_traceback()
            logger.error("Exception in creating error code filename with locale: %s" % (err_msg))
            raise

        return errcodes_file_name
    #end _get_error_code_locale_file_name