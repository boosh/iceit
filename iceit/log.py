import logging
import os

from .exceptions import IceItException

LOG_LEVEL = 'ICEIT_LOG_LEVEL'


def get_logger(name):
    """
    Set up a logger. The log level can be set by setting an environment
    variable called ICEIT_LOG_LEVEL to a valid log level, or NONE to disable
    all logging output.

    string name: The name of the logger. Set this to __name__ in the calling
    code (unless you have a VERY good reason not to)

    returns: A Logger instance
    """
    log = logging.getLogger(name)

    logging.basicConfig(format="%(asctime)s %(pathname)s %(name)s (%(lineno)d) %(levelname)s: %(message)s")

    try:
        log_level = getattr(logging, os.environ[LOG_LEVEL].upper())
    except AttributeError:
        log_level = os.environ[LOG_LEVEL].upper()
        if log_level != 'NONE':
            raise IceItException("'%s' is not a valid log level. Use a "
                                   "valid log level or 'NONE' to disable "
                                   "logging output." % log_level)
    except KeyError:
        log_level = logging.DEBUG

    if log_level == 'NONE':
        log.disabled = True
    else:
        log.setLevel(log_level)

    log.debug("Logger configured for %s" % name)

    return log
