# Base constants

# DayMiner (ah-ah-ah), fighter of the...
USER_AGENT = "NightMiner"
VERSION = [0, 1]

# Which algorithm for proof-of-work to use
ALGORITHM_SCRYPT = 'scrypt'
ALGORITHM_SHA256D = 'sha256d'

ALGORITHMS = [ALGORITHM_SCRYPT, ALGORITHM_SHA256D]

# Verbosity and log level
QUIET = False
DEBUG = False
DEBUG_PROTOCOL = False

LEVEL_PROTOCOL = 'protocol'
LEVEL_INFO = 'info'
LEVEL_DEBUG = 'debug'
LEVEL_ERROR = 'error'

# These control which scrypt implementation to use
SCRYPT_LIBRARY_AUTO = 'auto'
SCRYPT_LIBRARY_LTC = 'ltc_scrypt (https://github.com/forrestv/p2pool)'
SCRYPT_LIBRARY_SCRYPT = 'scrypt (https://pypi.python.org/pypi/scrypt/)'
SCRYPT_LIBRARY_PYTHON = 'pure python'
SCRYPT_LIBRARIES = [SCRYPT_LIBRARY_AUTO, SCRYPT_LIBRARY_LTC, SCRYPT_LIBRARY_SCRYPT, SCRYPT_LIBRARY_PYTHON]
