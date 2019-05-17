"""
This module contains the blacklist manager class object.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from .blacklist_manager import JWTBlacklistManager
from .exceptions import BlacklistManagerError, BlacklistTokenNotFound

############################
# BLACKLIST MANAGER OBJECT #
############################

jwt_blacklist_manager = JWTBlacklistManager()
