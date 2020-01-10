"""
This module contains the blacklist manager exception classes.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


class BlacklistManagerError(Exception):
    """
    Blacklist Manager Exception upper class.
    """
    pass


class BlacklistManagerMissingConfigParams(BlacklistManagerError):
    """
    This exception will be raised at the initialization time when there are missing configuration parameters.
    """
    pass


class BlacklistTokenNotFound(BlacklistManagerError):
    """
    This exception will be raised when a specified token is not found into the Redis shared cache
    """
    pass


class BlacklistInvalidTokenData(BlacklistManagerError):
    """
    This exception will be raised when we try to save a token with invalid data.
    """
    pass


class RedisConnectionError(BlacklistManagerError):
    """
    This exception will be raised when there is a connection error with the Redis server.
    """
    pass
