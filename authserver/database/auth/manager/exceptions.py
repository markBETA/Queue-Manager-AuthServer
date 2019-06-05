"""
This module contains the database manager exception classes.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


class DBManagerError(Exception):
    """
    DB Manager Exception upper class.
    """
    pass


class InvalidParameter(DBManagerError):
    """
    This exception represents an invalid parameter input in one of the manager methods.
    """
    pass


class DBInternalError(DBManagerError):
    """
    This exception will be raised when we are unable to write or read from the database
    """
    pass


class UniqueConstraintError(DBManagerError):
    """
    This exception will be raise when the UNIQUE constraint fails
    """
    def __init__(self, msg, column):
        self.msg = msg
        self.column = column

    def __str__(self):
        return self.msg
