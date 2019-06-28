"""
This module contains the database manager class.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


from sqlalchemy.orm import scoped_session

from .exceptions import (
    DBManagerError, InvalidParameter, DBInternalError, UniqueConstraintError
)
from .printer import DBManagerPrinter
from .users import DBManagerUsers


class DBManager(DBManagerUsers, DBManagerPrinter):
    def __init__(self, autocommit: bool = True, override_session: scoped_session = None):
        super(DBManagerUsers, self).__init__(autocommit, override_session)
        super(DBManagerPrinter, self).__init__(autocommit, override_session)

    def init_static_values(self):
        super(DBManagerUsers, self).init_static_values()
        super(DBManagerPrinter, self).init_static_values()
