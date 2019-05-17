"""
This module contains the database manager base class.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import current_app
from sqlalchemy import exc
from sqlalchemy.orm import Query, scoped_session

from .exceptions import (
    UniqueConstraintError, DBInternalError
)
from ..definitions import db_conn as db


class DBManagerBase(object):
    """
    This class implements the database manager base class
    """

    def __init__(self, autocommit: bool = True, override_session: scoped_session = None):
        self.autocommit = autocommit
        self._initial_autocommit = autocommit
        self.db_session = db.session if override_session is None else override_session
        self._session_object = None
        self._unique_constraint_failed_msg = "UNIQUE constraint failed:"

    def init_static_values(self):
        pass

    def _set_autocommit(self, value: bool):
        self.autocommit = value

    def _restore_autocommit(self):
        self.autocommit = self._initial_autocommit

    def update_session(self, session: scoped_session):
        self.db_session = session
        self.set_session_object()

    def set_session_object(self):
        self._session_object = self.db_session()

    def commit_changes(self):
        # Update the database with error catching
        try:
            self.db_session.commit()
        except exc.IntegrityError as e:
            self.db_session.rollback()
            current_app.logger.error("Database integrity error detected. Rolling back. Details: %s", str(e))
            if self._unique_constraint_failed_msg in str(e):
                s = str(e)
                column = s[25+len("UNIQUE constraint failed:"):s.find("\n")].strip().split('.')[1]
                raise UniqueConstraintError(str(e))
            else:
                raise DBInternalError(str(e))
        except exc.SQLAlchemyError as e:
            self.db_session.rollback()
            current_app.logger.error("Can't update the database. Rolling back. Details: %s", str(e))
            raise DBInternalError("Can't update the database")
        current_app.logger.debug("Changes successfully committed to the database")

    def add_row(self, row_obj):
        self.db_session.add(row_obj)
        current_app.logger.info("Object '%s' added to the database", str(row_obj))

    def del_row(self, row_obj):
        self.db_session.delete(row_obj)
        current_app.logger.info("Object '%s' deleted from the database", str(row_obj))

    def execute_query(self, query: Query, use_list=True):
        try:
            if self._session_object is not None:
                query = query.with_session(self._session_object)
            if use_list:
                return query.all()
            else:
                return query.first()
        except exc.SQLAlchemyError as e:
            current_app.logger.error("Can't execute the requested query. Details: %s", str(e))
            raise DBInternalError("Can't execute the requested query")

    def execute_update(self, query: Query, values: dict):
        try:
            if self._session_object is not None:
                query = query.with_session(self._session_object)
            result = query.update(values)
        except exc.SQLAlchemyError as e:
            current_app.logger.error("Can't execute the requested update query. Details: %s", str(e))
            raise DBInternalError("Can't execute the requested update query")

        current_app.logger.debug("Updates successfully committed to the database")
        return result
