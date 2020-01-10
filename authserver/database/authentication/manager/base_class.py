"""
This module contains the database manager base class.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import Flask
from parse import parse
from sqlalchemy import exc
from sqlalchemy.orm import Query, Session, scoped_session

from .exceptions import (
    UniqueConstraintError, DBInternalError
)
from ..definitions import db_conn as db


class DBManagerBase(object):
    """
    This class implements the database manager base class
    """

    def __init__(self, app: Flask = None, autocommit: bool = True, override_session: scoped_session = None):
        self.app = app
        self.autocommit = autocommit
        self._initial_autocommit = autocommit
        self.db_session = db.session if override_session is None else override_session
        self._session_object = None

    def init_app(self, app: Flask):
        """
        Links the Flask application instance with this object

        :param app: Flask application object
        """
        self.app = app

    def init_static_values(self):
        """
        Save in memory the database static values
        """
        pass

    @staticmethod
    def _detect_unique_constraint_error_column(e):
        """
        Parses the SQLAlchemy error message to extract which column violated the Unique
        constraint.

        :param e: The SQLAlchemy `IntegityError` exception object.
        :return: The column where the error happened or None if can't parse the data.
        """
        parsed_data = parse('duplicate key value violates unique constraint "{constraint}"\n'
                            'DETAIL:  Key ({field})=({input}) already exists.\n', str(e.orig))
        if parsed_data:
            return parsed_data["field"]
        else:
            return None

    def _set_session_object(self):
        """
        Sets the session object that the manager will use to make queries from
        the scoped session object.
        """
        self._session_object = self.db_session()

    def update_session(self, session: scoped_session):
        """
        Replace the SQLAlchemy scoped session object used by the DBManager.

        :param session: A SQLAlchemy scoped_session object
        """
        self.db_session = session
        self._set_session_object()

    def commit_changes(self):
        """
        Commit the changes made to the SQLAlchemy model objects to the database.
        """
        # Update the database with error catching
        try:
            self.db_session.commit()
            self.db_session.flush()
        except exc.IntegrityError as e:
            self.db_session.rollback()
            self.app.logger.error("Database integrity error detected. Rolling back. Details: %s", str(e))
            unique_duplicated_column = self._detect_unique_constraint_error_column(e)
            if unique_duplicated_column:
                raise UniqueConstraintError(str(e), column=unique_duplicated_column)
            else:
                raise DBInternalError(str(e))
        except exc.SQLAlchemyError as e:
            self.db_session.rollback()
            self.app.logger.error("Can't update the database. Rolling back. Details: %s", str(e))
            raise DBInternalError("Can't update the database")
        self.app.logger.debug("Changes successfully committed to the database")

    def add_row(self, row_obj):
        """
        Add a new row to the database from a SQLAlchemy model object.

        :param row_obj: SQLAlchemy database model object
        """
        self.db_session.add(row_obj)
        self.commit_changes()
        self.db_session.refresh(row_obj)
        self.app.logger.info("Object '%s' added to the database", str(row_obj))

    def del_row(self, row_obj):
        """
        Delete an existing from the database from a SQLAlchemy model object.

        :param row_obj: SQLAlchemy database model object
        """
        object_session = Session.object_session(row_obj)
        if object_session != self.db_session:
            object_session.expunge(row_obj)
            self.db_session.add(row_obj)

        self.db_session.delete(row_obj)
        self.app.logger.info("Object '%s' deleted from the database", str(row_obj))

    def execute_query(self, query: Query, use_list=True, count=False):
        """
        Executes a new database query and return its result.

        :param query: The SQLAlchemy query object
        :param use_list: Flag to specify if want the returned elements as a list or not
        :param count: Flag to specify if we only want to count the rows that match the query
        :return: The query result
        """
        try:
            if self._session_object is not None:
                query = query.with_session(self._session_object)
            if count:
                return query.count()
            elif use_list:
                return query.all()
            else:
                return query.first()
        except exc.SQLAlchemyError as e:
            self.app.logger.error("Can't execute the requested query. Details: %s", str(e))
            raise DBInternalError("Can't execute the requested query")

    def execute_update(self, query: Query, values: dict):
        """
        Executes a new database update query and return its result.

        :param query: The SQLAlchemy query object
        :param values: The values to update
        :return: The query result
        """
        try:
            if self._session_object is not None:
                query = query.with_session(self._session_object)
            result = query.update(values)
        except exc.SQLAlchemyError as e:
            self.app.logger.error("Can't execute the requested update query. Details: %s", str(e))
            raise DBInternalError("Can't execute the requested update query")

        self.app.logger.debug("Updates successfully committed to the database")
        return result
