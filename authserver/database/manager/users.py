"""
This module contains the database manager class for the user operations.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from datetime import datetime

from .base_class import DBManagerBase
from .exceptions import (
    InvalidParameter
)
from ..models import (
    User
)


class DBManagerUsers(DBManagerBase):
    """
    This class implements the database manager class for the user operations
    """
    def insert_user(self, username: str, fullname: str, email: str, password: str, is_admin: bool = False):
        # Check parameter values
        if username == "":
            raise InvalidParameter("The 'username' parameter can't be an empty string")
        if fullname == "":
            raise InvalidParameter("The 'fullname' parameter can't be an empty string")
        if email == "":
            raise InvalidParameter("The 'email' parameter can't be an empty string")
        if password == "":
            raise InvalidParameter("The 'password' parameter can't be an empty string")

        # Create the new user object
        user = User(
            username=username,
            fullname=fullname,
            email=email,
            isAdmin=is_admin,
            registeredOn=datetime.now()
        )

        # Hash the password and save the value
        user.hash_password(password)

        # Add the new row to the database
        self.add_row(user)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return user

    def get_users(self, **kwargs):
        # Create the query object
        query = User.query

        # Filter by the given kwargs
        for key, value in kwargs.items():
            if hasattr(User, key):
                if key in ("id", "username", "email"):
                    return self.execute_query(query.filter_by(**{key: value}), use_list=False)
                else:
                    query = query.filter_by(**{key: value})
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Return all the filtered items
        return self.execute_query(query)

    def delete_user(self, user: User):
        # Delete the row at the database
        self.del_row(user)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

    def update_user(self, user: User, **kwargs):
        # Modify the specified user fields
        for key, value in kwargs.items():
            if key == "password":
                user.hash_password(value)
            elif hasattr(User, key):
                setattr(user, key, value)
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return user
