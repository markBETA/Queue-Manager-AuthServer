"""
This module contains the database manager class for the user operations.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from .base_class import DBManagerBase
from .exceptions import (
    InvalidParameter
)
from ..models import (
    UserAuth
)


class DBManagerUsers(DBManagerBase):
    """
    This class implements the database manager class for the user operations
    """
    def insert_user(self, user_id: int, email: str, password: str, is_admin: bool = False, enabled: bool = False):
        """
        TODO: Docs

        :param user_id:
        :param email:
        :param password:
        :param is_admin:
        :param enabled:
        :return:
        """
        # Check parameter values
        if user_id <= 0:
            raise InvalidParameter("The 'user_id' parameter needs to be an integer bigger than 0")
        if email == "":
            raise InvalidParameter("The 'email' parameter can't be an empty string")
        if password == "":
            raise InvalidParameter("The 'password' parameter can't be an empty string")

        # Create the new user object
        user = UserAuth(
            id=user_id,
            email=email,
            isAdmin=is_admin,
            enabled=enabled
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
        """
        TODO: Docs

        :param kwargs:
        :return:
        """
        # Create the query object
        query = UserAuth.query

        # Filter by the given kwargs
        for key, value in kwargs.items():
            if hasattr(UserAuth, key):
                if key in ("id", "email"):
                    return self.execute_query(query.filter_by(**{key: value}), use_list=False)
                else:
                    query = query.filter_by(**{key: value})
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Return all the filtered items
        return self.execute_query(query)

    def count_admin_users(self):
        """
        TODO: Docs

        :return:
        """
        # Create the query object
        query = UserAuth.query.filter_by(isAdmin=True)

        # Return the count result
        return self.execute_query(query, count=True)

    def delete_user(self, user: UserAuth):
        """
        TODO: Docs

        :param user:
        """
        # Delete the row at the database
        self.del_row(user)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

    def update_user(self, user: UserAuth, **kwargs):
        """
        TODO: Docs

        :param user:
        :param kwargs:
        :return:
        """
        # Modify the specified user fields
        for key, value in kwargs.items():
            if key == "password":
                user.hash_password(value)
            elif hasattr(UserAuth, key):
                setattr(user, key, value)
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return user
