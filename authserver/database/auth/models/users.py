"""
This module implements the user data related database models.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from werkzeug.security import generate_password_hash, check_password_hash

from .table_names import (
    USERS_TABLE
)
from ..definitions import bind_key, db_conn as db


class UserAuth(db.Model):
    """
    Definition of table USERS_TABLE that contains all users
    """
    __bind_key__ = bind_key
    __tablename__ = USERS_TABLE

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256))
    isAdmin = db.Column(db.Boolean, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=False)

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        if self.password:
            return check_password_hash(self.password, password)
        else:
            return False

    @property
    def identity(self):
        return {
            "type": "user",
            "id": self.id,
            "is_admin": self.isAdmin
        }

    def __repr__(self):
        return '[{}]<id: {} / email: {} / isAdmin: {}>'.format(self.__tablename__, self.id,
                                                               self.email, self.isAdmin)
