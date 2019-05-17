"""
This module implements the user data related database models.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from werkzeug.security import generate_password_hash, check_password_hash

from .table_names import (
    USERS_TABLE
)
from ..definitions import db_conn as db


class User(db.Model):
    """
    Definition of table USERS_TABLE that contains all users
    """
    __tablename__ = USERS_TABLE

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(256), unique=True)
    fullname = db.Column(db.String(256))
    email = db.Column(db.String(256), unique=True)
    password = db.Column(db.String(256))
    isAdmin = db.Column(db.Boolean, nullable=False, default=False)
    registeredOn = db.Column(db.DateTime)

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
        return '[{}]<id: {} / username: {} / fullname: {} / isAdmin: {}>'.format(self.__tablename__, self.id,
                                                                                 self.username, self.fullname,
                                                                                 self.isAdmin)
