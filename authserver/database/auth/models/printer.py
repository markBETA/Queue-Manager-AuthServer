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
    PRINTER_TABLE
)
from ..definitions import bind_key, db_conn as db


class PrinterAuth(db.Model):
    """
    Definition of table PRINTER_TABLE that contains all users
    """
    __bind_key__ = bind_key
    __tablename__ = PRINTER_TABLE

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=False)
    serialNumber = db.Column(db.String(256), unique=True, nullable=False)
    printerKey = db.Column(db.String(256), nullable=False)

    def hash_key(self, key):
        self.printerKey = generate_password_hash(key)

    def verify_key(self, key):
        return check_password_hash(self.printerKey, key)

    @property
    def identity(self):
        return {
            "type": "printer",
            "id": self.id,
            "serial_number": self.serialNumber
        }

    def __repr__(self):
        return '[{}]<id: {} / serialNumber: {}>'.format(self.__tablename__, self.id, self.serialNumber)
