"""
This module contains the database manager class for the printer operations.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import random
import string

from .base_class import DBManagerBase
from .exceptions import (
    InvalidParameter
)
from ..models import (
    Printer
)


class DBManagerPrinter(DBManagerBase):
    """
    This class implements the database manager class for the user operations
    """
    @staticmethod
    def _generate_random_key(key_length=32):
        # Define the usable characters in the key string
        key_characters = string.ascii_letters + string.digits + string.punctuation
        # Return the generated random key
        return ''.join(random.choice(key_characters) for _i in range(key_length))

    def insert_printer(self, printer_id: int, serial_number: str, printer_key: str = None):
        # Check parameter values
        if printer_id <= 0:
            raise InvalidParameter("The 'printer_id' parameter needs to be an integer bigger than 0")
        if serial_number == "":
            raise InvalidParameter("The 'serial_number' parameter can't be an empty string")
        if printer_key == "":
            raise InvalidParameter("The 'printer_key' parameter can't be an empty string")

        if printer_key is None:
            printer_key = self._generate_random_key()

        # Create the printer object
        printer = Printer(
            id=printer_id,
            serialNumber=serial_number
        )

        # Hash the key and save the value
        printer.hash_key(printer_key)

        # Add the new row to the database
        self.add_row(printer)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return printer

    def get_printers(self, **kwargs):
        # Create the query object
        query = Printer.query

        # Filter by the given kwargs
        for key, value in kwargs.items():
            if hasattr(Printer, key):
                if key in ("id", "serialNumber"):
                    return self.execute_query(query.filter_by(**{key: value}), use_list=False)
                else:
                    query = query.filter_by(**{key: value})
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Return all the filtered items
        return self.execute_query(query)

    def delete_printer(self, printer: Printer):
        # Delete the row at the database
        self.del_row(printer)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

    def update_printer(self, printer: Printer, **kwargs):
        # Modify the specified printer fields
        for key, value in kwargs.items():
            if key == "printerKey":
                printer.hash_key(value)
            elif hasattr(Printer, key):
                setattr(printer, key, value)
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return printer
