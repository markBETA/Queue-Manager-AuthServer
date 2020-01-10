"""
This module contains the database manager class for the printer operations.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
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
    PrinterAuth
)


class DBManagerPrinter(DBManagerBase):
    """
    This class implements the database manager class for the printer operations
    """
    @staticmethod
    def _generate_random_key(key_length=32):
        """
        TODO: Docs

        :param key_length:
        :return:
        """
        # Define the usable characters in the key string
        key_characters = string.ascii_letters + string.digits + string.punctuation
        # Return the generated random key
        return ''.join(random.choice(key_characters) for _i in range(key_length))

    def insert_printer(self, printer_id: int, serial_number: str, printer_key: str = None):
        """
        TODO: Docs

        :param printer_id:
        :param serial_number:
        :param printer_key:
        :return:
        """
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
        printer = PrinterAuth(
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

        return printer, printer_key

    def get_printers(self, **kwargs):
        """
        TODO: Docs

        :param kwargs:
        :return:
        """
        # Create the query object
        query = PrinterAuth.query

        # Filter by the given kwargs
        for key, value in kwargs.items():
            if hasattr(PrinterAuth, key):
                if key in ("id", "serialNumber"):
                    return self.execute_query(query.filter_by(**{key: value}), use_list=False)
                else:
                    query = query.filter_by(**{key: value})
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Return all the filtered items
        return self.execute_query(query)

    def delete_printer(self, printer: PrinterAuth):
        """
        TODO: Docs

        :param printer:
        """
        # Delete the row at the database
        self.del_row(printer)

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

    def update_printer(self, printer: PrinterAuth, **kwargs):
        """
        TODO: Docs

        :param printer:
        :param kwargs:
        :return:
        """
        # Modify the specified printer fields
        for key, value in kwargs.items():
            if key == "printerKey":
                printer.hash_key(value)
            elif hasattr(PrinterAuth, key):
                setattr(printer, key, value)
            else:
                raise InvalidParameter("Invalid '{}' parameter".format(key))

        # Commit the changes to the database
        if self.autocommit:
            self.commit_changes()

        return printer
