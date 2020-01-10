"""
This module implements the printer data related database manager testing.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


def _add_printer(db_manager):
    printer, printer_key = db_manager.insert_printer(2, "000.00000.0000")
    assert printer.verify_key(printer_key)

    return printer


def test_printers_db_manager(db_manager):
    expected_printer = _add_printer(db_manager)

    printer = db_manager.get_printers(id=2)
    assert expected_printer == printer

    db_manager.update_printer(printer, id=4, printerKey="abcd")
    printer = db_manager.get_printers(id=printer.id)
    assert printer.id == 4
    assert printer.verify_key("abcd")

    db_manager.delete_printer(printer)
    printer = db_manager.get_printers(serialNumber=printer.serialNumber)
    assert printer is None
