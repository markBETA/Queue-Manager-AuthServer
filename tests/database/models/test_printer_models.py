"""
This module implements the printer data related database models testing.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from authserver.database import (
    Printer
)
from authserver.database import printer_initial_values


def add_printer(session):
    printer = Printer(
        id=2,
        serialNumber="000.00000.0000"
    )
    printer.hash_key("1234")

    session.add(printer)
    session.commit()

    return printer


def test_printer_model(session):
    expected_printers = printer_initial_values()

    for i in range(len(expected_printers)):
        expected_printers[i].id = i + 1

    printer = add_printer(session)
    expected_printers.append(printer)
    
    str(printer)

    assert printer.id > 0
    assert printer.verify_key("1234")
    assert printer.identity == {
        "type": "printer",
        "id": printer.id,
        "serial_number": printer.serialNumber
    }

    printers = Printer.query.all()
    
    assert len(printers) == len(expected_printers)
    
    for i in range(len(expected_printers)):
        assert expected_printers[i].id == printers[i].id
        assert expected_printers[i].serialNumber == printers[i].serialNumber