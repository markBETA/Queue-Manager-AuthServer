"""
This module defines the all the api resources for the printers namespace.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from .definitions import api
from .models import (
    printer_credentials_model, printer_model
)
from .resources import (
    CurrentPrinter, PrinterLogin, PrinterAccessRefresh, PrinterCheckAccessToken, PrinterCheckRefreshToken,
    PrinterLogout
)
