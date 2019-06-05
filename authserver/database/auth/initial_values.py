"""
This module implements the database initializers and the tables population data.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from werkzeug.security import generate_password_hash

from .models import (
    UserAuth, PrinterAuth
)


#############################
# USER TABLE INITIAL VALUES #
#############################

def user_initial_values():
    return [
        UserAuth(
            id=1, email="cloudservices@bcn3dtechnologies.com", password=generate_password_hash("bcn3d"), isAdmin=True,
            enabled=True
        ),
    ]


#######################################
# PRINTER ACCESS TABLE INITIAL VALUES #
#######################################

def printer_initial_values():
    return [
        PrinterAuth(
            id=1, serialNumber="020.238778.0823", printerKey=generate_password_hash('rdRwtlHI$$Y!L:Mff(JtHjUdAf!{w_in')
        ),
    ]
