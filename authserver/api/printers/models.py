"""
This module defines the all the api models of the files namespace
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_restplus import fields

from .definitions import api

#####################################
# PRINTER ACCESS MODELS DECLARATION #
#####################################

printer_credentials_model = api.model('PrinterCredentials', {
    'serial_number': fields.String(required=True),
    'key': fields.String(required=True),
})
