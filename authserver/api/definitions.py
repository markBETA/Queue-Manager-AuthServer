"""
This module defines the all the global variables needed API namespaces.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import Blueprint
from flask_restplus import fields, Api


#########################
# API GLOBAL DEFINITION #
#########################

api_bp = Blueprint('api', __name__)

api = Api(
    title='Queue Manager Auth API',
    version='0.1',
    description='This API manages all the authentication operations for the queue manager',
    authorizations={
        'user_refresh_jwt': {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
        },
        'user_access_jwt': {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
        },
        'printer_refresh_jwt': {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
        },
        'printer_access_jwt': {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
        }
    },
)


####################
# GLOBAL FUNCTIONS #
####################

def underscore_to_camel_case(s: str):
    new_s = ""
    i = 0
    while i < len(s):
        if s[i] == "_":
            i += 1
            new_s += s[i].upper()
        else:
            new_s += s[i]
        i += 1

    return new_s


#######################
# CUSTOM MODEL FIELDS #
#######################

class EmailField(fields.String):
    """ This field is used to validate email fields """
    __schema_type__ = 'string'
    __schema_format__ = 'email'
    __schema_example__ = 'email@domain.com'

    import re
    EMAIL_REGEX = re.compile(r'\S+@\S+\.\S+')

    def validate(self, value):
        if not value:
            return False if self.required else True
        if not self.EMAIL_REGEX.match(value):
            return False
        return True
