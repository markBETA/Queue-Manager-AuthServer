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
from ..definitions import EmailField

###########################
# USER MODELS DECLARATION #
###########################

user_credentials_model = api.model('UserCredentials', {
    'email': EmailField(required=True),
    'password': fields.String(required=True)
})

user_register_model = api.model('UserRegister', {
    'username': fields.String(required=True),
    'fullname': fields.String(required=True),
    'email': EmailField(required=True),
    'password': fields.String(required=True),
})

user_model = api.model('User', {
    'id': fields.Integer(required=True),
    'username': fields.String(required=True),
    'fullname': fields.String(required=True),
    'email': EmailField(required=True),
    'is_admin': fields.Boolean(attribute="isAdmin", required=True),
    'registered_on': fields.DateTime(attribute="registeredOn", required=True)
})
