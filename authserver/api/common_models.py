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

#############################
# COMMON MODELS DECLARATION #
#############################

token_create_model = api.model('TokenCreate', {
    'access_token': fields.String(required=True),
    'refresh_token': fields.String(required=True),
})

token_refresh_model = api.model('TokenRefresh', {
    'access_token': fields.String(required=True),
})
