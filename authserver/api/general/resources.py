"""
This module defines the all the api resources for the user and printer authentication namespace.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import json

from flask import current_app
from flask_jwt_extended import (
    jwt_refresh_token_required, jwt_required, get_jwt_identity
)
from flask_restplus import Resource

from .definitions import api


@api.route("/check_access_token")
class CheckAccessToken(Resource):
    """
    /general/check_access_token
    """
    @api.doc(id="general_access_check")
    @api.doc(security=["user_access_jwt", "printer_access_jwt"])
    @api.response(200, "Valid access token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_required
    def post(self):
        """
        Checks if the given access token is still valid or not.
        """
        identity = get_jwt_identity()
        identity_data = json.dumps(identity, separators=(',', ':'))
        headers = {current_app.config.get("IDENTITY_HEADER", "X-Identity"): identity_data}

        return {'message': 'Valid access token.'}, 200, headers


@api.route("/check_refresh_token")
class CheckRefreshToken(Resource):
    """
    /general/check_refresh_token
    """
    @api.doc(id="general_refresh_check")
    @api.doc(security=["user_refresh_jwt", "printer_refresh_jwt"])
    @api.response(200, "Valid refresh token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Checks if the given refresh token is still valid or not.
        """
        return {'message': 'Valid refresh token.'}, 200
