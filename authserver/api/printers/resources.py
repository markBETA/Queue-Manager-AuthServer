"""
This module defines the all the api resources for the printer authentication namespace
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import request
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_refresh_token_required, jwt_required,
    get_jwt_identity, get_raw_jwt
)
from flask_restplus import Resource, marshal

from .definitions import api
from .models import (
    printer_credentials_model, printer_model
)
from ..common_models import (
    token_create_model, token_refresh_model
)
from ...blacklist_manager import jwt_blacklist_manager
from ...database import auth_db_mgr


@api.route("/current")
class Printer(Resource):
    """
    /printer/current
    """
    @api.doc(id="printer_login")
    @api.response(200, "Success", printer_model)
    @api.response(401, "Wrong credentials")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def get(self):
        """
        Get the user information from the identity of the given access token
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "printer":
            return {'message': 'Only printer access tokens are allowed.'}, 422

        printer_auth_data = auth_db_mgr.get_printers(id=current_user.get('id'))

        if printer_auth_data is None:
            return {'message': 'There isn\'t any registered printer with this identity.'}, 404

        return marshal(printer_auth_data, printer_model), 200


@api.route("/login")
class PrinterLogin(Resource):
    """
    /printer/login
    """
    @api.doc(id="printer_login")
    @api.expect(printer_credentials_model, validate=True)
    @api.response(200, "Success", token_create_model)
    @api.response(401, "Wrong credentials")
    @api.response(500, "Unable to read the data from the database")
    def post(self):
        """
        Generate an access and refresh token for a printer if the credentials are correct
        """
        # Initialize the credentials variables
        serial_number = request.json["serial_number"]
        key = request.json["key"]

        printer = auth_db_mgr.get_printers(serialNumber=serial_number)

        if printer is None:
            return {'message': 'There isn\'t any registered printer with this serial number.'}, 401
        elif not printer.verify_key(key):
            return {'message': 'Incorrect printer key.'}, 401

        access_token = create_access_token(printer.identity)
        refresh_token = create_refresh_token(printer.identity)

        jwt_blacklist_manager.add_token_set(access_token, refresh_token)

        token_create_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        return marshal(token_create_data, token_create_model), 200


@api.route("/access_refresh")
class PrinterAccessRefresh(Resource):
    """
    /printer/access_refresh
    """
    @api.doc(id="printer_access_refresh")
    @api.doc(security="printer_refresh_jwt")
    @api.response(200, "Success", token_refresh_model)
    @api.response(422, "Invalid refresh token")
    @api.response(401, "Unauthorized token")
    @api.response(500, "Unable to read the data from the database")
    @jwt_refresh_token_required
    def post(self):
        """
        Generate a new access token with the identity contained in the received refresh token
        """
        refresh_token = get_raw_jwt()
        current_printer = get_jwt_identity()

        if current_printer.get('type') != "printer":
            return {'message': 'Only printer refresh tokens are allowed.'}, 422

        new_access_token = create_access_token(identity=current_printer)

        jwt_blacklist_manager.update_refresh_associated_access_token(
            refresh_token, new_access_token, refresh_encoded=False, access_encoded=True
        )

        token_refresh_data = {
            "access_token": new_access_token
        }

        return marshal(token_refresh_data, token_refresh_model), 200


@api.route("/logout")
class PrinterLogout(Resource):
    """
    /printer/logout
    """
    @api.doc(id="printer_logout")
    @api.doc(security="printer_refresh_jwt")
    @api.response(200, "Printer logged out successfully")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Logout a printer session at the server side using it's refresh token
        """
        current_printer = get_jwt_identity()

        if current_printer.get('type') != "printer":
            return {'message': 'Only printer refresh tokens are allowed.'}, 422

        token = get_raw_jwt()

        if not token.get('jti'):
            return {'message': 'Missing or invalid token identification.'}, 422

        jwt_blacklist_manager.revoke_refresh_token(token, encoded=False, revoke_associated_access_token=True)

        return {'message': 'Printer logged out.'}, 200


@api.route("/check_access_token")
class PrinterCheckAccessToken(Resource):
    """
    /printer/check_access_token
    """
    @api.doc(id="printer_access_check")
    @api.doc(security="printer_access_jwt")
    @api.response(200, "Valid access token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_required
    def post(self):
        """
        Checks if the given access token is still valid or not
        """
        current_printer = get_jwt_identity()

        if current_printer.get('type') != "printer":
            return {'message': 'Only printer access tokens are allowed.'}, 422

        return {'message': 'Valid access token.'}, 200


@api.route("/check_refresh_token")
class PrinterCheckRefreshToken(Resource):
    """
    /printer/check_refresh_token
    """
    @api.doc(id="printer_access_check")
    @api.doc(security="printer_refresh_jwt")
    @api.response(200, "Valid refresh token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Checks if the given refresh token is still valid or not
        """
        current_printer = get_jwt_identity()

        if current_printer.get('type') != "printer":
            return {'message': 'Only printer refresh tokens are allowed.'}, 422

        return {'message': 'Valid refresh token.'}, 200
