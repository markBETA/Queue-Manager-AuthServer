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

from datetime import datetime

from flask import request
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_refresh_token_required
)
from flask_restplus import Resource, marshal

from .definitions import api
from .models import (
    printer_credentials_model
)
from ..common_models import (
    token_create_model
)
from ...blacklist_manager import jwt_blacklist_manager
from ...blacklist_manager.exceptions import BlacklistManagerError
from ...database import db_mgr
from ...database.manager.exceptions import (
    DBInternalError
)


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

        try:
            printer = db_mgr.get_printers(serialNumber=serial_number)
        except DBInternalError:
            return {'message': 'Unable to read the data from the database'}, 500

        if printer is None:
            return {'message': 'There isn\'t any registered printer with this serial number'}, 401
        elif not printer.verify_key(key):
            return {'message': 'Incorrect key for this printer serial number'}, 401

        access_token = create_access_token(printer.identity)
        refresh_token = create_refresh_token(printer.identity)

        try:
            jwt_blacklist_manager.add_token_set(access_token, refresh_token)
        except BlacklistManagerError as e:
            return {'message': str(e)}, 500

        token_create_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_token_expiration_datetime": datetime.now() + jwt_blacklist_manager.access_expiration_time
        }

        return marshal(token_create_data, token_create_model), 200


@api.route("/access_refresh")
class PrinterAccessRefresh(Resource):
    """
    /printer/access_refresh
    """
    @api.doc(id="printer_access_refresh")
    @api.doc(security="jwt")
    # @api.expect(printer_credentials_model, validate=True)
    @api.response(200, "Success", token_create_model)
    @api.response(401, "Invalid refresh token")
    @api.response(500, "Unable to read the data from the database")
    @jwt_refresh_token_required
    def post(self):
        pass
