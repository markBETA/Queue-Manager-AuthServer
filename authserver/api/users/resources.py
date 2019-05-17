"""
This module defines the all the api resources for the user authentication namespace
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
from flask_restplus.mask import apply as apply_mask

from .definitions import api
from .models import (
    user_credentials_model, user_register_model, user_model
)
from ..common_models import (
    token_create_model, token_refresh_model
)
from ...blacklist_manager import jwt_blacklist_manager
from ...database import db_mgr, UniqueConstraintError


@api.route("")
class User(Resource):
    """
    /user
    """
    @api.doc(id="get_user_data")
    @api.doc(security="access_jwt")
    @api.response(200, "Success", user_model)
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def get(self):
        """
        Get the user information from the identity of the given access token
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user refresh tokens are allowed.'}, 422

        user = db_mgr.get_users(id=current_user.get('id'))

        if user is None:
            return {'message': 'There isn\'t any registered user with this identity.'}, 422

        return marshal(user, user_model), 200

    @api.doc(id="register_user")
    @api.expect(user_register_model, validate=True)
    @api.response(200, "Success", user_model)
    @api.response(400, "Username or email already used")
    @api.response(500, "Unable to read/write data at the database")
    def post(self):
        """
        Register a new user
        """
        # Delete the unwanted keys from the Json payload
        payload = apply_mask(request.json, user_register_model)

        try:
            user = db_mgr.insert_user(**payload)
        except UniqueConstraintError as e:
            return {'message': str(e)}, 400

        return marshal(user, user_model), 200


@api.route("/login")
class UserLogin(Resource):
    """
    /user/login
    """
    @api.doc(id="user_login")
    @api.expect(user_credentials_model, validate=True)
    @api.response(200, "Success", token_create_model)
    @api.response(400, "Payload validation failed")
    @api.response(401, "Wrong credentials")
    @api.response(500, "Unable to read the data from the database")
    def post(self):
        """
        Generate an access and refresh token for a user if the credentials are correct
        """
        # Initialize the credentials variables
        email = request.json["email"]
        password = request.json["password"]

        if not user_credentials_model['email'].validate(email):
            return {'message': 'Invalid email format.'}, 400

        user = db_mgr.get_users(email=email)

        if user is None:
            return {'message': 'There isn\'t any registered user with this email.'}, 401
        elif not user.verify_password(password):
            return {'message': 'Incorrect password for this user.'}, 401

        access_token = create_access_token(user.identity)
        refresh_token = create_refresh_token(user.identity)

        jwt_blacklist_manager.add_token_set(access_token, refresh_token)

        token_create_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        return marshal(token_create_data, token_create_model), 200


@api.route("/access_refresh")
class UserAccessRefresh(Resource):
    """
    /user/access_refresh
    """
    @api.doc(id="user_access_refresh")
    @api.doc(security="refresh_jwt")
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
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user refresh tokens are allowed.'}, 422

        new_access_token = create_access_token(identity=current_user)

        jwt_blacklist_manager.update_refresh_associated_access_token(
            refresh_token, new_access_token, refresh_encoded=False, access_encoded=True
        )

        token_refresh_data = {
            "access_token": new_access_token
        }

        return marshal(token_refresh_data, token_refresh_model), 200


@api.route("/logout")
class UserLogout(Resource):
    """
    /user/logout
    """
    @api.doc(id="user_logout")
    @api.doc(security="refresh_jwt")
    @api.response(200, "User logged out successfully")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Logout a user session at the server side using it's refresh token
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user refresh tokens are allowed.'}, 422

        token = get_raw_jwt()

        if not token.get('jti'):
            return {'message': 'Missing or invalid token identification.'}, 422

        jwt_blacklist_manager.revoke_refresh_token(token, encoded=False, revoke_associated_access_token=True)

        return {'message': 'User logged out.'}, 200


@api.route("/check_access_token")
class UserCheckAccessToken(Resource):
    """
    /user/check_access_token
    """
    @api.doc(id="user_access_check")
    @api.doc(security="access_jwt")
    @api.response(200, "Valid access token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_required
    def post(self):
        """
        Checks if the given access token is still valid or not
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422

        return {'message': 'Valid access token.'}, 200


@api.route("/check_refresh_token")
class UserCheckRefreshToken(Resource):
    """
    /user/check_refresh_token
    """
    @api.doc(id="user_access_check")
    @api.doc(security="refresh_jwt")
    @api.response(200, "Valid refresh token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Checks if the given refresh token is still valid or not
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user refresh tokens are allowed.'}, 422

        return {'message': 'Valid refresh token.'}, 200
