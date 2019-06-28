"""
This module defines the all the api resources for the user authentication namespace
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
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
    user_credentials_model, user_register_model, user_model, authorization_data_model, user_data_model,
    edit_user_model
)
from ..common_models import (
    token_create_model, token_refresh_model
)
from ...blacklist_manager import jwt_blacklist_manager
from ...database import auth_db_mgr, app_db_mgr
from ...database.app import UniqueConstraintError as AppUniqueConstraintError
from ...database.auth import UniqueConstraintError as AuthUniqueConstraintError


@api.route("")
class Users(Resource):
    """
    /users
    """
    @api.doc(id="get_users_data")
    @api.doc(security="user_access_jwt")
    @api.response(200, "Success", [user_model])
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def get(self):
        """
        List all the registered users. Only admin users can execute this request.
        """
        users_data = []
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422
        if not current_user.get('is_admin'):
            return {'message': 'Only users with administrator privileges can list all users.'}, 403

        users = app_db_mgr.get_users()

        for user in users:
            authorization_data = auth_db_mgr.get_users(id=user.id)
            users_data.append({"user_data": user, "authorization_data": authorization_data})

        return marshal(users_data, user_model), 200

    @api.doc(id="register_user")
    @api.expect(user_register_model, validate=True)
    @api.response(201, "User created successfully", user_model)
    @api.response(400, "Input payload validation failed")
    @api.response(409, "Username or email already in use")
    @api.response(500, "Unable to read/write data at the database")
    def post(self):
        """
        Register a new user.
        """
        # Delete the unwanted keys from the Json payload
        payload = apply_mask(request.json, user_register_model)

        if not user_credentials_model['email'].validate(payload["email"]):
            return {
                'message': 'Input payload validation failed',
                'errors': {
                    'email': "Invalid email format"
                }
            }, 400

        try:
            user = app_db_mgr.insert_user(payload["username"], payload["fullname"], payload["email"])
        except AppUniqueConstraintError as e:
            if e.column == "username":
                return {'message': 'Username already in use'}, 409
            elif e.column == "email":
                return {'message': 'Email already in use'}, 409
            else:
                return {'message': 'Unable to read/write data at the database.'}, 500

        try:
            authorization_data = auth_db_mgr.insert_user(user.id, user.email, payload["password"])
        except AuthUniqueConstraintError as e:
            app_db_mgr.delete_user(user)
            if e.column == "email":
                return {'message': 'Email already in use'}, 409
            else:
                return {'message': 'Unable to read/write data at the database.'}, 500

        return marshal({"user_data": user, "authorization_data": authorization_data}, user_model), 201


@api.route("/current")
class CurrentUser(Resource):
    """
    /users/current
    """
    @api.doc(id="get_current_user_data")
    @api.doc(security="user_access_jwt")
    @api.response(200, "Success", user_model)
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(404, "User not found")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def get(self):
        """
        Get the user information from the identity of the given access token.
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422

        user = app_db_mgr.get_users(id=current_user.get('id'))

        if user is None:
            return {'message': 'There isn\'t any registered user with this identity.'}, 404

        authorization_data = auth_db_mgr.get_users(id=user.id)

        return marshal({"user_data": user, "authorization_data": authorization_data}, user_model), 200

    @api.doc(id="edit_current_user")
    @api.doc(security="user_access_jwt")
    @api.expect(edit_user_model, validate=True)
    @api.response(200, "Success", user_data_model)
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(404, "User not found")
    @api.response(500, "Unable to read/write the data at the database")
    @jwt_required
    def put(self):
        """
        Edit the user information from the identity of the given access token.
        """
        # Delete the unwanted keys from the Json payload
        payload = apply_mask(request.json, edit_user_model, skip=True)

        if "email" in payload and not user_credentials_model['email'].validate(payload["email"]):
            return {
                'message': 'Input payload validation failed',
                'errors': {
                    'email': "Invalid email format"
                }
            }, 400

        current_password = payload.pop('current_password', '')
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422

        user = app_db_mgr.get_users(id=current_user.get('id'))
        auth_data = auth_db_mgr.get_users(id=user.id)

        if user is None or auth_data is None:
            return {'message': 'There isn\'t any registered user with this identifier.'}, 404
        elif not auth_data.verify_password(current_password):
            return {'message': 'Incorrect current password for this user.'}, 401

        # Prepare which fields to update go to each database
        auth_fields_to_update = {}
        user_data_fields_to_update = {}

        for key, value in payload.items():
            if key == 'new_password':
                auth_fields_to_update['password'] = value
            elif key == 'email':
                auth_fields_to_update[key] = value
                user_data_fields_to_update[key] = value
            else:
                user_data_fields_to_update[key] = value

        # Update the authorization fields
        if auth_fields_to_update:
            try:
                auth_db_mgr.update_user(auth_data, **auth_fields_to_update)
            except AuthUniqueConstraintError as e:
                if e.column == "username":
                    return {'message': 'Username already in use'}, 409
                elif e.column == "email":
                    return {'message': 'Email already in use'}, 409
                else:
                    return {'message': 'Unable to read/write data at the database.'}, 500

        # Update the user data fields
        if user_data_fields_to_update:
            try:
                app_db_mgr.update_user(user, **user_data_fields_to_update)
            except AppUniqueConstraintError as e:
                if e.column == "username":
                    return {'message': 'Username already in use'}, 409
                elif e.column == "email":
                    return {'message': 'Email already in use'}, 409
                else:
                    return {'message': 'Unable to read/write data at the database.'}, 500

        return {'message': 'User data updated successfully.'}, 200


@api.route("/<int:user_id>")
class User(Resource):
    """
    /users/<int:user_id>
    """
    @api.doc(id="get_user")
    @api.doc(security="user_access_jwt")
    @api.response(200, "Success", user_model)
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(404, "User not found")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def get(self, user_id: int):
        """
        Get the user information from it's ID. Only admin users can get the information of another users.
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422
        if current_user.get('id') != user_id and not current_user.get('is_admin'):
            return {'message': 'You need to be an administrator to see another user data.'}, 403

        user = app_db_mgr.get_users(id=user_id)

        if user is None:
            return {'message': 'There isn\'t any registered user with this identifier.'}, 404

        authorization_data = auth_db_mgr.get_users(id=user.id)

        return marshal({"user_data": user, "authorization_data": authorization_data}, user_model), 200

    @api.doc(id="delete_user")
    @api.doc(security="user_access_jwt")
    @api.response(200, "Success", user_model)
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(404, "User not found")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def delete(self, user_id: int):
        """
        Delete the user from it's ID. Only admin users can delete another users.
        """
        current_user = get_jwt_identity()
        current_user_is_admin = current_user.get('is_admin')

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422
        if current_user.get('id') != user_id and not current_user_is_admin:
            return {'message': 'You need to be an administrator to delete another user.'}, 403

        # Check if the user to delete isn't the only admin user
        if current_user_is_admin:
            if auth_db_mgr.count_admin_users() <= 1:
                return {'message': 'At least one admin user is needed.'}, 403

        user = app_db_mgr.get_users(id=user_id)

        if user is None:
            return {'message': 'There isn\'t any registered user with this identifier.'}, 404

        authorization_data = auth_db_mgr.get_users(id=user.id)

        if authorization_data is not None:
            auth_db_mgr.delete_user(authorization_data)

        app_db_mgr.delete_user(user)

        return marshal({"user_data": user, "authorization_data": authorization_data}, user_model), 200


@api.route("/<int:user_id>/authorization")
class UserAuthorization(Resource):
    """
    /users/<int:user_id>/authorization
    """
    @api.doc(id="edit_user_authorization_data")
    @api.doc(security="user_access_jwt")
    @api.expect(authorization_data_model, validate=True)
    @api.response(200, "Success")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized")
    @api.response(403, "Forbidden")
    @api.response(404, "User not found")
    @api.response(500, "Unable to read the data from the database")
    @jwt_required
    def put(self, user_id: int):
        """
        Edit the user authorization data from it's ID. Only admin users edit it.
        """
        # Delete the unwanted keys from the Json payload
        payload = apply_mask(request.json, authorization_data_model, skip=True)

        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422
        if not current_user.get('is_admin'):
            return {'message': 'You need to be an administrator to edit users authorization data.'}, 403

        authorization_data = auth_db_mgr.get_users(id=user_id)

        if authorization_data is None:
            return {'message': 'There isn\'t any registered user with this identifier.'}, 404

        if "is_admin" in payload:
            payload["isAdmin"] = payload["is_admin"]
            del payload["is_admin"]

        auth_db_mgr.update_user(authorization_data, **payload)

        return {'message': 'User authorization data updated successfully.'}, 200


@api.route("/login")
class UserLogin(Resource):
    """
    /users/login
    """
    @api.doc(id="user_login")
    @api.expect(user_credentials_model, validate=True)
    @api.response(200, "Success", token_create_model)
    @api.response(400, "Payload validation failed")
    @api.response(401, "Wrong credentials")
    @api.response(500, "Unable to read the data from the database")
    def post(self):
        """
        Generate an access and refresh token for a user if the credentials are correct.
        """
        # Initialize the credentials variables
        email = request.json["email"]
        password = request.json["password"]

        if not user_credentials_model['email'].validate(email):
            return {
               'message': 'Input payload validation failed',
               'errors': {
                   'email': "Invalid email format"
               }
            }, 400

        user = auth_db_mgr.get_users(email=email)

        if user is None:
            return {'message': 'There isn\'t any registered user with this email.'}, 401
        elif not user.enabled:
            return {'message': 'This user is not enabled. Please contact with the administrator to enable it.'}, 401
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
    /users/access_refresh
    """
    @api.doc(id="user_access_refresh")
    @api.doc(security="user_refresh_jwt")
    @api.response(200, "Success", token_refresh_model)
    @api.response(422, "Invalid refresh token")
    @api.response(401, "Unauthorized token")
    @api.response(500, "Unable to read the data from the database")
    @jwt_refresh_token_required
    def post(self):
        """
        Generate a new access token with the identity contained in the received refresh token.
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
    /users/logout
    """
    @api.doc(id="user_logout")
    @api.doc(security="user_refresh_jwt")
    @api.response(200, "User logged out successfully")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Logout a user session at the server side using it's refresh token.
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
    /users/check_access_token
    """
    @api.doc(id="user_access_check")
    @api.doc(security="user_access_jwt")
    @api.response(200, "Valid access token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_required
    def post(self):
        """
        Checks if the given access token is still valid or not.
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user access tokens are allowed.'}, 422

        return {'message': 'Valid access token.'}, 200


@api.route("/check_refresh_token")
class UserCheckRefreshToken(Resource):
    """
    /users/check_refresh_token
    """
    @api.doc(id="user_refresh_check")
    @api.doc(security="user_refresh_jwt")
    @api.response(200, "Valid refresh token")
    @api.response(422, "Invalid access token")
    @api.response(401, "Unauthorized token")
    @jwt_refresh_token_required
    def post(self):
        """
        Checks if the given refresh token is still valid or not.
        """
        current_user = get_jwt_identity()

        if current_user.get('type') != "user":
            return {'message': 'Only user refresh tokens are allowed.'}, 422

        return {'message': 'Valid refresh token.'}, 200
