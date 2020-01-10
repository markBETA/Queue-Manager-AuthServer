"""
This module contains the blacklist manager class.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import json
from datetime import datetime, timedelta

from flask_jwt_extended import decode_token
from redis import StrictRedis, exceptions as redis_exceptions

from .exceptions import (
    BlacklistTokenNotFound, RedisConnectionError, BlacklistManagerMissingConfigParams, BlacklistInvalidTokenData,
)


class JWTBlacklistManager(object):
    """
    This class implements the interface for storing and retrieving token identifications
    in the active token shared cache.
    """
    def __init__(self, app=None, strict_redis_class=StrictRedis):
        self.app = None
        self.redis_store = None
        self.strict_redis_class = strict_redis_class
        self.access_expiration_time = None
        self.refresh_expiration_time = None

        if app is not None:
            self.init_app(app)

    def _redis_value_exists(self, key=""):
        try:
            return self.redis_store.exists(key) > 0
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            self.app.logger.error("Can't connect to the Redis shared cache.")
            raise RedisConnectionError("Can't connect to the Redis shared cache.")
        except redis_exceptions.RedisError:
            self.app.logger.error("Can't execute the EXISTS method at the Redis shared cache.")
            raise RedisConnectionError("Can't execute the EXISTS method at the Redis shared cache.")

    def _get_redis_value(self, key=""):
        try:
            return self.redis_store.get(key)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            self.app.logger.error("Can't connect to the Redis shared cache.")
            raise RedisConnectionError("Can't connect to the Redis shared cache.")
        except redis_exceptions.RedisError:
            self.app.logger.error("Can't execute the GET method at the Redis shared cache.")
            raise RedisConnectionError("Can't execute the GET method at the Redis shared cache.")

    def _set_redis_value(self, key, value, expiration_time):
        try:
            return self.redis_store.set(key, value, expiration_time)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            self.app.logger.error("Can't connect to the Redis shared cache.")
            raise RedisConnectionError("Can't connect to the Redis shared cache.")
        except redis_exceptions.RedisError:
            self.app.logger.error("Can't execute the SET method at the Redis shared cache.")
            raise RedisConnectionError("Can't execute the SET method at the Redis shared cache.")

    def _delete_redis_value(self, key):
        try:
            return self.redis_store.delete(key)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            self.app.logger.error("Can't connect to the Redis shared cache.")
            raise RedisConnectionError("Can't connect to the Redis shared cache.")
        except redis_exceptions.RedisError:
            self.app.logger.error("Can't execute the DELETE method at the Redis shared cache.")
            raise RedisConnectionError("Can't execute the DELETE method at the Redis shared cache.")

    def _check_redis_connection(self):
        try:
            return self.redis_store.info() is not None
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            raise RedisConnectionError("Can't connect to the Redis shared cache.")
        except redis_exceptions.RedisError:
            raise RedisConnectionError("Can't get the Redis server initial information")

    @staticmethod
    def _get_decoded_token(encoded_token):
        return decode_token(encoded_token)

    @staticmethod
    def _get_jti(token):
        return token.get('jti')

    @staticmethod
    def _get_type(token):
        return token.get('type')

    @staticmethod
    def _get_expiration_datetime(token):
        return datetime.fromtimestamp(token.get('exp'))

    @staticmethod
    def _get_token_data_str(token_type, access_jti=None):
        if token_type == "access" and access_jti is not None:
            raise BlacklistInvalidTokenData("An access token can't have an associated access token")
        elif token_type == "refresh" and access_jti is None:
            raise BlacklistInvalidTokenData(
                "A refresh token need an associated access token and can't be associated with")

        if token_type == "refresh":
            return json.dumps({"access_jti": access_jti}, separators=(",", ":"))
        elif token_type == "access":
            return "{}"
        else:
            raise BlacklistInvalidTokenData("Unrecognized token type")

    def _get_token_data_dict(self, data_str: str):
        if data_str:
            try:
                return json.loads(data_str)
            except ValueError as e:
                self.app.logger.error("Error decoding active token information. Details: {}".format(str(e)))
                return None
        else:
            return None

    @staticmethod
    def _check_token_type(token, expected_type):
        # Raise an exception if the token type don't meed the expected one
        if token.get('type') != expected_type:
            raise BlacklistInvalidTokenData("Invalid '{}' token type. Expected: {}".format(
                token.get('type'), expected_type))

    @staticmethod
    def _calculate_token_expiration_time(expires_at: datetime):
        now = datetime.now()
        if expires_at > now:
            return expires_at - now
        else:
            return timedelta(seconds=0)

    def _load_config_parameters(self):
        config_parameters = {
            "REDIS_SERVER_HOST": 'host',
            "REDIS_SERVER_PORT": 'port',
            "TOKEN_BLACKLIST_REDIS_DB": 'db',
            "REDIS_SERVER_PASSWORD": 'password',
            "REDIS_SERVER_SOCKET_TIMEOUT": 'socket_timeout',
            "REDIS_SERVER_SOCKET_CONNECT_TIMEOUT": 'socket_connect_timeout',
            "REDIS_SERVER_SOCKET_KEEPALIVE": 'socket_keepalive',
            "REDIS_SERVER_SOCKET_KEEPALIVE_OPTIONS": 'socket_keepalive_options',
            "REDIS_SERVER_RETRY_ON_TIMEOUT": 'retry_on_timeout',
            "REDIS_SERVER_SSL_EN": 'ssl',
            "REDIS_SERVER_SSL_KEYFILE": 'ssl_keyfile',
            "REDIS_SERVER_SSL_CERTFILE": 'ssl_certfile',
            "REDIS_SERVER_SSL_CERT_REQS": 'ssl_cert_reqs',
            "REDIS_SERVER_SSL_CA_CERTS": 'ssl_ca_certs',
            "REDIS_SERVER_MAX_CONNECTIONS": 'max_connections',
        }
        redis_client_config_parameters = dict(
            host='localhost',
            port=6379,
            db=0,
            password=None,
            socket_timeout=None,
            socket_connect_timeout=None,
            socket_keepalive=None,
            socket_keepalive_options=None,
            connection_pool=None,
            unix_socket_path=None,
            encoding='utf-8',
            encoding_errors='strict',
            charset=None,
            errors=None,
            decode_responses=True,
            retry_on_timeout=False,
            ssl=False,
            ssl_keyfile=None,
            ssl_certfile=None,
            ssl_cert_reqs='required',
            ssl_ca_certs=None,
            max_connections=None
        )

        for app_config_key, redis_parameter in config_parameters.items():
            try:
                config_value = self.app.config[app_config_key]
            except KeyError:
                continue
            redis_client_config_parameters[redis_parameter] = config_value

        try:
            self.access_expiration_time = self.app.config['JWT_ACCESS_TOKEN_EXPIRES']
            self.refresh_expiration_time = self.app.config['JWT_REFRESH_TOKEN_EXPIRES']
        except KeyError:
            raise BlacklistManagerMissingConfigParams("The access or refresh token expiration time is missing in "
                                                      "the application configuration")

        return redis_client_config_parameters

    def init_app(self, app):
        self.app = app

        config_parameters = self._load_config_parameters()

        self.redis_store = self.strict_redis_class(**config_parameters)
        # Try the connection with the server
        self._check_redis_connection()

    def check_if_token_is_revoked(self, token, encoded=False):
        # Decode the token if it is encoded
        if encoded:
            token = self._get_decoded_token(token)
        # Read the token jti from the decoded token
        jti = self._get_jti(token)

        # Return true if the token isn't found in the active list
        return not self._redis_value_exists(jti)

    def add_access_token(self, access_token):
        # Get the token jti and the token data
        access_jti = self._get_jti(access_token)
        access_data = self._get_token_data_str("access")

        # If the token is already registered in the active list, don't re-save it
        if self._get_redis_value(access_jti) is not None:
            self.app.logger.warning("Token already registered in the active tokens list.")
            return

        # Save the token to the Redis shared cache
        self._set_redis_value(access_jti, access_data, self.access_expiration_time * 1.2)
        self.app.logger.info("Access token (jti: '{}') saved to the active token list.".format(access_jti))

        return access_jti

    def add_refresh_token(self, refresh_token, access_jti):
        # Get the token jti and the token data
        refresh_jti = self._get_jti(refresh_token)
        refresh_data = self._get_token_data_str("refresh", access_jti=access_jti)

        # If the token is already registered in the active list, don't re-save it
        if self._get_redis_value(refresh_jti) is not None:
            self.app.logger.warning("Token already registered in the active tokens list.")
            return
        # Check that the associated access token is already in the Redis shared cache
        if not self._redis_value_exists(access_jti):
            raise BlacklistTokenNotFound("There is no access token with this jti in the active tokens list.")

        # Save the token to the Redis shared cache
        self._set_redis_value(refresh_jti, refresh_data, self.refresh_expiration_time * 1.2)
        self.app.logger.info("Refresh token (jti: '{}') saved to the active token list.".format(refresh_jti))

        return refresh_jti

    def add_token_set(self, access_token, refresh_token, access_encoded=True, refresh_encoded=True):
        # Decode the tokens if they are encoded
        if refresh_encoded:
            refresh_token = self._get_decoded_token(refresh_token)
        if access_encoded:
            access_token = self._get_decoded_token(access_token)

        # Add the access and refresh token to the active list
        access_jti = self.add_access_token(access_token)
        self.add_refresh_token(refresh_token, access_jti)

    def revoke_access_token(self, token, encoded=True):
        # Decode the token if it is encoded
        if encoded:
            token = self._get_decoded_token(token)

        # Check the token type
        self._check_token_type(token, "access")

        # Get the jti from the token claims
        token_jti = self._get_jti(token)

        # Delete the token from the Redis cache
        deleted_count = self._delete_redis_value(token_jti)

        # Print a warning if the token was already revoked (not found in the Redis cache)
        if deleted_count == 0:
            self.app.logger.warning("Access token (jti: '{}') to revoke not found in the Redis cache. "
                                    "Considering it already revoked.".format(token_jti))
        else:
            self.app.logger.info("Access token (jti: '{}') successfully revoked from the active list.".
                                 format(token_jti))

    def revoke_refresh_token(self, token, encoded=True, revoke_associated_access_token=True):
        # Decode the token if it is encoded
        if encoded:
            token = self._get_decoded_token(token)

        # Check the token type
        self._check_token_type(token, "refresh")

        # Get the jti from the token claims
        token_jti = self._get_jti(token)
        # Read the refresh token data from the Redis cache
        token_data = self._get_token_data_dict(self._get_redis_value(token_jti))

        if token_data:
            # Delete the token from the Redis cache
            self._delete_redis_value(token_jti)
            self.app.logger.info("Refresh token (jti: '{}') successfully revoked from the active list.".
                                 format(token_jti))
        else:
            # Print a warning if the token was already revoked (not found in the Redis cache)
            self.app.logger.warning("Refresh token (jti: '{}') to revoke not found in the Redis cache. "
                                    "Considering it already revoked.".format(token_jti))
            return

        if revoke_associated_access_token:
            self.revoke_access_token({"jti": token_data.get("access_jti"), "type": "access"}, encoded=False)

    def update_refresh_associated_access_token(self, refresh_token, new_access_token, access_encoded=True,
                                               refresh_encoded=True):
        # Decode the tokens if they are encoded
        if refresh_encoded:
            refresh_token = self._get_decoded_token(refresh_token)
        if access_encoded:
            new_access_token = self._get_decoded_token(new_access_token)

        # Get the refresh token jti from the token claims
        refresh_token_jti = self._get_jti(refresh_token)
        # Read the refresh token data from the Redis cache
        refresh_token_data = self._get_token_data_dict(self._get_redis_value(refresh_token_jti))

        # If the refresh token isn't in the active list, consider it already revoked
        if not refresh_token_data:
            raise BlacklistTokenNotFound("Refresh token (jti: '{}') not found in the blacklist cache. "
                                         "Maybe is already revoked.".format(refresh_token_jti))

        # Calculate the new refresh token expiration time to set in the redis cache
        refresh_token_expires_at = self._get_expiration_datetime(refresh_token)
        new_expiration_time = self._calculate_token_expiration_time(refresh_token_expires_at)

        # If the new token expiration time is 0, delete it from the active list and return
        if new_expiration_time.total_seconds() == 0:
            self.app.logger.info("The remaining refresh token (jti: '{}') expiration time is 0. "
                                 "Deleting it from the Redis cache.".format(refresh_token_jti))
            self._delete_redis_value(refresh_token_jti)
            return

        # Set a security margin of the expiration time
        new_expiration_time += self.refresh_expiration_time * 0.2

        # Revoke the old access token before setting up the new one
        self.revoke_access_token({"jti": refresh_token_data.get("access_jti"), "type": "access"}, encoded=False)

        # Add the new access token to the token active list
        new_access_token_jti = self.add_access_token(new_access_token)

        # Update the refresh token data with the new associated access token
        new_refresh_token_data = self._get_token_data_str("refresh", new_access_token_jti)
        self._set_redis_value(refresh_token_jti, new_refresh_token_data, new_expiration_time)

        self.app.logger.info("Refresh token (jti: '{}') associated access token successfully updated.".
                             format(refresh_token_jti))
