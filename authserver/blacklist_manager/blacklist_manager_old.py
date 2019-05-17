"""
This module contains the blacklist manager class.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import json
from datetime import datetime, timedelta

from flask_jwt_extended import get_jti
from redis import StrictRedis, exceptions as redis_exceptions

from .exceptions import (
    BlacklistTokenNotFound, RedisConnectionError, BlacklistManagerMissingConfigParams,
    BlacklistedRefreshToken
)


class JWTBlacklistManager(object):
    def __init__(self, app=None, strict_redis_class=StrictRedis):
        self.app = None
        self.redis_store = None
        self.strict_redis_class = strict_redis_class
        self.access_expiration_time = None
        self.refresh_expiration_time = None

        if app is not None:
            self.init_app(app)

    def _get_redis_value(self, key=""):
        try:
            return self.redis_store.get(key)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            raise RedisConnectionError("Can't connect to the Redis shared cache")
        except redis_exceptions.RedisError:
            raise RedisConnectionError("Can't execute the GET method at the Redis shared cache")

    def _set_redis_value(self, key, value, expiration_time):
        try:
            return self.redis_store.set(key, value, expiration_time)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            raise RedisConnectionError("Can't connect to the Redis shared cache")
        except redis_exceptions.RedisError:
            raise RedisConnectionError("Can't execute the SET method at the Redis shared cache")

    def _delete_redis_value(self, key):
        try:
            return self.redis_store.delete(key)
        except (redis_exceptions.ConnectionError, redis_exceptions.BusyLoadingError):
            raise RedisConnectionError("Can't connect to the Redis shared cache")
        except redis_exceptions.RedisError:
            raise RedisConnectionError("Can't execute the DELETE method at the Redis shared cache")

    @staticmethod
    def _get_jti(token, encoded):
        if encoded:
            return get_jti(encoded_token=token)
        else:
            return token.get('jti')

    @staticmethod
    def _get_token_data_str(expires_at: datetime, token_type, blacklisted=False, access_jti=None):
        if token_type == "access" and access_jti is not None:
            raise Exception("An access token can't have an associated access token")
        elif token_type == "refresh" and access_jti is None:
            raise Exception("A refresh token need an associated access token")

        data = {
            "expires_at": expires_at.timestamp(),
            "blacklisted": blacklisted,
            "token_type": token_type,
            "access_jti": access_jti
        }
        return json.dumps(data)

    @staticmethod
    def _get_token_data_dict(data_str: str):
        if data_str:
            data = json.loads(data_str)
            data["expires_at"] = datetime.fromtimestamp(data["expires_at"])
            return data
        else:
            return None

    @staticmethod
    def _calculate_token_expiration_time(expires_at: datetime):
        now = datetime.now()
        if expires_at > now:
            return expires_at - now
        else:
            return timedelta(seconds=0)

    @staticmethod
    def _calculate_token_expiration_date(expiration_time: timedelta):
        return datetime.now() + expiration_time

    def _add_access_token(self, access_token, encoded=False):
        access_jti = self._get_jti(access_token, encoded)
        access_expiration_date = self._calculate_token_expiration_date(self.access_expiration_time)
        access_data = self._get_token_data_str(access_expiration_date, "access")
        self._set_redis_value(access_jti, access_data, self.access_expiration_time * 1.2)

        return access_jti

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
        self._get_redis_value()

    def check_if_token_is_revoked(self, token, encoded=False):
        """
        Create our function to check if a token has been blacklisted. In this simple
        case, we will just store the tokens jti (unique identifier) in redis
        whenever we create a new token (with the revoked status being 'false'). This
        function will return the revoked status of a token. If a token doesn't
        exist in this store, we don't know where it came from (as we are adding newly
        created tokens to our store with a revoked status of 'false'). In this case
        we will consider the token to be revoked, for safety purposes.

        :param token:
        :param encoded:
        :return:
        """
        jti = self._get_jti(token, encoded)
        entry = self._get_redis_value(jti)

        if entry is None:
            return True
        else:
            return bool(json.loads(entry)["blacklisted"])

    def add_token_set(self, access_token, refresh_token, access_encoded=True, refresh_encoded=True):
        access_jti = self._add_access_token(access_token, access_encoded)

        refresh_jti = self._get_jti(refresh_token, refresh_encoded)
        refresh_expiration_date = self._calculate_token_expiration_date(self.refresh_expiration_time)
        refresh_data = self._get_token_data_str(refresh_expiration_date, "refresh", access_jti=access_jti)
        self._set_redis_value(refresh_jti, refresh_data, self.refresh_expiration_time * 1.2)

        current_app.logger.info("Token '{}' a")

    def revoke_access_token(self, token, encoded=True):
        token_jti = self._get_jti(token, encoded)
        token_data = self._get_token_data_dict(self._get_redis_value(token_jti))

        if not token_data:
            raise BlacklistTokenNotFound("Token not found in the blacklist cache")

        new_expiration_time = self._calculate_token_expiration_time(token_data["expires_at"])

        if new_expiration_time.total_seconds() > 0:
            token_data["blacklisted"] = True
            new_token_data = self._get_token_data_str(**token_data)
            self._set_redis_value(token_jti, new_token_data, new_expiration_time * 1.2)
        else:
            self._delete_redis_value(token_jti)

    def revoke_refresh_token(self, token, encoded=True, revoke_associated_access_token=True):
        token_jti = self._get_jti(token, encoded)
        token_data = self._get_token_data_dict(self._get_redis_value(token_jti))

        if not token_data:
            raise BlacklistTokenNotFound("Token not found in the blacklist cache")

        new_expiration_time = self._calculate_token_expiration_time(token_data["expires_at"])

        if new_expiration_time.total_seconds() > 0:
            token_data["blacklisted"] = True
            new_token_data = self._get_token_data_str(**token_data)
            self._set_redis_value(token_jti, new_token_data, new_expiration_time * 1.2)
        else:
            self._delete_redis_value(token_jti)

        if revoke_associated_access_token:
            try:
                self.revoke_access_token({"jti": token_data["access_jti"]}, encoded=False)
            except BlacklistTokenNotFound:
                pass

    def update_refresh_associated_access_token(self, refresh_token, new_access_token, access_encoded=True,
                                               refresh_encoded=True):
        refresh_token_jti = self._get_jti(refresh_token, refresh_encoded)
        refresh_token_data = self._get_token_data_dict(self._get_redis_value(refresh_token_jti))

        new_expiration_time = self._calculate_token_expiration_time(refresh_token_data["expires_at"])

        if not new_expiration_time.total_seconds() > 0:
            self._delete_redis_value(refresh_token_jti)
            return

        if not refresh_token_data:
            raise BlacklistTokenNotFound("Refresh token not found in the blacklist cache")
        elif refresh_token_data["blacklisted"]:
            raise BlacklistedRefreshToken("The refresh token is blacklisted and can't be updated anymore")

        try:
            self.revoke_access_token({"jti": refresh_token_data["access_jti"]}, encoded=False)
        except BlacklistTokenNotFound:
            pass

        new_access_token_jti = self._add_access_token(new_access_token, access_encoded)

        refresh_token_data["access_jti"] = new_access_token_jti
        new_refresh_token_data = self._get_token_data_str(**refresh_token_data)
        self._set_redis_value(refresh_token_jti, new_refresh_token_data, new_expiration_time * 1.2)
