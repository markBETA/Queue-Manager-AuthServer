"""
Config file of the Flask App.
"""

import datetime
import os

DEBUG = int(os.getenv('DEBUG', 0))
ENV = "development" if DEBUG > 0 else "production"

# SECRET_KEY = os.getenv('SECRET_KEY', 'my_secret_key')

SQLALCHEMY_BINDS = {
    'app': 'postgresql+psycopg2://postgres:dev@postgres.dev.server/app',
    'auth': 'postgresql+psycopg2://postgres:dev@postgres.dev.server/auth'
}
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = False

RESTPLUS_VALIDATE = True
SWAGGER_UI_DOC_EXPANSION = 'list'

REDIS_SERVER_HOST = 'redis.dev.server'
REDIS_SERVER_PORT = 6379
TOKEN_BLACKLIST_REDIS_DB = 0

JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(seconds=45)
JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)
JWT_BLACKLIST_ENABLED = True
JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
JWT_ERROR_MESSAGE_KEY = "message"
JWT_IDENTITY_CLAIM = "sub"
JWT_ALGORITHM = "RS256"
with open("instance/jwt.key", "r") as f:
    JWT_PRIVATE_KEY = f.read()
with open("instance/jwt.key.pub", "r") as f:
    JWT_PUBLIC_KEY = f.read()
