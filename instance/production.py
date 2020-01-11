"""
Production config file of the Flask App.
"""

import datetime

from .config import Config as _Config


class Config(_Config):
    DEBUG = 0
    ENV = "production"

    SQLALCHEMY_BINDS = {
        'app': 'postgresql+psycopg2://postgres:7T#uZqxfL[z%,GGA@queue-manager-database.cdsfc1sk270d.eu-west-1.rds.amazonaws.com/app',
        'auth': 'postgresql+psycopg2://postgres:7T#uZqxfL[z%,GGA@queue-manager-database.cdsfc1sk270d.eu-west-1.rds.amazonaws.com/auth'
    }

    REDIS_SERVER_HOST = 'queue-manager-redis.kklcm3.0001.euw1.cache.amazonaws.com'

    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)
    with open("/etc/auth-server/keys/jwt.key", "r") as f:
        JWT_PRIVATE_KEY = f.read()
    with open("/etc/auth-server/keys/jwt.key.pub", "r") as f:
        JWT_PUBLIC_KEY = f.read()

    CORS_ALLOWED_ORIGINS = ["http://queuemanagerbcn3d.ml", "http://www.queuemanagerbcn3d.ml"]
