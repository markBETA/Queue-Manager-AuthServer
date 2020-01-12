"""
Production config file of the Flask App.
"""

from .config import Config as _Config


class Config(_Config):
    DEBUG = 0
    ENV = "production"
