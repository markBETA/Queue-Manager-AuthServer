"""
This server manages the authentication process of the Queue Manager authentication server
In this package has all needed modules for the mentioned server.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from eventlet import monkey_patch
monkey_patch()


def create_app(name=__name__, testing=False, init_db_manager_values=False, enabled_modules="all"):
    """Create and configure an instance of the Flask application."""
    import os

    if enabled_modules == "all":
        enabled_modules = {
            "flask-cors",
            "error-handlers",
            "auth-database",
            "app-database",
            "blacklist-manager",
            "api"
        }

    from flask import Flask
    app = Flask(name, instance_relative_config=True)

    if testing:
        # Load the instance testing config
        app.config.from_object("instance.testing.Config")
        os.environ["ENV"] = "testing"
    else:
        env = os.getenv("ENV", "production")
        if env == "development":
            # Load the instance development config
            app.config.from_object("instance.development.Config")
        elif env == "production":
            # Load the instance development config
            app.config.from_object("instance.production.Config")
        elif env == "production-dds":
            # Load the instance production config for the DDS servers
            app.config.from_object("instance.production-dds.Config")
        else:
            raise RuntimeError("Unknown environment '{}'".format(env))

    # If the application is loaded from gunicorn, use it's own logger
    if "gunicorn" in os.environ.get("SERVER_SOFTWARE", ""):
        import logging
        gunicorn_logger = logging.getLogger('gunicorn.error')
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)
    else:
        from logging import INFO, DEBUG
        # Set the logger level
        if app.config.get("DEBUG") > 1:
            app.logger.setLevel(DEBUG)
        else:
            app.logger.setLevel(INFO)

    app.logger.info("Loading server modules...")

    with app.app_context():
        # Register the app database commands
        if "app-database" in enabled_modules or "auth-database" in enabled_modules:
            from .database import init_app as db_init_app
            db_init_app(app)

        # Init the auth database manager
        if init_db_manager_values and "auth-database" in enabled_modules:
            from .database import auth_db_mgr
            auth_db_mgr.init_static_values()

        # Init the app database manager
        if init_db_manager_values and "app-database" in enabled_modules:
            from .database import app_db_mgr
            app_db_mgr.init_static_values()

        # Set the exception handlers
        if "error-handlers" in enabled_modules:
            from .error_handlers import set_exception_handlers
            set_exception_handlers(app)

        # Init blacklist manager
        if "blacklist-manager" in enabled_modules:
            from .blacklist_manager import jwt_blacklist_manager
            jwt_blacklist_manager.init_app(app)

        # Register the API blueprint
        if "api" in enabled_modules:
            from .api import init_app as api_init_app
            api_init_app(app)

        # Init Flask-CORS plugin
        if "flask-cors" in enabled_modules:
            kwargs = dict()
            if app.config['CORS_ALLOWED_ORIGINS'] is not None:
                kwargs["resources"] = {r"/api/*": {"origins": app.config['CORS_ALLOWED_ORIGINS']}}

            from flask_cors import CORS
            CORS(app, **kwargs)

    app.logger.info("Server modules loaded")

    return app
