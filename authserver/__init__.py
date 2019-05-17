"""
This server manages the authentication process of the Queue Manager application server
In this package has all needed modules for the mentioned server.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from eventlet import monkey_patch

monkey_patch()


def create_app(name=__name__, override_config=None, init_db_manager_values=False):
    """Create and configure an instance of the Flask application."""
    from flask import Flask
    app = Flask(name, instance_relative_config=True)

    from flask_cors import CORS
    CORS(app)

    if override_config is None:
        # Load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(override_config)

    from logging import INFO, DEBUG

    # Set the logger level
    if app.config.get("DEBUG") > 1:
        app.logger.setLevel(DEBUG)
    else:
        app.logger.setLevel(INFO)

    # Set the exception handlers
    from .error_handlers import set_exception_handlers
    set_exception_handlers(app)

    # Register the database commands
    from .database import init_app as db_init_app
    db_init_app(app)

    # Init blacklist manager
    from .blacklist_manager import jwt_blacklist_manager
    jwt_blacklist_manager.init_app(app)

    # Register the API blueprint
    from .api import init_app as api_init_app
    api_init_app(app)

    if init_db_manager_values:
        # Init the database manager
        with app.app_context():
            from .database import db_mgr
            db_mgr.init_static_values()

    return app
