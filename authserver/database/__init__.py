"""
This module implements the database structure and the model classes. Also implements
the database initializers.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from .application import db_mgr as app_db_mgr
from .application.definitions import init_db_command as app_init_db_command
from .authentication.definitions import init_db_command as auth_init_db_command
from .authentication import db_mgr as auth_db_mgr
from .definitions import db_conn as db


def init_app(app, *args, **kwargs):
    """Initializes the app context for the database operation."""
    # Initialize the database connection instance
    db.init_app(app, *args, **kwargs)
    db.engine.pool._use_threadlocal = True
    app.cli.add_command(app_init_db_command)
    app.cli.add_command(auth_init_db_command)
    # Initialize the database manager instances
    app_db_mgr.init_app(app)
    auth_db_mgr.init_app(app)
