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

from .definitions import db_conn as db, bind_key, init_db, init_db_command
from .listeners import (
    user_initial_values, printer_initial_values
)
from .manager import db_mgr
from .manager import (
    DBManager, DBManagerError, InvalidParameter, DBInternalError, UniqueConstraintError
)
from .models import (
    UserAuth, PrinterAuth
)


def init_app(app, *args, **kwargs):
    """Initializes the app context for the database operation."""
    # Initialize the database connection instance
    db.init_app(app, *args, **kwargs)
    db.engine.pool._use_threadlocal = True
    app.cli.add_command(init_db_command)
    # Initialize the database manager instance
    db_mgr.init_app(app)
