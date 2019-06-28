"""
This module implements the database structure and the model classes. Also implements
the database initializers.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import click
from flask import current_app
from flask.cli import with_appcontext

from .app import db_mgr as app_db_mgr
from .auth import db_mgr as auth_db_mgr
from .definitions import db_conn as db


########################
# DATABASE INITIALIZER #
########################

def init_db():
    """Clear existing data and create new tables."""
    with current_app.app_context():
        from .app import init_db as app_init_db
        from .auth import init_db as auth_init_db
        db.drop_all()
        db.create_all()


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Register the 'init-db' command to use it with the Flask command interface"""
    init_db()
    click.echo('Database created successfully.')


def init_app(app):
    """Initializes the app context for the database operation."""
    db.init_app(app)
    db.engine.pool._use_threadlocal = True
    app.cli.add_command(init_db_command)
