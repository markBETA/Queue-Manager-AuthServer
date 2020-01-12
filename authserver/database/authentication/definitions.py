"""
This module defines the all the global variables needed by the database module
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import click

from flask import current_app
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy


#################################
# SQLALCHEMY CONNECTION MANAGER #
#################################

try:
    from ..definitions import db_conn
except ImportError:
    db_conn = SQLAlchemy()


#####################
# DATABASE BIND KEY #
#####################

bind_key = "auth"


########################
# DATABASE INITIALIZER #
########################

def init_db(app):
    """Clear existing data and create new tables."""
    with app.app_context():
        db_conn.drop_all(bind=bind_key)
        db_conn.create_all(bind=bind_key)


@click.command('init-'+bind_key+'-db')
@with_appcontext
def init_db_command():
    """Register the 'init-db' command to use it with the Flask command interface."""
    init_db(current_app)
    click.echo('Database created successfully.')
