"""
This module implements the database initializers and the tables population data.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from sqlalchemy.event import listens_for

from .definitions import db_conn as db
from .initial_values import (
    user_initial_values, printer_initial_values
)
from .models import (
    UserAuth, PrinterAuth
)


def _add_rows(row_list):
    for row in row_list:
        db.session.add(row)
    db.session.commit()


########################
# USER TABLE LISTENERS #
########################

@listens_for(UserAuth.__table__, "after_create")
def insert_initial_values(*_args, **_kwargs):
    _add_rows(user_initial_values())


###########################
# PRINTER TABLE LISTENERS #
###########################

@listens_for(PrinterAuth.__table__, "after_create")
def insert_initial_values(*_args, **_kwargs):
    _add_rows(printer_initial_values())
