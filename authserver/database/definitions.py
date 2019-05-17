"""
This module defines the all the global variables needed by the database module
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_sqlalchemy import SQLAlchemy


#################################
# SQLALCHEMY CONNECTION MANAGER #
#################################

db_conn = SQLAlchemy()
