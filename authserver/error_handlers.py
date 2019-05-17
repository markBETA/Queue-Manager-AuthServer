"""
This module sets all the exception handlers of this application
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import jsonify
from werkzeug.exceptions import HTTPException

from .blacklist_manager import BlacklistManagerError
from .database import DBManagerError


def set_exception_handlers(app, from_api=False):
    if not from_api:
        @app.errorhandler(HTTPException)
        def http_exception_handler(e):
            return jsonify({"message": str(e.description)}), e.code

    @app.errorhandler(DBManagerError)
    def db_manager_error_handler(_e):
        return jsonify({'message': 'Unable to read/write data at the database.'}), 500

    @app.errorhandler(BlacklistManagerError)
    def blacklist_manager_error(e):
        return jsonify({'message': str(e)}), 500
