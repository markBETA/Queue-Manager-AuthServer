"""
This module sets all the exception handlers of this application
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask import jsonify
from werkzeug.exceptions import HTTPException

from .blacklist_manager import BlacklistManagerError
from .database.app import DBManagerError as AppDBManagerError, InvalidParameter as AppInvalidParameter
from .database.auth import DBManagerError as AuthDBManagerError, InvalidParameter as AuthInvalidParameter


def set_exception_handlers(app, from_api=False):
    if not from_api:
        @app.errorhandler(HTTPException)
        def http_exception_handler(e):
            return jsonify({"message": str(e.description)}), e.code

    @app.errorhandler(AppInvalidParameter)
    @app.errorhandler(AuthInvalidParameter)
    def db_manager_error_handler(e):
        return jsonify({'message': str(e)}), 400

    @app.errorhandler(AppDBManagerError)
    @app.errorhandler(AuthDBManagerError)
    def db_manager_error_handler(_e):
        return jsonify({'message': 'Unable to read/write data at the database.'}), 500

    @app.errorhandler(BlacklistManagerError)
    def blacklist_manager_error(e):
        return jsonify({'message': str(e)}), 500
