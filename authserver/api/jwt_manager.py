"""
This module defines the all the JWT manager object and the related decorators definition
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_jwt_extended import JWTManager as _JWTManager

from ..blacklist_manager import jwt_blacklist_manager


##########################
# JWT MANAGER DEFINITION #
##########################

class JWTManager(_JWTManager):
    """
    Added a non-protected method for setting up all the error handlers.
    Needed for working with the flask-restplus extension.
    """
    def set_error_handler_callbacks(self, app):
        self._set_error_handler_callbacks(app)


jwt_manager = JWTManager()


#########################
# JWT MANAGER CALLBACKS #
#########################

@jwt_manager.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return jwt_blacklist_manager.check_if_token_is_revoked(decrypted_token)
