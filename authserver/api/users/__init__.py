"""
This module defines the all the api resources for the users namespace
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from .definitions import api
from .models import (
    user_model, user_data_model, user_register_model, user_credentials_model, edit_user_model, authorization_data_model
)
from .resources import (
    User, Users, UserLogin, UserAccessRefresh, UserAuthorization, UserCheckAccessToken, UserCheckRefreshToken,
    UserLogout, CurrentUser
)
