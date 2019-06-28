"""
This module defines the all the global variables needed by the users namespace
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_restplus import Namespace


NAMESPACE_IDENTIFIER = "users"
NAMESPACE_DESCRIPTION = "User authentication related operations"


################################
# NAMESPACE OBJECT DECLARATION #
################################

api = Namespace(NAMESPACE_IDENTIFIER, description=NAMESPACE_DESCRIPTION)
