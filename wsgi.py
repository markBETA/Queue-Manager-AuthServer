"""
This file implements the way to run the server from a WSGI server
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from authserver import create_app

app = create_app(__name__, init_db_manager_values=True)

if __name__ == "__main__":
    from eventlet import wsgi, listen
    wsgi.server(listen(('0.0.0.0', 5001)), app)
