"""
This module can build a new database according to the structure defined in the 'database' module.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import os

if __name__ == '__main__':
    os.makedirs('./data', exist_ok=True)

    from flask import Flask

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_pyfile('config.py', silent=True)
    app.app_context().push()

    from authserver.database import init_app, init_db
    init_app(app)
    init_db()
