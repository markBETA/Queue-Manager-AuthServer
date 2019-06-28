# coding=utf-8
import os

# Read the root folder
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_RUN = os.path.join(_ROOT, 'run/')

# Create the 'run' if don't exist
if not os.path.exists(_RUN):
    os.mkdir(_RUN)

# Set the logger configuration
loglevel = 'info'

# Configure the socket address and the number of workers
bind = 'unix:%s' % os.path.join(_ROOT, 'run/gunicorn.sock')
worker_class = 'eventlet'

timeout = 3 * 60  # 3 minutes
keepalive = 24 * 60 * 60  # 1 day
