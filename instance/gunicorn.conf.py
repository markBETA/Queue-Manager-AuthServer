# coding=utf-8

# Set the logger configuration
loglevel = 'info'

# Configure the socket address and the number of workers
worker_class = 'eventlet'

timeout = 3 * 60  # 3 minutes
keepalive = 24 * 60 * 60  # 1 day
