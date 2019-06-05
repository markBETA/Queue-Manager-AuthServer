#!/usr/bin/env bash

source venv/bin/activate
gunicorn wsgi:app --worker-class eventlet --bind 0.0.0.0:5001
