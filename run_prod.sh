#!/usr/bin/env bash

source venv/bin/activate
gunicorn wsgi:app --worker-class eventlet -w 4 --bind 0.0.0.0:5003
