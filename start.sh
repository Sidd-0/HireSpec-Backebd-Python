#!/bin/sh
# Startup script for gunicorn - ensures PORT variable is properly expanded
exec gunicorn --bind "0.0.0.0:${PORT:-5000}" --workers 2 --threads 4 --timeout 120 app:app
