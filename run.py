#!/usr/bin/env python3
"""Startup script that reads PORT from environment and launches gunicorn."""
import os
import subprocess
import sys

port = os.environ.get('PORT', '5000')
cmd = [
    'gunicorn',
    '--bind', f'0.0.0.0:{port}',
    '--workers', '2',
    '--threads', '4',
    '--timeout', '120',
    'app:app'
]
print(f"Starting gunicorn on port {port}...")
sys.exit(subprocess.call(cmd))
