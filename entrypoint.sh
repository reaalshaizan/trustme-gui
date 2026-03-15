#!/bin/sh
# Fix /app/reports permissions at runtime.
# Volume mounts overwrite container dir ownership with host dir ownership.
# This script runs as root, fixes perms, then drops to trustme (uid 1000).

mkdir -p /app/reports
chown 1000:1000 /app/reports 2>/dev/null || chmod 777 /app/reports

# Drop privileges and exec the app (gosu is installed in the image)
exec gosu trustme python3 server.py
