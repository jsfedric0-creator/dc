#!/bin/bash

# Create directories
mkdir -p /app/data /tmp/hls /tmp/dash

# Initialize database
python3 -c "
from dashboard.app import init_db
init_db()
print('Database initialized')
"

# Start services
supervisord -c /etc/supervisor/conf.d/supervisord.conf
