#!/bin/bash

echo "🚀 Starting CyberGuard Container..."

# 1. Initialize Database
python3 setup_db.py

# 2. Start Sniffer in Background (&)
# We don't need 'sudo' inside Docker because Docker runs as root by default
python3 sniffer_service.py &

# 3. Start Web Dashboard
# Host 0.0.0.0 is required to be accessible outside the container
uvicorn web_app:app --host 0.0.0.0 --port 8000