#!/bin/bash
# Kill existing processes if they are running
pkill -f "python.*server.py" || true
pkill -f "python.*app.py" || true
sleep 1

source venv/bin/activate
export PYTHONUNBUFFERED=1
python3 server.py > logs/server_out.log 2>&1 &
python3 app.py > logs/app_out.log 2>&1 &
echo "Processes started."
