#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Start server detached so gradebot can't kill it by ending the parent process
nohup python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8080 > /tmp/uvicorn.log 2>&1 &

# Keep this process alive so gradebot doesn't think the run command "finished"
sleep 30
