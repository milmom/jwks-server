#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Start uvicorn in background
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8080 > /tmp/uvicorn.log 2>&1 &
UVICORN_PID=$!

# Wait up to ~5 seconds for the port to open
python3 - <<'PY'
import socket, time, sys
host, port = "127.0.0.1", 8080
for _ in range(50):  # 50 * 0.1s = 5s
    try:
        with socket.create_connection((host, port), timeout=0.2):
            sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY

# If readiness failed, show logs and exit nonzero
if ! python3 - <<'PY'
import socket
try:
    with socket.create_connection(("127.0.0.1", 8080), timeout=0.2):
        raise SystemExit(0)
except OSError:
    raise SystemExit(1)
PY
then
  tail -n 200 /tmp/uvicorn.log || true
  kill "$UVICORN_PID" || true
  exit 1
fi

# Keep process alive for gradebot by waiting on uvicorn
wait "$UVICORN_PID"
