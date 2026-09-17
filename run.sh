#!/usr/bin/env bash
# run.sh — Launch the EDR Dashboard
# Usage:
#   ./run.sh          # replay mode (no root needed)
#   sudo ./run.sh     # live mode (tails /var/log/audit/audit.log)

set -e
cd "$(dirname "$0")"

VENV_PYTHON=".venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
  echo "No .venv found — running: uv sync"
  uv sync
fi

exec "$VENV_PYTHON" ui/app.py "$@"
