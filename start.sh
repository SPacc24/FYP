#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$ROOT_DIR/project/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/project/.venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  printf '[ERROR] Python was not found. Create/activate a Python environment first.\n' >&2
  exit 1
fi

cd "$ROOT_DIR/project"
exec "$PYTHON_BIN" app.py "$@"
