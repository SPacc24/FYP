#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -x "$PROJECT_DIR/.venv/bin/python" ]]; then
  printf '[ERROR] Virtual environment missing. Run: bash install.sh\n' >&2
  exit 1
fi

cd "$PROJECT_DIR"
exec "$PROJECT_DIR/.venv/bin/python" app.py "$@"
