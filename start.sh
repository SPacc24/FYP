#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$ROOT_DIR/project"
PYTHON="$PROJECT_DIR/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  printf '[ERROR] Python virtual environment is missing.\n' >&2
  printf 'Run: ./install.sh\n' >&2
  exit 1
fi

cd "$PROJECT_DIR"

# Make sure .env is complete before Config is imported by app.py.
"$PYTHON" runtime_env.py >/dev/null

exec "$PYTHON" app.py "$@"


#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "$ROOT_DIR/project/.venv/bin/python" ]]; then
  printf '[ERROR] Project virtual environment is missing or incomplete.\n' >&2
  printf 'Run this first: cd "%s" && bash install.sh\n' "$ROOT_DIR" >&2
  exit 1
fi

cd "$ROOT_DIR/project"
exec "$ROOT_DIR/project/.venv/bin/python" app.py "$@"
