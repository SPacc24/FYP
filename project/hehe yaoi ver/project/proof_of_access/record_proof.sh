#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 TICKET_FILE VALIDATOR_URL [OUTPUT_DIR]" >&2
    exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT_DIR=${3:-./proof-of-access}

python3 "$SCRIPT_DIR/record_proof.py" \
    --ticket-file "$1" \
    --validator-url "$2" \
    --output-dir "$OUTPUT_DIR"
