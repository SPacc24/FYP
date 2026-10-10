#!/usr/bin/env bash
# Starts the Metasploit RPC daemon for PenPilot using the password from project/.env.
# Reading the value via python-dotenv guarantees it matches what the Flask app uses.
set -euo pipefail

PROJECT_DIR="/home/kali/Documents/IHL/FYP/project"
cd "$PROJECT_DIR"

MPASS="$("$PROJECT_DIR/.venv/bin/python" -c "from dotenv import dotenv_values; print(dotenv_values('.env')['METASPLOIT_RPC_PASS'])")"

exec msfrpcd -U msf -P "$MPASS" -p 55552 -a 127.0.0.1 -f
