#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$ROOT_DIR/project"
PYTHON_BIN="${PYTHON_BIN:-python3}"

SUDO=()
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO=(sudo)
fi

log() { printf '\n[*] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }

cd "$ROOT_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  printf '[ERROR] %s was not found. Install Python 3.10+ first.\n' "$PYTHON_BIN" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" ]] && command -v apt-get >/dev/null 2>&1; then
  log "Updating apt metadata"
  "${SUDO[@]}" apt-get update -y

  log "Installing required reconnaissance/reporting dependencies"
  "${SUDO[@]}" apt-get install -y --no-install-recommends \
    arp-scan nmap bind9-dnsutils jq gobuster enum4linux-ng smbclient smbmap \
    snmp ldap-utils sslscan mtr-tiny traceroute hydra seclists git \
    tshark rpcbind nfs-common postgresql-client curl openssl \
    iputils-ping iputils-tracepath python3 python3-venv python3-pip \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi-dev shared-mime-info \
    mysql-client

  log "Installing optional enumeration helpers"
  "${SUDO[@]}" apt-get install -y --no-install-recommends snmp-mibs-downloader \
    || warn "snmp-mibs-downloader unavailable; SNMP enumeration can still run without downloaded MIB names."
  "${SUDO[@]}" apt-get install -y --no-install-recommends ssh-audit \
    || warn "ssh-audit unavailable; SSH evidence source will be marked unavailable if the command is missing."
  "${SUDO[@]}" apt-get install -y --no-install-recommends httpx-toolkit \
    || warn "httpx-toolkit unavailable; Nmap HTTP scripts remain the HTTP fallback."
  "${SUDO[@]}" apt-get install -y --no-install-recommends rdpscan \
    || warn "rdpscan unavailable; RDP enumeration will use Nmap RDP scripts when applicable."
else
  warn "Automatic apt dependency installation is only supported on Debian/Kali-style Linux. Continuing with Python setup."
fi

log "Creating Python virtual environment"
cd "$PROJECT_DIR"
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements.txt

log "Preparing storage directories"
mkdir -p storage/scans storage/results storage/mitre_cve storage/msrc storage/msrc_windows storage/nvd_cache storage/missions

log "Creating complete local .env configuration"
.venv/bin/python runtime_env.py

log "Checking core external tooling"
if ! .venv/bin/python scripts/check_tooling.py; then
  warn "Some core external tools are unavailable. The Flask application can still start, but live scanning may be limited."
fi

log "Syncing the official CVE List mirror when network access is available"
.venv/bin/python scripts/sync_mitre_cve_database.py || warn "CVE List sync did not complete. Retry later with: ./project/.venv/bin/python project/scripts/sync_mitre_cve_database.py"

log "Caching recent Microsoft Security Update Guide data"
.venv/bin/python scripts/sync_msrc_security_updates.py --months 3 || warn "MSRC cache sync did not complete. Retry later if Windows remediation data is required."

CURRENT_YEAR="$(date +%Y)"
MSRC_HISTORY_YEARS="$(.venv/bin/python - <<'PY'
from pathlib import Path
import re
p = Path('.env')
for line in p.read_text(encoding='utf-8').splitlines():
    if line.startswith('MSRC_HISTORY_YEARS='):
        print(line.split('=', 1)[1].strip())
        break
else:
    print('15')
PY
)"
MSRC_START_YEAR=$((CURRENT_YEAR - MSRC_HISTORY_YEARS))
log "Building Microsoft Windows advisory history"
.venv/bin/python scripts/rebuild_msrc_windows_index.py --start-year "$MSRC_START_YEAR" || warn "Microsoft advisory index was not built. The scanner can still run with available CVE data."

cd "$ROOT_DIR"
printf '\n[+] Setup complete.\n'
printf '    Start the application with: ./start.sh\n'
printf '    Show local generated secrets: ./project/.venv/bin/python project/runtime_env.py --show-secrets\n'
printf '    Do not commit project/.env.\n'
