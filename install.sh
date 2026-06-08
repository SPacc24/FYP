#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

printf '[*] Updating apt metadata...\n'
apt-get update -y

printf '[*] Installing required Kali enumeration tools...\n'
apt-get install -y --no-install-recommends \
  arp-scan nmap bind9-dnsutils jq gobuster enum4linux-ng smbclient smbmap \
  snmp ldap-utils sslscan mtr-tiny traceroute hydra seclists git \
  python3 python3-venv python3-pip libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi-dev shared-mime-info

printf '[*] Installing optional Kali enumeration helpers where available...\n'
apt-get install -y --no-install-recommends snmp-mibs-downloader || printf '[WARN] snmp-mibs-downloader unavailable; SNMP enumeration still works without downloaded MIB names.\n'
apt-get install -y --no-install-recommends ssh-audit || printf '[WARN] ssh-audit unavailable from apt; SSH evidence source will be marked unavailable if command is missing.\n'
apt-get install -y --no-install-recommends httpx-toolkit || printf '[WARN] httpx-toolkit unavailable from apt; Nmap HTTP scripts remain the HTTP fallback evidence source.\n'
apt-get install -y --no-install-recommends rdpscan || printf '[WARN] rdpscan is not available in this Kali repo; RDP enumeration will use Nmap RDP scripts when RDP is observed.\n'

printf '[*] Creating Python virtual environment...\n'
cd project
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

printf '[*] Preparing storage directories...\n'
mkdir -p storage/scans storage/results storage/mitre_cve

printf '[*] Syncing official CVE List mirror from CVEProject/cvelistV5 if network is available...\n'
python scripts/sync_mitre_cve_database.py || {
  printf '[WARN] Official CVE List sync did not complete. The app still runs; run this later:\n'
  printf '       cd project && . .venv/bin/activate && python scripts/sync_mitre_cve_database.py\n'
}

printf '\n[+] Install complete. Start the app with:\n'
printf '    cd project && sudo .venv/bin/python app.py\n'
