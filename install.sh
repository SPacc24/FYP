#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

SUDO=''
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  SUDO='sudo'
fi

printf '[*] Updating apt metadata...\n'
$SUDO apt-get update -y

printf '[*] Installing required Kali enumeration tools...\n'
$SUDO apt-get install -y --no-install-recommends \
  arp-scan nmap bind9-dnsutils jq gobuster enum4linux-ng smbclient smbmap \
  snmp sshpass proxychains4 ldap-utils sslscan mtr-tiny traceroute hydra seclists git \
  tshark rpcbind nfs-common postgresql-client curl openssl iputils-ping iputils-tracepath \
  python3 python3-venv python3-pip libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi-dev shared-mime-info libcap2-bin

printf '[*] Preparing scoped ARP discovery capability...\n'
ARP_SCAN_BIN="$(command -v arp-scan || true)"
if [ -n "$ARP_SCAN_BIN" ]; then
  $SUDO setcap cap_net_raw,cap_net_admin=eip "$ARP_SCAN_BIN" || \
    printf '[WARN] Could not grant packet-socket capability to arp-scan. ARP execution will be reported as unavailable if privileges are insufficient.\n'
else
  printf '[WARN] arp-scan was not found after installation.\n'
fi

printf '[*] Preparing bounded packet-capture capability for supplemental topology evidence...\n'
DUMPCAP_BIN="$(command -v dumpcap || true)"
if [ -n "$DUMPCAP_BIN" ]; then
  $SUDO setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP_BIN" || \
    printf '[WARN] Could not grant packet-capture capability to dumpcap. Supplemental passive topology evidence will be reported as unavailable if capture permission is denied.\n'
else
  printf '[WARN] dumpcap was not found after tshark installation. Supplemental passive topology evidence will be unavailable.\n'
fi

printf '[*] Installing optional Kali enumeration helpers where available...\n'
$SUDO apt-get install -y --no-install-recommends snmp-mibs-downloader || printf '[WARN] snmp-mibs-downloader unavailable; SNMP enumeration still works without downloaded MIB names.\n'
$SUDO apt-get install -y --no-install-recommends ssh-audit || printf '[WARN] ssh-audit unavailable from apt; SSH evidence source will be marked unavailable if command is missing.\n'
$SUDO apt-get install -y --no-install-recommends httpx-toolkit || printf '[WARN] httpx-toolkit unavailable from apt; Nmap HTTP scripts remain the HTTP fallback evidence source.\n'
$SUDO apt-get install -y --no-install-recommends rdpscan || printf '[WARN] rdpscan is not available in this Kali repo; RDP enumeration will use Nmap RDP scripts when RDP is observed.\n'

printf '[*] Creating Python virtual environment...\n'
cd project
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

printf '[*] Preparing storage directories...\n'
mkdir -p storage/scans storage/results storage/mitre_cve storage/msrc storage/msrc_windows storage/nvd_cache

printf '[*] Creating local runtime configuration...\n'
python runtime_env.py

printf '[*] Syncing official CVE List mirror from CVEProject/cvelistV5 if network is available...\n'
# If a previous run was interrupted (Ctrl+C, no disk space, no network partway
# through), storage/mitre_cve/cvelistV5 can be left behind without a .git
# directory. sync_mitre_cve_database.py now auto-recovers from this itself,
# but we also guard here so a re-run of install.sh never inherits a stale
# half-cloned folder.
if [ -d storage/mitre_cve/cvelistV5 ] && [ ! -d storage/mitre_cve/cvelistV5/.git ]; then
  printf '[*] Removing incomplete CVE List clone from a previous run...\n'
  rm -rf storage/mitre_cve/cvelistV5
fi
python scripts/sync_mitre_cve_database.py || {
  printf '[WARN] Official CVE List sync did not complete. The app still runs; run this later:\n'
  printf '       cd project && . .venv/bin/activate && python scripts/sync_mitre_cve_database.py\n'
}

printf '[*] Caching recent Microsoft Security Update Guide data for Windows remediation checks if network is available...\n'
python scripts/sync_msrc_security_updates.py --months 3 || {
  printf '[WARN] Microsoft remediation cache sync did not complete. Targeted lookups can retry during a later scan, or run:\n'
  printf '       cd project && . .venv/bin/activate && python scripts/sync_msrc_security_updates.py --months 3\n'
}

printf '[*] Building Microsoft Windows advisory history if network is available...\n'
CURRENT_YEAR="$(date +%Y)"
MSRC_HISTORY_YEARS="${MSRC_HISTORY_YEARS:-15}"
MSRC_START_YEAR="$((CURRENT_YEAR - MSRC_HISTORY_YEARS))"
python scripts/rebuild_msrc_windows_index.py --start-year "$MSRC_START_YEAR" || {
  printf '[WARN] The Windows advisory applicability index was not built. The scanner still runs with the CVE List index.\n'
  printf '       Retry later: cd project && . .venv/bin/activate && python scripts/rebuild_msrc_windows_index.py --start-year %s\n' "$MSRC_START_YEAR"
}

printf '\n[+] Install complete. Start the app with:\n'
printf '    bash start.sh\n'
