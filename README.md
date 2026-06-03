# AutoPenTest

AutoPenTest is a Flask-based authorised lab assessment dashboard. It runs reconnaissance, normalises evidence, links official CVE List records where product/version evidence supports them, plans MITRE ATT&CK techniques with an optional local LLM, and can hand selected techniques to MITRE Caldera.

## What This Build Does

This build includes the v32.8 recon-module handoff fixes:

- Evidence collection and normalisation for Nmap, Gobuster, SMB, SSH, SNMP, LDAP, TLS, RDP, Hydra, and supporting tools.
- Official CVE List matching using the local CVEProject/cvelistV5 mirror.
- Service-centric Attack Surface Workbench with exposure evidence, CVE findings, candidate references, evidence gaps, and service-check evidence.
- HTML/PDF reports and JSON handoff output.
- Sanitised Hydra credential combos, safer command-output decoding, partial Gobuster result handling, improved SMB/Samba evidence merging, and clearer CVE wording.

Recon boundaries:

```text
footprinting
enumeration
evidence normalisation
official CVE List strict matching
service-level exposure checks
JSON/PDF handoff generation
```

The recon module does not score, rank, prioritise, exploit, or make execution decisions by itself.

## Quick Start On Kali

Place the project zip on the Kali desktop, then run:

```bash
cd /home/kali/Desktop
unzip AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31.zip
cd AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31
chmod +x install.sh
sudo ./install.sh
cd project
sudo .venv/bin/python app.py
```

Open:

```text
http://<kali-ip>:5000
```

If running locally on the same machine:

```text
http://127.0.0.1:5000
```

## Manual Python Setup

```bash
cd project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
```

## Environment

Create `project/.env` or export these variables:

```bash
SECRET_KEY=change-me
DEBUG=false

CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=your-caldera-api-key
ENABLE_CALDERA_EXECUTION=0
AGENT_GROUP=red
KALI_IP=192.168.x.x
OPERATION_TIMEOUT=180

OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
OLLAMA_TIMEOUT=180

MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=your-password
MYSQL_DB=autopentest

ENABLE_CONTEXT_FOOTPRINTING=0
ENABLE_ARP_SCAN=0
ENABLE_HTTPX=0
ENABLE_DEEP_WEB_DISCOVERY=0
ENABLE_SMBMAP=0
ENABLE_HYDRA=0
GOBUSTER_WORDLIST=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
HYDRA_CREDENTIAL_FILE=
MITRE_CVE_REPO=https://github.com/CVEProject/cvelistV5.git
```

MySQL is optional for the GUI to load, but database persistence requires a reachable MySQL server and the configured credentials.

## Scanning Tools

The Kali installer installs the main toolchain:

```bash
sudo apt-get install -y \
  arp-scan nmap bind9-dnsutils jq gobuster enum4linux-ng smbclient smbmap \
  snmp ldap-utils sslscan mtr-tiny traceroute hydra seclists git \
  python3 python3-venv python3-pip
```

Optional helpers are used when available:

```bash
sudo apt-get install -y ssh-audit httpx-toolkit rdpscan snmp-mibs-downloader
```

Check local tool availability:

```bash
cd project
source .venv/bin/activate
python scripts/check_tooling.py
```

## CVE Data

Sync or rebuild the official CVE List mirror:

```bash
cd project
source .venv/bin/activate
python scripts/sync_mitre_cve_database.py
python scripts/rebuild_mitre_cve_index.py
python scripts/mitre_cve_status.py
```

If CVE data looks stale or CVSS metadata is missing:

```bash
python scripts/audit_cve_source.py
```

## Ollama

Install and start Ollama, then pull the configured model:

```bash
ollama serve
ollama pull llama3.2:1b
```

The app uses Ollama for AI technique planning and the AI chat panel. If Ollama is unavailable, the app still runs and returns a safe unavailable message.

## Caldera

Start MITRE Caldera separately and configure `CALDERA_URL` plus `CALDERA_API_KEY`. The dashboard checks agent readiness for the scanned target IP and shows a copyable deploy command when no trusted agent is matched.

Typical flow:

```bash
cd /path/to/caldera
python3 server.py --insecure
```

Then in AutoPenTest:

1. Run a scan.
2. Open the dashboard.
3. Use the Caldera panel to refresh agent status.
4. Copy the deploy command into the authorised lab target if needed.
5. Select techniques and run Caldera only when execution is explicitly enabled and authorised.

## Testing

From repository root:

```bash
pytest -q
python -m py_compile project/app.py project/config.py project/storage/*.py project/scanners/*.py project/scripts/*.py
python project/scripts/audit_no_scoring.py
python project/scripts/audit_cve_source.py
```

## Project Layout

```text
project/
  app.py                 Flask routes and dashboard endpoints
  ai/                    Ollama client, AI planner, safety filters
  caldera/               Caldera API client and operation manager
  exploitation/          Lab-safe validation helpers
  mapping/               MITRE ATT&CK mapping helpers
  reports/               Text report generation
  scanners/              Recon pipeline, parsers, tooling, CVE matching
  scripts/               Tool checks and CVE index maintenance
  storage/               Runtime scan state and database helpers
  templates/             Dashboard HTML
  static/                CSS and browser JavaScript
  tests/                 Pytest coverage
```
