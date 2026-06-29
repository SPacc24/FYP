# AutoPenTest

AutoPenTest is a Flask-based Final Year Project dashboard for authorised lab assessment, reconnaissance evidence collection, MITRE ATT&CK planning, lab-safe validation, CALDERA handoff, and remediation-focused reporting.

This project is intended only for owned or explicitly authorised cyber range and lab environments.

## Current Features

- Web dashboard for scan setup, progress tracking, results review, ATT&CK technique selection, CALDERA execution, validation evidence, AI chat, and report export.
- Async reconnaissance pipeline for Nmap, Gobuster, SMB, SSH, SNMP, LDAP, TLS, RDP, Hydra, and supporting tools where available.
- Evidence normalisation for hosts, services, command logs, tool coverage, candidate references, and handoff JSON.
- Official CVE List matching using a local CVEProject/cvelistV5 mirror, with strict product/version evidence checks.
- Service-centric Attack Surface Workbench with confirmed CVEs, candidate CVE references, evidence gaps, and service-check output.
- MITRE ATT&CK mapping and optional Ollama-assisted technique planning with deterministic fallback.
- CALDERA integration for agent readiness checks, Sandcat deploy-command display, ability coverage checks, custom adversary creation, operation polling, and result parsing.
- Lab-safe exploitability validation for non-destructive checks such as TCP reachability, HTTP default-content checks, and FTP anonymous-login validation.
- Optional controlled proof-of-access tickets for authorised lab demonstrations.
- Risk scoring, remediation guidance, HTML/PDF/text reporting, and MySQL persistence helpers.
- Pytest coverage for planner behavior, CALDERA integration, validation helpers, report quality, scan profiles, and frontend quality checks.

Recon and validation boundaries:

```text
footprinting
enumeration
evidence normalisation
official CVE List strict matching
service-level exposure checks
JSON/PDF/text handoff generation
CALDERA post-access emulation when explicitly enabled
```

The recon module does not exploit targets or make execution decisions by itself. CALDERA execution requires explicit configuration and an authorised trusted agent.

## Project Layout

```text
project/
  app.py                 Flask routes and dashboard endpoints
  ai/                    Ollama client, AI planner, safety filters
  caldera/               CALDERA API client, coverage checker, operation manager
  exploitation/          Lab-safe validation helpers
  mapping/               Vulnerability-to-ATT&CK mapping helpers
  reports/               Report summary and export generation
  scanners/              Recon pipeline, parsers, tooling, CVE matching
  scripts/               Tool checks and CVE index maintenance
  storage/               Runtime scan state and database helpers
  templates/             Dashboard HTML
  static/                CSS and browser JavaScript
  tests/                 Pytest coverage
```

## Quick Start

Run commands from the repository root unless noted.

```bash
cd project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
```

On Windows PowerShell:

```powershell
cd project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Environment

Create `project/.env` or export equivalent variables:

```env
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

PROOF_OF_ACCESS_ENABLED=false
PROOF_OF_ACCESS_SECRET=
PROOF_OF_ACCESS_TTL=300
```

MySQL is optional for the GUI to load, but database persistence requires a reachable MySQL server and matching credentials.

## Kali Runbook

Terminal 1, install and start AutoPenTest:

```bash
chmod +x install.sh
sudo ./install.sh
cd project
sudo .venv/bin/python app.py
```

Terminal 2, start Ollama:

```bash
ollama serve
```

Terminal 3, pull/check the configured model:

```bash
ollama pull llama3.2:1b
ollama list
curl http://127.0.0.1:11434/api/tags
```

Terminal 4, start CALDERA:

```bash
cd /path/to/caldera
source .venv/bin/activate 2>/dev/null || true
python3 server.py --insecure
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

## Dashboard Flow

1. Enter an authorised target and choose a scan profile/tool set.
2. Wait for the scan progress page to complete, then open the results dashboard.
3. Review service evidence, confirmed CVEs, candidate references, evidence gaps, ATT&CK recommendations, and AI planning notes.
4. Optionally run lab-safe validation to collect non-destructive exposure evidence.
5. Refresh CALDERA agent status and deploy/confirm Sandcat only inside the authorised lab.
6. Select supported techniques and run CALDERA when execution is explicitly enabled and authorised.
7. Generate the report, review the technical appendix, and export JSON/PDF/text handoff artefacts.

## Cleanup

Preview cleanup:

```bash
cd project
python3 utils/cleanup.py --dry-run
```

Run default cleanup:

```bash
python3 utils/cleanup.py
```

Default cleanup removes transient logs, scan evidence files, generated report files, and Python caches. It preserves saved result JSON, handoff packages, the local CVE mirror/index, and `.env`.

## Testing

From repository root:

```bash
cd project
python3 -m pytest tests -q
python3 -m py_compile app.py config.py storage/*.py scanners/*.py scripts/*.py utils/cleanup.py
python3 scripts/audit_no_scoring.py
python3 scripts/audit_cve_source.py
```

Some tests mock CALDERA and Ollama behavior. Tests that depend on a real CALDERA server, agent, MySQL instance, Kali tooling, or network-reachable lab target need matching local configuration.

## Safety Notes

AutoPenTest is designed as a decision-support and authorised emulation tool. The AI chat safety layer refuses exploit commands, payloads, credential theft steps, bypass instructions, and intrusion walkthroughs. CALDERA execution and proof-of-access features should only be used against systems where you have explicit permission to test.

## License

No license has been specified yet.
