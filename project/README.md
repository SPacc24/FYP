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
  runtime_env.py         .env bootstrap and generated local secrets
  ai/                    Ollama client, AI planner, safety filters
  caldera/               CALDERA API client, coverage checker, operation manager
  exploitation/          Lab-safe validation and Metasploit policy helpers
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

`python app.py` creates or refreshes `project/.env` on startup. From the
repository root, you can use the launcher instead:

```bash
bash start.sh
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

Or from the repository root:

```powershell
.\start_windows.ps1
```

Open:

```text
http://127.0.0.1:5000
```

## Environment

`project/.env` is created automatically by `python app.py`, `bash start.sh`,
`.\start_windows.ps1`, or:

```bash
python project/scripts/bootstrap_env.py
```

The bootstrapper fills generated local secrets and safe defaults while
preserving existing non-placeholder values. The generated file uses this shape:

```env
SECRET_KEY=<generated-secret-key>
DEBUG=false
OPERATOR_TOKEN=<generated-operator-token>
APP_HOST=127.0.0.1

CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=your-caldera-api-key
ENABLE_CALDERA_EXECUTION=0
AGENT_GROUP=red
KALI_IP=192.168.x.x
OPERATION_TIMEOUT=180

OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
OLLAMA_TIMEOUT=180

ENABLE_METASPLOIT=0
ENABLE_METASPLOIT_EXPLOITS=0
METASPLOIT_RPC_URL=https://127.0.0.1:55552
METASPLOIT_RPC_USER=msf
METASPLOIT_RPC_PASS=<generated-rpc-password>
METASPLOIT_RPC_VERIFY_SSL=0
METASPLOIT_RPC_TIMEOUT=20

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
PROOF_OF_ACCESS_SECRET=<generated-proof-secret>
PROOF_OF_ACCESS_TTL=300
```

To print the current generated operator/RPC values in a trusted terminal:

```bash
python project/scripts/bootstrap_env.py --show-secrets
```

Keep `APP_HOST=127.0.0.1` for local-only use. If you need to open the Kali
dashboard from the Windows host browser, set `APP_HOST=0.0.0.0` and configure
`OPERATOR_TOKEN` first. The bootstrapper generates `OPERATOR_TOKEN`; copy it
from `project/.env` or print it with `--show-secrets`.

MySQL is optional for the GUI to load, but database persistence requires a reachable MySQL server and matching credentials.

## Kali Runbook

Kali is the preferred runtime when using Nmap, Metasploit, and the wider
enumeration toolchain.

Install once from the repository root:

```bash
chmod +x install.sh
./install.sh
```

The installer creates `project/.venv`, installs Python packages, prepares
storage folders, and creates `project/.env` with generated local secrets.

Start or restart the dashboard:

```bash
bash start.sh
```

For access from the Windows host browser, keep `OPERATOR_TOKEN` configured and
start the dashboard with `APP_HOST=0.0.0.0 bash start.sh`, then unlock the
browser session on the landing page.

Start Ollama in another terminal:

```bash
ollama serve
```

Pull/check the configured model:

```bash
ollama pull llama3.2:1b
ollama list
curl http://127.0.0.1:11434/api/tags
```

Optional Metasploit RPC setup:

```bash
python project/scripts/bootstrap_env.py --show-secrets
```

Set `ENABLE_METASPLOIT=1` in `project/.env`, then start RPC with the exact
generated `METASPLOIT_RPC_PASS`:

```bash
msfrpcd -U msf -P <METASPLOIT_RPC_PASS> -a 127.0.0.1 -p 55552
```

Leave `ENABLE_METASPLOIT_EXPLOITS=0` unless a supervised lab run explicitly
requires exploit-class modules. Restart the Flask app after editing `.env`.

Optional CALDERA setup:

```bash
cd /path/to/caldera
source .venv/bin/activate 2>/dev/null || true
python3 server.py --insecure
```

Update an existing Kali checkout:

```bash
cd ~/FYP
git pull origin main
python project/scripts/bootstrap_env.py
```

Reinstall Python requirements only when `project/requirements.txt` changes:

```bash
cd ~/FYP/project
source .venv/bin/activate
python -m pip install -r requirements.txt
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

## Metasploit Integration

Ollama and the browser do not choose arbitrary Metasploit modules. Ollama can
generate attack-path reasoning, but AutoPenTest maps scan evidence to a server
side allowlist before any RPC action is available.

Default allowlist:

- `auxiliary/scanner/ftp/anonymous`
- `auxiliary/scanner/http/title`
- `auxiliary/scanner/smb/smb_version`
- `auxiliary/scanner/rdp/rdp_scanner`
- `auxiliary/scanner/winrm/winrm_auth_methods`
- `auxiliary/scanner/ssh/ssh_version`
- `auxiliary/scanner/mysql/mysql_version`

Actions are offered only when the matching service and port were observed in
the active scan. To add exploit-class modules later, update
`project/exploitation/metasploit_allowlist.py`, start with `mode="check"` and
`requires_approval=True`, test inside the isolated lab, then enable
`ENABLE_METASPLOIT_EXPLOITS=1` only for a supervised run. Do not add routes or
UI fields that accept arbitrary module names.

Useful Metasploit troubleshooting:

- `Metasploit RPC integration is disabled`: set `ENABLE_METASPLOIT=1` and restart Flask.
- `Metasploit RPC authentication failed`: confirm `METASPLOIT_RPC_USER` and `METASPLOIT_RPC_PASS` match the running `msfrpcd` or `msgrpc` instance.
- TLS errors: keep `METASPLOIT_RPC_VERIFY_SSL=0` for the local self-signed lab RPC service, or configure a trusted certificate.
- No actions loaded: confirm the scan completed and found open services matching the allowlist.

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
