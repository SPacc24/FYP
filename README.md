# AutoPenTest

AutoPenTest is a Flask-based Final Year Project dashboard for authorised vulnerability assessment and attack emulation planning. It runs controlled Nmap scans, parses scan output, maps findings to safe vulnerability context and MITRE ATT&CK techniques, optionally uses a local Ollama model for technique reasoning, launches supported MITRE CALDERA operations, scores risk, and generates remediation-focused reports.

This project is intended for owned or explicitly authorised lab environments only.

## Current Features

- Web dashboard for scan configuration, results review, ATT&CK technique selection, CALDERA execution, risk scoring, AI chat, and report export.
- Controlled Nmap scanning with target, port range, timing intensity, and quick/standard/deep scan profiles.
- Nmap XML parsing into structured host, OS, service, port, script, and scan metadata.
- Rule-based vulnerability mapping for common lab services and known CVE signatures.
- MITRE ATT&CK technique recommendations with auto, hybrid, and manual selection modes.
- Optional Ollama-assisted technique planning with deterministic fallback when the LLM is unavailable.
- Safe AI chat endpoint that explains findings, mappings, risk, remediation, and reporting context without exploit walkthroughs.
- MITRE CALDERA integration for agent readiness checks, technique-to-ability lookup, custom adversary creation, operation polling, and operation result parsing.
- Risk scoring that combines vulnerability severity with CALDERA technique outcomes.
- MySQL storage helpers for scans, vulnerabilities, operations, and technique results.
- Text report generation with target summary, mapped findings, attack plan, operation results, risk, and remediation guidance.
- Pytest suite covering CALDERA client behavior, LLM fallback/settings, safety checks, and technique planning.

## Project Structure

```text
FYP/
|-- README.md
`-- project/
    |-- app.py                         # Main Flask application
    |-- config.py                      # Environment-driven configuration
    |-- ai/                            # Ollama client, safe chat, technique planner
    |-- caldera/                       # CALDERA API client, operation manager, risk scorer
    |-- mapping/                       # Vulnerability-to-ATT&CK mapping logic
    |-- reports/                       # Report summary and text export generation
    |-- scanners/                      # Nmap command runner and XML parser
    |-- storage/
    |   |-- db.py                      # MySQL storage layer
    |   |-- logs/                      # Generated CALDERA operation logs
    |   `-- scans/                     # Generated Nmap XML scan output
    |-- static/                        # Dashboard JavaScript and CSS
    |-- templates/                     # Flask HTML templates
    |-- tests/                         # Pytest tests
    `-- utils/
        `-- requirements.txt           # Python dependencies
```

## Requirements

- Python 3.10 or newer
- Nmap installed and available on `PATH`, or configured with `NMAP_PATH`
- MySQL server for persistence features
- MITRE CALDERA for attack emulation features
- A trusted CALDERA Sandcat agent in the configured agent group before running operations
- Ollama for optional local AI planning/chat features

Scans and mapped recommendations still work without Ollama. CALDERA execution requires a reachable CALDERA server and an online trusted agent.

## Setup

Run commands from the `project` directory so generated scan and log paths resolve to `project/storage`.

```powershell
cd project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r utils\requirements.txt
```

Create `project/.env`:

```env
SECRET_KEY=change-this-secret
DEBUG=true

CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=your-caldera-api-key
AGENT_GROUP=red
KALI_IP=192.168.xx.xx
OPERATION_TIMEOUT=180

MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=your-password
MYSQL_DB=autopentest

NMAP_PATH=C:\Program Files\Nmap\nmap.exe
NMAP_DEFAULT_PORTS=1-1024
NMAP_DEFAULT_INTENSITY=3
NMAP_DEFAULT_PROFILE=standard

OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
OLLAMA_TIMEOUT=120

# Optional, used only when enriching CVE context through NVD.
NVD_API_KEY=
```

If Nmap is already on `PATH`, `NMAP_PATH` can be omitted.

## Optional Ollama Setup

Install and start Ollama, then pull the configured model:

```powershell
ollama serve
ollama pull llama3.2:1b
```

If Ollama is unavailable, AutoPenTest falls back to the highest-priority mapped techniques and displays an LLM-unavailable message for chat.

## Running The App

From `project`:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Typical workflow:

1. Enter an authorised target, port range, scan intensity, scan profile, and technique mode.
2. Review parsed Nmap results, mapped vulnerabilities, top risks, ATT&CK recommendations, and AI planning notes.
3. Confirm selected techniques before launching a CALDERA operation.
4. Review operation results, final risk score, remediation guidance, and export the text report.

## Flask Routes

- `GET /` - scan configuration dashboard
- `POST /scan` - run Nmap, parse results, map vulnerabilities, and build the technique plan
- `GET /results` - reload the current session results dashboard
- `POST /ai/chat` - ask safe questions about current findings and report context
- `GET /caldera/status` - check CALDERA connectivity and trusted agent readiness
- `POST /caldera/run` - run selected ATT&CK techniques through CALDERA
- `GET /caldera/operation/status` - return current session operation results
- `GET /caldera/operation/<operation_id>` - poll a CALDERA operation
- `POST /generate_report` - build the current report summary
- `GET /report/export` - download a generated text report after an operation
- `POST /scan/save` - save scan data to MySQL
- `POST /vulnerabilities/save` - save mapped vulnerabilities to MySQL

## Testing

From `project`:

```powershell
pytest tests
```

Some tests mock CALDERA and Ollama behavior. Tests that depend on a real CALDERA server, agent, or MySQL instance need matching local configuration before they can pass.

## Generated Data

- Nmap XML output is written to `project/storage/scans/`.
- CALDERA operation logs are written to `project/storage/logs/`.
- Text reports are written to `project/storage/reports/`.
- MITRE and CVE enrichment caches are written under `project/ai/.cache/`.

## Safety Notes

AutoPenTest is designed as a decision-support and authorised emulation tool. The AI chat safety layer refuses exploit commands, payloads, credential theft steps, bypass instructions, and intrusion walkthroughs. CALDERA execution should only be used against systems where you have explicit permission to test.

## License

No license has been specified yet.
