# AutoPenTest

AutoPenTest is a Flask-based automated penetration testing platform developed as a controlled cyber-range MVP. It combines reconnaissance, evidence normalisation, vulnerability correlation, MITRE ATT&CK mapping, AI-assisted attack planning, controlled validation/exploitation, CALDERA post-exploitation, and report generation in a single workflow.

> **Scope:** The project is intended for authorised lab/cyber-range assessments. High-impact actions remain subject to operator approval and configured execution policies.

## Core workflow

```text
Target / Scope
      ↓
Reconnaissance (Nmap + service enumeration)
      ↓
Evidence normalisation
      ↓
CVE / vulnerability correlation
      ↓
MITRE ATT&CK technique mapping
      ↓
AI-assisted attack planning
      ↓
Operator review / approval
      ↓
Controlled validation & exploitation
      ├── Generic service validation
      ├── SMB validation / exploitation
      ├── Web validation / exploitation
      └── Metasploit modules
      ↓
CALDERA post-exploitation / adversary emulation
      ↓
Evidence, risk and remediation
      ↓
PDF report
```

## Main components

### Reconnaissance and vulnerability assessment

The `scanners/` package performs target discovery, Nmap execution/parsing, service and platform identification, evidence collection, CPE/CVE correlation, CVSS handling, Windows inventory/patch assessment, and result normalisation.

Reconnaissance produces candidate evidence. It does **not** by itself claim that a CVE is exploitable; exploitability is determined by the downstream validation/exploitation stages.

### AI-assisted attack planning

The `ai/`, `pentest_ai/`, and `mapping/` packages support AI-assisted ATT&CK planning. Reconnaissance and vulnerability evidence are mapped to known ATT&CK techniques before the local LLM is asked to recommend relevant techniques.

The AI is constrained by the available technique context and safety checks. It does not directly receive unrestricted execution authority.

### Validation and exploitation

Validation is intentionally split by capability instead of maintaining multiple overlapping generic exploitability implementations:

- `exploitation/validator.py` performs **generic, non-destructive service reachability checks** for services that do not have a dedicated exploit workflow.
- `exploitation/smb_expliotation.py` contains the controlled SMB workflow, including SMB fingerprinting, credential testing, share/file operations, evidence collection, and the combined SMB chain.
- `exploitation/web_validator.py` contains controlled web validation and action generation.
- `exploitation/web_exploiter.py` contains the controlled web exploitation/callback workflow.
- `exploitation/metasploit_service.py` provides the policy-controlled Metasploit execution layer.
- `exploitation/metasploit_policy.py`, `metasploit_allowlist.py`, and `module_catalog.py` constrain which modules/actions may be submitted.

**SMB and web functionality are intentionally retained.** The cleanup removes duplicated validation logic rather than removing exploitation capabilities.

### CALDERA

The `caldera/` package integrates with MITRE CALDERA for controlled post-exploitation and adversary emulation. CALDERA is used after the platform has established the appropriate assessment context; it is not treated as the primary vulnerability/exploit engine.

### Reporting

`reports/report_generator.py` consolidates scan findings, vulnerability/CVSS information, ATT&CK recommendations, validation/exploitation results, CALDERA results, risk information, evidence and remediation guidance into the final report.

## Project structure

```text
project/
├── ai/                     AI planning and safety logic
├── caldera/                CALDERA API and operation management
├── core/                   Shared services and helpers
├── enumeration/            Evidence/intelligence helpers
├── exploitation/           Validation, SMB, web and Metasploit workflows
├── mapping/                Vulnerability → ATT&CK mapping
├── pentest_ai/             Attack-advisor interfaces/schemas
├── policies/               Execution and engagement policies
├── reports/                Report generation
├── routes/                 Flask API/UI routes
├── scanners/               Reconnaissance and vulnerability assessment
├── storage/                Database and scan persistence
├── templates/              Flask HTML templates
├── static/                 Frontend JavaScript/CSS
├── tests/                  Application-level tests
└── README.md
```

## Installation

Create and activate a Python virtual environment, then install the project requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r utils/requirements.txt
```

Create the environment file from the supplied template:

```bash
cp .env.example .env
```

Set the required database, operator authentication, AI, Metasploit and CALDERA values for the lab environment. Keep exploit execution disabled until the assessment environment is ready.

## Running the application

For local development:

```bash
python app.py
```

The application performs runtime checks before allowing non-loopback deployment. For an exposed lab deployment, configure a strong `SECRET_KEY`, an `OPERATOR_TOKEN`, and `DEBUG=false`.

## External services

### Ollama

The AI planner can use a local Ollama model. Configure the model and endpoint through the environment settings used by `ai/llm_client.py`.

### Metasploit

Metasploit RPC is optional and is controlled through:

```text
ENABLE_METASPLOIT=1
ENABLE_METASPLOIT_EXPLOITS=1
METASPLOIT_RPC_URL=...
METASPLOIT_RPC_USER=...
METASPLOIT_RPC_PASS=...
```

Only allowlisted/configured modules should be used in the authorised lab.

### CALDERA

Configure the CALDERA URL/API key and enable execution only when the CALDERA server and test agents are ready.

## SMB workflow

The controlled SMB workflow is exposed through `routes/smb_routes.py` and supports:

1. SMB fingerprinting
2. Credential testing through the configured lab mechanism
3. Share enumeration/authentication
4. Controlled file create/modify/delete operations
5. Evidence capture
6. An end-to-end SMB chain with persisted run status

SMB execution is controlled by `ENABLE_SMB_EXPLOITATION` and should only be used against authorised lab targets.

## Web workflow

The web workflow remains separate from the generic validator:

1. Discover web services/forms
2. Generate allowlisted validation actions
3. Require operator approval for execution
4. Record validation evidence
5. Where enabled, perform the controlled web exploitation/callback workflow
6. Preserve the results for reporting

Web validation and exploitation are controlled independently through their corresponding configuration flags.

## Testing

Run the application and scanner tests from the project virtual environment:

```bash
pytest -q
```

The repository contains tests for AI safety/planning, scanner evidence/CVE handling, Metasploit policy/execution behaviour, CALDERA integration, web validation/exploitation, SMB-related routes, authentication and report-related flows.

## Security and execution model

AutoPenTest is designed around an evidence-driven workflow:

- Reconnaissance identifies and normalises evidence.
- Vulnerability correlation produces candidate findings.
- ATT&CK mapping provides structured attack context.
- AI recommends techniques using the supplied context.
- Validation/exploitation components perform controlled checks.
- Metasploit execution is policy controlled.
- SMB and web workflows use dedicated service-specific logic.
- CALDERA handles post-exploitation/adversary-emulation activities.
- Results are persisted as evidence for reporting.

The platform should only be operated against targets for which the project team has explicit authorisation.
