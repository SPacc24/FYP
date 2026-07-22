# Setup Guide (minimum viable lab)

## Prerequisites

- Python 3.10+
- Git
- Nmap (for live recon)
- Kali Linux recommended for full external tooling
- Optional: Metasploit (`msfrpcd`), CALDERA, Ollama, Chisel, proxychains4

## Install

```bash
cd FYP-main
./install.sh          # or: python3 -m venv project/.venv && source project/.venv/bin/activate
cd project
python scripts/bootstrap_env.py
# Review .env — set strong SECRET_KEY and OPERATOR_TOKEN for non-local demos
```

Windows: `install_windows.ps1` then `start_windows.ps1`.

## Configure (safe defaults)

| Variable | Safe demo default | Notes |
|----------|-------------------|-------|
| `OPERATOR_TOKEN` | strong random | Required when remote binding |
| `ALLOW_INSECURE_OPERATOR_ACCESS` | `0` | Only `1` on isolated localhost labs |
| `ENABLE_METASPLOIT` | `0` | Turn on only with RPC up |
| `ENABLE_METASPLOIT_EXPLOITS` | `0` | Keep off unless deliberate review |
| `ENABLE_CALDERA_EXECUTION` | `0` | Keep off until agent trusted |
| `ENABLE_WEB_VALIDATION` | `0` | On only for authorised lab diagnostics host |
| `MITRE_CVE_REPO` / local index | synced optionally | `python scripts/sync_mitre_cve_database.py` then rebuild index |

Lab web fingerprint (optional overrides — avoids hardcoding only one page forever):

| Variable | Default |
|----------|---------|
| `LAB_WEB_EXPECTED_TITLE` | `AutoPentest Lab Diagnostics` |
| `LAB_WEB_EXPLOIT_ENDPOINT` | `/diagnostics.php` |
| `LAB_WEB_EXPLOIT_PARAMETER` | `host` |
| `LAB_WEB_EXPLOIT_METHOD` | `POST` |

## Run

```bash
cd FYP-main
./start.sh
# open http://127.0.0.1:5000
# unlock with OPERATOR_TOKEN if prompted
```

## First mission without external tools

External RPCs are **not** required for the orchestration story:

1. Import or paste fixtures / run a local scan of lab private IPs only.
2. Open **Mission Console** `/mission`.
3. Start playbook `edge_to_internal_proof` or `surface_validation_only`.
4. Advance: safe auto-queue → suppress unsupported MS17 → approve/skip impact → attach proof → export report.

## Verify install

```bash
cd project
source .venv/bin/activate   # if used
python -m pytest tests -q
python scripts/check_tooling.py
python scripts/run_orchestration_evaluation.py
```

## Clean runtime data

```bash
python utils/cleanup.py --dry-run
python utils/cleanup.py
```

## Troubleshooting shortcuts

| Symptom | Check |
|---------|--------|
| Target refused | `policies/engagement_policy.json` — public IPs denied |
| 403 on POSTs | Operator unlock + CSRF token |
| Empty CVE column | Sync + rebuild CVE index |
| MSF no proposals | `ENABLE_METASPLOIT=1`, RPC password match, scan has matching service |
| PDF export odd | ReportLab PDF path; text export always available |

Full operating procedure: `operator_runbook.md`.
