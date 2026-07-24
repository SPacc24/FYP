# AutoPenTest

AutoPenTest is a Flask-based assessment dashboard for authorised cyber ranges and lab environments. It orchestrates evidence-first reconnaissance, normalises service findings, correlates version evidence with the official CVE List, maps findings to MITRE ATT&CK, and produces reviewable reports and handoff artefacts. Optional integrations add local Ollama guidance, allowlisted Metasploit validation, CALDERA emulation, proof-of-access recording, and an experimental Chisel/proxychains pivot workflow.

> **Authorised use only.** Run this project only against systems you own or have explicit written permission to test. The default engagement policy rejects public targets, but it is a demo policy—not a substitute for signed rules of engagement.

For the step-by-step operating procedure, see the **[Operator Runbook](project/docs/operator_runbook.md)**.

## What the project does

- Runs one asynchronous, policy-gated adaptive vulnerability scan. The operator selects numerical TCP/UDP coverage; observed protocol evidence selects specialist modules automatically.
- Accepts a single IP, multiple IPs, CIDR blocks, and short or explicit IP ranges, up to the configured scope limit.
- Collects adaptive host-discovery evidence, operator-selected TCP/UDP exposure, port-independent service fingerprints, and protocol-specific readiness evidence.
- Uses Nmap and optional native tools for web, SSH, SMB, LDAP, DNS, SNMP, RPC/NFS, RDP, WinRM, database, container, Kubernetes, VPN, and TLS observations.
- Builds a service-centric attack-surface workbench with raw evidence links, evidence gaps, security observations, and tool-coverage status.
- Correlates observed identity and version evidence with machine-readable affected data from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5). Candidate requires a direct published applicability match. Confirmed requires target-specific validation evidence. CVE description prose never creates a finding.
- Maps findings to MITRE ATT&CK and generates a deterministic technique plan, optionally enriched by a local Ollama model.
- Performs allowlisted, non-destructive exposure validation and optional evidence-derived Metasploit auxiliary scans.
- Integrates with CALDERA for agent readiness, ability coverage, adversary creation, operation monitoring, result parsing, risk context, and proof-of-access tickets.
- Exports persisted scan JSON, CALDERA handoff JSON, HTML, PDF, plain-text reports, evidence manifests, and technical appendices.
- Provides an experimental pivot UI for Chisel SOCKS setup and proxychains-based internal scanning.

## Safety and maturity boundaries

The main reconnaissance pipeline is designed to collect evidence without selecting or launching exploits. Optional active features have separate controls:

| Capability | Default | Boundary |
| --- | --- | --- |
| Reconnaissance | Available | Targets must pass `engagement_policy.json`; public targets are denied by default. |
| Ollama planning/chat | Optional | Local-model output is constrained to observed context and safe guidance; deterministic fallbacks remain available. |
| Lab validation | On demand | Uses allowlisted reachability and service-exposure checks. Credential checks require configured lab credentials. |
| Web validation | Disabled | Requires a complete private-lab fingerprint, an evidence-derived action ID, and explicit operator approval. |
| Metasploit RPC | Disabled | Browser and LLM input cannot supply arbitrary module names; actions are generated from scan evidence and a server-side allowlist. |
| CALDERA execution | Disabled | Requires a configured CALDERA key, a trusted agent, supported techniques, and `ENABLE_CALDERA_EXECUTION=1`. |
| Proof of access | Disabled | Issues short-lived, signed, one-use tickets only after qualifying completed CALDERA links. |
| Pivot workflow | Experimental | Starts Chisel, changes proxychains configuration, scans through a tunnel, and generates lateral-movement commands. Use only in an isolated range and review the implementation before enabling access. |

The Flask server uses an operator-session gate and CSRF validation when `OPERATOR_TOKEN` is configured. It is a development server; do not expose it directly to an untrusted network or treat it as a production multi-user service.

## Architecture

```text
Browser dashboard
      |
      v
Flask routes + operator/CSRF gate
      |
      +--> Recon pipeline --> native tools --> normalised evidence
      |                              |              |
      |                              v              v
      |                         raw artefacts   CVE correlation
      |                                             |
      +--> ATT&CK mapper <---------------------------+
      |       |
      |       +--> deterministic/Ollama plan
      |       +--> CALDERA handoff and execution
      |
      +--> lab validation / allowlisted Metasploit
      +--> reports, evidence manifests, JSON persistence
      +--> experimental pivot workflow
```

Important directories:

```text
project/
  app.py                 Application factory and development entry point
  config.py              Environment-backed configuration
  runtime_env.py         Safe .env bootstrap and secret generation
  routes/                HTTP routes grouped by feature
  scanners/              Recon orchestration, parsing, profiles, CVE matching
  enumeration/           Intelligence and operational-maturity summaries
  mapping/               Evidence-to-ATT&CK mapping
  ai/                    Ollama client, safety layer, technique planning
  pentest_ai/             Evidence-based attack-path advice
  exploitation/          Validation, Metasploit policy/RPC, web validation
  caldera/               API client, coverage, operations, risk/remediation
  proof_of_access/        Signed ticket issuance and marker clients
  pivot/                  Experimental Chisel/proxychains workflow
  reports/                Plain-text report generation
  storage/                Runtime scan state, evidence, results, optional DB
  policies/               Scope, collector, objective, and review controls
  templates/              Jinja dashboard and report pages
  static/                 Browser JavaScript and CSS
  scripts/                Environment, tooling, and CVE maintenance commands
  tests/                  Backend and integration-oriented tests
tests/                    Repository-level UI/report/recon quality tests
```

## Requirements

- Python 3.10 or newer
- Git
- Nmap for meaningful live discovery
- Kali Linux is recommended for the complete external toolchain
- A browser with cookies enabled

The Kali installer also installs or attempts to install tools such as `arp-scan`, `gobuster`, `enum4linux-ng`, `smbclient`, `smbmap`, `snmp`, LDAP utilities, `sslscan`, `mtr`, `traceroute`, Hydra, `ssh-audit`, and ProjectDiscovery `httpx`. Other collectors such as `tshark`, `p0f`, and `nuclei` are optional and are reported as unavailable when absent.

Ollama, CALDERA, Metasploit RPC, MySQL, Chisel, and proxychains are optional and are needed only for their corresponding features.

## Installation

### Kali Linux (recommended)

From the repository root:

```bash
chmod +x install.sh start.sh
./install.sh
bash start.sh
```

`install.sh` installs the Kali packages, creates `project/.venv`, installs Python dependencies, prepares storage, creates `project/.env`, and attempts to sync the official CVE List mirror.

### Portable Python setup

This is sufficient for the UI, tests, reports, and whichever external tools are available on the host:

```bash
cd project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python scripts/bootstrap_env.py
python scripts/check_tooling.py
python app.py
```

On Windows PowerShell, run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
.\start_windows.ps1
```

Native Windows can run the dashboard, but full recon coverage depends on installed binaries. WSL or Kali is recommended for Linux-oriented tools.

Open `http://127.0.0.1:5000`. If the landing page asks for an operator token, retrieve it in a trusted terminal:

```bash
python project/scripts/bootstrap_env.py --show-secrets
```

## Configuration

`project/.env` is loaded by `project/config.py`. Direct startup and the launch scripts create or refresh it through `runtime_env.py`; existing non-placeholder values are preserved. On Unix, the generated file is restricted to mode `0600` when possible.

Never commit `.env` or paste values produced by `--show-secrets` into logs, screenshots, or reports.

### Core settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | generated | Flask session signing key. |
| `OPERATOR_TOKEN` | generated | Unlocks a browser operator session and enables CSRF enforcement. |
| `APP_HOST` | `127.0.0.1` | Flask bind address. |
| `PORT` | `5000` | Flask port. |
| `DEBUG` | `false` | Flask debug mode; must remain false for non-loopback binding. |
| `MAX_EXPANDED_TARGETS` | `256` | Application-level limit after CIDR/range expansion. |
| `ENGAGEMENT_POLICY_FILE` | bundled policy | Optional path to a replacement scope/RoE policy. |
| `AUTOPENTEST_RESULTS_DIR` | `project/storage/results` | Optional persisted-result directory override. |
| `AUTOPENTEST_SCANS_DIR` | `project/storage/scans` | Optional raw-evidence directory override. |
| `AUTOPENTEST_PASSIVE_INTERFACE` | unset | Approved interface for listen-only `tshark`/`p0f` collection. |

If `APP_HOST` is non-loopback, startup refuses unsafe combinations: `SECRET_KEY` must be at least 32 characters, an operator token must be configured, and debug mode must be off. `ALLOW_INSECURE_OPERATOR_ACCESS=1` exists for controlled testing but is not recommended.

### Optional integrations

| Area | Variables |
| --- | --- |
| Ollama | `OLLAMA_URL`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT` |
| CALDERA | `CALDERA_URL`, `CALDERA_API_KEY`, `ENABLE_CALDERA_EXECUTION`, `AGENT_GROUP`, `KALI_IP`, `OPERATION_TIMEOUT` |
| Metasploit | `ENABLE_METASPLOIT`, `ENABLE_METASPLOIT_EXPLOITS`, `METASPLOIT_RPC_URL`, `METASPLOIT_RPC_USER`, `METASPLOIT_RPC_PASS`, `METASPLOIT_RPC_VERIFY_SSL`, `METASPLOIT_RPC_TIMEOUT`, `METASPLOIT_RESULT_TIMEOUT`, `METASPLOIT_POLL_INTERVAL` |
| Web validation | `ENABLE_WEB_VALIDATION`, `WEB_VALIDATION_TIMEOUT`, `WEB_VALIDATION_MAX_RESPONSE_BYTES`, `WEB_VALIDATION_MAX_REDIRECTS`, `LAB_WEB_OS` |
| Proof of access | `PROOF_OF_ACCESS_ENABLED`, `PROOF_OF_ACCESS_SECRET`, `PROOF_OF_ACCESS_TTL` |
| MySQL | `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASS`, `MYSQL_DB` |
| CVE List V5 data | `MITRE_CVE_REPO` (optional official CVE List mirror override) |
| Recon toggles | `ENABLE_CONTEXT_FOOTPRINTING`, `ENABLE_ARP_SCAN`, `ENABLE_HTTPX`, `ENABLE_DEEP_WEB_DISCOVERY`, `ENABLE_SMBMAP`, `ENABLE_HYDRA`, `GOBUSTER_WORDLIST`, `HYDRA_CREDENTIAL_FILE` |
| Lab credentials | `LAB_USER`, `LAB_PASS`, or service-specific `LAB_<SERVICE>_USER` and `LAB_<SERVICE>_PASS` |
| Pivot declarations | `PIVOT_CHISEL_BINARY`, `PIVOT_DEFAULT_SOCKS_PORT`, `PIVOT_DEFAULT_CHISEL_PORT` (declared in configuration; the experimental engine currently uses its own hard-coded binary and route defaults) |

Restart the Flask process after changing `.env` because most services are initialised at import time.

## Scope policy and targets

Before active collection, the pipeline expands and validates targets against `project/policies/engagement_policy.json`. Supported input examples are:

```text
192.168.56.10
192.168.56.10,192.168.56.20
192.168.56.10-30
192.168.56.10-192.168.56.30
192.168.56.0/28
```

The main dashboard pipeline expects IP address input. The bundled demo policy allows private, loopback, and link-local lab addresses, denies public targets, and caps a scan at 256 expanded hosts. For a real assessment, copy the policy, populate explicit `allowed_networks`, engagement dates, approval records, and data-handling requirements, then set `ENGAGEMENT_POLICY_FILE` to that file.

The policy limit and `MAX_EXPANDED_TARGETS` both apply; the lower effective limit wins.

## Typical workflow

1. Confirm written authorisation and configure the engagement policy.
2. Start the app and unlock the browser session.
3. Enter authorised IP targets, select complete/common/custom numerical port coverage, and adjust the optional advanced workload settings.
4. Review the generated plan, then follow asynchronous task and command progress in the dashboard.
5. Review service evidence, Candidate/Confirmed CVE findings, evidence gaps, ATT&CK mapping, dataset status, and the technical appendix.
6. Optionally request attack-path advice or run explicitly approved lab validation.
7. If configured, check CALDERA coverage, select a trusted agent, and run supported techniques.
8. Export the handoff JSON, evidence manifest, PDF, or text report.

Scan state is held in memory while running and persisted as JSON under `project/storage/results/` when the pipeline completes. Raw command evidence is stored under `project/storage/scans/`. If those directories are unwritable, the store falls back to `/tmp/autopentest/` on Unix-like systems.

## Optional integrations

### Ollama

Start Ollama separately and install the configured model:

```bash
ollama serve
ollama pull llama3.2:1b
curl http://127.0.0.1:11434/api/tags
```

The planner validates model-selected technique IDs against the evidence-derived allowlist and falls back to deterministic planning when Ollama is unavailable or returns invalid output.

### CALDERA

Configure `CALDERA_URL` and `CALDERA_API_KEY`, start CALDERA, and keep `ENABLE_CALDERA_EXECUTION=0` until agent identity, ability coverage, and authorisation have been reviewed. The dashboard can display Sandcat deployment commands, manage the selected agent, create an adversary from supported techniques, poll the operation, and persist parsed results.

Execution is rejected unless `ENABLE_CALDERA_EXECUTION=1`. See `project/docs/cyber_range_demo_flow.md` for the intended demonstration order.

### Metasploit RPC

The current allowlist contains auxiliary scanners for FTP anonymous access, HTTP/HTTPS titles, SMB version, RDP, WinRM authentication methods, SSH version, and MySQL version. A proposal is created only when the active scan contains a matching open service.

```bash
python project/scripts/bootstrap_env.py --show-secrets
```

Set `ENABLE_METASPLOIT=1`, then start the RPC service with the exact generated password:

```bash
msfrpcd -U msf -P '<METASPLOIT_RPC_PASS>' -a 127.0.0.1 -p 55552
```

Keep `ENABLE_METASPLOIT_EXPLOITS=0`. The shipped policies contain auxiliary modules only; adding an exploit policy requires deliberate code review, approval gating, and isolated-lab testing.

### MySQL

MySQL is not required for the primary JSON-backed dashboard flow. When reachable, the app initialises an `autopentest` schema and can save scans, vulnerabilities, CALDERA operations, and technique results through explicit save paths. Connection failures are logged and do not prevent the UI from starting.

### Proof of access

Enable this only for an authorised demonstration. A qualifying completed CALDERA link can produce a signed ticket which the supplied PowerShell or shell client redeems and records as a harmless local JSON marker. See `project/docs/proof_of_access.md` for the full trust and deployment flow.

### Experimental pivot workflow

The `/pivot` routes can start a Chisel reverse-SOCKS server, modify `/etc/proxychains4.conf`, scan an internal range through `proxychains`, and generate operator-run lateral-movement commands. This path assumes a compromised lab host and currently contains range-specific demonstration defaults. It may require elevated filesystem permissions and additional binaries (`chisel`, `proxychains`, Nmap, and technique-specific tools).

Treat this subsystem as experimental research code. Do not expose the dashboard remotely, do not use supplied example credentials, and do not run generated commands without reviewing target scope and impact.

## CVE data maintenance

The application matches against a local official CVE List mirror and generated index:

```bash
cd project
source .venv/bin/activate
python scripts/sync_mitre_cve_database.py
python scripts/rebuild_mitre_cve_index.py
python scripts/mitre_cve_status.py
python -m pytest scanners/tests/test_policy_and_source_hygiene.py -q
```

The CVE List mirror and generated local indexes are runtime data under `project/storage/mitre_cve/` and are intentionally excluded from the release ZIP. The first sync downloads the official repository; later syncs retrieve only changes. Existing validated local data remains usable offline. CVSS metadata may be absent for the selected version; the UI reports that absence rather than converting, estimating, or substituting a score.

## API overview

The browser UI is the supported interface. Key route groups are:

- `/scan`, `/scan/status/<id>`, `/scan/results/<id>` — scan lifecycle.
- `/results`, `/technical-appendix`, `/generate_report`, `/report/*`, `/download/*` — review and export.
- `/ai/chat`, `/ai/status`, `/pentest/advice` — local-model and attack-path guidance.
- `/exploitation/run`, `/pentest/metasploit/*`, `/pentest/web-validation/*` — controlled validation.
- `/caldera/*`, `/api/caldera/check-coverage` — agent, coverage, and operation workflow.
- `/proof-of-access/redeem` — signed proof-ticket redemption.
- `/pivot/*` — experimental tunnel, internal scan, command generation, and cleanup.

With an operator token configured, non-public routes require an unlocked session. State-changing requests must also include the session CSRF token; use the dashboard JavaScript as the reference client.

## Testing and checks

Install the test runner if it is not already available:

```bash
cd project
python -m pip install pytest
python -m pytest tests -q
python -m py_compile app.py config.py runtime_env.py routes/*.py scanners/*.py storage/*.py
```

Run repository-level quality tests from the repository root with the project on `PYTHONPATH`:

```bash
PYTHONPATH=project python -m pytest tests -q
```

Recon-boundary wording and CVE-index provenance are covered by two tests in
`scanners/tests/test_policy_and_source_hygiene.py`:

```bash
cd project
python -m pytest scanners/tests/test_policy_and_source_hygiene.py -q
```

`test_no_forbidden_scoring_wording_in_shipped_assets` fails if scanner-owned
policy/static assets present business-risk wording as if it were a scanner
output. `test_cve_index_uses_official_source_only` is skipped until the
local CVE index has been built, then fails if a sampled indexed record is
attributed to a non-official source.

Most tests mock network services. Tests explicitly aimed at live CALDERA, MySQL, external binaries, or lab targets require those dependencies and suitable local configuration.

## Cleanup

Preview the default cleanup:

```bash
cd project
python utils/cleanup.py --dry-run
```

Then run it without `--dry-run` to remove logs, generated reports, raw scan evidence, and Python caches. Saved result JSON, the CVE mirror/index, and `.env` are preserved unless `--include-results` or `--include-cve-data` is supplied.

## Troubleshooting

- **Live scan coverage is limited:** run `python project/scripts/check_tooling.py`; missing optional tools are recorded as unavailable rather than crashing the pipeline.
- **A target is refused:** inspect the active engagement policy, target type, engagement window, approval records, and both target limits.
- **Remote browser cannot connect:** bind with `APP_HOST=0.0.0.0` only on a trusted lab network. Startup requires a strong secret, operator token, and debug disabled.
- **Operator requests return 403:** unlock the browser with the generated token; API POSTs also need the current CSRF token.
- **Ollama is unavailable:** verify the URL and model with `/api/tags`; deterministic planning still works.
- **CALDERA cannot execute:** confirm the API key, trusted online agent, technique coverage, and `ENABLE_CALDERA_EXECUTION=1`.
- **Metasploit has no proposed actions:** enable RPC, complete a scan, and confirm a matching open service exists in the server-side allowlist.
- **PDF export fails:** install the native Pango/Cairo dependencies used by WeasyPrint; a ReportLab fallback is included.
- **MySQL logs connection errors:** configure a reachable server or ignore them when using only JSON-backed scan persistence.

## License

No licence file is currently included. Unless the repository owner states otherwise, no permission to copy, modify, or redistribute the code is granted.
