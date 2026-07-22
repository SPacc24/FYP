# AutoPenTest

**Evidence-closed-loop pentest orchestration** for authorised cyber ranges and lab environments.

> We don't let AI invent attacks. Evidence drives a closed loop of safe actions; policy + humans unlock impact — and when a path dies, the system **branches** instead of dying with it. JSON playbooks/catalogs **reduce** hardcoded decision trees; they do not eliminate engineered safety defaults (approval gates, proof-before-pivot).

AutoPenTest is not a scanner clone, not an “AI hacker”, and not a PentestGPT-style freeform reasoner. It is an orchestration product:

1. **Surface lock** — ingest authorised Ethernet/LAN scan evidence into a living attack graph  
2. **Hypothesis** — match evidence only against the JSON module catalog (MSF / web profiles / lateral)  
3. **Safe validation storm** — auto-queue low/medium-risk auxiliaries (no shells)  
4. **Branch brain** — if celebrity exploit paths (e.g. MS17-010) are not evidenced, **suppress** them and enable alternate lateral  
5. **Impact gate** — high-risk catalog actions wait for human approval + a proof plan  
6. **Pivot expand** — only after a recorded foothold **proof** may internal segments be recommended  
7. **Mission debrief** — proved findings, suppressed paths, research queue, blue-team timeline  

Optional layers still include Ollama planning, allowlisted Metasploit, CALDERA, proof-of-access tickets, and Chisel/proxychains pivot plumbing — all under the same custody model.

> **Authorised use only.** Run this project only against systems you own or have explicit written permission to test. The default engagement policy rejects public targets; it is a demo policy—not a substitute for signed rules of engagement.

**30-second pitch:** [product_positioning_30s.md](project/docs/product_positioning_30s.md) · **Operator runbook:** [operator_runbook.md](project/docs/operator_runbook.md) · **Evaluation (RQ1–RQ3):** [evaluation_protocol.md](project/docs/evaluation_protocol.md) · **Hostile viva drill:** [hostile_viva_qa.md](project/docs/hostile_viva_qa.md)

## Product USP (why this is designation-grade)

| Claim | How the product enforces it |
| --- | --- |
| AI never invents exploits | LLM may **rank/explain** catalog items only; module paths live in `policies/exploit_module_catalog.json` |
| Mission trees not hardcoded in Python | Stages, branch rules, detectors, and pivot segments live in `policies/playbooks/*.json` (engineed gates remain) |
| Safe by default | Auxiliaries auto-queue; exploits/web footholds require operator approval |
| Paths branch, not die | Patched/absent MS17-class evidence fires `branch_ms17_suppressed` and unlocks alternate lateral |
| No finding without proof | Mission debrief “confirmed” count is bound to the proof store, not scanner noise |
| Unknown surface readiness | Uncatalogued services enter a **research queue** (class hints only) — never hallucinated traits |

## What the project does

### Closed-loop mission orchestration (core)
- **Mission Console** at `/mission` — start playbooks, approve impact, attach proofs, view attack graph/debrief
- Declarative playbooks in `project/policies/playbooks/` (no Python hardcoding of steps)
- Living **attack graph** built from scan evidence + catalog matches
- **Proof store** under `project/storage/proofs/` — foothold artefacts unlock pivot expansion
- Persistent missions under `project/storage/missions/`

### Recon + intelligence (supporting)
- Asynchronous, policy-gated recon (**Full** / **Custom**), multi-host / CIDR targets
- Nmap + optional native collectors (web, SSH, SMB, LDAP, DNS, SNMP, RPC/NFS, RDP, WinRM, DB, K8s, TLS, …)
- Service-centric attack-surface workbench with evidence gaps and tool coverage
- CVE List correlation ([CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)) — weak hits stay candidates
- MITRE ATT&CK mapping + deterministic technique plan (optional Ollama enrichment)
- Allowlisted Metasploit auxiliary validation; CALDERA readiness/ops; proof-of-access tickets
- Reports (HTML/PDF/text), evidence manifests, technical appendix
- Experimental pivot UI (Chisel SOCKS + proxychains internal scan)

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
Browser  ──►  Flask routes + operator / CSRF gate
                 │
                 ├─ Recon pipeline ──► normalised evidence + CVE correlation
                 │         │
                 │         ▼
                 ├─ Mission Console (/mission)  ◄── playbooks JSON
                 │         │
                 │         ▼
                 │   PlaybookEngine (closed loop)
                 │         ├─ Attack graph (hosts/services/catalog)
                 │         ├─ Safe auto-queue (catalog auxiliaries)
                 │         ├─ Branch brain (suppress / alternate)
                 │         ├─ Impact gate (human approval)
                 │         ├─ Proof store ──► unlock pivot segments
                 │         └─ Debrief (proved / suppressed / research / blue team)
                 │
                 ├─ Catalog custody  ◄── policies/exploit_module_catalog.json
                 ├─ ATT&CK plan (deterministic ± Ollama rank-only)
                 ├─ Allowlisted Metasploit / web validation / CALDERA
                 └─ Reports + JSON persistence
```

### Mission API (operator-authenticated)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/mission` | Mission Console UI |
| GET | `/api/mission/playbooks` | List declarative playbooks |
| GET | `/api/mission/list` | Recent missions |
| POST | `/api/mission/start` | Start mission (`playbook_id`, `parsed_results` or `scan_id`) |
| GET | `/api/mission/<id>` | Full mission state (graph, queue, flags, debrief) |
| POST | `/api/mission/<id>/approve` | Approve / skip gated action |
| POST | `/api/mission/<id>/proof` | Attach foothold proof → unlock pivot |
| POST | `/api/mission/<id>/outcome` | Record MSF/web execution outcome / flags |
| POST | `/api/mission/<id>/continue` | Advance non-auto / skip locked stage |
| POST | `/api/mission/<id>/abort` | Abort and compile debrief |

### Important directories

```text
project/
  app.py                 Application factory
  automation/            ★ Playbook engine, mission service, attack graph, proof store
  policies/
    playbooks/           ★ JSON mission playbooks (no hardcoded trees in Python)
    exploit_module_catalog.json  ★ Single custody of MSF/web/lateral techniques
  routes/mission_routes.py       ★ Mission API + console
  templates/mission_console.html ★ Operator mission UI
  storage/missions/      Persistent mission JSON
  storage/proofs/        Proof-of-impact artefacts
  scanners/              Recon orchestration + CVE matching
  exploitation/          Catalog loader, MSF policy, web validation
  mapping/ ai/ caldera/ pivot/ reports/ …
  docs/                  Report, evaluation, viva, and ops material
    architecture.md / setup_guide.md / test_cases.md
    research_to_implementation_narrative.md  ★ Final-report narrative
    research_to_implementation_matrix.md     ★ 1-page objective map
    directors_pack.md                        ★ 8-slide director pack
    evaluation_protocol.md                   ★ RQ experiments + baseline
    graceful_degradation.md / hostile_viva_qa.md / anti_rejection_checklist.md
    product_positioning_30s.md / cyber_range_demo_flow.md
  scripts/run_orchestration_evaluation.py    ★ RQ1–RQ3 metrics harness
  tests/test_mission_orchestration.py
  tests/test_evaluation_conditions.py
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

## Closed-loop playbooks

Registered in `project/policies/playbooks/index.json`:

| ID | Intent |
| --- | --- |
| `edge_to_internal_proof` (default) | Full closed loop: surface → safe auto → branch → impact gate → alternate lateral → proof-gated pivot → debrief |
| `surface_validation_only` | Safe-only posture: map + auxiliary validation, **no** impact queue |

Playbook JSON owns: `stages`, `actions` (`kind` + `filter`), `evidence_detectors`, `branches` (boolean flag logic), `pivot_segments`, and `blue_team_timeline_templates`.  
Python only **evaluates** those rules and consults the module catalog — module names/paths are never hardcoded in the engine.

## Internal verification (what to test)

### Fast offline (no VMs)

From repo root, with the project virtualenv if you use one:

```bash
cd project
python -m pytest tests/ -q
# Focused:
python -m pytest tests/test_mission_orchestration.py tests/test_module_catalog.py -q
```

Expected: all tests green (mission suite covers branch-on-patched-MS17, safe-only posture, research queue, proof→pivot unlock, API console smoke).

Manual mission loop without live targets:

```bash
cd project && python app.py
# browser: http://127.0.0.1:5000/mission
# 1) Pick playbook "Edge to internal impact proof"
# 2) Demo profile "Web + SMB (MS17 absent — branch)" → Start
# 3) Confirm flags include branch_ms17_suppressed + impact_path_available (via web)
# 4) Approve the web foothold action at the impact gate
# 5) Mission blocks on pivot until you click "Attach foothold proof"
# 6) Pivot VLAN segments appear as awaiting_approval — approve or skip
# 7) Debrief shows professional notes (suppressed EB path is a success of the system)
```

### Recommended lab VMs (Ethernet segment narrative)

Assign **static IPs on an isolated lab vSwitch / physical Ethernet**. Do **not** use guest internet egress for exploitation demos.

| Role | Example OS | Example IP | Why it is in the demo |
| --- | --- | --- | --- |
| **Operator (Kali)** | Kali Linux 2024+ | `10.10.10.10` | Runs AutoPenTest, nmap, msfrpcd, optional Chisel client |
| **Edge web foothold** | Ubuntu 20.04 + vulnerable “diagnostics” web app (catalog web profile) **or** DVWA/custom CMDi lab | `10.10.10.20` | Produces `http_present` + web catalog match → impact unlock |
| **Patched Windows (branch proof)** | Windows 10/Server with MS17-010 **patched**, SMB enabled | `10.10.10.30` | SMB open, **no** CVE-2017-014x evidence → EB exploit suppressed, alternate lateral planned |
| **Legacy Windows (optional** EB path) | Windows 7 SP1 / Server 2008 R2, unpatched MS17-010, **isolated** | `10.10.10.40` | Only if ROE allows: check auxiliary + gated exploit after approval |
| **Internal USERS host** | Ubuntu/Win10 join | `10.10.20.10` | Reachable **only after** foothold pivot (no direct route from Kali) |
| **Internal ADMIN host** | Domain-ish lab box | `10.10.30.10` | Second hop narrative for ADMIN VLAN |

Suggested topology:

```text
[ Kali 10.10.10.10 ]---- edge VLAN 10.10.10.0/24 ----[ Web  .20 ] [ Win-patched .30 ]
                              |
                    (after foothold + Chisel/pivot)
                              |
                    +---- USERS 10.10.20.0/24 ----[ .10 ]
                    +---- ADMIN 10.10.30.0/24 ----[ .10 ]
```

> Ethernet scanning teammates own L2 discovery specifics. Mission pivot segment CIDRs are declared in the playbook JSON (`pivot_segments`) and can be overridden per-mission via `scope.pivot_segments` — not baked into Python.

### End-to-end lab checklist (distinction narrative)

1. **Scope lock** — engagement notes + authorised CIDRs only; public targets denied by policy  
2. **Scan edge** — Full Recon against `10.10.10.0/24` from Kali  
3. **Start mission** — Mission Console → bind `scan_id` or paste results → `edge_to_internal_proof`  
4. **Watch branch brain** — on patched SMB host, debrief must **not** claim EternalBlue success  
5. **Safe storm** — auxiliaries show `queued_auto`; no shell modules auto-run  
6. **Impact gate** — approve **one** foothold path (web CMDi profile or gated MSF exploit)  
7. **Proof** — attach operator-attested proof (callback / session evidence). Without it, pivot stays locked  
8. **Pivot** — approve USERS/ADMIN segment scans through established tunnel  
9. **Debrief** — export notes: proved findings count = proofs only; research queue listed; blue-team timeline from playbook templates  

### Optional service dependencies

| Service | When needed | Check |
| --- | --- | --- |
| msfrpcd | Metasploit actions | `ENABLE_METASPLOIT=1`, RPC on loopback |
| CALDERA | Emulation ops | `ENABLE_CALDERA_EXECUTION=1` + API key + trusted agent |
| Ollama | AI planner rank/explain | local model; never supplies module paths |
| Chisel + proxychains | Live pivot | isolated range only; review `pivot/` first |

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
| Recon toggles | `ENABLE_CONTEXT_FOOTPRINTING`, `ENABLE_ARP_SCAN`, `ENABLE_HTTPX`, `ENABLE_DEEP_WEB_DISCOVERY`, `ENABLE_SMBMAP`, `ENABLE_HYDRA`, `GOBUSTER_WORDLIST`, `HYDRA_CREDENTIAL_FILE`, `MITRE_CVE_REPO` |
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
2. Start the app, unlock the browser session, and choose **Full Recon** or exact **Custom Recon** collectors.
3. Enter authorised IP targets and select `auto`, `hybrid`, or `manual` ATT&CK technique mode.
4. Follow asynchronous task and command progress in the dashboard.
5. Review service evidence, CVE classifications, candidate references, evidence gaps, ATT&CK mapping, and the technical appendix.
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
python scripts/audit_cve_source.py
```

The mirror and index are runtime data under `project/storage/mitre_cve/` and are intentionally excluded from normal Git tracking. CVSS metadata may be incomplete in source records; the UI distinguishes unavailable scoring from confirmed evidence rather than inventing a score.

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

Two additional audit scripts report recon-boundary wording and CVE-index provenance:

```bash
cd project
python scripts/audit_no_scoring.py
python scripts/audit_cve_source.py
```

These are policy audits rather than test-suite prerequisites. They intentionally return a failure when disallowed UI wording is present or a sampled index contains an unexpected source; the CVE audit also reports when the local index has not yet been built.

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
