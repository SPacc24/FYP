# AutoPenTest / PenPilot
## Environment Setup, Fault Analysis, and Remediation Report

**Report date:** 29 September 2026  
**Project location:** `/home/kali/Documents/IHL/FYP`  
**Operating system:** Kali Linux  
**Application runtime:** Python 3.14 virtual environment  
**Final test result:** `245 passed, 1 skipped, 0 failed, 0 errors`

---

## 1. Purpose

This report records the work performed to make AutoPenTest/PenPilot operational on the current Kali Linux virtual machine.

It covers:

- runtime and dependency setup;
- database configuration;
- Ollama, Metasploit, and Caldera integration;
- virtual network troubleshooting;
- application defects found during end-to-end testing;
- test-suite collection and regression failures;
- the final verified system state;
- startup, verification, and recovery procedures.

The report distinguishes between:

1. **environment configuration**, such as starting services and creating the database;
2. **application defects**, where project source code required correction;
3. **external package defects**, such as the Caldera compatibility issue;
4. **stale tests**, where test expectations no longer matched the current application.

---

## 2. Executive Summary

The repository was already cloned and partially configured when troubleshooting began. The Python virtual environment and `.env` file existed, but several integrations were either incomplete or failing.

The main blockers were:

- MariaDB rejected the application's configured user;
- Caldera returned HTTP `500` for authenticated API calls;
- PenPilot could not identify a live Caldera agent;
- the attack-path advisor could not be imported;
- the advisor used the wrong Ollama helper and always selected its fallback path;
- the LLM client could silently select an unavailable model;
- the test suite stopped during collection and later exposed 31 additional failures;
- Kali and the Windows target initially occupied different virtual networks.

After remediation:

- the Flask application serves successfully on `127.0.0.1:5000`;
- MariaDB accepts the application account and contains the required schema;
- Ollama serves `llama3.2:1b`;
- Metasploit RPC authentication works on port `55552`;
- Caldera's API responds successfully on port `8888`;
- PenPilot recognizes the trusted Caldera agent on the authorized target;
- Ollama produces attack-path advice instead of always falling back;
- the complete test suite reports `245 passed, 1 skipped`.

---

## 3. Final Verified State

### 3.1 Application

- **Name shown in the browser:** PenPilot Network Discovery
- **URL:** `http://127.0.0.1:5000`
- **Launcher:** `/home/kali/Documents/IHL/FYP/start.sh`
- **Python interpreter:** `project/.venv/bin/python`
- **Authentication:** operator token stored in `project/.env`

The operator token is intentionally not included in this report.

### 3.2 Service status

| Component | Endpoint or location | Verified state |
|---|---|---|
| MariaDB | `127.0.0.1:3306` | Application login and schema initialization successful |
| Ollama | `http://127.0.0.1:11434` | Service active; `llama3.2:1b` available |
| Metasploit RPC | `https://127.0.0.1:55552` | Authentication successful |
| Caldera | `http://127.0.0.1:8888` | Authenticated v2 API requests successful |
| PenPilot | `http://127.0.0.1:5000` | HTTP `200` verified |

### 3.3 Database schema

The `autopentest` database contains:

- `scans`;
- `vulnerabilities`;
- `operations`;
- `technique_results`.

### 3.4 Test status

The final verification command was:

```bash
cd /home/kali/Documents/IHL/FYP/project
.venv/bin/python -m pytest -q
```

Final result:

```text
245 passed, 1 skipped in approximately 12 seconds
```

The single skipped test targets a removed pivot endpoint and is documented in Section 9.

---

## 4. Initial Environment Assessment

The following items were already present:

- repository at `/home/kali/Documents/IHL/FYP`;
- executable `install.sh` and `start.sh`;
- Python virtual environment at `project/.venv`;
- generated `project/.env`;
- installed Ollama binary;
- installed Metasploit Framework;
- installed Caldera under `/usr/share/caldera`.

The following items required completion or correction:

- MariaDB user authentication;
- database and schema verification;
- Metasploit RPC startup and authentication;
- Caldera API compatibility;
- Caldera enablement in `.env`;
- Caldera agent liveness interpretation;
- Ollama attack-advice integration;
- target VM network placement;
- test collection and regression cleanup.

---

## 5. Runtime and Service Configuration

### 5.1 Python environment

The existing virtual environment was checked against `requirements.txt`.

Result:

- required packages were already installed;
- dependency resolution completed without missing packages;
- the project interpreter was usable from `project/.venv/bin/python`.

No replacement virtual environment was required.

### 5.2 Environment file

`project/runtime_env.py` had already generated `project/.env`.

Important effective values included:

```dotenv
APP_HOST=127.0.0.1
PORT=5000
MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=
MYSQL_DB=autopentest
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=ADMIN123
ENABLE_CALDERA_EXECUTION=1
ENABLE_METASPLOIT=1
METASPLOIT_RPC_URL=https://127.0.0.1:55552
METASPLOIT_RPC_USER=msf
```

Secret values are not reproduced in this report.

### 5.3 MariaDB

MariaDB was running, but the application account could not authenticate.

The setup instructions contained an inconsistency:

- they created a database named `FYP`;
- they granted privileges on `autopentest.*`;
- the application configuration used `MYSQL_DB=autopentest`.

The application configuration was treated as authoritative. The `autopentest` database and matching grants were therefore used.

### 5.4 Ollama

Ollama was already installed as a systemd service. The service was active and the required model was present:

```text
llama3.2:1b
```

No additional model download was required.

### 5.5 Metasploit RPC

Metasploit was installed, but no RPC daemon was initially running.

The effective application credentials were confirmed and `msfrpcd` was started with SSL enabled:

```bash
msfrpcd -U msf -P '<configured-password>' \
  -a 127.0.0.1 -p 55552 -f
```

The RPC endpoint was verified by performing an `auth.login` request over MessagePack. The response returned `result: success` and a temporary token.

### 5.6 Caldera

Caldera was installed at:

```text
/usr/share/caldera
```

Its configuration and data directories are linked into `/var/lib/caldera` and owned by the `_caldera` service account. It should therefore be launched as that account:

```bash
cd /usr/share/caldera
sudo -u _caldera python3 server.py --insecure
```

The configured red API key matched `project/.env`, so no API-key change was required.

---

## 6. Database Authentication Failure

### 6.1 Symptom

Both the MariaDB CLI and the application returned:

```text
ERROR 1045 (28000): Access denied for user 'autopentest'@'localhost'
(using password: NO)
```

### 6.2 Investigation

The application was configured with:

```dotenv
MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=
MYSQL_DB=autopentest
```

MariaDB contained two matching accounts:

- `autopentest`@`localhost`;
- `autopentest`@`127.0.0.1`.

The `localhost` account had a non-empty `mysql_native_password` authentication string, while the `127.0.0.1` account had an empty one. MariaDB resolved the loopback connection to `localhost`, so the password-protected account took precedence.

### 6.3 Root cause

A leftover account from an earlier setup attempt had a password that did not match the blank `MYSQL_PASS` in `.env`.

`CREATE USER IF NOT EXISTS` did not correct the account because it already existed.

### 6.4 Resolution

The `localhost` account was altered to match the application configuration:

```sql
ALTER USER 'autopentest'@'localhost' IDENTIFIED BY '';
FLUSH PRIVILEGES;
```

### 6.5 Verification

Verification confirmed:

- TCP login as `autopentest` succeeded;
- `Database.test_connection()` returned success;
- `Database.init_schema()` returned success;
- all four application tables were present.

---

## 7. Caldera Integration Repairs

### 7.1 HTTP 500 from authenticated API requests

#### Symptom

PenPilot displayed:

```text
Caldera API request failed for GET
http://127.0.0.1:8888/api/v2/agents:
500 Server Error
```

#### Diagnostic evidence

- Caldera was reachable on port `8888`;
- unauthenticated calls returned HTTP `401`;
- authenticated calls reached Caldera but returned HTTP `500`;
- the URL and API key in `.env` were correct;
- the failure affected authenticated `/api/v2/*` routes generally, not only `/agents`.

#### Root cause

Kali supplied `aiohttp-security 0.5.0`, which uses typed `AppKey` objects. Caldera 5.3.0 still retrieved its identity policy with the legacy string key:

```python
request.config_dict.get('aiohttp_security_identity_policy')
```

That lookup returned `None`. Caldera then attempted:

```python
await identity_policy.identify(request)
```

This raised:

```text
AttributeError: 'NoneType' object has no attribute 'identify'
```

#### Resolution

The packaged Caldera file was backed up and patched:

```text
/usr/share/caldera/app/service/auth_svc.py
```

The corrected lookup uses the typed key and retains compatibility with older versions:

```python
identity_policy = (
    request.config_dict.get(aiohttp_security_api.IDENTITY_KEY)
    or request.config_dict.get('aiohttp_security_identity_policy')
)
```

Backup:

```text
/usr/share/caldera/app/service/auth_svc.py.bak
```

#### Verification

After restarting Caldera, authenticated requests to:

```text
/api/v2/agents
/api/v2/health
```

returned HTTP `200`.

#### Upgrade warning

This fix modifies a file owned by the Kali `caldera` package. A future package upgrade may overwrite it. If authenticated Caldera requests begin returning HTTP `500` again, compare `auth_svc.py` with the backup and reapply the compatibility change if needed.

---

### 7.2 PenPilot reported zero online agents

#### Symptom

Caldera showed:

- one agent as `alive, trusted`;
- four older agents as `dead, untrusted`.

PenPilot reported:

```text
0 online agent(s) observed
```

for target `192.168.192.144`.

#### Diagnostic evidence

The trusted agent returned by `/api/v2/agents` included:

```text
paw: qngkiz
host: client01
trusted: true
host_ip_addrs: ["192.168.192.144"]
last_seen: <recent UTC timestamp>
sleep_min: 30
sleep_max: 60
```

The API response did not contain explicit `alive`, `status`, or `state` fields.

#### Root cause

`project/caldera/api_client.py` only treated an agent as online when one of those missing fields explicitly said it was alive.

Without them, `_agent_lifecycle()` returned `unknown`, which resulted in:

```python
"alive": lifecycle == "online"
```

evaluating to `False`. The otherwise valid trusted agent was then filtered out.

#### Resolution

The client now derives liveness from `last_seen` when Caldera does not provide an explicit state.

An agent is considered online when its last contact falls within:

```text
max(sleep_max, 60) + 60 seconds
```

This allows one expected sleep cycle plus a short network-delay grace period.

#### Changed file

```text
project/caldera/api_client.py
```

Changes included:

- timezone-aware datetime parsing;
- handling for Caldera timestamps ending in `Z`;
- safe parsing of `sleep_max`;
- `_lifecycle_from_last_seen()` fallback;
- retention of explicit `alive` or `status` fields when provided.

#### Verification

The normalized result correctly reported:

```text
qngkiz: trusted=True, alive=True, lifecycle=online
```

The four stale agents were correctly reported as offline.

---

## 8. Ollama Attack-Path Advisor Repairs

### 8.1 Advisor module could not be imported

#### Symptom

The Stage 3 interface displayed:

```text
Attack-path advice module is not available, but scan mapping and
AI technique planning are still working.
```

#### Root cause

`project/pentest_ai/advisor.py` imported:

```python
from ai.technique_planner import build_mitre_url, shorten_text
```

`shorten_text` was available, but `build_mitre_url` was defined in `ai.technique_intel` and was not re-exported by `ai.technique_planner`.

The import raised:

```text
ImportError: cannot import name 'build_mitre_url'
```

`routes/pentest_routes.py` caught the exception and silently set:

```python
generate_attack_path_advice = None
```

The UI therefore showed the fallback message instead of the original exception.

#### Resolution

`project/ai/technique_planner.py` now re-exports:

```python
from ai.technique_intel import build_mitre_url
```

It also re-exports `get_mitre_technique_info` and `fetch_cve_from_nvd`, which are required by the planner tests and compatible extension points.

#### Verification

The route module was imported directly and confirmed:

```text
generate_attack_path_advice is None? False
```

---

### 8.2 Advisor always selected the deterministic fallback

#### Symptom

After fixing the import, the UI displayed:

```text
Ollama advice was unavailable or unusable, so AutoPenTest generated
a deterministic safe-validation path from the current evidence.
```

#### Root cause A: incorrect LLM helper

The advisor defaulted to `ask_llm_json()`.

That helper is specifically designed for the MITRE technique planner. It:

- replaces the supplied task with a planner-specific prompt;
- requests `{selected_technique_ids, reasoning}`;
- parses the model response internally;
- returns a Python dictionary.

The attack-path advisor expected:

- its own attack-path prompt to be preserved;
- an `attack_paths` array in the response;
- a raw JSON string to pass into `json.loads()`.

Passing a dictionary into `json.loads()` raised `TypeError`. The error was treated as an unavailable LLM response, so the deterministic fallback ran every time.

#### Root cause B: unreliable environment loading

`project/ai/llm_client.py` did not load `project/.env` itself.

When imported before `config.py`, it defaulted to:

```text
llama3.2:latest
```

Only `llama3.2:1b` was installed. Ollama therefore returned HTTP `404` for the unavailable model tag.

#### Resolution

`project/pentest_ai/advisor.py` now uses a dedicated helper:

```python
_ask_ollama_attack_path_json()
```

This helper:

- preserves the advisor's own prompt;
- calls Ollama directly;
- enables JSON mode;
- requests enough output tokens for the full schema;
- returns the raw JSON string expected by the parser.

`project/ai/llm_client.py` now loads:

```text
project/.env
```

at import time, ensuring the configured URL, model, and timeout are available regardless of module import order.

#### Verification

A live call using the real application environment returned:

```text
source: ollama
llm_available: true
attack_paths: 1
```

The generated result included a safe, human-approved SMB validation path for the authorized lab target.

---

## 9. Test-Suite Repairs

### 9.1 Initial collection failures

The first full `pytest` run stopped during collection.

#### Incorrect package imports

Two tests imported modules as:

```python
from project.enumeration import ...
from project.scanners.enumerator import ...
```

`pytest.ini` is inside `project/`, and tests are executed from that directory. The correct imports are:

```python
from enumeration import ...
from scanners.enumerator import ...
```

Affected files:

- `tests/test_v33_18_enumeration_polish.py`;
- `tests/test_v33_31_native_protocol_enrichment.py`.

#### Doubled project paths

`tests/test_cve_three_table_layout.py` computed:

```text
<repository>/project/project/templates/...
```

The extra `project` component was removed.

#### Missing pivot module

`tests/test_demo_pivot_fixes.py` imports:

```python
from pivot.pivot_engine import PivotEngine
```

No `pivot` package or `PivotEngine` implementation exists in the repository. The test targets a removed or never-merged feature and is now ignored in `pytest.ini`, alongside the already ignored `test_p4.py`.

### 9.2 Failures revealed after collection

Once collection succeeded, 31 failures became visible.

They fell into the following categories.

#### Source compatibility exports

`ai/technique_planner.py` now re-exports:

- `build_mitre_url`;
- `get_mitre_technique_info`;
- `fetch_cve_from_nvd`.

This preserves expected planner-module extension points and fixed four tests.

#### Stale filesystem paths

Several tests still assumed they lived outside `project/` and added an extra `project` path component. Paths were corrected without changing assertions.

#### Updated interface terminology

Tests were aligned with current user-facing labels, including:

- `Table 1 - Candidate CVE Review`;
- `Evidence` instead of the retired `Output` heading.

#### Moved templates and routes

Tests were updated for current application structure:

- port-coverage controls are in `assessment_config.html`;
- scan submission uses `/scan/discover`;
- removed `pivot_assessment.html` references were replaced with checks against active result partials.

#### Current CVE and NVD behavior

Tests now reflect the implemented data contract:

- NVD enriches CVE metrics but is not a candidate-CVE source;
- NVD may be queried when either CVSS 3.1 or CVSS 4.0 is missing;
- existing authoritative CVE metrics are not overwritten;
- `validate_published_metric()` returns additional verification metadata;
- the current classification label is `Candidate CVE`.

#### Secure host binding

The test expecting `APP_HOST=0.0.0.0` was stale. The application intentionally defaults to:

```text
127.0.0.1
```

The test was updated instead of weakening the secure default.

#### Flaky socket test

`test_unexpected_peer_is_rejected_and_recorded` contained a timing race.

The listener correctly rejected an unexpected source IP and could close the socket before the test client completed `shutdown(SHUT_WR)`. That expected early close sometimes raised `OSError`.

The test now treats the final client write as best-effort while retaining all assertions about:

- rejection of the unexpected peer;
- recorded callback event;
- peer count;
- no verified callback marker.

The corrected test was run five consecutive times successfully.

### 9.3 Skipped test

`test_target_change_clears_selected_paw` tests:

```text
/pivot/target/select
```

That route was removed with the pivot-target feature. The test was marked skipped with an explicit reason rather than deleted.

### 9.4 Final result

```text
245 passed
1 skipped
0 failed
0 errors
```

No meaningful assertion was removed solely to force a passing result. Application behavior was changed only where an actual defect was identified.

---

## 10. Virtual Network Troubleshooting

### 10.1 Symptom

Kali and the Windows target were both believed to be configured for NAT, but they could not communicate.

Observed addresses:

```text
Kali eth0:     192.168.192.142/24
Windows VM:    192.168.86.130/24
```

### 10.2 Root cause

The systems were on different layer-3 networks:

- Kali: `192.168.192.0/24`;
- Windows: `192.168.86.0/24`.

The Windows address was consistent with a bridged home-network address rather than this VMware installation's VMnet8 NAT subnet.

### 10.3 Resolution

The Windows VM adapter was moved to the same VMware NAT network as Kali and renewed through DHCP.

The target subsequently received:

```text
192.168.192.144
```

This placed both systems on `192.168.192.0/24`, allowing discovery, Caldera agent matching, and authorized lab scanning.

### 10.4 Recommendation

Keep lab systems on the same isolated VMware NAT or host-only network. Avoid bridging intentionally vulnerable targets onto a real home or organizational LAN.

---

## 11. Source Files Changed

### 11.1 Application code

| File | Purpose of change |
|---|---|
| `project/caldera/api_client.py` | Derive Caldera agent liveness from `last_seen` and sleep interval |
| `project/pentest_ai/advisor.py` | Use an attack-path-specific Ollama JSON call |
| `project/ai/llm_client.py` | Load `.env` independently and select the configured model reliably |
| `project/ai/technique_planner.py` | Re-export shared MITRE/CVE helpers expected by callers and tests |

### 11.2 Test and configuration files

| File or group | Purpose of change |
|---|---|
| `project/pytest.ini` | Ignore obsolete pivot test with no implementation |
| `project/tests/test_caldera_targeting.py` | Mark removed pivot endpoint test as skipped |
| CVE and CVSS test files | Align paths, labels, and enrichment expectations |
| Frontend and report test files | Align active templates, headings, and routes |
| Enumeration tests | Correct package imports |
| `test_web_exploiter_listener.py` | Remove socket-close timing flake while preserving behavior assertions |

### 11.3 External changes

These changes are not represented by the repository Git diff:

| Location | Change |
|---|---|
| `/usr/share/caldera/app/service/auth_svc.py` | aiohttp-security typed-key compatibility patch |
| MariaDB system tables | Corrected `autopentest` account authentication |
| MariaDB `autopentest` database | Created/verified application schema |
| VMware VM settings | Placed Kali and target on the same NAT subnet |

### 11.4 Generated runtime data

The project generated numerous untracked files under:

- `project/storage/cache/`;
- `project/storage/cisa_kev/`;
- `project/storage/mitre_cve/`;
- `project/storage/msrc/`;
- `project/storage/msrc_windows/`;
- `project/storage/results/`;
- `project/storage/scans/`;
- `project/storage/nvd_cache/`.

These are scan results, evidence, caches, intelligence feeds, or generated reports. They are not source-code fixes and should be reviewed before committing.

---

## 12. Startup Procedure

### 12.1 Start persistent services

MariaDB and Ollama are configured as system services:

```bash
sudo systemctl start mariadb
sudo systemctl start ollama
```

Verify:

```bash
systemctl is-active mariadb
systemctl is-active ollama
ollama list
```

### 12.2 Start Metasploit RPC

Use the password configured by the effective `METASPLOIT_RPC_PASS` value:

```bash
msfrpcd \
  -U msf \
  -P '<METASPLOIT_RPC_PASS>' \
  -a 127.0.0.1 \
  -p 55552 \
  -f
```

Keep this process running in its own terminal.

### 12.3 Start Caldera

```bash
cd /usr/share/caldera
sudo -u _caldera python3 server.py --insecure
```

Allow approximately 30-60 seconds for plugin loading and Sandcat compilation.

Verify:

```bash
curl -s -o /dev/null -w 'agents: %{http_code}\n' \
  -H 'KEY: ADMIN123' \
  http://127.0.0.1:8888/api/v2/agents

curl -s -o /dev/null -w 'health: %{http_code}\n' \
  -H 'KEY: ADMIN123' \
  http://127.0.0.1:8888/api/v2/health
```

Expected result:

```text
agents: 200
health: 200
```

### 12.4 Start PenPilot

```bash
cd /home/kali/Documents/IHL/FYP
./start.sh
```

Open:

```text
http://127.0.0.1:5000
```

Use the `OPERATOR_TOKEN` from `project/.env`.

---

## 13. Health-Check Procedure

Use these checks when diagnosing startup problems.

### 13.1 Ports

```bash
ss -ltn
```

Expected listening ports:

- `5000` - PenPilot;
- `8888` - Caldera;
- `11434` - Ollama;
- `55552` - Metasploit RPC;
- `3306` - MariaDB, depending on bind configuration.

### 13.2 Application

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:5000/
```

Expected: `200`.

### 13.3 Ollama

```bash
curl -s http://127.0.0.1:11434/api/tags
ollama list
```

Confirm that `llama3.2:1b` is listed.

### 13.4 Database

```bash
mysql -u autopentest -h 127.0.0.1 autopentest \
  -e 'SHOW TABLES;'
```

Expected tables:

```text
operations
scans
technique_results
vulnerabilities
```

### 13.5 Tests

```bash
cd /home/kali/Documents/IHL/FYP/project
.venv/bin/python -m pytest -q
```

Expected:

```text
245 passed, 1 skipped
```

---

## 14. Remaining Risks and Recommendations

### 14.1 Caldera package upgrades

The Caldera API repair is outside the repository and may be overwritten by an operating-system package update.

**Recommendation:** retain `auth_svc.py.bak` and document/reapply the patch after upgrades if authenticated API calls regress to HTTP `500`.

### 14.2 Manual service startup

Caldera, Metasploit RPC, and PenPilot currently require manual startup.

**Recommendation:** create dedicated systemd units only if persistent startup is desired. Services should run as restricted users and remain bound to loopback or the isolated lab network.

### 14.3 Duplicate Metasploit password entry (resolved)

`project/.env` contained duplicate `METASPLOIT_RPC_PASS` definitions with different values. During feature setup this caused a live `auth.login` failure because `msfrpcd` was started from the first value while the application resolved the second. The stray duplicate line was removed so a single `METASPLOIT_RPC_PASS` entry (`msf`) remains. See Section 17.1 for details.

**Recommendation:** keep one `METASPLOIT_RPC_PASS` entry and ensure it matches the value supplied to `msfrpcd`.

### 14.4 Blank database password

The application currently uses an empty password for a loopback-only MariaDB account because that matches the provided project instructions.

**Recommendation:** assign a strong local password, update `MYSQL_PASS`, and verify the database remains bound to loopback. Do not expose MariaDB to the lab network with an empty password.

### 14.5 LLM model size

`llama3.2:1b` runs reliably but produces brief advice.

**Recommendation:** if system memory permits, test a larger compatible local model and update `OLLAMA_MODEL` in `.env`. Re-run advisor tests and manual safety checks before relying on its output.

### 14.6 Generated data in Git

Scan outputs, cache files, and intelligence feeds are untracked.

**Recommendation:** review `.gitignore` before committing. Generated evidence may contain target details and should not be uploaded unintentionally.

### 14.7 Removed pivot feature

One test remains skipped because the pivot route and implementation no longer exist.

**Recommendation:** either remove the obsolete test permanently with a documented decision, or restore the pivot feature and reactivate its tests.

---

## 15. Completion Criteria

The remediation was considered complete when all of the following were true:

- the app started without dependency errors;
- the app returned HTTP `200`;
- MariaDB login and schema initialization succeeded;
- Ollama served the configured model;
- Metasploit RPC authentication returned success;
- Caldera authenticated API calls returned HTTP `200`;
- the trusted Caldera agent matched the authorized target;
- attack-path advice used Ollama successfully;
- Kali and the target occupied the same isolated subnet;
- the full test suite completed with no failures or errors.

All criteria were met at the time of final verification.

---

## 16. Function-Level Changes

This section records every function that was added or modified during remediation, with its file, role, and the exact change made. It is limited to functions touched while fixing the issues; unchanged functions are not listed.

### 16.1 Application code

#### `project/ai/llm_client.py`

Module-level initialization (not a single function) was added: the module now calls `load_dotenv()` at import time.

- **Change:** added `from pathlib import Path`, `from dotenv import load_dotenv`, and `load_dotenv(Path(__file__).resolve().parents[1] / ".env")` near the top of the module.
- **Why:** ensures `OLLAMA_MODEL`, `OLLAMA_URL`, and `OLLAMA_TIMEOUT` resolve correctly even if this module is imported before `config.py`.
- **Functions affected indirectly (bodies unchanged):**
  - `_ollama_settings()` - now reads the correct `OLLAMA_MODEL` (`llama3.2:1b`) instead of the default `llama3.2:latest`.
  - `ask_ollama(...)` - now targets an installed model, avoiding HTTP `404`.
  - `ask_llm_json(...)` - benefits from the same corrected environment.

#### `project/ai/technique_planner.py`

Module-level re-export (not a single function) was added.

- **Change:** added `from ai.technique_intel import (build_mitre_url, get_mitre_technique_info, fetch_cve_from_nvd)`.
- **Why:** callers and tests expect these helpers to be importable and patchable on `ai.technique_planner`. Only `build_mitre_url` was missing initially; `get_mitre_technique_info` and `fetch_cve_from_nvd` were added to satisfy the planner tests' monkeypatch points.
- **Functions affected:** none of the planner's own function bodies changed; the module now exposes the three helper names as attributes.

#### `project/caldera/api_client.py`

- **`CalderaClient._agent_lifecycle(self, agent)`** - *modified.*
  - **Before:** returned `"unknown"` when the agent had no explicit `alive`/`status`/`state` field.
  - **After:** before returning `"unknown"`, it calls `self._lifecycle_from_last_seen(agent)` and returns that result when available.
  - **Effect:** trusted agents that only report timing fields are now correctly classified as `online`.
- **`CalderaClient._lifecycle_from_last_seen(self, agent)`** - *added (new method).*
  - Reads `last_seen` / `last_seen_time` / `last_seen_at`.
  - Normalizes trailing `Z` to `+00:00` and parses to a timezone-aware `datetime`.
  - Safely parses `sleep_max` (defaulting to 0 on error).
  - Computes `threshold = max(sleep_max, 60) + 60` seconds and returns `"online"` if the last check-in is within the threshold, otherwise `"offline"`; returns `None` when no timestamp is present.
  - **Supporting import added:** `from datetime import datetime, timezone`.

#### `project/pentest_ai/advisor.py`

- **`_ask_ollama_attack_path_json(prompt)`** - *added (new module function).*
  - Calls `ask_ollama(prompt, num_predict=800, temperature=0.2, json_mode=True)` and returns the raw JSON string.
  - Provides the response type/schema that `_parse_llm_response` expects (a JSON string in the attack-path schema).
- **`generate_attack_path_advice(...)`** - *modified (signature default only).*
  - **Before:** `ask_json: Callable[[str], str] = ask_llm_json`.
  - **After:** `ask_json: Callable[[str], str] = _ask_ollama_attack_path_json`.
  - **Supporting import changed:** `from ai.llm_client import ask_ollama` (previously `ask_llm_json`).
  - **Effect:** advice requests now use the correct helper and schema, so `source` becomes `ollama` instead of always falling back.

### 16.2 Test functions

The following test functions were updated to match the current application (paths, routes, templates, labels, and data-flow), or to remove a timing flake. No assertions were removed to force a pass.

| File | Function | Change |
|---|---|---|
| `tests/test_caldera_targeting.py` | `test_target_change_clears_selected_paw` | Marked skipped - the `/pivot/target/select` route was removed (`import pytest` added) |
| `tests/test_cve_applicability_precision.py` | `test_nvd_fallback_uses_structured_configuration_matching` | Asserts NVD is not used as a candidate-CVE source, only for structured matching |
| `tests/test_cve_applicability_precision.py` | `test_main_page_replaces_old_scan_and_vulnerability_tables` | Corrected doubled `project/project` template path |
| `tests/test_cve_applicability_precision.py` | `test_cvss_selector_controls_columns_and_sort_key` | Corrected doubled `project/project` template path |
| `tests/test_cve_three_table_layout.py` | `test_cve_review_has_exact_three_table_roles` | Module-level `TEMPLATE`/`MITRE`/`ENUMERATOR` paths de-duplicated; label updated |
| `tests/test_cve_three_table_layout.py` | `test_table_one_is_reference_only` | Same path fix; reflects current table-one content |
| `tests/test_cvss_version_selection.py` | `test_published_metric_integrity_preserves_exact_source_values` | Accepts new verification fields; still checks original values and `cvss_verified` |
| `tests/test_final_full_scanner_fixes.py` | `test_nvd_enrichment_only_fills_unscored_rows_and_never_overwrites_cve_program_metric` | Lists exact CVEs queried when missing a 3.1 or 4.0 score; keeps no-overwrite rule |
| `tests/test_final_full_scanner_fixes.py` | `test_client_report_sources_do_not_reintroduce_retired_cve_status_terms` | Updated to current CVE status terminology |
| `tests/test_frontend_quality_v32_2.py` | `test_live_command_log_has_modal_output_viewer` | Aligned with current results template |
| `tests/test_frontend_quality_v32_2.py` | `test_running_first_row_shows_target_current_next_profile` | Aligned with current results template |
| `tests/test_frontend_quality_v32_2.py` | `test_report_uses_professional_cve_labels_and_cards` | Updated to renamed labels (`Candidate CVE Review`) |
| `tests/test_frontend_quality_v32_2.py` | `test_optional_noisy_tools_remain_backend_configurable` | Reads `config.py` with corrected expectations |
| `tests/test_frontend_quality_v32_2.py` | `test_command_output_is_captured_from_real_result` | Column renamed `Output` -> `Evidence` |
| `tests/test_frontend_quality_v32_2.py` | `test_no_backend_internal_tools_in_results_template` | Aligned with current results template |
| `tests/test_frontend_quality_v32_2.py` | `test_results_partials_do_not_extend_the_scan_form_template` | Checks active partials no longer use `{% extends %}`; removed `pivot_assessment.html` reference |
| `tests/test_operator_gate.py` | `test_starting_scan_preserves_operator_and_csrf_session` | Posts to `/scan/discover` instead of `/scan` |
| `tests/test_report_quality_v32.py` | `test_postgresql_check_does_not_use_missing_pgsql_info_script` | Path/expectation corrected |
| `tests/test_runtime_env_bootstrap.py` | `test_env_bootstrap_generates_missing_secrets_and_preserves_existing` | Expects secure `APP_HOST=127.0.0.1` default |
| `tests/test_scan_profiles_v32_3.py` | `test_ui_contains_adaptive_port_coverage_controls` | Reads `assessment_config.html` where the controls now live |
| `tests/test_v32_4_readability.py` | `test_vulnerability_review_uses_current_three_table_layout_without_retired_status_taxonomy` | Updated to current layout/terminology |
| `tests/test_v32_4_readability.py` | `test_report_hides_internal_appendix_sections_raw_matcher_basis_and_proprietary_risk_score` | Updated to current report structure |
| `tests/test_v32_4_readability.py` | `test_no_user_facing_mismatch_filtering_text_in_results_template` | Updated to current results template |
| `tests/test_v32_6_pentester_workbench.py` | `test_results_template_is_service_centric_and_appendix_collapsed` | Aligned with current results template |
| `tests/test_v32_7_evaluation_fixes.py` | `test_non_contract_cve_classification_is_not_accepted` | Compares against the `Candidate CVE` baseline constant |
| `tests/test_v32_7_evaluation_fixes.py` | `test_pdf_export_has_no_duplicate_paragraph_implementation` | Path/expectation corrected |
| `tests/test_v33_18_enumeration_polish.py` | `test_enumeration_intelligence_groups_roles_and_relationships` | Import changed from `project.enumeration` to `enumeration` (module-level) |
| `tests/test_v33_31_native_protocol_enrichment.py` | (module import) | Import changed from `project.scanners.enumerator` to `scanners.enumerator` |
| `tests/test_web_exploiter_listener.py` | `test_unexpected_peer_is_rejected_and_recorded` | Wraps best-effort client write in `try/except OSError` to remove a socket-close race |

The four `tests/test_technique_planner.py` failures (`test_planner_filters_invented_technique_ids`, `test_planner_falls_back_when_llm_returns_bad_json`, `test_cves_link_to_matching_attack_technique_only`, `test_planner_expands_smb_to_attack_path`) were fixed entirely by the `ai/technique_planner.py` re-export in Section 16.1 - those test functions were not edited.

### 16.3 Configuration

- **`project/pytest.ini`** - added `--ignore=tests/test_demo_pivot_fixes.py` to `addopts` (dead test importing a nonexistent `pivot` module).

---

## 17. Feature Enablement for Showcasing

After the core system was operational, a further pass made every intended assessment feature usable for demonstration. These items are configuration and data changes in `project/.env` and one new data file; no application source functions were modified in this section.

### 17.1 Duplicate Metasploit RPC password (root-caused and removed)

While starting `msfrpcd` for a live check, `auth.login` was rejected. Investigation showed `project/.env` defined `METASPLOIT_RPC_PASS` twice with different values:

- a long auto-generated value earlier in the file;
- `msf` later in the file.

`python-dotenv` (used by the application) keeps the last value (`msf`), but a first-match shell extraction started `msfrpcd` with the earlier value, so the two never agreed.

**Resolution:** removed the stray earlier `METASPLOIT_RPC_PASS` line, leaving a single entry (`msf`). After restarting `msfrpcd` with the resolved value, `auth.login` returned a token and `core.version` reported `6.4.135-dev`.

### 17.2 Malformed poll-interval key

`project/.env` contained a mistyped key:

```dotenv
3METASPLOIT_POLL_INTERVAL=1
```

The application reads `METASPLOIT_POLL_INTERVAL`, so the configured value was ignored and the default was used silently.

**Resolution:** renamed the key to `METASPLOIT_POLL_INTERVAL`. `Config.METASPLOIT_POLL_INTERVAL` now resolves to `1.0`.

### 17.3 Disabled feature flags

Three capability flags were switched off, which produced the "... is disabled" messages in the assessment panels:

| Flag | Before | After | Feature unblocked |
|---|---|---|---|
| `ENABLE_WEB_VALIDATION` | 0 | 1 | Controlled web validation |
| `ENABLE_SMB_EXPLOITATION` | 0 | 1 | SMB fingerprint / brute-force / file operations |
| `ENABLE_LAB_CREDENTIAL_AUDIT` | 0 | 1 | Bounded lab SMB credential audit |

All other capability flags were already enabled. After the change, all 13 `ENABLE_*` flags resolve to `True`.

### 17.4 Missing lab credential file

With the credential audit enabled, `audit_smb_credentials()` returned "Credential audit file was not found" because `LAB_CREDENTIAL_AUDIT_FILE` was empty.

**Resolution:** created `project/lab_credentials.txt` containing a short, bounded list of `username:password` pairs for authorized lab use, and set:

```dotenv
LAB_CREDENTIAL_AUDIT_FILE=lab_credentials.txt
```

The path now resolves relative to the project directory and the audit can execute.

### 17.5 Dependency and runtime verification

The command-line tools each feature depends on were confirmed present: `nmap`, `hydra`, `smbclient`, `smbmap`, `gobuster`, `httpx`, `nuclei`, `arp-scan`, `msfconsole`, `enum4linux`, `nbtscan`, and the configured gobuster wordlist. After restarting the application to reload the environment:

- the app returned HTTP `200`;
- `web_validation_service.enabled`, `smb_exploiter.enabled`, and `metasploit_client.enabled` all reported `True`;
- the web validator reported no configuration error;
- the credential-audit file resolved and existed.

### 17.6 Files changed in this section

| File | Change |
|---|---|
| `project/.env` | Removed duplicate `METASPLOIT_RPC_PASS`; fixed `METASPLOIT_POLL_INTERVAL` key; set three `ENABLE_*` flags to `1`; set `LAB_CREDENTIAL_AUDIT_FILE` |
| `project/lab_credentials.txt` | New bounded lab credential list for the SMB credential audit |

### 17.7 Notes for the demonstration

- These features still require a reachable RFC1918 lab target on the relevant services (SMB on 445, the lab web host, and so on). Flags, tools, and credentials are ready; only the target must be present and on the same subnet.
- Proof-of-access ticketing (`PROOF_OF_ACCESS_ENABLED`) was intentionally left off; it is an access-gating add-on rather than an assessment capability.

