# AutoPenTest / PenPilot - Issues Register

**Project:** AutoPenTest / PenPilot  
**Environment:** Kali Linux virtual machine  
**Repository:** `/home/kali/Documents/IHL/FYP`  
**Evidence date:** 28 September 2026  

## Scope

This document records the project issues visible in the supplied screenshots and terminal output.

It intentionally describes only:

- the observed symptom;
- the available technical evidence;
- the affected component;
- the operational impact;
- the likely or confirmed cause.

Resolutions, implementation steps, and startup instructions are documented separately in `FIXES_REPORT.md`.

---

## Issue 1 - Caldera authenticated API requests return HTTP 500

### Observed symptom

PenPilot rejects a Caldera-dependent action and displays:

```text
Caldera API request failed for GET http://127.0.0.1:8888/api/v2/agents:
500 Server Error: Internal Server Error for url:
http://127.0.0.1:8888/api/v2/agents
```

### Affected components

- PenPilot Caldera integration;
- Caldera REST API;
- `/api/v2/agents`;
- authenticated `/api/v2/*` requests.

### Technical evidence

- Caldera is reachable on `127.0.0.1:8888`.
- The request reaches Caldera rather than failing with connection refused.
- Caldera returns HTTP `500`, meaning the server raises an internal exception while handling the authenticated request.
- The failure occurs before PenPilot can retrieve or evaluate agent data.

### Confirmed cause

The installed Caldera version expects the legacy string application key:

```text
aiohttp_security_identity_policy
```

The installed `aiohttp-security` version uses a typed `AppKey` instead. Caldera retrieves `None` for its identity policy and then attempts to call `identify()` on it.

Representative exception:

```text
AttributeError: 'NoneType' object has no attribute 'identify'
```

### Impact

- PenPilot cannot query Caldera agents.
- Caldera readiness checks fail.
- Agent selection and validation workflows are blocked.
- Operations that depend on Caldera are rejected even though the Caldera web interface is reachable.

### Severity

**High** - blocks an entire external integration and related assessment stages.

---

## Issue 2 - PenPilot reports zero online agents while Caldera shows one

### Observed symptom

PenPilot displays:

```text
0 online agent(s) observed. Target checked: 192.168.192.144.
```

At the same time, Caldera's Agents page shows:

- `1 alive`;
- `1 trusted`;
- several older agents marked `dead, untrusted`;
- a live Windows agent on host `client01`.

### Affected components

- `project/caldera/api_client.py`;
- Caldera agent normalization;
- PenPilot's agent-availability check;
- target-to-agent matching.

### Technical evidence

The trusted agent contains the expected target address:

```text
host_ip_addrs: ["192.168.192.144"]
```

The same agent is shown by Caldera as alive and trusted, but PenPilot filters it out.

Caldera's v2 API supplies timing fields such as:

```text
last_seen
sleep_min
sleep_max
```

It does not supply the explicit fields PenPilot originally expected:

```text
alive
status
state
```

### Confirmed cause

PenPilot derives agent liveness only from `alive`, `status`, or `state`. When those fields are absent, the lifecycle becomes `unknown`, which results in:

```text
alive = false
```

The otherwise valid trusted agent is then removed by the online-agent filter.

### Impact

- A healthy Caldera agent is treated as unavailable.
- PenPilot cannot proceed with agent-dependent validation.
- Users receive contradictory information between the Caldera and PenPilot interfaces.
- Targeted operations may be rejected despite a valid agent being present.

### Severity

**High** - produces a false negative that blocks authorized validation.

---

## Issue 3 - Attack-path advice module is unavailable

### Observed symptom

Assessment Stage 3 displays:

```text
Attack-path advice module is not available, but scan mapping and
AI technique planning are still working.
```

The attack-path table then displays:

```text
No safe attack-path advice could be generated from the current evidence.
```

### Affected components

- `project/pentest_ai/advisor.py`;
- `project/ai/technique_planner.py`;
- `project/routes/pentest_routes.py`;
- Assessment Stage 3 UI.

### Technical evidence

The advisor imports:

```python
from ai.technique_planner import build_mitre_url, shorten_text
```

`shorten_text` is available, but `build_mitre_url` is not exposed by `ai.technique_planner`.

The import raises:

```text
ImportError: cannot import name 'build_mitre_url'
from 'ai.technique_planner'
```

The route catches the exception and sets the advisor callable to `None`, hiding the underlying import failure from the UI.

### Confirmed cause

`build_mitre_url` exists in `ai.technique_intel`, but the planner module does not import or re-export it as expected by the advisor.

### Impact

- The attack-path advisor cannot load.
- The application silently substitutes a fallback response.
- No model-generated attack path is shown.
- The interface suggests that the module is optional or missing rather than exposing a source-code import defect.

### Severity

**High** - disables a primary assessment feature.

---

## Issue 4 - Ollama advice is always considered unavailable or unusable

### Observed symptom

After the advisor module becomes available, PenPilot displays:

```text
Ollama advice was unavailable or unusable, so AutoPenTest generated
a deterministic safe-validation path from the current evidence.
```

### Affected components

- `project/pentest_ai/advisor.py`;
- `project/ai/llm_client.py`;
- Ollama request and response handling;
- attack-path response parsing.

### Technical evidence

The advisor expects a raw JSON string containing:

```json
{
  "summary": "...",
  "attack_paths": [],
  "limitations": []
}
```

The configured helper, `ask_llm_json()`, is designed for a different task. It asks Ollama for:

```json
{
  "selected_technique_ids": [],
  "reasoning": ""
}
```

It parses the model output internally and returns a Python dictionary.

The advisor then attempts:

```python
json.loads(raw_response)
```

where `raw_response` is already a dictionary.

### Confirmed causes

#### Cause A - incompatible helper contract

The attack-path advisor uses the MITRE technique-planner helper. The prompt, expected schema, and return type do not match the advisor's parser.

#### Cause B - environment file not loaded by the LLM client

The LLM client can be imported before the main configuration module. In that case it does not load `project/.env` and falls back to:

```text
llama3.2:latest
```

Only this model is installed:

```text
llama3.2:1b
```

Requests for the unavailable model tag return HTTP `404`.

### Impact

- Ollama can be running normally while the application still reports it as unusable.
- Model-generated advice is discarded.
- The deterministic fallback runs for every request.
- Users cannot distinguish an unavailable model from a schema/typing error.

### Severity

**High** - the AI feature appears operational but never uses the model successfully.

---

## Issue 5 - Pytest aborts during test collection

### Observed symptom

Running:

```bash
pytest -q
```

produces multiple collection errors and terminates before the full suite can execute.

Screenshot output includes:

```text
Interrupted: 7 errors during collection
```

A later reproduction showed four principal collection failures after other environment differences were removed.

### Impact

- The regression suite cannot run.
- Passing and failing behavior cannot be assessed reliably.
- Application changes cannot be validated through CI-style testing.
- Additional failures remain hidden until collection succeeds.

### Severity

**High** - prevents all meaningful automated verification.

---

## Issue 6 - Test paths contain a duplicated `project` directory

### Observed symptom

Pytest raises:

```text
FileNotFoundError: [Errno 2] No such file or directory:
'/home/kali/Documents/IHL/FYP/project/project/templates/scan_vul.html'
```

The screenshot diff also shows test code changing from:

```python
ROOT / 'project' / 'templates' / 'scan_vul.html'
```

to:

```python
ROOT / 'templates' / 'scan_vul.html'
```

### Affected components

- `tests/test_cve_three_table_layout.py`;
- `tests/test_cve_applicability_precision.py`;
- other tests that derive paths from `Path(__file__).resolve().parents[1]`.

### Confirmed cause

For tests located in:

```text
project/tests/
```

`parents[1]` already resolves to:

```text
project/
```

Appending another `project` produces:

```text
project/project/
```

which does not exist.

### Impact

- Template and source-inspection tests fail during import.
- Test collection terminates before test functions run.
- Multiple unrelated tests appear broken because a shared path convention is wrong.

### Severity

**High** - directly causes collection failure.

---

## Issue 7 - Tests use package imports incompatible with the pytest root

### Observed symptom

Pytest raises:

```text
ModuleNotFoundError: No module named 'project'
```

Affected imports include:

```python
from project.enumeration import build_enumeration_intelligence
```

and:

```python
from project.scanners.enumerator import ...
```

### Affected components

- `tests/test_v33_18_enumeration_polish.py`;
- `tests/test_v33_31_native_protocol_enrichment.py`;
- pytest import-path configuration.

### Confirmed cause

`pytest.ini` is located in `project/`, and the suite is executed from that directory. The source packages are therefore imported directly:

```python
from enumeration import ...
from scanners.enumerator import ...
```

There is no installable top-level Python package named `project` in that execution context.

### Impact

- Enumeration test modules cannot be imported.
- Pytest terminates during collection.
- Native protocol enrichment behavior is not tested.

### Severity

**High** - directly causes collection failure.

---

## Issue 8 - Test references a nonexistent pivot package

### Observed symptom

Pytest raises:

```text
ModuleNotFoundError: No module named 'pivot'
```

The failing test imports:

```python
from pivot.pivot_engine import PivotEngine
```

### Affected component

```text
tests/test_demo_pivot_fixes.py
```

### Confirmed cause

No `pivot` package, `pivot_engine.py`, or `PivotEngine` class exists anywhere in the repository.

The test targets a feature that was removed, never merged, or left behind from another development branch.

### Impact

- Pytest collection fails.
- A dead test prevents unrelated active tests from running.
- The repository gives the false impression that a pivot engine is part of the current application.

### Severity

**High** for test execution; **informational** for the running application because the referenced feature does not exist.

---

## Issue 9 - Test references a removed pivot route

### Observed symptom

`test_target_change_clears_selected_paw` posts to:

```text
/pivot/target/select
```

Repository investigation shows that the route does not exist.

### Affected components

- `tests/test_caldera_targeting.py`;
- obsolete pivot-target workflow.

### Confirmed cause

The pivot feature was removed or refactored without removing or formally retiring its test.

No current route performs the behavior expected by this test.

### Impact

- The test fails against the current API.
- It is unclear from the suite whether pivot behavior is expected, deprecated, or accidentally missing.
- Maintenance time is wasted investigating behavior that is no longer implemented.

### Severity

**Medium** - does not break the active application, but creates misleading regression coverage.

---

## Issue 10 - Test suite contains stale route expectations

### Observed symptom

Tests expect:

```text
POST /scan
```

The current scan flow uses:

```text
POST /scan/discover
```

### Affected components

- operator-gate and CSRF session tests;
- scan workflow tests;
- route-level regression coverage.

### Confirmed cause

The scan flow was refactored, but tests retained the old endpoint.

### Impact

- Tests fail even when the current scan route behaves correctly.
- Session-preservation and CSRF behavior are tested against a route that no longer exists.
- Genuine route regressions may be obscured by obsolete endpoint failures.

### Severity

**Medium** - stale regression coverage rather than a runtime defect.

---

## Issue 11 - Test suite contains stale template locations

### Observed symptom

Tests inspect controls or partials in templates where those elements no longer reside.

Examples visible during investigation:

- port-coverage controls expected in `index.html` but located in `assessment_config.html`;
- tests referencing removed `pivot_assessment.html`;
- result-partial checks based on an older template structure.

### Affected components

- `tests/test_scan_profiles_v32_3.py`;
- `tests/test_frontend_quality_v32_2.py`;
- `tests/test_v32_6_pentester_workbench.py`;
- related frontend quality tests.

### Confirmed cause

Frontend templates were reorganized without updating tests that inspect source files directly.

### Impact

- Tests report failures despite the controls remaining present.
- Removed templates are still treated as active dependencies.
- Source-level UI regression tests no longer reflect the rendered application.

### Severity

**Medium** - test drift that reduces confidence in frontend regression checks.

---

## Issue 12 - Test suite expects retired UI wording and labels

### Observed symptom

Several tests assert exact user-facing text that no longer matches the templates.

Examples include:

```text
Table 1 - CVE References
```

while the current UI uses:

```text
Table 1 - Candidate CVE Review
```

Another test expects:

```text
Output
```

where the current interface uses:

```text
Evidence
```

### Affected components

- CVE layout tests;
- frontend quality tests;
- report quality tests;
- readability tests.

### Confirmed cause

Interface terminology was changed, but exact-string assertions were not updated.

### Impact

- Tests fail on wording differences rather than lost functionality.
- Genuine template regressions are mixed with intentional copy changes.
- The suite becomes brittle and expensive to maintain.

### Severity

**Low to Medium** - does not affect runtime behavior but produces significant test noise.

---

## Issue 13 - CVE/NVD tests expect an obsolete data-flow contract

### Observed symptom

Tests fail around:

- candidate CVE discovery;
- NVD fallback behavior;
- CVSS 3.1 and CVSS 4.0 enrichment;
- preservation of official CVE metrics;
- CVE classification labels.

### Affected components

- `tests/test_cve_applicability_precision.py`;
- `tests/test_final_full_scanner_fixes.py`;
- `tests/test_cvss_version_selection.py`;
- `tests/test_v32_7_evaluation_fixes.py`;
- NVD and CVE enrichment modules.

### Current application behavior

The implementation treats NVD as:

- a metric-enrichment source;
- not a source for introducing candidate CVEs;
- eligible to fill missing CVSS 3.1 or CVSS 4.0 data;
- unable to overwrite authoritative source metrics.

The current classification label is:

```text
Candidate CVE
```

`validate_published_metric()` also returns additional verification metadata.

### Confirmed cause

The tests were written for an older CVE data-flow contract and compare obsolete exact outputs or assumptions.

### Impact

- Correct current behavior is reported as failing.
- CVE-quality regression results are difficult to interpret.
- Important invariants, such as not overwriting authoritative metrics, are obscured by unrelated stale assertions.

### Severity

**Medium** - substantial test drift in a security-sensitive data pipeline.

---

## Issue 14 - Technique planner no longer exposes expected helper functions

### Observed symptom

Four planner tests fail with errors such as:

```text
AttributeError:
module 'ai.technique_planner' has no attribute
'get_mitre_technique_info'
```

Tests also expect to patch:

```text
fetch_cve_from_nvd
```

on the planner module.

### Affected components

- `project/ai/technique_planner.py`;
- `tests/test_technique_planner.py`;
- test monkeypatch integration points.

### Confirmed cause

The helper functions moved to `ai.technique_intel`, but the planner module no longer re-exports them. Existing callers and tests still treat the planner as the public integration surface.

### Impact

- Four planner tests fail before exercising planner logic.
- Tests cannot isolate external MITRE or NVD calls.
- The planner's effective public API is inconsistent with existing usage.

### Severity

**Medium** - breaks testability and compatibility, although direct internal imports may still work.

---

## Issue 15 - Runtime bootstrap test expects an insecure host default

### Observed symptom

The runtime environment test expects:

```dotenv
APP_HOST=0.0.0.0
```

The application currently defaults to:

```dotenv
APP_HOST=127.0.0.1
```

### Affected components

- `tests/test_runtime_env_bootstrap.py`;
- runtime configuration expectations.

### Confirmed cause

The application adopted a safer loopback-only default, while the test retained the older all-interface binding.

### Impact

- The bootstrap test fails despite the current default being more secure.
- A maintainer might incorrectly weaken the application binding just to satisfy the stale test.

### Severity

**Low** as a runtime issue; **Medium** as a potentially misleading security test.

---

## Issue 16 - Unexpected-peer listener test is timing-dependent

### Observed symptom

The full suite intermittently fails at:

```text
tests/test_web_exploiter_listener.py::
test_unexpected_peer_is_rejected_and_recorded
```

with:

```text
OSError
```

The same suite can pass on another run.

### Affected components

- `tests/test_web_exploiter_listener.py`;
- `ReverseShellListener` test client;
- socket shutdown timing.

### Confirmed cause

The listener correctly rejects a client whose source IP does not match `expected_peer`. It may close the connection before the test client completes:

```python
client.shutdown(socket.SHUT_WR)
```

That creates a race:

- if the client shuts down first, the test passes;
- if the listener closes first, the client receives `OSError`.

### Impact

- The suite is nondeterministic.
- A successful implementation can still produce a red build.
- One run reported `244 passed, 1 failed, 1 skipped` after a previous run had passed.

### Severity

**Medium** - intermittent test failure reduces confidence in CI results.

---

## Issue 17 - Duplicate Metasploit RPC password definitions

### Observed symptom

`project/.env` contains more than one:

```dotenv
METASPLOIT_RPC_PASS=...
```

The values are different.

### Affected components

- `.env` parsing;
- Metasploit RPC startup;
- PenPilot RPC authentication.

### Technical concern

The effective value depends on environment-file parsing and load order. The daemon may be started with one password while the application attempts another.

### Impact

- Authentication can fail after a restart.
- Troubleshooting is confusing because both values appear valid in the same file.
- Secret rotation may update one entry but leave the other active.

### Severity

**Medium** - latent configuration ambiguity.

---

## Issue 18 - Database account uses an empty password

### Observed condition

The application is configured with:

```dotenv
MYSQL_PASS=
```

The MariaDB `autopentest` account is configured to match.

### Affected components

- MariaDB account security;
- application database configuration.

### Risk

This is acceptable only while MariaDB remains restricted to loopback and the local account has limited privileges.

If MariaDB is exposed to another interface, the blank password becomes a serious security weakness.

### Impact

- Any local process may attempt authentication without a password.
- An accidental network bind could expose the database account to the lab network.

### Severity

**Medium**, rising to **Critical** if MariaDB is exposed beyond loopback.

---

## Issue 19 - Some required services do not persist across reboot

### Observed condition

MariaDB and Ollama run as systemd services, but these components require manual startup:

- Metasploit RPC;
- Caldera;
- PenPilot.

### Affected workflow

After a reboot, the application may start while one or more integrations remain unavailable.

### Impact

- Metasploit actions fail if `msfrpcd` is not running.
- Caldera actions fail if the server is not running.
- Users may misdiagnose missing services as application defects.

### Severity

**Medium** - operational reliability issue.

---

## Issue 20 - Caldera repair may be overwritten by package upgrades

### Observed condition

The Caldera compatibility problem exists in:

```text
/usr/share/caldera/app/service/auth_svc.py
```

This path is managed by the operating-system package.

### Risk

An `apt` upgrade or package reinstall can restore the incompatible upstream file.

### Impact

- Authenticated API calls may return HTTP `500` again.
- PenPilot's Caldera integration may regress without any repository change.
- The source-code test suite would not detect the external file replacement.

### Severity

**Medium** - external upgrade regression risk.

---

## Issue 21 - Kali and the target initially used different networks

### Observed symptom

Kali and the Windows target were both believed to be on NAT, but their addresses were:

```text
Kali:    192.168.192.142/24
Windows: 192.168.86.130/24
```

### Affected components

- VMware virtual network configuration;
- host discovery;
- authorized target validation;
- Caldera agent matching.

### Confirmed cause

The systems occupied different subnets:

```text
192.168.192.0/24
192.168.86.0/24
```

The Windows address was consistent with a bridged home-network address rather than the VMware VMnet8 NAT segment used by Kali.

### Impact

- Kali could not discover the Windows VM on its local segment.
- Direct communication required routing that was not configured.
- Caldera and scan workflows could not reliably associate the target.
- The lab risked placing an intentionally vulnerable target on a real LAN.

### Severity

**High** - blocks lab communication and creates a possible isolation risk.

---

## Issue 22 - Generated scan data is untracked and may contain sensitive details

### Observed condition

Git reports many untracked files under:

```text
project/storage/cache/
project/storage/cisa_kev/
project/storage/mitre_cve/
project/storage/msrc/
project/storage/msrc_windows/
project/storage/nvd_cache/
project/storage/results/
project/storage/scans/
```

### Data types observed

- Nmap XML output;
- ARP and ping evidence;
- SMB and RDP fingerprinting;
- HTTP and NTLM metadata;
- normalized scan data;
- knowledge graphs;
- evidence manifests;
- generated reports and assessment results.

### Risk

These files may contain:

- target IP addresses;
- service fingerprints;
- hostnames;
- discovered ports;
- evidence from authorized scans;
- generated security assessments.

### Impact

- Accidental Git commits may expose lab or client information.
- Large generated datasets can bloat repository history.
- Cached intelligence data may be mistaken for source code.

### Severity

**Medium** - repository hygiene and information-exposure risk.

---

## Issue 23 - Source-level tests are tightly coupled to exact implementation text

### Observed pattern

Many frontend and report tests inspect raw template or source text and require exact phrases, paths, or HTML fragments.

Examples include assertions for:

- exact table names;
- exact column headings;
- exact include paths;
- exact route strings;
- exact template locations.

### Affected components

- frontend quality tests;
- report quality tests;
- readability tests;
- CVE layout tests.

### Risk

Small refactors or harmless wording changes can create numerous failures without changing behavior.

### Impact

- High test-maintenance cost;
- noisy regressions;
- difficulty distinguishing broken behavior from changed copy;
- temptation to weaken application design to satisfy brittle assertions.

### Severity

**Low to Medium** - test-design issue affecting long-term maintainability.

---

## Issue 24 - Exploitation and validation features disabled by default flags

### Observed symptom

Several assessment panels reported the feature as switched off rather than running. Examples:

```text
SMB request failed: SMB exploitation is disabled.
Set ENABLE_SMB_EXPLOITATION=1 and restart the application.
```

```text
Controlled web validation is disabled.
```

### Affected components

- `project/.env` feature flags;
- `project/config.py` (`ENABLE_WEB_VALIDATION`, `ENABLE_SMB_EXPLOITATION`, `ENABLE_LAB_CREDENTIAL_AUDIT`);
- `project/routes/smb_routes.py`;
- `project/routes/pentest_routes.py`;
- `project/exploitation/web_validator.py`;
- `project/exploitation/credential_audit.py`.

### Technical evidence

`project/.env` contained:

```dotenv
ENABLE_WEB_VALIDATION=0
ENABLE_SMB_EXPLOITATION=0
ENABLE_LAB_CREDENTIAL_AUDIT=0
```

The route and service guards read these flags directly. When a flag is `0`, the request returns a structured `disabled` response before any action runs. The supporting command-line tools (`hydra`, `smbclient`, `smbmap`, `nmap`, and others) were already installed, so the block was purely configuration-driven.

### Confirmed cause

The three feature flags default to `0` and had not been enabled in `.env`. The application was behaving correctly; the capabilities were simply switched off.

### Impact

- Controlled web validation, SMB exploitation, and the lab credential audit could not be demonstrated.
- The panels implied a fault, when the true cause was a disabled flag.

### Severity

**Medium** - blocks demonstrable features, but is a configuration state rather than a code defect.

---

## Issue 25 - Malformed environment key prevents Metasploit poll interval from loading

### Observed symptom

`project/.env` defined the Metasploit poll interval with a stray leading character:

```dotenv
3METASPLOIT_POLL_INTERVAL=1
```

### Affected components

- `project/.env`;
- `project/config.py` (`METASPLOIT_POLL_INTERVAL`);
- Metasploit result polling.

### Technical evidence

The application reads `METASPLOIT_POLL_INTERVAL`, but the key on disk was `3METASPLOIT_POLL_INTERVAL`. The two names never match, so the configured value was ignored and the built-in default was used silently.

### Confirmed cause

A typo introduced a stray `3` prefix on the key name. Environment parsing does not warn about unknown keys, so the misconfiguration was silent.

### Impact

- The intended poll interval was never applied.
- The behaviour was correct by accident (default used), but the value in `.env` was misleading and untrustworthy.

### Severity

**Low** - silent configuration drift with no functional break at the default value.

---

## Issue 26 - Lab credential audit has no credential file configured

### Observed symptom

With the credential audit enabled, invoking it returns:

```text
Credential audit file was not found.
```

### Affected components

- `project/.env` (`LAB_CREDENTIAL_AUDIT_FILE`);
- `project/exploitation/credential_audit.py`.

### Technical evidence

`audit_smb_credentials()` reads a file of `username:password` pairs. When the path is missing it returns:

```python
{"ok": False, "status": "unavailable", "message": "Credential audit file was not found."}
```

`project/.env` set:

```dotenv
LAB_CREDENTIAL_AUDIT_FILE=
```

so no file was provided and the feature could not execute even when enabled.

### Confirmed cause

The credential audit requires an explicit, bounded lab credential list, but no file was configured. This is by design (the tool intentionally avoids large wordlists), but the missing default made the feature non-functional out of the box.

### Impact

- The lab credential audit could be enabled but never run.
- The feature failed gracefully rather than crashing, but produced no result.

### Severity

**Low to Medium** - the feature is unusable until a credential file is supplied.

---

## 27. Issue Summary by Severity

### High

1. Caldera authenticated API requests return HTTP `500`.
2. PenPilot reports zero online agents while Caldera shows one.
3. Attack-path advice module cannot be imported.
4. Ollama advice always falls back.
5. Pytest aborts during collection.
6. Tests build duplicated `project/project` paths.
7. Tests use incompatible `project.*` imports.
8. A nonexistent pivot package prevents test collection.
9. Kali and the target initially occupy different networks.

### Medium

1. Test references a removed pivot route.
2. Tests retain stale route and template expectations.
3. CVE/NVD tests use an obsolete data-flow contract.
4. Technique planner does not expose expected helpers.
5. Unexpected-peer listener test is timing-dependent.
6. Metasploit password is defined more than once.
7. Database account uses an empty password.
8. Required services do not all persist across reboot.
9. Caldera's external patch can be overwritten.
10. Generated scan evidence is untracked.
11. Exploitation and validation features disabled by default flags.
12. Lab credential audit has no credential file configured.

### Low or informational

1. Tests retain retired UI wording.
2. Runtime test expects an insecure host binding.
3. Source-level tests are tightly coupled to exact text.
4. Removed pivot functionality remains represented by obsolete tests.
5. Malformed environment key prevents the Metasploit poll interval from loading.

---

## 28. Overall Assessment

The project suffered from a combination of:

- incomplete local service setup;
- compatibility problems in an external Caldera package;
- API-schema assumptions that did not match Caldera v2;
- incompatible contracts between the attack advisor and LLM helper;
- unreliable environment loading;
- stale tests following route, template, and data-flow refactors;
- virtual-network misconfiguration;
- operational and repository-hygiene risks.

The most serious issues were not isolated UI defects. They prevented Caldera integration, agent detection, model-generated advice, and automated regression testing from functioning reliably.

---

## 29. Functions Involved Per Issue

This section records the specific functions associated with each issue - the function where the defect occurred and, where applicable, the function that was added or modified to address it. Only functions added or modified during this work are listed; unrelated functions are omitted. Full change descriptions are in `FIXES_REPORT.md`, Section 16.

### Application code

| Issue | File | Function | Role |
|---|---|---|---|
| Issue 1 (Caldera HTTP 500) | `/usr/share/caldera/app/service/auth_svc.py` | `AuthService.get_permissions()` | Defect site (external package); identity-key lookup patched |
| Issue 2 (zero online agents) | `project/caldera/api_client.py` | `CalderaClient._agent_lifecycle()` | Defect site; now falls back to timestamp-based liveness |
| Issue 2 (zero online agents) | `project/caldera/api_client.py` | `CalderaClient._lifecycle_from_last_seen()` | Added; derives `online`/`offline` from `last_seen` and `sleep_max` |
| Issue 2 (zero online agents) | `project/caldera/api_client.py` | `CalderaClient.get_online_agents()` | Consumer; now receives correct `alive` values (body unchanged) |
| Issue 3 (advice module unavailable) | `project/ai/technique_planner.py` | module-level re-export of `build_mitre_url` | Added; resolves the advisor's failing import |
| Issue 3 (advice module unavailable) | `project/pentest_ai/advisor.py` | `generate_attack_path_advice()` | Consumer; previously disabled by the import failure |
| Issue 4 (Ollama always fallback) | `project/pentest_ai/advisor.py` | `_ask_ollama_attack_path_json()` | Added; returns raw JSON string in the attack-path schema |
| Issue 4 (Ollama always fallback) | `project/pentest_ai/advisor.py` | `generate_attack_path_advice()` | Modified; default `ask_json` now points to the correct helper |
| Issue 4 (Ollama always fallback) | `project/ai/llm_client.py` | module-level `load_dotenv()` | Added; ensures the configured model is used |
| Issue 4 (Ollama always fallback) | `project/ai/llm_client.py` | `_ollama_settings()`, `ask_ollama()` | Affected indirectly; now resolve `llama3.2:1b` |
| Issue 14 (planner helpers) | `project/ai/technique_planner.py` | re-export of `get_mitre_technique_info`, `fetch_cve_from_nvd` | Added; restores expected planner integration surface |

### Test functions

| Issue | File | Function |
|---|---|---|
| Issue 6 (doubled path) | `tests/test_cve_three_table_layout.py` | `test_cve_review_has_exact_three_table_roles`, `test_table_one_is_reference_only` (module-level path constants) |
| Issue 6 (doubled path) | `tests/test_cve_applicability_precision.py` | `test_main_page_replaces_old_scan_and_vulnerability_tables`, `test_cvss_selector_controls_columns_and_sort_key` |
| Issue 7 (project.* imports) | `tests/test_v33_18_enumeration_polish.py` | `test_enumeration_intelligence_groups_roles_and_relationships` (module import) |
| Issue 7 (project.* imports) | `tests/test_v33_31_native_protocol_enrichment.py` | module import of `scanners.enumerator` |
| Issue 8 (nonexistent pivot package) | `tests/test_demo_pivot_fixes.py` | entire module (ignored via `pytest.ini`) |
| Issue 9 (removed pivot route) | `tests/test_caldera_targeting.py` | `test_target_change_clears_selected_paw` (skipped) |
| Issue 10 (stale route) | `tests/test_operator_gate.py` | `test_starting_scan_preserves_operator_and_csrf_session` |
| Issue 11 (stale templates) | `tests/test_scan_profiles_v32_3.py` | `test_ui_contains_adaptive_port_coverage_controls` |
| Issue 11 (stale templates) | `tests/test_frontend_quality_v32_2.py` | `test_results_partials_do_not_extend_the_scan_form_template` |
| Issue 11 (stale templates) | `tests/test_v32_6_pentester_workbench.py` | `test_results_template_is_service_centric_and_appendix_collapsed` |
| Issue 12 (retired wording) | `tests/test_frontend_quality_v32_2.py` | `test_report_uses_professional_cve_labels_and_cards`, `test_command_output_is_captured_from_real_result`, `test_live_command_log_has_modal_output_viewer`, `test_running_first_row_shows_target_current_next_profile`, `test_optional_noisy_tools_remain_backend_configurable`, `test_no_backend_internal_tools_in_results_template` |
| Issue 12 (retired wording) | `tests/test_v32_4_readability.py` | `test_vulnerability_review_uses_current_three_table_layout_without_retired_status_taxonomy`, `test_report_hides_internal_appendix_sections_raw_matcher_basis_and_proprietary_risk_score`, `test_no_user_facing_mismatch_filtering_text_in_results_template` |
| Issue 13 (CVE/NVD contract) | `tests/test_cve_applicability_precision.py` | `test_nvd_fallback_uses_structured_configuration_matching` |
| Issue 13 (CVE/NVD contract) | `tests/test_final_full_scanner_fixes.py` | `test_nvd_enrichment_only_fills_unscored_rows_and_never_overwrites_cve_program_metric`, `test_client_report_sources_do_not_reintroduce_retired_cve_status_terms` |
| Issue 13 (CVE/NVD contract) | `tests/test_cvss_version_selection.py` | `test_published_metric_integrity_preserves_exact_source_values` |
| Issue 13 (CVE/NVD contract) | `tests/test_v32_7_evaluation_fixes.py` | `test_non_contract_cve_classification_is_not_accepted`, `test_pdf_export_has_no_duplicate_paragraph_implementation` |
| Issue 13 (CVE/NVD contract) | `tests/test_report_quality_v32.py` | `test_postgresql_check_does_not_use_missing_pgsql_info_script` |
| Issue 14 (planner helpers) | `tests/test_technique_planner.py` | `test_planner_filters_invented_technique_ids`, `test_planner_falls_back_when_llm_returns_bad_json`, `test_cves_link_to_matching_attack_technique_only`, `test_planner_expands_smb_to_attack_path` (fixed by source re-export; test bodies unchanged) |
| Issue 15 (insecure host default) | `tests/test_runtime_env_bootstrap.py` | `test_env_bootstrap_generates_missing_secrets_and_preserves_existing` |
| Issue 16 (listener race) | `tests/test_web_exploiter_listener.py` | `test_unexpected_peer_is_rejected_and_recorded` |

### Configuration-driven issues (no source function changes)

Issues 17 and 24 to 26 were resolved by configuration and data files rather than by editing functions. The functions listed below are the gates that read the affected settings; their bodies were not changed.

| Issue | File | Gate / function that reads the setting | Resolution |
|---|---|---|---|
| Issue 17 (duplicate RPC password) | `project/.env`, `project/config.py` | `Config.METASPLOIT_RPC_PASS` | Removed the stray duplicate `METASPLOIT_RPC_PASS` line so a single value (`msf`) remains |
| Issue 24 (features disabled) | `project/routes/smb_routes.py` | SMB route guards checking `Config.ENABLE_SMB_EXPLOITATION` | Set `ENABLE_SMB_EXPLOITATION=1` |
| Issue 24 (features disabled) | `project/exploitation/web_validator.py` | `web_validation_service.enabled` (reads `Config.ENABLE_WEB_VALIDATION`) | Set `ENABLE_WEB_VALIDATION=1` |
| Issue 24 (features disabled) | `project/routes/pentest_routes.py`, `project/exploitation/credential_audit.py` | credential-audit route guard checking `Config.ENABLE_LAB_CREDENTIAL_AUDIT` | Set `ENABLE_LAB_CREDENTIAL_AUDIT=1` |
| Issue 25 (malformed key) | `project/.env`, `project/config.py` | `Config.METASPLOIT_POLL_INTERVAL` | Renamed `3METASPLOIT_POLL_INTERVAL` to `METASPLOIT_POLL_INTERVAL` |
| Issue 26 (missing audit file) | `project/exploitation/credential_audit.py` | `audit_smb_credentials(target, port, credential_file, ...)` | Created `project/lab_credentials.txt` and set `LAB_CREDENTIAL_AUDIT_FILE` to it |

