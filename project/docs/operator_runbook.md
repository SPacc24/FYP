# AutoPenTest Operator Runbook

This runbook is the practical operating procedure for preparing, starting, using, stopping, and recovering AutoPenTest in an authorised lab. Commands are written for Kali Linux unless a Windows alternative is shown.

> Use AutoPenTest only against systems covered by written authorisation. Confirm the target list and engagement policy before every scan. The bundled policy is suitable for a private FYP lab demonstration, not a company assessment.

## 1. Pre-flight checklist

Before starting the application, confirm:

- The Kali/controller host and authorised target VMs are on the intended isolated network.
- Target IP addresses and ranges are covered by `project/policies/engagement_policy.json` or the file selected by `ENGAGEMENT_POLICY_FILE`.
- The target count is within both the policy limit and `MAX_EXPANDED_TARGETS`.
- `project/.env` is present, readable only by the operator, and not committed to Git.
- Nmap is installed. Optional tools needed for the selected collectors are available.
- Ollama, CALDERA, Metasploit RPC, MySQL, and proof of access are disabled unless the current exercise requires them.
- Old scan evidence has been archived or cleaned if it must not be mixed with the new assessment.

From the repository root:

```bash
cd /home/kali/FYP
python project/scripts/bootstrap_env.py
python project/scripts/check_tooling.py
```

To display the operator token in a trusted terminal:

```bash
python project/scripts/bootstrap_env.py --show-secrets
```

Do not paste the output into chat, tickets, reports, or screenshots.

## 2. First-time installation

### Kali Linux

```bash
cd /home/kali/FYP
chmod +x install.sh start.sh
./install.sh
```

The installer creates `project/.venv`, installs Python and Kali dependencies, prepares storage, generates local secrets, and attempts to synchronise the official CVE List.

If only Python dependencies need to be refreshed:

```bash
cd /home/kali/FYP/project
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Windows or VS Code

In PowerShell from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
```

Native Windows supports the Flask UI and reporting workflow. Kali or WSL is recommended for complete external-tool coverage.

## 3. Configuration check

Open `project/.env` locally and check at least these values:

```env
DEBUG=false
APP_HOST=127.0.0.1
PORT=5000
OPERATOR_TOKEN=<generated-value>
ENABLE_CALDERA_EXECUTION=0
ENABLE_METASPLOIT=0
ENABLE_METASPLOIT_EXPLOITS=0
ENABLE_WEB_VALIDATION=0
PROOF_OF_ACCESS_ENABLED=false
```

For access from another host on the trusted lab network, set:

```env
APP_HOST=0.0.0.0
```

Non-loopback startup is refused unless the secret key is strong, the operator token is configured, and debug mode is disabled. Allow inbound TCP port 5000 only from the intended management host. Do not expose the Flask development server to the internet.

After any `.env` change, restart Flask. Most service clients are initialised when the application imports.

## 4. Start the core application

From the repository root:

```bash
bash start.sh
```

The launcher prefers `project/.venv`, changes into `project/`, and runs `app.py`. Expected output includes the Flask listening address. On first startup it may also report generated configuration values.

Windows PowerShell:

```powershell
.\start_windows.ps1
```

Open:

```text
http://127.0.0.1:5000
```

For a trusted remote browser, replace `127.0.0.1` with the Kali/controller IP. Enter the generated operator token on the landing page when prompted.

## 5. Optional service startup

Start only the services required for the exercise, preferably in separate terminals.

### Ollama

```bash
ollama serve
```

In another terminal:

```bash
ollama pull llama3.2:1b
curl http://127.0.0.1:11434/api/tags
```

Set `OLLAMA_MODEL` to an installed model. The dashboard's AI status should show the configured model as installed. Recon and deterministic technique planning still work if Ollama is unavailable.

### CALDERA

Start CALDERA according to its local installation, for example:

```bash
cd /path/to/caldera
source .venv/bin/activate 2>/dev/null || true
python3 server.py --insecure
```

Then verify these values in `project/.env`:

```env
CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=<local-api-key>
AGENT_GROUP=red
KALI_IP=<controller-ip-reachable-by-agent>
ENABLE_CALDERA_EXECUTION=0
```

Keep execution disabled while checking connectivity, agent identity, and ability coverage. Enable it only immediately before an approved operation, then restart Flask:

```env
ENABLE_CALDERA_EXECUTION=1
```

### Metasploit RPC

Retrieve the configured password in a trusted terminal:

```bash
cd /home/kali/FYP
python project/scripts/bootstrap_env.py --show-secrets
```

Start RPC with the exact configured credentials:

```bash
msfrpcd -U msf -P '<METASPLOIT_RPC_PASS>' -a 127.0.0.1 -p 55552
```

Set `ENABLE_METASPLOIT=1` and restart Flask. Keep `ENABLE_METASPLOIT_EXPLOITS=0`; the shipped policy uses evidence-derived auxiliary scanner actions only.

### MySQL

MySQL is optional. When used, ensure the configured account can create and use the `autopentest` database:

```env
MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=<local-password>
MYSQL_DB=autopentest
```

The primary scan workflow persists JSON without MySQL. A database connection error at startup does not prevent the dashboard from loading.

## 6. CVE data readiness

Check the local official CVE index:

```bash
cd /home/kali/FYP/project
source .venv/bin/activate
python scripts/mitre_cve_status.py
python scripts/audit_cve_source.py
```

If the mirror or index is absent or stale:

```bash
python scripts/sync_mitre_cve_database.py
python scripts/rebuild_mitre_cve_index.py
python scripts/mitre_cve_status.py
```

The sync step requires internet access. A scan can still run without a ready index, but CVE correlation will be unavailable or incomplete.

## 7. Run an assessment

### 7.1 Validate scope

Confirm the exact target input before submitting it. Supported dashboard forms include:

```text
192.168.56.10
192.168.56.10,192.168.56.20
192.168.56.10-30
192.168.56.0/28
```

The main pipeline expects IP addresses, not hostnames. Do not rely on the private-lab fallback for a real engagement; use explicit `allowed_networks` in a dedicated policy file.

### 7.2 Choose numerical port coverage

- **Complete TCP coverage** tests ports 1 through 65,535.
- **Common TCP coverage** uses the versioned numerical set in `policies/port_coverage.json`.
- **Custom TCP coverage** tests only operator-entered ports and ranges.
- Additional and excluded port fields modify the selected base coverage.
- UDP coverage is selected and executed separately; it is disabled by default.

The port choice determines where the scanner looks. It does not determine which service is present. Every observed open port is submitted to the general fingerprinting stage before specialist modules are dispatched.

The Advanced section defaults to 256 ports per sequential microbatch, four concurrent targets, a three-second probe timeout, and one retry. Only one microbatch runs at a time for any individual target.

### 7.3 Monitor execution

After submission, remain on the progress page and watch:

- Current and next task
- Task completion percentage
- Tool status and unavailable collectors
- Commands and summarised output
- Pipeline errors or timeouts

Closing the browser does not stop the in-process worker, but restarting Flask does. Active scan state is initially held in memory.

### 7.4 Review results

When the scan completes, review in this order:

1. Scope-validation result and warnings.
2. Host and service inventory.
3. Service evidence and raw artefact references.
4. Confirmed CVE matches and their version evidence.
5. Candidate CVE references and evidence gaps.
6. Security observations and attack-surface workbench.
7. ATT&CK mapping and technique explanations.
8. Tool coverage and incomplete checks.
9. Technical appendix and evidence manifest.

Treat candidate CVEs as research leads, not confirmed vulnerabilities. Confirm product identity, version applicability, and compensating controls before reporting them as findings.

## 8. Controlled validation procedure

Validation is a separate operator action after recon review.

1. Confirm the active scan and target shown by the dashboard.
2. Review the proposed validation action and the evidence that authorised it.
3. Confirm it is allowed by the current rules of engagement.
4. Run only the server-generated action; never substitute arbitrary module or target data.
5. Review the returned evidence and record whether it is confirmed, not confirmed, blocked, or failed.
6. Recalculate/review report context after validation.

Web validation must remain disabled unless the lab contains the expected private target fingerprint. It requires `ENABLE_WEB_VALIDATION=1`, an evidence-derived action ID, and explicit approval.

Credential validation requires dedicated lab credentials through `LAB_USER`/`LAB_PASS` or service-specific `LAB_<SERVICE>_USER`/`LAB_<SERVICE>_PASS`. Never place production credentials in `.env`.

## 9. CALDERA operation procedure

1. Complete and review a scan.
2. Open the CALDERA section and refresh status.
3. Verify the displayed CALDERA URL, target, expected agent host, agent group, and online/trusted state.
4. Remove stale agents only after confirming they are not part of another exercise.
5. If no trusted agent is present, review the displayed Sandcat command before deploying it to the authorised target.
6. Check technique coverage.
7. Select only techniques supported by the current scan mode and mapping.
8. Set `ENABLE_CALDERA_EXECUTION=1` and restart Flask only after approval.
9. Start the operation and monitor it until completion or timeout.
10. Review each technique result, operation totals, validation context, risk/remediation output, and proof-ticket eligibility.
11. Disable execution again after the exercise and restart Flask.

Do not interpret a successful CALDERA link as proof that an unrelated CVE is exploitable. It demonstrates the behaviour executed by that ability on the trusted agent.

## 10. Reporting and evidence

From the results page, generate and review:

- Results dashboard
- Attack Surface Workbench
- Technical appendix
- Handoff JSON
- Evidence manifest and hashes
- PDF report
- Plain-text report

Runtime locations:

```text
project/storage/scans/      raw command and scan evidence
project/storage/results/    persisted scan JSON and generated packages
project/storage/mitre_cve/  local CVE mirror and index
```

If the configured storage directories are unwritable, scan/result storage may fall back to `/tmp/autopentest/`. Check the application log and generated package paths before collecting evidence.

Before distributing a report:

- Confirm every reported target is in scope.
- Separate confirmed findings from candidate references and evidence gaps.
- Remove secrets, tokens, passwords, raw credentials, and unnecessary target data.
- Confirm timestamps and evidence hashes.
- Record missing tools and incomplete checks as limitations.
- Store the report according to the engagement's data-handling requirements.

## 11. Experimental pivot workflow

The pivot subsystem is not part of the routine evidence-only scan procedure. It can start Chisel, edit `/etc/proxychains4.conf`, scan through a SOCKS tunnel, and generate lateral-movement commands with range-specific demonstration defaults.

Before even opening this workflow:

- Obtain explicit approval for pivoting and internal-range access.
- Review `project/routes/pivot_routes.py` and `project/pivot/pivot_engine.py`.
- Replace demonstration ranges and credentials.
- Back up proxychains configuration.
- Confirm Chisel and proxychains binaries and permissions.
- Ensure the entry host and every internal target are explicitly in scope.

Generated commands are suggestions for manual review, not automatically authorised actions. Always use the cleanup action after a lab pivot and verify that the Chisel process has stopped.

## 12. Normal shutdown

1. Wait for active scans and CALDERA operations to finish or stop them through their owning service.
2. Export required evidence and reports.
3. Use pivot cleanup if the experimental pivot workflow was started.
4. Disable optional execution flags in `.env`.
5. Stop Flask with `Ctrl+C` in its terminal.
6. Stop Metasploit RPC, Ollama, CALDERA, and MySQL if they were started solely for the exercise.
7. Remove or terminate test agents according to the lab reset procedure.
8. Archive or clean runtime data according to the engagement policy.

Preview cleanup:

```bash
cd /home/kali/FYP/project
python utils/cleanup.py --dry-run
```

Run the default cleanup:

```bash
python utils/cleanup.py
```

Default cleanup preserves persisted result JSON, the CVE mirror/index, and `.env`. Review `--include-results`, `--include-cve-data`, and `--keep-scan-evidence` before using them.

## 13. Recovery procedures

### Flask will not start

```bash
cd /home/kali/FYP/project
source .venv/bin/activate
python scripts/bootstrap_env.py
python -m py_compile app.py config.py runtime_env.py routes/*.py
python app.py
```

Check for an invalid integer in `.env`, a missing Python dependency, an occupied port, or rejected non-loopback security settings.

### Browser receives 403

- Return to the landing page and unlock with the current `OPERATOR_TOKEN`.
- If `.env` was regenerated, use the new token.
- Refresh the page so browser JavaScript receives the current CSRF token.
- API POST requests must send the same session cookie and CSRF token.

### Scan appears stuck

- Check the Flask terminal for a running external command or timeout.
- Inspect the progress page command log.
- Verify Nmap and selected optional binaries are available.
- Confirm the target is reachable from the controller network.
- Do not restart Flask if in-memory scan progress must be preserved.
- If recovery is impossible, record the incomplete run, restart, and launch a new scan ID.

### Results page cannot find a scan

- Confirm the scan ID in the URL.
- Check `project/storage/results/<scan_id>.json`.
- Check `/tmp/autopentest/results/` if the normal storage directory was unwritable.
- A scan interrupted before persistence may exist only in the terminated process's memory and cannot be recovered.

### CVE results are missing

```bash
cd /home/kali/FYP/project
source .venv/bin/activate
python scripts/mitre_cve_status.py
python scripts/nvd_status.py
python scripts/rebuild_mitre_cve_index.py
python scripts/sync_nvd_database.py
python scripts/audit_cve_source.py
```

Also confirm that the service has a concrete CPE and sufficiently specific product/version evidence. The main table requires official NVD vulnerable-CPE applicability with satisfied configuration nodes. Incomplete conditions appear only under Analyst Review. CVE description prose is never parsed as matching proof.

### PDF export fails

- Confirm Python requirements are installed.
- On Kali, install the Pango, Cairo, FFI, and shared MIME packages used by WeasyPrint.
- Review the returned text error attachment.
- The application attempts a ReportLab fallback if WeasyPrint fails.

### CALDERA is unavailable

- Confirm CALDERA is listening on `CALDERA_URL`.
- Verify the API key and restart Flask after changing it.
- Check that the selected agent is trusted, online, and belongs to the intended target.
- Keep execution disabled until readiness is restored.

### Metasploit RPC fails

- Confirm `ENABLE_METASPLOIT=1` and restart Flask.
- Verify URL, username, password, port, and TLS settings match `msfrpcd`.
- Ensure the active scan has an open service matching a shipped allowlist policy.

## 14. Post-run checklist

- [ ] Required reports and evidence were exported.
- [ ] Candidate and confirmed findings were clearly separated.
- [ ] Missing-tool and incomplete-test limitations were recorded.
- [ ] CALDERA execution, Metasploit, web validation, and proof-of-access flags were returned to safe defaults.
- [ ] Test agents and pivot processes were removed.
- [ ] Secrets were not included in evidence or reports.
- [ ] Runtime data was archived or cleaned according to policy.
- [ ] The lab was returned to its expected snapshot or baseline.
