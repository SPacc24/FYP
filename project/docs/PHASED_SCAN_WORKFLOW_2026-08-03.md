# Continuous External → Internal → Assessment Workflow

## Implemented scope

This change adds scanner-owned Phase 1 and Phase 2 discovery before the existing Phase 3 assessment. The mission keeps one `scan_id`, operator session, audit log, command log, evidence directory, and final report.

### Phase 1 — External

- Accepts one external/gateway IP only.
- Performs low-impact ICMP and Nmap host-discovery reachability checks.
- Inspects `ip -j route get`, `ip -j addr show`, and `ip -j route show`.
- Derives bounded private subnet candidates from concrete route/interface relationships, including already-established tunnel routes associated with the assessment environment.
- Does not guess `/24` and does not reconfigure Kali interfaces.
- Refuses to treat a normal default Internet route as permission to scan an unrelated home/office LAN.

### Phase 2 — Internal

- Automatically runs Nmap `-sn` against the discovered subnet.
- Retains IP, hostname, MAC, vendor, gateway/scanner role, discovery source, and XML evidence.
- Does not run service fingerprinting, protocol collectors, CVE correlation, exploitation, AI planning, or Caldera.
- Excludes the scanner's own address from selectable Phase 3 targets.

### Phase 3 — Assessment

- Uses the existing assessment configuration and `run_pipeline()` implementation.
- Replaces only the manual IP/CIDR/range field with discovered-host checkboxes populated from Phase 2.
- Allows one or multiple discovered hosts, requires at least one, and backend-validates every selected IP against the stored discovery inventory and selected subnet.
- Retains existing TCP/UDP modes, collector controls, host evidence settings, service identity settings, advanced settings, technique mapping, AI planning, reporting, and downstream handoffs.
- Appends assessment tasks to the same mission instead of erasing Phase 1/2 history.

## Workflow states

- `external_discovery`
- `awaiting_subnet_selection` (only when multiple route-derived candidates exist)
- `internal_discovery`
- `awaiting_assessment_configuration`
- `assessment_running`
- `success` / `failed`

The transition into `assessment_running` is atomic, preventing duplicate Phase 3 submissions.

## Main files

- `scanners/phase_discovery.py`
- `scanners/command_builders.py`
- `routes/scan_routes.py`
- `storage/scan_store.py`
- `templates/index.html`
- `templates/assessment_config.html`
- `templates/scanning.html`
- `scanners/enumerator.py`
- `tests/test_phase_workflow.py`

## Ownership boundary

No changes were made inside `ai/`, `caldera/`, `exploitation/`, `mapping/`, or `pivot/`. Existing teammate-owned logic continues to receive the assessment results and configuration through the current Phase 3 pipeline.


## Route-derived subnet and multi-target updates

- Internal subnet candidates are derived from current route/interface evidence; a default route alone never authorises scanning the scanner's local management subnet.
- When more than one eligible route-derived subnet exists, the mission pauses and the operator selects one of those persisted candidates. No arbitrary CIDR entry is accepted.
- Phase 3 presents every selectable Phase 2 host as a checkbox. One or multiple hosts may be selected, but the backend requires at least one and validates every submitted address against the persisted inventory and selected subnet.
- The Phase 1 selected interface is passed to interface-bound Phase 2/Phase 3 collectors.
- CVE references remain classification-neutral and now expose separate applicability, patch-state, and validation-state fields; the UI groups them by target IP.
