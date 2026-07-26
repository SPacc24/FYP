# Scanner Custom Collector Lifecycle — 2026-07-26

## Scope

This release redesigns the scanner/recon configuration and evidence-assurance workflow. It does not add target-specific, CVE-specific, product-specific, or lab-specific answers. Metasploit/exploitation, pivot, CALDERA, AI, and ATT&CK/mapping source logic are outside this change.

## Evidence Collection Plan

- Replaced the flat evidence-tool checklist with a grouped Evidence Collection Plan.
- Added starting presets: Recommended, Maximum Evidence, Minimal / Low Interaction, and Custom.
- Presets are editable starting points rather than fixed scan modes.
- Separated core discovery/service-identification controls from optional evidence collectors.
- Added category-level enable/disable controls.
- Added per-collector execution modes (`auto` for service-conditional collectors; host collectors use explicit enabled/disabled intent).
- Policy-blocked collectors remain visible with the block reason instead of silently disappearing.
- Current binary availability is shown as advisory pre-flight information.
- Added live requested, policy-permitted, policy-blocked, and runtime-unavailable counts.

## Structured Collector Customisation

- Added bounded operator settings where the collector has a real safe runtime knob.
- Examples include HTTPX rate/threads/timeout, Nuclei request window/retries, passive capture duration/interface, and bounded timeouts for protocol-specific collectors.
- Values are clamped to existing policy/safety ceilings.
- No arbitrary raw command-line argument field was added.

## Host Discovery and Service Identification

- Added independent controls for ARP, ICMP echo, Nmap host discovery, reverse DNS, route tracing, and assume-live continuation.
- ICMP now executes when requested and policy-permitted instead of being silently skipped by the old passive-first path.
- Host-level checks record an explicit lifecycle outcome when disabled, blocked, unavailable, deferred, or assumed-live.
- Service identification controls expose bounded Nmap version intensity, banner probing, and targeted version recovery settings.
- Version recovery remains limited to already-open in-scope TCP endpoints and does not add hidden port coverage.
- Removed `--open` from authoritative TCP discovery so the scanner can retain exact returned Nmap port states; only open endpoints proceed to service fingerprinting.

## Collector Lifecycle / Eligibility Engine

Operator intent, policy permission, applicability, execution, and result are recorded separately.

Canonical lifecycle outcomes include:

- Executed — evidence retained
- Executed — no additional evidence
- Executed — failed
- Not applicable
- Disabled by operator
- Disabled by policy
- Tool unavailable
- Scope blocked
- Deferred
- Assumed live

Service-conditional collectors are evaluated after service discovery and again after identity/version recovery where later evidence can make them applicable.

Aggregate orchestration summaries are excluded from independent evidence-action KPI counts so they do not double-count underlying checks.

## Collector Coverage Matrix

- Added endpoint-oriented collector coverage showing requested mode, policy state, applicability, and actual outcome.
- Added host-level lifecycle records for host discovery/passive collectors.
- A collector-wide successful run does not automatically mark every endpoint as evidence-producing; endpoint-specific evidence is required for an endpoint evidence outcome.

## Evidence Gaps / Unresolved Identity Queue

- Added an explicit queue for unknown service identities, missing products, missing exact versions, and range-valued versions.
- Records whether targeted recovery was attempted.
- Missing information remains missing rather than being guessed.

## Vulnerability Intelligence Freshness

- CVE Program status now records local-index availability, indexed record count, index update time/age, repository head time, and CVSS 3.1/4.0 metadata counts where available.
- NVD status records enrichment availability/cache state and freshness where available.
- Freshness is captured in the assessment/report so later database updates do not erase which intelligence state supported the assessment.

## CVSS UI

- Fixed the persistent CVSS 3.1 / CVSS 4.0 / Both selector by defining and using a stable local-storage key.
- The selector remains UI state and does not alter CVE applicability data.
- CVSS 3.1 and 4.0 remain independent published metrics; no conversion/fallback was introduced.

## Scan Plan Usability

- Added pre-scan plan review.
- Added local saved scan plans.
- Added JSON import/export using an AutoPenTest recon-plan schema.
- Added “New Scan Using Same Settings” cloning from a previous assessment.
- Saved/imported plans contain scanner configuration, not target findings or vulnerability facts.

## Reporting

Browser, Technical Appendix, HTML/WeasyPrint PDF and ReportLab fallback now expose:

- effective evidence plan and host/service-identity controls;
- vulnerability-intelligence freshness;
- exact evidence-action execution/not-executed breakdown;
- collector coverage matrix;
- unresolved identity queue;
- observed security conditions;
- evidence-derived scan findings.

Retired Candidate/Confirmed/Validated-MITRE presentation is not reintroduced by these scanner reporting changes.

## No-Hardcoding Guardrails

This change does not add:

- target IP-specific behavior;
- Metasploitable-specific expected results;
- hardcoded CVE IDs or affected versions;
- port-to-product answer rules;
- invented CVSS values;
- proprietary vulnerability/exploitability scores;
- raw operator command injection fields.

Collectors are selected and applied from declared capabilities, service-family evidence, operator intent, runtime availability, and effective policy.

## Validation

Focused scanner/CVE/CVSS/customisation regression set:

- 51 passed

Scanner hardening:

- 20 passed
- 4 subtests passed

All tests under `project/scanners/tests`:

- 48 passed
- 4 subtests passed

Static validation:

- Python compilation: PASS
- Jinja parsing: 7 affected templates PASS
- Inline JavaScript syntax: `index.html` and `scan_vul.html` PASS

PDF validation:

- ReportLab fallback generation: PASS
- HTML/WeasyPrint generation: PASS
- Both PDFs rendered to page images successfully
- Collector matrix, freshness, unresolved gaps, security conditions and scan-findings tables were visually inspected without clipping/overlap in the synthetic QA report
- Retired Candidate/Validated-MITRE/Key-Exposure/Risk-score wording was absent from the generated scanner QA PDFs

No live Kali target scan was executed in the build container. A fresh Kali assessment remains the final environment-level verification step.
