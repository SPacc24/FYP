# Scanner Evidence Assurance Full Fix — 2026-07-26

## Scope
Scanner/recon/CVE/CVSS/reporting only. No Metasploit, exploitation, CALDERA, AI, ATT&CK/mapping, or teammate-owned execution logic was modified.

## Implemented
- Restored Effective Scan Configuration to main results, technical appendix, and PDF reporting.
- Preserved selected-scope coverage separately from executed coverage; full TCP range state is explicit.
- Restored service evidence sources in the technical appendix and humanised collector identifiers for presentation.
- Replaced ambiguous CVSS "Verified" wording with CVSS Integrity wording and retained the published vector verification result.
- Added data-driven Observed Security Conditions from Nmap script output and structured collector fields. No CVE, CVSS, product, version, target, or lab-specific security condition is hardcoded.
- Added structured CVE prerequisite context using official affected-entry modules, platforms, and packageName fields without changing canonical product/version applicability.
- Added generic bounded version-evidence recovery for already-open TCP endpoints whose version is missing or range-valued. No new ports are introduced by the recovery pass.
- Added exact-CVE-ID NVD CVSS enrichment for CVE Program records without CVSS metadata. It never creates a match or overwrites a CVE Program metric, and stops additional network lookups after NVD becomes unavailable/degraded.
- Added explicit per-row NVD enrichment status and retained raw provider IDs in the technical appendix while using human-readable provider/publisher names in client-facing CVE tables where metadata permits.
- Renamed ambiguous report terms: Open Service Endpoints, Versioned Service Endpoints, TCP Re-Probe Coverage, Selected TCP/UDP Scope.
- Reworked evidence action accounting to distinguish execution, completion without error, produced evidence, no evidence, failures, and skipped/not-applicable checks.
- Sanitised local storage paths from client-facing appendix command logs and exported handoff JSON, preserving relative evidence identity.
- Preserved raw evidence and CVE Program structured data; missing facts remain missing rather than inferred.

## No-hardcoding guarantees for this change
No target IP, Metasploitable identity, expected vulnerability, CVE ID, service/version answer, CVSS score, known-backdoor list, Apache branch floor, Samba version, UnrealIRCd version, or proprietary risk rule was added to production logic.

## Validation
Focused suite:
- 43 passed

Static validation:
- Python compileall: PASS
- Jinja parse: PASS for results.html, scan_vul.html, technical_appendix.html, pdf_report.html, scan_summary_sidebar.html, scanning.html, index.html
- Node JavaScript syntax check: PASS for index.html, scan_vul.html, results.html inline scripts

Broader historical tests:
- Scanner hardening: 19 passed, 1 pre-existing assertion mismatch (`fingerprint_confidence_advisory` vs legacy expected `fingerprint_confidence_below_cve_threshold`).
- A legacy report-quality module cannot collect because it imports the retired Candidate/Confirmed `ALLOWED_CVE_STATUSES` API.
- Baseline comparison of the older broad suite showed 11 failures already present in the input build. The only additional old-suite assertion is the intentionally changed label `TCP Coverage` -> `Selected TCP Scope`.
