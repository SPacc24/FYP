# Scanner final polish — 2026-07-25

Implemented operator-facing polish without changing teammate-owned technical mapping logic:

- Prominent CVSS 3.1 / CVSS 4.0 / Both selector above Severity & Triage.
- CVSS selector drives visible columns, source/vector details, severity filtering and score sorting.
- Dashboard now counts unique CVE references from the rendered CVE review rather than strict-only cve_matches.
- Effective scan configuration summary is shown on the results page and PDF report.
- Technical appendix Service Inventory now displays retained evidence_sources instead of N/A where evidence exists.
- CVSS source UUIDs are humanised for triage when the publisher can be resolved; raw source remains retained in backend/Table 3 data.
- Custom TCP/UDP fields now show a live unique-port count and client-side syntax feedback; server-side validation remains authoritative.
- Parallel scanning now presents a visibility/noise warning when enabled.
- Full-range warning remains visible, explicitly noting full UDP can be substantially slower.
