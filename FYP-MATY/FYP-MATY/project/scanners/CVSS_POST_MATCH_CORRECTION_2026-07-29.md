# CVSS Post-Match Architecture Correction — 2026-07-29

CVSS 3.1 and CVSS 4.0 are vulnerability-scoring metadata applied only after canonical CVE applicability has been established.

They do not influence:
- discovery commands or port coverage,
- TCP/UDP adaptive evidence recovery,
- identity construction or reconciliation,
- CVE Program applicability matching,
- NVD exact-ID applicability corroboration,
- whether a CVE finding exists,
- the number of CVE findings,
- scan launch readiness.

The selected CVSS version may only control the scoring view/order of already-matched findings. Missing metrics never fall back across CVSS versions. CVSS verifier availability is reported as score-integrity metadata and never blocks the scanner.
