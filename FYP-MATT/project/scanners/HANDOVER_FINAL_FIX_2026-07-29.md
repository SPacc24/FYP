# Scanner Handover Final Fix — 2026-07-29

Scanner-owned final hardening after the first heterogeneous two-target assessment.

## Correctness
- Service-level Nmap OS/CPE hints are no longer promoted into host OS identity or CVE applicability.
- CVE vendor compatibility no longer treats a missing published vendor or arbitrary token subsets as a positive vendor match.
- Structured component matching no longer collapses prose ranges or partial numeric versions into point versions.
- CVE and component matchers isolate per-record processing errors; prior valid matches are retained and the review is marked degraded instead of silently returning zero.

## Adaptive recovery
- TCP and UDP adaptive recovery now respect the operator `ports_per_batch` setting.
- Recovery audit rows include pass and batch numbers.
- Unresolved identity rows recognise adaptive recovery evidence as an attempted recovery.
- UDP `open|filtered` remains unresolved unless follow-up evidence changes the state.

## Multi-target handoff
- Scanner-owned CVE export/report data carries host attribution and structured `applicability_evidence`.
- Scanner PDF CVE tables show Host explicitly.
- Scanner PDF uses the operator-selected CVSS version for ordering; it never ranks by max(CVSS 3.1, CVSS 4.0).

## Audit consistency
- NVD cache state is separated into scan-start, added-during-assessment, and completion values.
- Collector assurance failure KPI is reconciled with overall pipeline execution failures.
- CVE review completeness is exposed as `complete` or `degraded`.

No target IP, lab topology, CVE ID, expected finding, or product/version result is hardcoded by these changes.
