# AutoPenTest v1.5.0 Full Standalone Project

- Adds official NVD CVE API 2.0 enrichment when a CVE List record lacks the
  operator-selected CVSS version.
- Keeps CVE identity and applicability exclusively tied to official CVE List
  records and captured service evidence.
- Does not convert CVSS scores or fall back between CVSS versions.
- Classifies package/distribution-provenance conditions as
  `Conditional Candidate (High chance of matching)` until provenance is evidenced.
- Retains legacy descriptive version statements only as conditional candidates
  after independent product identity and exact/range version evidence agree.
- Adds explicit diagnostics for evidence-eligible services that return no official
  candidate match.
- Removes runtime static CVE signatures from the shared mapping path.
- Prevents mapper-derived CVE severity, priority, titles, hints, or remediation from
  influencing scanner-owned canonical CVE output.
- Disables direct browser-submitted vulnerability persistence and validates the
  scanner canonical v3 contract for database writes.
- Corrects the mapping contract version so current scan analysis is not rebuilt as
  legacy data.
- Adds CVE applicability, match basis, selected CVSS metric, provider, and diagnostic
  lineage to the technical appendix and PDF report.
- Preserves `project/ai`, `project/caldera`, `project/exploitation`, and
  `project/pivot` byte-for-byte from v1.4.1.
