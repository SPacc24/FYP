# CVE/CVSS Three-Table Review Layout — 2026-07-25

## Implemented

- Table 1 now contains only: Identifier, Affected Service, Why It Matched, Published By, Links.
- Table 2 now contains only severity/triage data: Identifier, Affected Service, CVSS 3.1, Severity, CVSS 4.0, Severity, Score Source, Vector, Verified.
- CVSS 3.1 / 4.0 / Both selector controls both visible metric data and ranking.
- Missing CVSS versions remain `Not published`; no score conversion or zero substitution is performed.
- Table 3 adds the complete technical information dump, including classification, description, match basis, observed evidence sources, matched tokens, published affected vendors/products/versions/CPEs, structured affected entries, both CVSS metric records, and references.
- CVE publisher/CNA metadata is now retained separately from CVSS score-source metadata.
- The ReportLab PDF export mirrors the same three-section separation.

## Compatibility

Existing legacy single-CVSS fields remain untouched for downstream compatibility. The review tables use the dual `cvss_metrics` structure.
