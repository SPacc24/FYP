# AutoPenTest v1.5.1 Full Standalone Project

Release date: 22 July 2026

## Vulnerability mapping

- Restored the primary mapping format to one evidence-linked CVE per row:
  `Port | Service | CVE | Severity | Score | Description`.
- Removed the user-facing candidate-reference abstraction from the dashboard and PDF.
- Kept applicability separate from technical severity. Product, version, CPE, configuration,
  and provenance evidence decide whether a CVE is confirmed or requires analyst validation.
- Conditional rows are labelled `Conditional CVE Match — Analyst Validation Required`.

## CVSS source integrity

- Severity, score, and vector are accepted only when published for the operator-selected CVSS version.
- CVE List V5 CNA/ADP data is used first; the official NVD API can enrich only the same selected version.
- No score is generated, estimated, converted, substituted, or copied from another CVSS version.
- Published metrics with a wrong vector prefix, missing Base metrics, duplicate metrics, or a severity
  inconsistent with the FIRST qualitative band are rejected.
- Every displayed metric retains provider attribution and its authoritative record URL.
- If no selected-version metric is published, both Severity and Score display
  `Not provided for CVSS vX`.

## Hardcoded fallback removal

- The active scanner, CVE mapper, scoring policy, helpers, and report templates contain no fixed CVE IDs
  or published CVSS scores.
- Removed the legacy fixed operational-risk fallback value. Calculation failure now displays `Unavailable`.
- Generic exposure priority and operational risk remain explicitly non-CVSS and cannot populate the
  vulnerability mapping Severity or Score columns.

## Compatibility and scope

- Full standalone Kali project; no earlier ZIP or hotfix is required.
- `ai/`, `caldera/`, `exploitation/`, and `pivot/` are unchanged from v1.5.0.
- Runtime storage, secrets, virtual environments, caches, downloaded CVE data, and scan evidence are excluded.
