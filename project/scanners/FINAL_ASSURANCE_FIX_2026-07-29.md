# Scanner Final Assurance Fix — 2026-07-29

Scope: `project/scanners/` only.

## Changes

- Component CVE applicability remains anchored to structured CVE Program affected data.
- Exact-ID NVD corroboration now supports records that express an already-matched component CVE only through vulnerable host/platform CPEs, while refusing host-only bypass when NVD supplies conflicting vulnerable application CPEs.
- Same-protocol duplicate CVE endpoints retain exact endpoint provenance without duplicating protocol suffixes in existing report consumers.
- CISA KEV is optional post-match threat intelligence only. It cannot create, suppress, or alter CVE applicability.
- Patch state and exact-ID NVD corroboration are appended to the existing scanner match-evidence field so current report consumers can display assurance context without template changes.
- ARP discovery performs a no-traffic raw-socket privilege preflight and reports insufficient privilege instead of launching a collector that is known to fail.
- Microsoft CVRF history parsing accepts both JSON and XML representations, including wrapped scalar/status fields. Rebuilds are atomic and refuse to replace an existing index with an empty parse result.
- Scanner-owned PDF wording distinguishes NVD CVSS enrichment from applicability corroboration and reports CISA KEV source state.

## Trust boundaries

No CVE identifier, target address, observed Windows build, credential, lab product, or build-to-release lookup table is embedded in production matching logic. CISA KEV and Microsoft remediation data are enrichment sources only and do not replace canonical CVE applicability.

No files outside `project/scanners/` are intentionally modified by this change.
