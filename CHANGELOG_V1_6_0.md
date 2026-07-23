# AutoPenTest v1.6.0 Full Standalone Project

## Applicability integrity

- Deleted production `legacy_description:*` matching and `_text_version_match()`.
- Removed the product alias registry from the active source tree. Product identity now comes only from observed fingerprints/CPEs and machine-readable official fields.
- Added official NVD `cpeName` + `isVulnerable` queries for concrete observed CPEs.
- Added evaluation of NVD AND/OR/NEGATE configuration nodes against collected host CPE evidence.
- Added four explicit outcomes: validated applicability, analyst review, rejected, and not evaluated.
- Restricted the primary Vulnerability Mapping table to validated applicability only.
- Isolated Analyst Review records from exposure risk, ATT&CK mapping, AI planning, CALDERA and exploitation handoffs.
- Preserved rejected/not-evaluated decisions only as diagnostics.

## Full NVD repository

- Added a SQLite NVD repository containing CVE records, descriptions, metrics, affected data, configuration trees and indexed CPE criteria.
- Added complete offset-paginated initial population, incremental last-modified updates, resumable progress, transaction-safe upserts and update-error status.
- Added fully paginated per-CPE applicability queries with a persistent TTL cache.
- Added exact-CPE local repository use when the NVD API is unavailable; private range comparison is never substituted for NVD matching.
- Added `scripts/sync_nvd_database.py` and `scripts/nvd_status.py`.
- Updated Kali installation to populate the complete repository and show a clear recovery command if the network/API interrupts it.
- Added the NVD-required non-endorsement notice to report surfaces.

## CVSS integrity

- Preserved exact selected-version metrics only.
- CVSS v3.1 accepts only a published `CVSS:3.1` metric; CVSS v4.0 accepts only a published `CVSS:4.0` metric.
- No v2/v3.0/cross-version fallback, conversion, estimation or internal severity substitution.
- The NVD repository is checked before an on-demand metric request.
- Missing selected-version metrics remain `Not provided for CVSS vX`.

## Reports and contracts

- Primary format remains `Port | Service | CVE | Severity | Score | Description`.
- Added a separate Analyst Review table with required conditions, official basis and description.
- Added dataset source, completeness, record count, CPE-criteria count, last successful update and last error to the UI and technical appendix.
- Updated the canonical downstream contract to `scanner-canonical-v4`.
- Prevented analyst-review CVE IDs from being attached to generic vulnerability rows.
- Corrected the saved-results route so it builds CVE rows from the canonical stored result.

## Protected teammate modules

The following directories are unchanged from v1.5.1:

- `project/ai/`
- `project/caldera/`
- `project/exploitation/`
- `project/pivot/`

## Data-source standards

- NVD CVE API 2.0: <https://nvd.nist.gov/developers/vulnerabilities>
- NVD API population and maintenance guidance: <https://nvd.nist.gov/developers/start-here>
- CVE List V5: <https://github.com/CVEProject/cvelistV5>
- FIRST CVSS v3.1: <https://www.first.org/cvss/v3.1/specification-document>
- FIRST CVSS v4.0: <https://www.first.org/cvss/v4.0/specification-document>
