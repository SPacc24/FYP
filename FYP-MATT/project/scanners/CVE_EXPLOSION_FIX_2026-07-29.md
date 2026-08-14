# CVE Explosion Fix — 2026-07-29

## Live regression
A Windows scan with direct build evidence and SMBv1 evidence expanded from a small evidence-backed CVE set to 1,915 references after MSRC historical advisory indexing became available.

## Root cause
MSRC build-line product candidates were merged into the observed host-identity map and assigned direct-evidence authority. The host CVE matcher also contained a second path that could create CVE references directly from MSRC product/fixed-build records. This converted remediation metadata into applicability evidence.

## Correction
- MSRC build-line product resolution is diagnostic/remediation context only and never mutates observed host identity.
- `official_product_resolution` and `resolution_candidate` identities are permanently CVE-ineligible.
- The host CVE matcher rejects advisory-resolution identities defensively.
- MSRC no longer creates CVE references in `_match_cves`.
- MSRC remains available after canonical matching for patch/remediation assessment when inventory evidence is supplied.
- Direct host OS evidence, CVE Program structured affected records, exact-ID NVD component/platform corroboration, and post-match KEV enrichment are unchanged.

## Hardcoding
No CVE, target, Windows build, release mapping, advisory product, or lab fact is encoded in production matching logic.
