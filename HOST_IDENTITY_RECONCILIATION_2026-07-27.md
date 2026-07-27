# Host Identity Reconciliation — 2026-07-27

## Purpose
Prevent probabilistic host OS fingerprints from expanding CVE applicability when stronger directly observed host identity evidence is available.

## Evidence hierarchy
The resolver uses collection semantics only; it contains no target-specific, OS-release, build-to-marketing-name, CVE, KB, or vulnerability-specific mappings.

1. Authenticated inventory
2. Direct protocol assertion
3. Service OS hint
4. Probabilistic OS fingerprint

All evidence remains visible in `host_identity_inventory`. Only reconciled `cve_identities` are sent into host-OS CVE matching.

When only probabilistic fingerprints exist, the resolver uses the collector's own reported accuracy and requires a single unambiguous highest-ranked identity. Equal/conflicting or explicitly ambiguous fingerprints remain supporting evidence only.

## Files changed
- `project/scanners/platform_identity.py`
- `project/scanners/enumerator.py`
- `project/scanners/parsers.py`
- `project/scanners/nmap_parser.py`
- `project/scanners/windows_patch_inventory.py`
- `project/scanners/tests/test_cross_platform_identity.py`

## Validation
- Scanner regression: 113 passed, 4 subtests passed.
- Teammate-owned `exploitation/`, `caldera/`, `ai/`, `mapping/`, and `routes/` unchanged.
