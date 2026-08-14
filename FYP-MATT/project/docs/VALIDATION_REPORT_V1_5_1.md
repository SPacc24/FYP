# AutoPenTest v1.5.1 Validation Report

Validation date: 22 July 2026

## Automated tests

- 231 tests passed.
- 4 subtests passed.
- 1 test was intentionally skipped.
- The only warning was a ReportLab dependency deprecation notice; it did not affect rendering.

## CVSS integrity checks

- Confirmed exact selected-version score, severity, vector, provider, and record URL propagation.
- Confirmed CVSS v3.1 does not use CVSS v3.0, v2.0, or v4.0 as a fallback.
- Confirmed CVSS v4.0 does not use CVSS v3.1, v3.0, or v2.0 as a fallback.
- Confirmed malformed, incomplete, cross-version, and severity-inconsistent metrics are rejected.
- Confirmed missing selected-version metrics render as unavailable rather than as an internal score.

## Mapping and report checks

- Parsed all 19 Jinja templates.
- Rendered the mapping table with the six required columns:
  `Port | Service | CVE | Severity | Score | Description`.
- Rendered and text-extracted the PDF mapping table with a complete CVSS v3.1 score and vector.
- Confirmed the dashboard no longer renders mapping output from generic exposure rows.
- Confirmed operational risk is labelled non-CVSS.

## Runtime literal audit

The active scanner, mapping, core helper, and report-template paths were checked for:

- fixed CVE identifiers;
- fixed published CVSS score assignments;
- example or placeholder CVSS vectors;
- user-facing candidate-reference wording; and
- legacy cross-version fallback behavior.

No violations were found.

## Release integrity

- Python compilation passed.
- Shell syntax validation passed.
- Scanner policy, product-registry, and configuration JSON validation passed. The protected teammate
  `ai/mitre_attack_cache.json` remains byte-for-byte identical to v1.5.0 and was outside this release's edit scope.
- ZIP integrity and clean extraction tests passed.
- Protected teammate source directories matched v1.5.0 byte-for-byte.
