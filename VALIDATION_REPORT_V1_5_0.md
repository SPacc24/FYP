# AutoPenTest v1.5.0 Validation Report

Validation date: 22 July 2026

## Scope

This validation covers the complete standalone Kali project, including scanner,
shared mapping integration, routes, persistence, reports, templates, installer,
and regression tests. The protected teammate directories `project/ai`,
`project/caldera`, `project/exploitation`, and `project/pivot` were not edited.

## Results

- Full automated suite: 227 tests passed, 4 subtests passed, 1 test skipped.
- Python source compilation: passed.
- Jinja template parsing: 19 templates passed.
- Shell syntax: `install.sh` and `start.sh` passed `bash -n`.
- Non-protected policy/configuration JSON: passed JSON parsing.
- Runtime fixed-CVE literal audit across scanner, mapping, routes, core, storage,
  and report code: no fixed CVE identifier found.
- Protected-directory comparison against v1.4.1: source files byte-for-byte identical.
- CVSS version policy: CVSS v3.1 and v4.0 supported; conversion and cross-version
  fallback remain disabled.
- NVD enrichment: mocked official API parsing, provider selection, caching,
  exact-version enforcement, unavailable-source handling, and bounded batching passed.
- Applicability: package-provenance conditions and legacy descriptive records are
  retained as conditional candidates rather than confirmed findings.
- Canonical integration: mapping exposure severity/priority remains separate from
  CVSS; static mapping CVE signatures are absent; canonical mapping contract v2
  and scanner result contract v3 are enforced.
- Persistence: direct browser/client vulnerability writes are disabled; only the
  completed scanner canonical contract is accepted by the canonical persistence path.

## Dependency notice

The test run emitted one upstream ReportLab deprecation warning concerning Python
3.14 compatibility. It does not affect the current Kali/Python runtime or report
generation.

## Expected fresh-install behaviour

The archive excludes generated secrets, virtual environments, scan evidence,
downloaded CVE data, caches, and compiled Python files. `install.sh` creates the
virtual environment, generates `.env`, synchronises the official CVE List, and
creates the NVD metric cache directory.
