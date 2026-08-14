# AutoPenTest v1.9.0 — standards-backed two-status CVE flow

- Restricted the complete CVE finding contract to Candidate and Confirmed.
- Removed all alternative CVE state code, storage, counters, UI blocks, report
  sections, and test expectations.
- Removed description-based legacy matching and generic natural-version ranges.
- Rebuilt the local CVE List V5 index as schema v4 with exact structured identity
  keys and preserved affected constraints.
- Added exact CPE 2.3 component matching without private aliases.
- Implemented the CVE List V5 published version-selection algorithm for exact
  values, SemVer ranges, and status changes, including source-independent
  ordering of `changes` entries as required by the schema.
- Enforced SemVer 2.0.0 syntax and precedence without accepting leading `v`
  extensions or numeric prerelease identifiers with leading zeroes.
- Evaluated each published affected entry independently; a different published
  entry cannot silently remove an otherwise qualifying Candidate.
- Required observed evidence for represented platform, module, package, file, and
  routine constraints.
- Kept CVSS v3.1/v4.0 as published technical severity only, with no conversion,
  fallback, or influence on finding status.
- Removed scanner-derived attacker-outcome, remediation, and vulnerability-type
  claims.
- Added regression checks for two-status enforcement, no fixed runtime CVEs or
  targets, no prose matching, CVSS/applicability separation, schema-defined
  change ordering, strict SemVer parsing, and protected-directory integrity.
