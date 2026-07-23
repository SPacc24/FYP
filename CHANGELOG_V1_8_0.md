# AutoPenTest v1.8.0 — CVE List V5 Local Matching

## CVE source and matching

- Replaced the required NVD runtime, API sync, cache, and setup path with the
  official CVEProject CVE List V5 repository and validated local indexes.
- Added conservative structured affected-product, platform, module, exact-version,
  default-status, exception, and SemVer range evaluation.
- Unsupported ecosystem range types are retained as unresolved audit data rather
  than being compared with an unsafe generic algorithm.
- CVE descriptions, CVSS severity, confidence scores, and static CVE tables never
  create a finding.

## Finding status

- User-facing vulnerability findings use only `Candidate` and `Confirmed`.
- A structured affected-product/version decision creates a `Candidate`.
- Only approved target-specific evidence can promote a Candidate to `Confirmed`.
- Conclusive unaffected evidence suppresses the finding while preserving the
  decision in audit data.
- Removed obsolete Potential Applicability, Needs Context, Conditional Candidate,
  Hold for Analyst Review, and misleading internal confirmed-CVE container names.

## CVSS technical severity

- Operators select CVSS v3.1 or v4.0.
- Only the exact selected version published in CVE List V5 CNA/ADP data is shown.
- Missing selected-version data displays `CVSS unavailable`.
- No conversion, cross-version fallback, estimation, organisational-risk score,
  or private remediation-priority score is used.

## Integration and cleanup

- Removed obsolete NVD scanner modules, setup/status scripts, environment defaults,
  tests, installer steps, UI status blocks, and active documentation.
- Updated scanner contracts, UI, PDF, technical appendix, topology, runbook, policy,
  setup guide, and handoff documentation to the same flow.
- Teammate-owned `mapping/`, `exploitation/`, `ai/`, `caldera/`, and `routes/`
  directories are unchanged from v1.7.0.
