# Adaptive Evidence Recovery and CVSS 3.1/4.0

## Scope

This scanner-owned change keeps vulnerability applicability, evidence recovery, and CVSS handling deterministic and evidence-driven. It does not add CVE-specific exceptions, target-specific behavior, build-to-release lookup tables, proprietary severity/confidence scores, exploitation, or Candidate/Confirmed classification.

## CVSS contract

- Supported standards are CVSS 3.1 and CVSS 4.0 only.
- CVSS is attached only after CVE applicability has been established.
- Published CVE Program metrics are preserved exactly.
- Exact-ID NVD enrichment may fill a missing metric only for that same CVSS version.
- No conversion, substitution, fallback, or cross-version numeric ranking is permitted.
- The selected CVSS version controls the effective score/severity/vector used for ordering and display.
- A missing selected metric remains `Not published`; the other CVSS version is not substituted.
- CVSS verifier availability is post-match scoring metadata only and never blocks scanner execution.

## Adaptive evidence recovery

Recovery starts only from facts that remain unresolved after normal discovery/fingerprinting. It does not search for expected products or vulnerabilities.

The engine records missing evidence types such as endpoint state, service product, service version, or host OS. It then performs bounded recovery using the operator's existing service-identity and advanced execution settings. Version-intensity escalation is deterministic and never exceeds the configured recovery intensity or configured pass count. The operator command timeout is used for both initial service fingerprinting and recovery.

Recovery never adds ports outside the operator-selected scope. A collector capability registry states which evidence types each collector can produce; this metadata is used to explain and plan recovery opportunities without predetermining findings.

## UDP evidence recovery

UDP discovery preserves uncertainty. `open|filtered` is not promoted to `open` simply because recovery was attempted.

When UDP recovery is enabled, already-selected unresolved UDP endpoints may receive a bounded Nmap UDP service/version follow-up (`-sU`). Only actual follow-up output may refine state or identity. No response remains unresolved and is reported as such.

## Audit output

The normalized scan package and scanner-owned PDF export include adaptive recovery state, configured bounds, recovery history, before/after missing-evidence counts, and the remaining unresolved endpoint queue.

## Integration boundary

The scanner backend accepts a CVSS selection and defaults to CVSS 3.1. The current teammate-owned web route/template does not yet pass a scan-start CVSS selection into the scanner. No route, template, core, AI, CALDERA, exploitation, or mapping source was modified by this change.

## Architecture correction — post-match scoring only

CVSS 3.1/4.0 selection and verification occur only after canonical CVE applicability has been established. CVSS cannot change discovery commands, adaptive recovery, UDP recovery, identity construction, CVE matching, or CVE count. A missing verifier may mark score integrity as unavailable, but it never blocks the scan or removes a CVE finding.
