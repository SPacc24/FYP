# Host Identity / CVE Reconciliation Fix — 28 July 2026

## Fault reproduced from the supplied assessment

The scan directly observed a concrete SMB operating-system product/CPE and an
independent NTLM/RDP numeric build, but the scanner kept those facts in separate
host identities. The SMB host-script parser also discarded the OS CPE. As a
result, CVE review could receive an unversioned product while the report still
claimed that the release/build was unresolved. Probabilistic cross-family Nmap
OS guesses also remained eligible independently of stronger direct host evidence.

## Repair

- Parse and retain `smb-os-discovery` OS CPE evidence.
- Correlate complementary direct host-OS observations only when they agree on
  host, OS family/vendor, and exactly one independently observed version/build.
- Preserve all original evidence and provenance; no build-to-release table is
  embedded in runtime code.
- Use the correlated product/CPE + version/build identity as the CVE lookup input.
- Retain incompatible probabilistic OS fingerprints for audit, but exclude them
  from CVE applicability when stronger direct host-OS evidence exists.
- Keep baseline CVE references classification-neutral; no separate CVE status
  label or promotion gate is required.
- Report the separate Windows advisory/build index status so missing historical
  Windows intelligence is visible instead of being hidden behind the generic
  Microsoft remediation cache status.

## Regression coverage

Synthetic tests use documentation-range addresses, synthetic products/builds,
and synthetic CVE records. No target address, real CVE identifier, or build-to-
release mapping is embedded in production scanner code.
