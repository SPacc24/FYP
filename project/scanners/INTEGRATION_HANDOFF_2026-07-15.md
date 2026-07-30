# Scanner Integration Handoff — 2026-07-15

The scanner publishes `canonical_cve_contract` with version
`scanner-canonical-v4-baseline-references`.

Downstream consumers must:

1. Consume `baseline_cve_references` and `held_diagnostics` from that contract.
2. Preserve the source, match basis, observed host/port, product/version, confidence, and references.
3. Never infer or insert a CVE identifier from service name, port number, operating-system guess, lab-target identity, or a static lookup table.
4. Treat missing index, missing version, low confidence, contradictions, and parser failure as explicit evidence gaps—not as “no vulnerabilities.”
5. Keep exposure priority separate from CVSS severity.
6. Treat scanner CVE references as classification-neutral evidence records. Do not
   require, infer, or add a separate CVE status label as part of this contract.

The scanner integration guard removes non-canonical CVE links returned by downstream mapping before planning. The mapping owner should remove static CVE signatures from their source in a separately owned change; scanner files do not modify that directory.
