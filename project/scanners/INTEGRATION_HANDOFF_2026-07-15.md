# Scanner Integration Handoff — 2026-07-15

The scanner publishes `canonical_cve_contract` with version `scanner-canonical-v5`.

Downstream consumers must:

1. Consume `potential_applicability`, `needs_context`, and `diagnostics` from that contract.
2. Preserve the source, match basis, observed host/port, concrete CPE, CVSS vector/provider, and references.
3. Never infer or insert a CVE identifier from service name, port number, operating-system guess, lab-target identity, or a static lookup table.
4. Treat a missing concrete CPE, unresolved NVD condition, NVD outage, and parser failure as explicit evidence gaps—not as “no vulnerabilities.”
5. Keep exposure priority separate from CVSS severity.
6. Do not promote `potential_applicability` to a confirmed vulnerability without a vulnerability-specific test, authenticated package/patch evidence, or equivalent target-specific proof.

The scanner integration guard removes non-canonical CVE links before planning. Runtime mapping
contains no static CVE signature table and contributes only generic exposure and ATT&CK context.
Direct browser-submitted vulnerability persistence is disabled.
