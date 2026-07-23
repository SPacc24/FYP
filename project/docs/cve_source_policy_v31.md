# v32-from-v31 CVE Source and Strict Presentation Policy

This build uses the official CVE List mirror `CVEProject/cvelistV5` for CVE identity,
description, references, affected-product data, and applicability. It may use the official
NVD CVE API 2.0 only to enrich a missing metric for the operator-selected CVSS version.

Accepted source:
- Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)
- NIST NVD CVE API 2.0 for same-version CVSS enrichment after a CVE List match exists

Rejected as strict CVE evidence:
- NVD data used to create or broaden a CVE applicability match
- Exploit-DB/Searchsploit text
- Nuclei template names or scanner labels unless the CVE exists in the official CVE List index and the observed product/version/context also matches
- broad keyword matches such as apache, bind, mysql, ssh, linux, samba, or vnc
- version-range-only matches without exact observed affected version/CPE basis
- module-dependent CVEs without module evidence
- configuration-dependent CVEs without configuration evidence
- authenticated-user CVEs without authentication context evidence
- OS/platform-specific CVEs where the collected platform evidence does not match
- package/distribution-specific CVEs without package provenance evidence

Confirmed CVE:
- Contains only official CVE records whose required product/version/context is directly evidenced.
- Deduplicates repeated CVEs across ports by host + product + version + CVE ID.

Conditional Candidate (High chance of matching):
- Contains evidence-linked CVE/version correlations that still lack required context, such as
  package provenance, configuration, module, authentication, or legacy-record confirmation.
- This section is for downstream AI/exploitation/analyst modules and does not perform scoring, ranking, or execution decisions.

CVSS rules:
- Prefer the selected-version metric from CVE List CNA data, then CVE List ADP data.
- If absent, request only the same selected version from the official NVD API.
- Never convert scores and never substitute another CVSS version.
- Keep published CVSS severity separate from target applicability and exposure priority.
