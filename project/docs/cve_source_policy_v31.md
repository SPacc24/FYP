# v32-from-v31 CVE Source and Strict Presentation Policy

This build uses only the official CVE List mirror `CVEProject/cvelistV5` for CVE records.

Accepted source:
- Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)

Rejected as strict CVE evidence:
- NVD-only enrichment that is not present in the official CVE List index
- Exploit-DB/Searchsploit text
- Nuclei template names or scanner labels unless the CVE exists in the official CVE List index and the observed product/version/context also matches
- broad keyword matches such as apache, bind, mysql, ssh, linux, samba, or vnc
- version-range-only matches without exact observed affected version/CPE basis
- module-dependent CVEs without module evidence
- configuration-dependent CVEs without configuration evidence
- authenticated-user CVEs without authentication context evidence
- OS/platform-specific CVEs where the collected platform evidence does not match

Strict CVE table:
- Contains only confirmed CVE findings.
- Deduplicates repeated CVEs across ports by host + product + version + CVE ID.

Relevant Version / Exposure Information:
- Contains useful CVE/version correlations that are not strict enough for the CVE table.
- This section is for downstream AI/exploitation/analyst modules and does not perform scoring, ranking, or execution decisions.
