# Live Evidence Scanner Fix — 2026-07-29

Scope: `project/scanners/` only.

## Corrected

- Collector applicability is protocol-aware; TCP-only SMB collectors cannot be credited to UDP endpoints.
- UDP NSE collectors explicitly use UDP scanning when the observed endpoint is UDP.
- Microsoft RPC is distinct from ONC RPC/rpcbind/NFS; `rpcinfo` and `showmount` are not scheduled for Microsoft RPC endpoints.
- Timeout/failed external collectors remain incomplete evidence and cannot become zero-result observations.
- Information-gathering summaries exclude timed-out/failed native collector results.
- Direct protocol component versions can be retained from successful collector evidence.
- Specialised SMB protocol collectors now pass their real NSE output, protocol, and lifecycle into component correlation instead of dropping those fields.
- Directly observed protocol components are included in the existing scanner component inventory for reporting without changing teammate templates.
- Component CVE candidate retrieval uses only structured CVE Program affected product/version fields.
- Component CVE references require exact-CVE-ID NVD CPE/configuration corroboration against authoritative host CPE context. NVD keyword CVE discovery is not used.
- Official CPE resolution supports build values that omit servicing revisions without maintaining a build/release table.
- Missing CVSS wording in scanner-owned report output is scoped to absence from the CVE Program record rather than claiming the metric was never published anywhere.

## Trust boundaries

- No production CVE IDs are hardcoded.
- No target addresses, lab topology, Windows release/build mapping table, or credentials are hardcoded.
- Candidate/Confirmed classification is not used.
- CVE description prose and product alias registries are not applicability sources.
- NVD does not generate CVE candidates; it is used only after a canonical CVE Program candidate exists.
