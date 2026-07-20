# Scanner Accuracy and Evidence Hardening — 2026-07-15

Scope: `scanners/` only. No teammate-owned source directory was modified.

## Changed

- Added multi-source service fingerprint consensus using captured Nmap, HTTP, TLS, SMB, SSH, and native-protocol evidence.
- HTTP identity now considers captured title, technology, header, and relevant CPE evidence; contradictory products block CVE matching.
- Removed target-specific HTTP/AJP correlation and all fixed private target examples from scanner runtime code.
- CVE matching now supports exact dynamic product/CPE identities beyond the alias registry, normalises CPE 2.2/2.3 identities, and never caps canonical results.
- CVE index absence, malformed rows, missing versions, unsupported identities, and matcher exceptions are retained as explicit diagnostics.
- Added a canonical downstream CVE contract sourced only from the official CVE List index and observed service evidence.
- Added an integration guard that removes downstream guessed CVE links before AI/mapping consumption and replaces them only with canonical scanner results.
- HTTP transport success is separated from evidence success; 404, server error, and transport failures are not retained as findings.
- Recon policy loading fails closed. Explicitly disabled tools win conflicts, and the effective policy SHA-256 plus conflict resolution are recorded.
- Passive packet capture is restricted to authorized targets. Ambient p0f is skipped unless policy explicitly permits unscoped ambient capture.
- Port coverage is reported accurately as policy-selected coverage, including requested/open TCP and UDP ports and the full-sweep limitation.
- PDF output includes policy provenance, port coverage, CVE diagnostics, pagination protection, and page numbers.
- Added 19 scanner regression tests, including a release gate for fixed CVE IDs and private scan targets in scanner runtime.

## Security boundary

- No exploitation, credential guessing, brute force, persistence, or target modification was added.
- No scan result or target is embedded in scanner runtime code.
- CVE identifiers emitted at runtime originate from the synchronized official CVE index, never a scanner literal.
