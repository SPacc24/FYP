# v32.3 Scan Profiles

Added UI scan profiles:

- Fast Scan: selected core evidence tools for quicker scans while retaining service/version/CPE collection for CVE matching.
- Full Scan: all recon tools enabled.
- Custom Scan: per-tool enable/disable controls from the UI.

CVE review is not treated as a scanner toggle. It remains active and begins once service identity evidence is available. Final CVE findings are recalculated after evidence consolidation.
