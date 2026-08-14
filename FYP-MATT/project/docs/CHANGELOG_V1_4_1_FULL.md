# AutoPenTest v1.4.1 Full Standalone Package

- Includes the complete `FYP-hehe` runtime project for a fresh Kali VM.
- Includes `ai`, `caldera`, `exploitation`, `mapping`, `pivot`, `routes`,
  `scanners`, templates, policies, reports, storage code, and startup scripts.
- Preserves the protected teammate module directories from the configurable
  project base.
- Places the CVSS v3.1/v4.0 selector directly below the target field.
- Keeps TCP/UDP coverage, microbatch, concurrency, timeout, and retry controls.
- Persists the selected CVSS version into the scan result, canonical CVE rows,
  downstream handoff data, and reports.
- Stores metrics for each supported CVSS version from the official CVE List.
- Does not convert CVSS scores or fall back to another CVSS version.
- Corrects the results-page partial so `pivot_assessment.html` no longer extends
  the scan-start page or requires `scan_defaults` during result rendering.
- Uses the configured and validated `MYSQL_DB` value when creating the schema.
- Excludes generated `.env` secrets, virtual environments, caches, scan output,
  locally built CVE indexes, and credential wordlist contents.

