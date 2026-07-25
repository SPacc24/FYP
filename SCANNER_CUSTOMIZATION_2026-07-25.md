# Scanner Customisation and UI Polish — 2026-07-25

Scope: reconnaissance scanner configuration and CVSS presentation only. Technique mapping logic was not modified.

## Operator inputs

- Target: single IP, CIDR, or supported multi-target input.
- TCP coverage: Full (1-65535), Essentials (policy-defined), or Custom.
- UDP coverage: Full (1-65535), Essentials (policy-defined), or Custom.
- Custom port syntax accepts comma/space-separated ports and inclusive ranges, for example `22,80,443,8000-8100`.
- Evidence-collection tool selection remains independently configurable.

## Advanced scan settings

- Per-batch command timeout: 30-3600 seconds.
- Retry failed batches: optional, 0-3 retries.
- Ports per batch: 1-2048.
- Parallel port batches: optional, 1-8 workers.
- Parallel execution is disabled by default.
- Policy stop conditions continue to override operator settings.

## Scanner behaviour

- Port choices affect the actual Nmap TCP/UDP coverage; they are not display-only settings.
- Custom coverage receives no hidden targeted port expansion after discovery.
- Full mode covers the complete 1-65535 port-number space.
- Essentials comes from `project/policies/recon_policy.json`, not a scanner-source lookup table.
- Failed-batch retry is command-level and is distinct from Nmap packet retransmission.
- Parallel scans execute in bounded waves so policy stop conditions can be checked between waves.

## CVSS UI

- Replaced the compact CVSS dropdown with a visible `CVSS 3.1 | CVSS 4.0 | Both` switch.
- The selected view controls score/severity columns, source/vector details, severity filtering, and score sorting.
- CVSS 3.1 and 4.0 remain independent published metrics; no score conversion is introduced.
