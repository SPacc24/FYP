# Windows Authenticated Patch / CVE Enrichment

## Purpose

Add evidence-driven Windows OS patch awareness without changing canonical CVE applicability rules or teammate-owned exploitation code.

## Data flow

1. CVEProject/cvelistV5 remains the canonical CVE applicability source.
2. When the operator explicitly enables `windows_patch_inventory`, the scanner reads an already-approved cached SMB credential.
3. The scanner collects read-only Windows WMI evidence and, only when already available, read-only `CurrentVersion` registry values. It never starts RemoteRegistry.
4. Installed KB identifiers, Windows version/build, release and directly observed UBR are retained as raw scan evidence.
5. Microsoft Security Response Center CVRF/Security Update Guide data supplies vendor remediation KB/fixed-build metadata for Windows host-OS CVEs that were already matched canonically.
6. Patch state is resolved conservatively:
   - matching remediation KB observed -> `Remediation observed`;
   - directly observed Windows build/revision at or above a comparable Microsoft fixed build -> `Remediation observed`;
   - directly observed build/revision older than all comparable fixed builds, with no remediation KB observed -> `Applicable update not observed`;
   - otherwise -> `Insufficient patch evidence`.

A missing KB alone is never proof that a CVE remains unremediated.

## Operator behaviour

`windows_patch_inventory` is credential-required and excluded from all presets, including Maximum Evidence. The operator must explicitly select it.

The collector uses only an existing credential cached by the established credential-audit workflow. Because credential auditing currently runs later in a teammate-owned exploitation workflow, a credential first discovered after a scan does not automatically restart recon. Rerun the scanner with the collector selected after the credential is cached unless the owning teammate later wires an approved callback.

## Safety boundaries

- private/loopback IPv4 targets only;
- no brute force or credential discovery;
- no remote shell/process creation;
- no service creation or service start/stop;
- no registry writes;
- no firewall changes;
- no remote filesystem writes;
- passwords/usernames are never retained in raw evidence, reports or command logs.

## Source separation

- CVE applicability: CVEProject/cvelistV5
- Windows remediation/build evidence: Microsoft Security Response Center Security Update Guide / CVRF API
- CVSS enrichment: existing targeted NVD path

## Maintenance commands

From `project/` with the virtual environment active:

```bash
python scripts/msrc_status.py
python scripts/sync_msrc_security_updates.py --months 3
python scripts/sync_msrc_security_updates.py --cve CVE-YYYY-NNNN
```
