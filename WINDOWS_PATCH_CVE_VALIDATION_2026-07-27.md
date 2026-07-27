# Windows Patch / CVE Enrichment Validation

## Implemented scope

- Scanner-owned authenticated Windows patch inventory.
- Existing cached credential consumption only; no changes to credential-audit/exploitation code.
- Read-only WMI/DCOM OS and QFE evidence.
- Optional read-only `CurrentVersion` registry evidence only when RemoteRegistry is already available; the scanner never starts the service.
- Microsoft Security Response Center CVRF client with JSON/XML parsing, local caching, targeted CVE remediation lookup and recent-month cache fallback.
- Windows patch applicability based on matching Microsoft Windows product identity, directly observed KBs and comparable fixed build/revision evidence.
- Conservative patch state: a missing KB alone never establishes that a CVE remains unremediated.
- Operator-explicit collector selection; credential-required collectors are excluded even from Maximum Evidence presets.
- MSRC status/sync scripts, installer integration, report/appendix output and raw-evidence retention.

## Automated validation

- `PYTHONPATH=. python -m pytest -q scanners/tests`
  - 84 tests passed
  - 4 subtests passed
- `python -m compileall -q scanners scripts`
  - passed
- `bash -n install.sh` and `bash -n start.sh`
  - passed
- Jinja template parsing/rendering for the modified report templates
  - passed
- ReportLab fallback PDF generated with Windows patch inventory and remediation-assessment fixture data
  - passed
- Production new-module scan for literal CVE/KB facts
  - no production CVE/KB literals found
- Scope comparison against the supplied ZIP after removing generated test caches
  - `project/exploitation`: unchanged
  - `project/caldera`: unchanged
  - `project/ai`: unchanged
  - `project/mapping`: unchanged
  - `project/routes`: unchanged

## Environment-limited validation

The full project test suite could not collect in the artifact execution environment because Flask is not installed there. A temporary dependency-install attempt was also blocked because that environment has no reachable Python package index. These are environment limitations rather than observed scanner test failures. The project's installer remains responsible for creating `.venv` and installing `project/requirements.txt` on Kali.

The MSRC live HTTP path was not executed from the artifact container because Python network access is unavailable there. Parser, cache, diagnostics and degraded-network behavior were tested locally; the endpoint/API design was externally verified separately.

## Runtime limitation retained intentionally

Credential auditing currently belongs to a downstream teammate-owned exploitation workflow. This implementation does not modify that module. Therefore a credential first discovered after recon does not cause recon to restart automatically. After a credential has been cached, rerun the scan with **Windows authenticated patch inventory** explicitly selected. A future automatic callback requires approval from the owner of the downstream credential-audit code.
