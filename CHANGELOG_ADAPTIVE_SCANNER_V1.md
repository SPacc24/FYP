# Adaptive Scanner v1

## 2026-07-21 results-page hotfix

- Fixed the scan-results HTTP 500 caused by loading the scan-form template from the included pivot panel without `scan_defaults`.
- Split the standalone pivot page wrapper from the results-dashboard partial so both rendering paths receive the correct template context.
- Added a regression test that prevents included dashboard partials from extending the scan form.
- Restored explicit policy disablement for `ssh_audit_native` so legacy custom input cannot bypass the collector policy.

## Changed

- Replaced the Full/Custom profile interface with one adaptive vulnerability scan.
- Reduced required operator input to authorised IP addresses, lists, ranges, or CIDRs.
- Added complete, common, and custom numerical TCP coverage with additional and excluded ports.
- Added separate disabled, common, complete, and custom UDP coverage.
- Added validated Advanced defaults: 256 ports per microbatch, four concurrent targets, three-second timeout, and one retry.
- Removed concurrent microbatches. Each target processes one ordered port batch at a time.
- Added concurrent discovery across different targets up to the configured limit.
- Added port-independent fingerprinting for every observed open TCP port and response-evidenced UDP fingerprinting.
- Changed HTTP, SMB, LDAP, Kerberos, TLS, RDP, FTP, WinRM, and web-module dispatch to prefer observed service/product/tunnel evidence instead of conventional port assignments.
- Added compact, exact scan-coverage records and limitations.
- Added `candidate` and `confirmed_affected` CVE applicability status, with exploitability explicitly left unvalidated.
- Moved port coverage sets and workload defaults into `project/policies/port_coverage.json`.
- Added malformed-port and configuration tests and repaired the repository acceptance-test contract drift.

## Verification

- Python compilation passed.
- 148 project tests passed.
- 45 repository acceptance tests passed.
- Flask landing-page rendering passed.
