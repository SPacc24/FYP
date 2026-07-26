# Cross-Platform Scanner Validation - 2026-07-26

## Automated validation

- Scanner test suite: 68 passed, 4 subtests passed.
- Python compileall: passed.
- Jinja parse: index, scan report, technical appendix, PDF report, and attack-surface workbench passed.
- Rendered starting-page JavaScript: `node --check` passed.
- ReportLab synthetic cross-platform PDF: generated and rendered successfully.
- WeasyPrint/Jinja synthetic cross-platform PDF: generated and rendered successfully.
- JSON policy files: parsed successfully.
- Bash installer syntax: passed.

## Regression coverage added

- OS CPE is kept separate from application CPE.
- CPE 2.2 product-only OS identities remain usable as broad evidence.
- Broad Windows ranges remain broad and are not converted to guessed numeric versions.
- NTLM `Product_Version` is retained as build evidence without mapping to a Windows marketing edition in code.
- macOS and Windows host identities enter the same host-scope matcher.
- Linux host identity remains separate from SSH/application identity.
- Component identity uses the same CVE engine with a distinct scope.
- Tomcat and Apache-Coyote layers remain distinct.
- Equivalent application aliases do not duplicate the same CVE presentation row.
- Equivalent security observations are deduplicated in reporting while raw evidence is retained.
- Missing collector terminal lifecycle state becomes an explicit assurance failure.
- Protocol-advertised RPC endpoint following is disabled by default.
- No EternalBlue/MS17-010 or real CVE detection shortcut is present in production scanner Python.

## Replay of the supplied Windows appendix

The historical Windows Nmap service-fingerprint XML embedded in the supplied appendix was replayed through the upgraded parser after HTML extraction. The parser retained:

- `netbios-ssn` and `microsoft-ds` services,
- service-provided Windows OS evidence,
- `cpe:/o:microsoft:windows` as a host OS CPE,
- the observed hostname,
- the broad Windows identity without converting it to a guessed Windows release.

This replay is parser validation only; it is not a new network scan.

## Environment limitation

The container used for this code review does not have the project's Flask/MySQL test dependencies installed and cannot download packages from PyPI, so the Flask-dependent whole-project test collection was not executed here. Scanner-owned tests and report/template validation passed as recorded above.

No live Kali, Windows, Linux, or macOS target scan was performed in this container. A fresh Kali regression scan against authorised targets remains the final runtime acceptance test.
