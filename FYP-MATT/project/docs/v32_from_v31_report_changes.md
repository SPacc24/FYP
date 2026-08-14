# v32-from-v31 Report Quality Changes

This update applies the senior-pentester report cleanup requested against the uploaded v31 project.

## Main changes

- Renamed the visible CVE section to **Confirmed CVE Findings**.
- CVEs only stay in the strict CVE table when the source is official CVE Program / MITRE, the product matches, the observed version/CPE is exact, and required context is supported by collected evidence.
- Version-range-only, module-dependent, configuration-dependent, authenticated-user, TLS/certificate, SQL-backend, SSH/SFTP, role-specific, and OS-context mismatch CVEs move to **Relevant Version / Exposure Information**.
- Duplicate CVEs across ports are merged by host + product + version + CVE ID.
- Tool coverage status wording now reports unavailable tools, missing inputs, timeouts, and not-applicable service checks honestly.
- Added **Service-Level Exposure Checks** for obvious attack surface such as FTP, Telnet, SMTP, DNS, SMB, RPC/NFS, r-services, RMI, bindshell, MySQL, PostgreSQL, VNC, X11, IRC, AJP/Tomcat, Ruby DRb, and unknown high ports.

## Scope boundaries

This update does not add scoring, prioritisation, ranking logic, exploitation decisions, or manual-validation wording.
