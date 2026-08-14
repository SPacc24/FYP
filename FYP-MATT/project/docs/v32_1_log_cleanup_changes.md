# v32.1 log and status cleanup

This update was made after a live Kali run showed that the new service-level checks were running, but some console log wording was still too generic or misleading.

Changes:

- `ssh-audit` non-zero exits that contain recommendation/evidence text are treated as evidence captured, not command failure warnings.
- `httpx-toolkit -h` capability probing is no longer shown as a user-facing enumeration command.
- Nmap service-level script logs now use specific descriptions for FTP, Telnet, SMTP, DNS, SMB, RPC/NFS, RMI, MySQL, PostgreSQL, VNC, X11, IRC, AJP/Tomcat, and banner checks.
- `arp-scan` logs now describe ARP visibility checking instead of generic enumeration.
- Report-quality tests were expanded to cover service-level command descriptions and ssh-audit evidence handling.

Scope remains unchanged: no scoring, no prioritisation, no severity ranking logic, and no manual-validation wording.
