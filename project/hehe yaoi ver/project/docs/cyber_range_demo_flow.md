# Cyber Range Demo Flow

## Positioning

This project performs automated vulnerability discovery, lab-safe exploitability
validation, and CALDERA-based post-access ATT&CK simulation.

The exploitation stage is intentionally implemented as controlled validation:
it confirms exposed or misconfigured lab services without deploying destructive
payloads. CALDERA then demonstrates realistic post-access behaviour through the
Sandcat agent.

## Demo Order

1. Start the Kali attacker VM and run the Flask dashboard.
2. Confirm the Win10, Windows Server 2012 DC, and RedHat storage VMs are reachable.
3. Run an Nmap scan from the dashboard.
4. Review vulnerability mapping and AI-selected MITRE ATT&CK techniques.
5. Run Lab Exploitability Validation.
6. Confirm the CALDERA Sandcat agent is online.
7. Run CALDERA execution for the selected techniques.
8. Generate the final report.

## What The Validation Stage Proves

- FTP anonymous access, if the lab service allows it.
- HTTP or HTTPS default pages and directory-listing style exposure.
- SMB, RDP, WinRM, SSH, NFS/RPC, and MySQL network exposure.
- Evidence that selected ATT&CK techniques are reasonable for the lab target.

## Suggested Assessor Explanation

The system does not fire arbitrary exploits at unknown systems. It uses an
allowlisted validation layer for the cyber range, records evidence, and then
hands validated attack paths to CALDERA for controlled ATT&CK simulation.
