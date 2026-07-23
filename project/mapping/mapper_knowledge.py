from __future__ import annotations

from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

SEVERITY_SCORE = {
    "Critical": 10,
    "High": 8,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

MITRE_ENTERPRISE_ATTACK_FILE = Path("data") / "enterprise_attack.json"


KNOWN_CVE_SIGNATURES: list[dict[str, Any]] = [
    {
        "match_type": "cpe_contains",
        "patterns": ["vsftpd:vsftpd:2.3.4"],
        "cve_id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 backdoor vulnerability",
        "severity": "Critical",
        "reason": "Detected vsftpd 2.3.4 CPE/version, a well-known vulnerable FTP daemon build used in lab targets.",
        "remediation": "Remove vsftpd 2.3.4, install a trusted patched version, disable anonymous access, and prefer SFTP/FTPS where possible.",
    },
    {
        "match_type": "product_version_contains",
        "product": "samba",
        "version_patterns": ["3.0.20"],
        "cve_id": "CVE-2007-2447",
        "title": "Samba username map script command execution risk",
        "severity": "Critical",
        "reason": "Detected Samba 3.0.20, which falls within the vulnerable Samba 3.0.0 to 3.0.25rc3 range when unsafe username map script configuration exists.",
        "remediation": "Upgrade Samba, disable unsafe username map script configuration, restrict SMB access, and segment file-sharing services.",
    },
    {
        "match_type": "product_version_contains",
        "product": "apache httpd",
        "version_patterns": ["2.2.8"],
        "cve_id": "CVE-2011-3192",
        "title": "Apache HTTPD byterange denial-of-service risk",
        "severity": "High",
        "reason": "Detected Apache httpd 2.2.8, an old 2.2.x release affected by historic Range-header denial-of-service issues.",
        "remediation": "Upgrade Apache httpd, apply vendor patches, review modules, remove default pages, and enforce secure web configuration.",
    },
]


SERVICE_KNOWLEDGE_BASE: dict[str, dict[str, Any]] = {
    "ftp": {
        "title": "FTP service exposed",
        "severity": "Medium",
        "cve_hint": "Check FTP product/version/CPE against NVD for anonymous access, weak authentication, or daemon-specific CVEs.",
        "recommendation": "Disable anonymous access, enforce strong authentication, prefer SFTP/FTPS, and patch the FTP server.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1078", "name": "Valid Accounts"},
        ],
    },
    "ssh": {
        "title": "SSH remote administration exposed",
        "severity": "Medium",
        "cve_hint": "Check OpenSSH/product version against NVD and vendor advisories.",
        "recommendation": "Use key-based authentication, disable root login, restrict source IPs, and patch SSH.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021.004", "name": "Remote Services: SSH"},
            {"id": "T1110", "name": "Brute Force"},
        ],
    },
    "telnet": {
        "title": "Telnet plaintext remote access exposed",
        "severity": "Critical",
        "cve_hint": "Telnet is usually a configuration/security weakness rather than one CVE; credentials and commands are transmitted in plaintext.",
        "recommendation": "Disable Telnet and replace it with SSH or another encrypted remote administration method.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1557", "name": "Adversary-in-the-Middle"},
        ],
    },
    "http": {
        "title": "HTTP web service exposed",
        "severity": "Medium",
        "cve_hint": "Check web server product/version/CPE and hosted application against NVD/vendor advisories.",
        "recommendation": "Patch the web server, remove default pages, enforce HTTPS, and review web application attack surface.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ],
    },
    "https": {
        "title": "HTTPS web service exposed",
        "severity": "Low",
        "cve_hint": "Check TLS configuration and web server product/version against NVD/vendor advisories.",
        "recommendation": "Validate certificate configuration, disable weak TLS, and patch the web server/application.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ],
    },
    "microsoft-ds": {
        "title": "SMB file-sharing service exposed",
        "severity": "High",
        "cve_hint": "Check SMB/Samba/Windows build and CPE against NVD and vendor advisories.",
        "recommendation": "Restrict SMB access, disable legacy SMB versions, patch the host, and limit file-sharing exposure.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "attack_path_stage": "Validation / Discovery"},
            {"id": "T1135", "name": "Network Share Discovery", "attack_path_stage": "Validation / Discovery"},
            {"id": "T1210", "name": "Exploitation of Remote Services", "attack_path_stage": "Controlled Exploitation Candidate"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "attack_path_stage": "Post-access Emulation"},
        ],
    },
    "netbios-ssn": {
        "title": "NetBIOS/SMB session service exposed",
        "severity": "High",
        "cve_hint": "Check Samba/NetBIOS exposure against public advisories and confirm whether legacy file-sharing is required.",
        "recommendation": "Disable NetBIOS where unnecessary, restrict SMB to trusted subnets, and patch Samba/Windows file-sharing components.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "attack_path_stage": "Validation / Discovery"},
            {"id": "T1135", "name": "Network Share Discovery", "attack_path_stage": "Validation / Discovery"},
            {"id": "T1210", "name": "Exploitation of Remote Services", "attack_path_stage": "Controlled Exploitation Candidate"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "attack_path_stage": "Post-access Emulation"},
        ],
    },
    "ms-wbt-server": {
        "title": "RDP remote access exposed",
        "severity": "High",
        "cve_hint": "Check Windows Server/RDP exposure against Microsoft advisories and NVD.",
        "recommendation": "Restrict RDP by source IP/VPN, enable NLA, enforce MFA, and patch Windows Server.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
            {"id": "T1110", "name": "Brute Force"},
        ],
    },
    "wsman": {
        "title": "WinRM remote management exposed",
        "severity": "High",
        "cve_hint": "Check Windows Remote Management configuration and related Microsoft advisories.",
        "recommendation": "Restrict WinRM to management hosts, enforce authentication, and monitor remote command activity.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021.006", "name": "Remote Services: Windows Remote Management"},
        ],
    },
    "mysql": {
        "title": "MySQL database service exposed",
        "severity": "High",
        "cve_hint": "Check MySQL product/version against NVD and vendor advisories.",
        "recommendation": "Restrict database access, patch MySQL, enforce strong credentials, and avoid public exposure.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1005", "name": "Data from Local System"},
        ],
    },
    "domain": {
        "title": "DNS service exposed",
        "severity": "Medium",
        "cve_hint": "Check DNS server product/version against NVD and review recursion/zone-transfer exposure.",
        "recommendation": "Disable open recursion, restrict zone transfers, patch DNS software, and limit access to trusted clients.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1018", "name": "Remote System Discovery"},
        ],
    },
    "smtp": {
        "title": "SMTP mail service exposed",
        "severity": "Medium",
        "cve_hint": "Check mail server product/version and open relay configuration against NVD/vendor advisories.",
        "recommendation": "Disable open relay, enforce authentication, restrict management exposure, and patch the mail server.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1598", "name": "Phishing for Information"},
        ],
    },
    "rpcbind": {
        "title": "RPC bind service exposed",
        "severity": "Medium",
        "cve_hint": "Check RPC/NFS-related exposure and service versions against NVD/vendor advisories.",
        "recommendation": "Restrict RPC services to trusted networks and disable unnecessary RPC/NFS components.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1018", "name": "Remote System Discovery"},
        ],
    },
    "exec": {
        "title": "Legacy remote shell exec service exposed",
        "severity": "High",
        "cve_hint": "Legacy rsh/rexec style services commonly expose plaintext remote command access and should be removed.",
        "recommendation": "Disable rexec/rsh services and replace them with SSH using strong authentication.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1110", "name": "Brute Force"},
        ],
    },
    "login": {
        "title": "Legacy remote login service exposed",
        "severity": "High",
        "cve_hint": "Legacy rlogin-style services commonly expose plaintext remote access and should be removed.",
        "recommendation": "Disable rlogin/login services and use SSH with hardened authentication controls.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1110", "name": "Brute Force"},
        ],
    },
    "tcpwrapped": {
        "title": "TCP-wrapped service observed",
        "severity": "Low",
        "cve_hint": "The service is protected or access-controlled; verify the underlying daemon and access policy.",
        "recommendation": "Confirm the service is required, restrict access, and identify the underlying daemon for version review.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"}
        ],
    },
}


PORT_FALLBACKS: dict[str, str] = {
    "21": "ftp",
    "22": "ssh",
    "23": "telnet",
    "25": "smtp",
    "53": "domain",
    "80": "http",
    "111": "rpcbind",
    "139": "netbios-ssn",
    "443": "https",
    "445": "microsoft-ds",
    "512": "exec",
    "513": "login",
    "514": "tcpwrapped",
    "3389": "ms-wbt-server",
    "5985": "wsman",
    "5986": "wsman",
    "3306": "mysql",
    "1433": "mssql",
}