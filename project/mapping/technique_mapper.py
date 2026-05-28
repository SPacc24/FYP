
"""
P3 Vulnerability Mapping + Technique Recommendation
Maps Nmap service findings to vulnerability context, known CVE matches, severity,
remediation, and Caldera-ready ATT&CK-style technique recommendations.

Educational / authorised testing only.
This module does not exploit anything; it only enriches scan results for analysis
and attack-mode planning.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEVERITY_SCORE = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 0}


@dataclass
class CVEMatch:
    cve_id: str
    title: str
    severity: str
    reason: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class VulnerabilityFinding:
    host: str
    port: str
    protocol: str
    service: str
    product: str
    version: str
    state: str
    title: str
    severity: str
    priority_score: int
    cve_ids: list[str]
    cve_matches: list[dict[str, str]]
    cve_hint: str
    evidence: str
    recommendation: str
    attack_techniques: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Exact/local CVE knowledge base for common lab targets such as Metasploitable.
# These matches are deterministic and safe: no exploit execution is performed.
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
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
            {"id": "T1135", "name": "Network Share Discovery"},
        ],
    },
    "netbios-ssn": {
        "title": "NetBIOS/SMB session service exposed",
        "severity": "High",
        "cve_hint": "Check Samba/NetBIOS exposure against public advisories and confirm whether legacy file-sharing is required.",
        "recommendation": "Disable NetBIOS where unnecessary, restrict SMB to trusted subnets, and patch Samba/Windows file-sharing components.",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
            {"id": "T1135", "name": "Network Share Discovery"},
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
        "techniques": [{"id": "T1046", "name": "Network Service Discovery"}],
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


def _normalise(value: Any) -> str:
    return str(value or "").lower().strip()


def _normalise_service(item: dict[str, Any]) -> str:
    service = _normalise(item.get("service"))
    if service in {"", "unknown"}:
        service = PORT_FALLBACKS.get(str(item.get("port", "")), "unknown")
    return service


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _build_evidence(host: str, item: dict[str, Any]) -> str:
    product = item.get("product") or "unknown product"
    version = item.get("version") or "unknown version"
    cpes = ", ".join(item.get("cpe", [])) or "no CPE reported"
    return (
        f"{host}:{item.get('port')}/{item.get('protocol')} "
        f"state={item.get('state')} service={item.get('service')} "
        f"product={product} version={version} cpe={cpes}"
    )


def _match_known_cves(item: dict[str, Any], service: str) -> list[CVEMatch]:
    product = _normalise(item.get("product"))
    version = _normalise(item.get("version"))
    cpes = [_normalise(cpe) for cpe in item.get("cpe", [])]
    matches: list[CVEMatch] = []

    for sig in KNOWN_CVE_SIGNATURES:
        matched = False

        if sig["match_type"] == "cpe_contains":
            for pattern in sig.get("patterns", []):
                if any(_normalise(pattern) in cpe for cpe in cpes):
                    matched = True
                    break

        elif sig["match_type"] == "product_version_contains":
            product_pattern = _normalise(sig.get("product"))
            version_patterns = [_normalise(p) for p in sig.get("version_patterns", [])]
            if product_pattern in product and any(p in version for p in version_patterns):
                matched = True
            # Some Nmap results identify Samba on netbios-ssn but product may still contain Samba.
            if service in {"microsoft-ds", "netbios-ssn"} and "samba" in product:
                if any(p in version for p in version_patterns):
                    matched = True

        if matched:
            matches.append(
                CVEMatch(
                    cve_id=sig["cve_id"],
                    title=sig["title"],
                    severity=sig["severity"],
                    reason=sig["reason"],
                    remediation=sig["remediation"],
                )
            )

    return matches


def _priority_score(severity: str, service: str, cve_matches: list[CVEMatch]) -> int:
    score = SEVERITY_SCORE.get(severity, 0)
    if cve_matches:
        score += 2
    if service in {"telnet", "ftp", "microsoft-ds", "netbios-ssn", "exec", "login", "mysql", "ms-wbt-server"}:
        score += 1
    return min(score, 10)


def _build_title(base_title: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_title
    return f"{base_title} ({', '.join(c.cve_id for c in cves)})"


def _build_cve_hint(base_hint: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_hint
    cve_lines = [f"{c.cve_id}: {c.title} — {c.reason}" for c in cves]
    return "Known match: " + " | ".join(cve_lines)


def _build_recommendation(base_recommendation: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_recommendation
    specific = " ".join(c.remediation for c in cves)
    return f"{specific} General hardening: {base_recommendation}"


def map_vulnerabilities(parsed_results: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities: list[dict[str, Any]] = []
    technique_counts: dict[str, dict[str, Any]] = {}

    for host in parsed_results.get("hosts", []):
        host_addr = host.get("address", {}).get("primary", "Unknown")

        for item in host.get("port_findings", []):
            state = item.get("state", "unknown")
            service = _normalise_service(item)

            if state == "filtered":
                finding = VulnerabilityFinding(
                    host=host_addr,
                    port=str(item.get("port", "")),
                    protocol=item.get("protocol", ""),
                    service=service,
                    product=item.get("product", ""),
                    version=item.get("version", ""),
                    state=state,
                    title="Filtered service observed",
                    severity="Info",
                    priority_score=0,
                    cve_ids=[],
                    cve_matches=[],
                    cve_hint="No direct CVE match because the service is filtered; investigate firewall/network policy and rescan if authorised.",
                    evidence=_build_evidence(host_addr, item),
                    recommendation="Confirm whether this port should be filtered. If exposure is expected, review firewall or network isolation rules.",
                    attack_techniques=[{"id": "T1046", "name": "Network Service Discovery"}],
                ).to_dict()
                vulnerabilities.append(finding)
                continue

            if state != "open":
                continue

            kb_entry = SERVICE_KNOWLEDGE_BASE.get(
                service,
                {
                    "title": f"Open {service} service detected",
                    "severity": "Low",
                    "cve_hint": "Check service product/version/CPE against NVD or vendor advisories.",
                    "recommendation": "Validate business need, restrict access, and patch the service.",
                    "techniques": [{"id": "T1046", "name": "Network Service Discovery"}],
                },
            )

            cves = _match_known_cves(item, service)
            severity = kb_entry["severity"]
            for cve in cves:
                severity = _max_severity(severity, cve.severity)

            title = _build_title(kb_entry["title"], cves)
            cve_hint = _build_cve_hint(kb_entry["cve_hint"], cves)
            recommendation = _build_recommendation(kb_entry["recommendation"], cves)
            priority = _priority_score(severity, service, cves)

            finding = VulnerabilityFinding(
                host=host_addr,
                port=str(item.get("port", "")),
                protocol=item.get("protocol", ""),
                service=service,
                product=item.get("product", ""),
                version=item.get("version", ""),
                state=state,
                title=title,
                severity=severity,
                priority_score=priority,
                cve_ids=[c.cve_id for c in cves],
                cve_matches=[c.to_dict() for c in cves],
                cve_hint=cve_hint,
                evidence=_build_evidence(host_addr, item),
                recommendation=recommendation,
                attack_techniques=kb_entry["techniques"],
            ).to_dict()
            vulnerabilities.append(finding)

            for technique in finding["attack_techniques"]:
                technique_id = technique["id"]
                if technique_id not in technique_counts:
                    technique_counts[technique_id] = {**technique, "count": 0, "max_severity": severity}
                technique_counts[technique_id]["count"] += 1
                if SEVERITY_ORDER[severity] > SEVERITY_ORDER[technique_counts[technique_id]["max_severity"]]:
                    technique_counts[technique_id]["max_severity"] = severity

    vulnerabilities.sort(
        key=lambda v: (SEVERITY_ORDER.get(v["severity"], 0), v.get("priority_score", 0)),
        reverse=True,
    )
    recommended_techniques = sorted(
        technique_counts.values(),
        key=lambda t: (SEVERITY_ORDER.get(t["max_severity"], 0), t["count"]),
        reverse=True,
    )

    return {
        "vulnerabilities": vulnerabilities,
        "top_risks": vulnerabilities[:5],
        "recommended_techniques": recommended_techniques,
        "severity_counts": _count_severities(vulnerabilities),
        "attack_modes": build_attack_modes(vulnerabilities, recommended_techniques),
        "attack_chain": build_attack_chain(vulnerabilities),
        "caldera_plan": build_caldera_plan(vulnerabilities, recommended_techniques),
    }


def _count_severities(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def build_attack_modes(vulnerabilities: list[dict[str, Any]], techniques: list[dict[str, Any]]) -> dict[str, Any]:
    high_priority = [v for v in vulnerabilities if v.get("severity") in {"Critical", "High"} and v.get("state") == "open"]

    return {
        "auto": {
            "description": "Automatically select critical/high-severity technique candidates from open services.",
            "recommended": bool(high_priority),
            "techniques": techniques[:3],
        },
        "hybrid": {
            "description": "System recommends a prioritised plan; analyst reviews before Caldera execution.",
            "recommended": True,
            "techniques": techniques[:6],
        },
        "manual": {
            "description": "Analyst browses all mapped techniques and selects manually.",
            "recommended": True,
            "techniques": techniques,
        },
    }


def build_attack_chain(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []

    if any(v["service"] in {"http", "https", "ftp", "telnet"} for v in vulnerabilities):
        chain.append({
            "stage": "Initial Access / Exposure Review",
            "logic": "Prioritise exposed public-facing or remote-access services first.",
            "techniques": "T1190 / T1021 / T1046",
        })

    if any(v["service"] in {"ftp", "ssh", "telnet", "mysql", "ms-wbt-server"} for v in vulnerabilities):
        chain.append({
            "stage": "Credential Attack Surface",
            "logic": "Services requiring authentication are candidates for password-policy review and brute-force-resistance validation.",
            "techniques": "T1110 / T1078",
        })

    if any(v["service"] in {"microsoft-ds", "netbios-ssn", "wsman"} for v in vulnerabilities):
        chain.append({
            "stage": "Lateral Movement Surface",
            "logic": "SMB/remote management services may support lateral movement if credentials are obtained.",
            "techniques": "T1021.002 / T1021.006 / T1135",
        })

    if not chain:
        chain.append({
            "stage": "Reconnaissance Only",
            "logic": "No open high-risk services were mapped. Continue monitoring filtered/closed results and rescan if exposure changes.",
            "techniques": "T1046",
        })

    return chain


def build_caldera_plan(vulnerabilities: list[dict[str, Any]], techniques: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [t for t in techniques if t.get("max_severity") in {"Critical", "High"}]
    if not selected:
        selected = techniques[:3]

    return {
        "ready_for_step_05": bool(selected),
        "selection_reason": "Prioritised by severity first, then number of supporting findings.",
        "selected_techniques": selected[:6],
        "blocked_note": "This module only prepares recommendations. Caldera execution still requires analyst confirmation and authorised lab scope.",
    }


# Backwards-compatible aliases in case app.py or future modules use different names.
def build_vulnerability_mapping(parsed_results: dict[str, Any]) -> dict[str, Any]:
    return map_vulnerabilities(parsed_results)


def map_results_to_vulnerabilities(parsed_results: dict[str, Any]) -> dict[str, Any]:
    return map_vulnerabilities(parsed_results)


# ATTACK MODE LOGIC

def select_attack_mode(mapping_result, mode, selected_ids=None):
    """
    Takes vulnerability mapping output and applies attack mode logic.

    mapping_result = output from map_vulnerabilities()
    mode = auto / hybrid / manual
    selected_ids = list of ATT&CK IDs chosen by analyst/user
    """

    mode = mode.lower()
    selected_ids = selected_ids or []

    recommended_techniques = mapping_result.get("recommended_techniques", [])

    if mode == "auto":
        return auto_attack_mode(recommended_techniques)

    elif mode == "hybrid":
        return hybrid_attack_mode(recommended_techniques, selected_ids)

    elif mode == "manual":
        return manual_attack_mode(recommended_techniques, selected_ids)

    else:
        raise ValueError("Invalid mode. Choose auto, hybrid, or manual.")


def auto_attack_mode(recommended_techniques):
    """
    Auto mode:
    System automatically selects the top recommended techniques.
    No user input needed.
    """

    selected = recommended_techniques[:3]

    return {
        "mode": "auto",
        "description": "Rule-based selection from vulnerability and service findings. No user input needed.",
        "attack_plan": selected
    }


def hybrid_attack_mode(recommended_techniques, selected_ids=None):
    """
    Hybrid mode:
    System recommends techniques.
    Analyst reviews and chooses which ones to keep.
    """

    selected_ids = selected_ids or []

    if selected_ids:
        selected = [
            tech for tech in recommended_techniques
            if tech.get("id") in selected_ids
        ]
    else:
        selected = recommended_techniques[:6]

    return {
        "mode": "hybrid",
        "description": "System recommends techniques, then analyst reviews and edits before confirming.",
        "recommended": recommended_techniques[:6],
        "attack_plan": selected,
        "editable": True
    }


def manual_attack_mode(recommended_techniques, selected_ids=None):
    """
    Manual mode:
    Analyst manually selects from all available mapped techniques.
    """

    selected_ids = selected_ids or []

    selected = [
        tech for tech in recommended_techniques
        if tech.get("id") in selected_ids
    ]

    return {
        "mode": "manual",
        "description": "Expert browses all available mapped techniques and selects manually.",
        "available_techniques": recommended_techniques,
        "attack_plan": selected,
        "editable": True
    }