from __future__ import annotations

from typing import Any

from mapping.mapper_models import CVEMatch, VulnerabilityFinding
from mapping.mapper_knowledge import (
    SERVICE_KNOWLEDGE_BASE,
    SEVERITY_ORDER,
)
from mapping.mapper_utils import (
    attach_tactics,
    normalise_service,
    max_severity,
    build_evidence,
    match_known_cves,
    priority_score,
    build_title,
    build_cve_hint,
    build_recommendation,
    host_os_text,
    is_legacy_windows_smb_candidate,
    apply_attack_path_context,
)


def map_vulnerabilities(parsed_results: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities: list[dict[str, Any]] = []
    technique_counts: dict[str, dict[str, Any]] = {}

    for host in parsed_results.get("hosts", []):
        host_addr = host.get("address", {}).get("primary", "Unknown")
        os_text = host_os_text(host, parsed_results)

        for item in host.get("port_findings", []):
            state = item.get("state", "unknown")
            service = normalise_service(item)

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
                    cve_hint=(
                        "No direct CVE match because the service is filtered; investigate "
                        "firewall/network policy and rescan if authorised."
                    ),
                    evidence=build_evidence(host_addr, item),
                    recommendation=(
                        "Confirm whether this port should be filtered. If exposure is expected, "
                        "review firewall or network isolation rules."
                    ),
                    attack_techniques=[
                        {"id": "T1046", "name": "Network Service Discovery"}
                    ],
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
                    "techniques": [
                        {"id": "T1046", "name": "Network Service Discovery"}
                    ],
                },
            )

            cves = match_known_cves(item, service)

            if is_legacy_windows_smb_candidate(item, service, os_text):
                cves.extend([
                    CVEMatch(
                        cve_id="CVE-2017-0143",
                        title="Microsoft SMBv1 remote code execution vulnerability",
                        severity="Critical",
                        reason=(
                            "SMB is exposed on a detected legacy Windows 10 build 10240 fingerprint. "
                            "Link this official CVE record for analyst validation against patch level and SMBv1 status."
                        ),
                        remediation="Apply Microsoft SMB security updates, disable SMBv1, and restrict SMB exposure.",
                    ),
                    CVEMatch(
                        cve_id="CVE-2017-0144",
                        title="Microsoft SMBv1 remote code execution vulnerability",
                        severity="Critical",
                        reason=(
                            "SMB is exposed on a detected legacy Windows 10 build 10240 fingerprint. "
                            "This is a candidate MS17-010-related CVE and should be validated using safe checks."
                        ),
                        remediation="Apply Microsoft MS17-010 updates, disable SMBv1, and restrict SMB exposure.",
                    ),
                    CVEMatch(
                        cve_id="CVE-2017-0145",
                        title="Microsoft SMBv1 remote code execution vulnerability",
                        severity="Critical",
                        reason=(
                            "SMB is exposed on a detected legacy Windows 10 build 10240 fingerprint. "
                            "Link this official CVE record for analyst validation against patch level and SMBv1 status."
                        ),
                        remediation="Apply Microsoft SMB security updates, disable SMBv1, and restrict SMB exposure.",
                    ),
                ])

            severity = kb_entry["severity"]

            for cve in cves:
                severity = max_severity(severity, cve.severity)

            title = build_title(kb_entry["title"], cves)
            cve_hint = build_cve_hint(kb_entry["cve_hint"], cves)
            recommendation = build_recommendation(kb_entry["recommendation"], cves)
            priority = priority_score(severity, service, cves)

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
                evidence=build_evidence(host_addr, item),
                recommendation=recommendation,
                attack_techniques=apply_attack_path_context(
                    kb_entry["techniques"],
                    service,
                    item,
                    os_text,
                ),
            ).to_dict()

            vulnerabilities.append(finding)

            for technique in finding["attack_techniques"]:
                technique_id = technique["id"]

                if technique_id not in technique_counts:
                    technique_counts[technique_id] = {
                        **technique,
                        "count": 0,
                        "max_severity": severity,
                        "reasons": [],
                        "supporting_services": [],
                    }

                technique_counts[technique_id]["count"] += 1

                reason = technique.get("reason")
                if reason and reason not in technique_counts[technique_id]["reasons"]:
                    technique_counts[technique_id]["reasons"].append(reason)

                if service not in technique_counts[technique_id]["supporting_services"]:
                    technique_counts[technique_id]["supporting_services"].append(service)

                if SEVERITY_ORDER[severity] > SEVERITY_ORDER[technique_counts[technique_id]["max_severity"]]:
                    technique_counts[technique_id]["max_severity"] = severity

    vulnerabilities.sort(
        key=lambda v: (
            SEVERITY_ORDER.get(v["severity"], 0),
            v.get("priority_score", 0),
        ),
        reverse=True,
    )

    recommended_techniques = sorted(
        technique_counts.values(),
        key=lambda t: (
            SEVERITY_ORDER.get(t["max_severity"], 0),
            t["count"],
        ),
        reverse=True,
    )

    recommended_techniques = attach_tactics(recommended_techniques)

    return {
        "vulnerabilities": vulnerabilities,
        "top_risks": vulnerabilities[:5],
        "recommended_techniques": recommended_techniques,
        "severity_counts": count_severities(vulnerabilities),
        "attack_modes": build_attack_modes(vulnerabilities, recommended_techniques),
        "attack_chain": build_attack_chain(vulnerabilities),
        "caldera_plan": build_caldera_plan(vulnerabilities, recommended_techniques),
    }


def count_severities(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def build_attack_modes(
    vulnerabilities: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> dict[str, Any]:

    high_priority = [
        v for v in vulnerabilities
        if v.get("severity") in {"Critical", "High"}
        and v.get("state") == "open"
    ]

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
            "logic": (
                "Services requiring authentication are candidates for password-policy review "
                "and brute-force-resistance validation."
            ),
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
            "logic": (
                "No open high-risk services were mapped. Continue monitoring filtered/closed "
                "results and rescan if exposure changes."
            ),
            "techniques": "T1046",
        })

    return chain


def build_caldera_plan(
    vulnerabilities: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> dict[str, Any]:

    selected = [
        t for t in techniques
        if t.get("max_severity") in {"Critical", "High"}
    ]

    if not selected:
        selected = techniques[:3]

    return {
        "ready_for_step_05": bool(selected),
        "selection_reason": "Prioritised by severity first, then number of supporting findings.",
        "selected_techniques": selected[:6],
        "blocked_note": (
            "This module only prepares recommendations. Caldera execution still requires "
            "analyst confirmation and authorised lab scope."
        ),
    }


def build_vulnerability_mapping(parsed_results: dict[str, Any]) -> dict[str, Any]:
    return map_vulnerabilities(parsed_results)


def map_results_to_vulnerabilities(parsed_results: dict[str, Any]) -> dict[str, Any]:
    return map_vulnerabilities(parsed_results)


def select_attack_mode(mapping_result, mode, selected_ids=None):
    mode = mode.lower()
    selected_ids = selected_ids or []

    recommended_techniques = mapping_result.get("recommended_techniques", [])

    if mode == "auto":
        return auto_attack_mode(recommended_techniques)

    if mode == "hybrid":
        return hybrid_attack_mode(recommended_techniques, selected_ids)

    if mode == "manual":
        return manual_attack_mode(recommended_techniques, selected_ids)

    raise ValueError("Invalid mode. Choose auto, hybrid, or manual.")


def auto_attack_mode(recommended_techniques):
    selected = recommended_techniques[:3]

    return {
        "mode": "auto",
        "description": "Rule-based selection from vulnerability and service findings. No user input needed.",
        "attack_plan": selected,
    }


def hybrid_attack_mode(recommended_techniques, selected_ids=None):
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
        "editable": True,
    }


def manual_attack_mode(recommended_techniques, selected_ids=None):
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
        "editable": True,
    }
