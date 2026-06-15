# HELPERS
import logging
import socket

from flask import session

from config import Config

from ai.technique_planner import generate_ai_technique_plan
from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from reports.report_generator import build_report_summary
from scanners.nmap_parser import parse_nmap_xml
from storage import scan_store

from core.services import caldera_client, risk_scorer

log = logging.getLogger(__name__)

def _scan_summary(scan_result, parsed_results):
    return {
        "target_ip": session.get("target_ip", ""),
        "port_range": session.get("port_range", "1-1024"),
        "output_file": scan_result.get("output_file", "")
        if isinstance(scan_result, dict)
        else "",
        "os": parsed_results.get("os", "Unknown")
        if isinstance(parsed_results, dict)
        else "Unknown",
        "ports": parsed_results.get("ports", [])
        if isinstance(parsed_results, dict)
        else [],
    }


def _safe_risk_calculate(vulns, op_results):
    """
    Handles missing / broken risk scorer gracefully.
    """
    try:
        op_results = dict(op_results or {})
        op_results.setdefault("scan_context", {
            "target_ip": session.get("target_ip", "Unknown"),
            "os": session.get("target_os", "Unknown"),
        })
        return risk_scorer.calculate(vulns, op_results)
    except Exception as e:
        log.warning(f"Risk score fallback triggered: {e}")
        return {
            "score": 50,
            "label": "Medium",
            "colour": "orange",
             "badge": "warning",
        }


def _load_current_scan_results():
    output_file = session.get("scan_output_file", "")
    if not output_file:
        scan_id = session.get("scan_id")
        data = scan_store.load(scan_id) if scan_id else None
        results = (data or {}).get("results") or {}
        if results:
            return _stored_results_to_parsed_results(results, data or {})
        return None
    try:
        return parse_nmap_xml(output_file)
    except Exception:
        log.exception("Could not reload scan results for validation")
        return None


def _stored_results_to_parsed_results(results: dict, scan_record: dict | None = None) -> dict:
    scan_record = scan_record or {}
    services = results.get("service_inventory") or []
    hosts = []
    grouped: dict[str, list[dict]] = {}

    for service in services:
        host = str(service.get("host") or scan_record.get("target") or results.get("target_input") or "Unknown")
        grouped.setdefault(host, []).append({
            "port": service.get("port"),
            "protocol": service.get("protocol", "tcp"),
            "state": service.get("state", "open"),
            "service": service.get("service", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "extrainfo": service.get("extrainfo", ""),
            "cpe": service.get("cpe", []),
            "scripts": service.get("scripts", []),
        })

    for host, port_findings in grouped.items():
        hosts.append({
            "address": {"primary": host},
            "os": {"name": results.get("os", "")},
            "port_findings": port_findings,
        })

    ports = []
    for service in services:
        ports.append({
            "port": service.get("port"),
            "protocol": service.get("protocol", "tcp"),
            "state": service.get("state", "open"),
            "service": service.get("service", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "extrainfo": service.get("extrainfo", ""),
        })

    target = scan_record.get("target") or results.get("target_input") or (hosts[0]["address"]["primary"] if hosts else "Unknown")
    return {
        **results,
        "target_ip": target,
        "os": results.get("os") or "Unknown",
        "hosts": hosts,
        "ports": ports,
        "cve_matches": results.get("cve_matches", []),
        "service_inventory": services,
    }


def _active_scan_record() -> dict:
    scan_id = session.get("scan_id")
    return (scan_store.load(scan_id) if scan_id else {}) or {}


def _active_mapping_results() -> dict:
    data = _active_scan_record()
    mapping = data.get("mapping") or session.get("mapping_results") or {}
    if isinstance(mapping, dict):
        return mapping
    return {}


def _active_ai_plan() -> dict:
    data = _active_scan_record()
    plan = data.get("ai_plan") or session.get("ai_plan") or {}
    return plan if isinstance(plan, dict) else {}


def _active_attack_plan() -> dict:
    data = _active_scan_record()
    plan = data.get("attack_plan") or session.get("attack_plan") or {}
    return plan if isinstance(plan, dict) else {}


def _active_validation_results() -> dict:
    data = _active_scan_record()
    validation = data.get("validation_results") or session.get("validation_results") or {}
    return validation if isinstance(validation, dict) else {}


def _active_approved_exploitation_results() -> dict:
    data = _active_scan_record()
    approved = data.get("approved_exploitation_results") or session.get("approved_exploitation_results") or {}
    return approved if isinstance(approved, dict) else {}


def _active_operation_results() -> dict:
    data = _active_scan_record()
    operation = data.get("operation_results") or session.get("operation_results") or {}
    return operation if isinstance(operation, dict) else {}


def _save_active_scan_fields(**fields):
    scan_id = session.get("scan_id")
    if not scan_id:
        return
    current = scan_store.load(scan_id) or {}
    current.update(fields)
    scan_store.update(scan_id, **fields)
    try:
        scan_store.persist(scan_id)
    except OSError as exc:
        log.warning("Could not persist active scan fields for %s: %s", scan_id, exc)


def _build_active_report_context(data: dict | None = None) -> dict:
    """
    Build the same report inputs for the inline API, full report page, and
    download route so all three surfaces show the same assessment state.
    """
    active = data or _active_scan_record()
    scan = {
        "target_ip": active.get("target") or session.get("target_ip", "Unknown"),
        "port_range": session.get("port_range", "1-1024"),
        "output_file": session.get("scan_output_file", ""),
    }
    parsed_results = _load_current_scan_results() or {}
    scan["os"] = parsed_results.get("os", session.get("target_os", "Unknown"))
    scan["ports"] = parsed_results.get("ports", [])

    mapping_results = active.get("mapping") or _active_mapping_results()
    operation_results = active.get("operation_results") or _active_operation_results()
    validation_results = active.get("validation_results") or _active_validation_results()
    approved_exploitation_results = active.get("approved_exploitation_results") or _active_approved_exploitation_results()
    risk = active.get("risk") or session.get("risk_score", {})
    remediations = active.get("remediations") or session.get("remediations", [])

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
        approved_exploitation=approved_exploitation_results,
    )

    return {
        "scan": scan,
        "mapping": mapping_results,
        "operation": operation_results,
        "validation": validation_results,
        "approved_exploitation": approved_exploitation_results,
        "risk": risk,
        "remediations": remediations,
        "report": report,
    }


def _ensure_scan_analysis(data: dict) -> dict:
    if not data:
        return data

    changed = False
    results = data.get("results") or {}
    parsed_results = _stored_results_to_parsed_results(results, data) if results else {}

    mapping_results = data.get("mapping")
    if not isinstance(mapping_results, dict) or not mapping_results.get("recommended_techniques"):
        try:
            mapping_results = map_vulnerabilities(parsed_results)
            data["mapping"] = mapping_results
            changed = True
        except Exception:
            log.exception("Could not build vulnerability mapping for stored scan")
            mapping_results = mapping_results if isinstance(mapping_results, dict) else {}

    mode = data.get("technique_mode") or session.get("technique_mode", "hybrid")

    ai_plan = data.get("ai_plan")
    ai_reasoning = str((ai_plan or {}).get("reasoning", ""))
    ai_plan_stale = ai_reasoning.startswith((
        "Local LLM timeout",
        "Local LLM unavailable",
        "Local LLM request failed",
        "Local LLM error",
    ))

    if not isinstance(ai_plan, dict) or not ai_plan.get("selected_technique_ids") or ai_plan_stale:
        try:
            ai_plan = generate_ai_technique_plan(mapping_results, preferred_mode=mode, caldera_client=caldera_client)
            data["ai_plan"] = ai_plan
            changed = True
        except Exception:
            log.exception("Could not build AI technique plan for stored scan")
            ai_plan = ai_plan if isinstance(ai_plan, dict) else {}

    attack_plan = data.get("attack_plan")
    if not isinstance(attack_plan, dict) or not (attack_plan.get("techniques") or attack_plan.get("available_techniques")):
        try:
            selected_ids = (ai_plan or {}).get("selected_technique_ids", [])
            mode_plan = select_attack_mode(mapping_results, mode, selected_ids)
            attack_plan = {
                "mode": mode_plan.get("mode", mode),
                "description": mode_plan.get("description", ""),
                "techniques": mode_plan.get("attack_plan") or mode_plan.get("recommended") or [],
                "available_techniques": mapping_results.get("recommended_techniques", []),
            }
            data["attack_plan"] = attack_plan
            changed = True
        except Exception:
            log.exception("Could not build attack plan for stored scan")

    risk = data.get("risk")
    if not isinstance(risk, dict) or "score" not in risk:
        risk = _safe_risk_calculate((mapping_results or {}).get("vulnerabilities", []), data.get("operation_results") or {})
        data["risk"] = risk
        changed = True

    if changed and data.get("scan_id"):
        scan_store.update(
            data.get("scan_id"),
            mapping=data.get("mapping") or {},
            ai_plan=data.get("ai_plan") or {},
            attack_plan=data.get("attack_plan") or {},
            risk=data.get("risk") or {},
        )
        try:
            scan_store.persist(data.get("scan_id"))
        except OSError as exc:
            log.warning("Could not persist generated scan analysis for %s: %s", data.get("scan_id"), exc)

    session["technique_mode"] = mode
    session["target_os"] = parsed_results.get("os", session.get("target_os", "Unknown"))
    return data


def _current_target_context():
    parsed_results = _load_current_scan_results() or {}
    target = (
        session.get("target_ip")
        or parsed_results.get("target_ip")
        or (parsed_results.get("hosts", [{}])[0].get("address", {}).get("primary") if parsed_results.get("hosts") else None)
        or "Unknown"
    )
    os_name = parsed_results.get("os") or session.get("target_os") or "Windows"
    return {
        "target": target,
        "os": os_name,
        "platform": "windows" if "win" in str(os_name).lower() else "linux",
    }


def _caldera_agent_server_host():
    configured = getattr(Config, "KALI_IP", "") or ""
    if configured and configured not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        return configured
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and not host_ip.startswith("127."):
            return host_ip
    except OSError:
        pass
    return None

def _official_cve_url(cve_id):
    return f"https://www.cve.org/CVERecord?id={cve_id}"


def _build_detected_cve_rows(ai_plan=None, mapping_result=None):
    cve_lookup = {}

    # 1. First: build from mapping.vulnerabilities directly
    for vuln in (mapping_result or {}).get("vulnerabilities", []):
        cve_ids = vuln.get("cve_ids", []) or []

        for cve_id in cve_ids:
            if not cve_id:
                continue

            cve_matches = vuln.get("cve_matches", []) or []
            matching_cve = next(
                (c for c in cve_matches if c.get("cve_id") == cve_id),
                {}
            )

            if cve_id not in cve_lookup:
                cve_lookup[cve_id] = {
                    "cve_id": cve_id,
                    "severity": (
                        matching_cve.get("severity")
                        or vuln.get("severity")
                        or "Unknown"
                    ),
                    "confidence": "Candidate / Needs validation",
                    "service_port": f"{vuln.get('service', 'Unknown')}/{vuln.get('port', 'Unknown')}",
                    "description": (
                        matching_cve.get("reason")
                        or matching_cve.get("title")
                        or vuln.get("title")
                        or "No CVE description available."
                    ),
                    "official_cve_url": _official_cve_url(cve_id),
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "linked_techniques": [],
                }

            for tech in vuln.get("attack_techniques", []) or []:
                technique_id = tech.get("id")
                if technique_id:
                    already_added = any(
                        item.get("id") == technique_id
                        for item in cve_lookup[cve_id]["linked_techniques"]
                    )

                    if not already_added:
                        cve_lookup[cve_id]["linked_techniques"].append({
                            "id": technique_id,
                            "name": tech.get("name", ""),
                            "mitre_url": (
                                f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                            ),
                        })

    # 2. Second: enrich from ai_plan.allowed_techniques if available
    for tech in (ai_plan or {}).get("allowed_techniques", []):
        technique_id = tech.get("id") or tech.get("technique_id")
        technique_name = tech.get("name") or tech.get("technique_name", "")
        mitre_url = tech.get("mitre_url", "")

        for cve in tech.get("linked_cves", []) or []:
            cve_id = cve.get("id")
            if not cve_id:
                continue

            if cve_id not in cve_lookup:
                nvd = cve.get("nvd", {}) or {}
                cvss = nvd.get("cvss", {}) or {}
                mapped_findings = cve.get("mapped_findings", [])
                first_finding = mapped_findings[0] if mapped_findings else {}

                cve_lookup[cve_id] = {
                    "cve_id": cve_id,
                    "severity": (
                        cvss.get("severity")
                        or first_finding.get("severity")
                        or "Unknown"
                    ),
                    "confidence": "Official CVE linked",
                    "service_port": f"{first_finding.get('service', 'Unknown')}/{first_finding.get('port', 'Unknown')}",
                    "description": (
                        nvd.get("description")
                        or first_finding.get("description")
                        or first_finding.get("title")
                        or "No CVE description available."
                    ),
                    "official_cve_url": _official_cve_url(cve_id),
                    "nvd_url": nvd.get(
                        "nvd_url",
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    ),
                    "linked_techniques": [],
                }

            if technique_id:
                already_added = any(
                    item.get("id") == technique_id
                    for item in cve_lookup[cve_id]["linked_techniques"]
                )

                if not already_added:
                    cve_lookup[cve_id]["linked_techniques"].append({
                        "id": technique_id,
                        "name": technique_name,
                        "mitre_url": mitre_url,
                    })

    return list(cve_lookup.values())
