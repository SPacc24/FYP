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


def _technique_id_from_mapping_item(item) -> str:
    if not isinstance(item, dict):
        return ""
    return str(item.get("id") or item.get("technique_id") or "").strip()


def _mapped_technique_ids(mapping_results: dict) -> set[str]:
    if not isinstance(mapping_results, dict):
        return set()
    return {
        technique_id
        for technique_id in (
            _technique_id_from_mapping_item(item)
            for item in mapping_results.get("recommended_techniques", [])
        )
        if technique_id
    }


def _normalise_selected_techniques(value) -> list[str]:
    if not isinstance(value, list):
        return []
    selected = []
    for item in value:
        technique_id = str(item or "").strip()
        if technique_id and technique_id not in selected:
            selected.append(technique_id)
    return selected


def _allowed_technique_ids_for_mode(
    mode: str,
    mapping_results: dict,
    ai_plan: dict,
) -> set[str]:
    mapped_ids = _mapped_technique_ids(mapping_results)
    if mode == "auto":
        ai_selected_ids = {
            str(technique_id).strip()
            for technique_id in ai_plan.get("selected_technique_ids", [])
            if str(technique_id or "").strip()
        }
        return ai_selected_ids & mapped_ids
    return mapped_ids


def _as_list(value) -> list:
    return value if isinstance(value, list) else []

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
        log.warning(f"Operational risk calculation unavailable: {e}")
        return {
            "score": None,
            "label": "Unavailable",
            "colour": "grey",
            "badge": "unavailable",
            "status": "calculation_unavailable",
            "error": str(e),
        }


def _load_current_scan_results():
    """
    Prefer the persisted normalised scan package because it contains
    web_inventory and the other post-Nmap evidence. Fall back to the raw Nmap
    XML only when no stored result package is available.
    """
    scan_id = session.get("scan_id")
    data = scan_store.load(scan_id) if scan_id else None
    results = (data or {}).get("results") or {}

    if results:
        return _stored_results_to_parsed_results(results, data or {})

    output_file = session.get("scan_output_file", "")
    if not output_file:
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
    mapping = data.get("mapping") or {}
    if (
        isinstance(mapping, dict)
        and mapping.get("cve_source_of_truth") == "scanner_official_index"
        and mapping.get("cve_contract_version") == "scanner-canonical-v4"
    ):
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


def _active_attack_advice() -> dict:
    data = _active_scan_record()
    advice = data.get("attack_advice") or session.get("attack_advice") or {}
    return advice if isinstance(advice, dict) else {}


def _active_metasploit_results() -> dict:
    data = _active_scan_record()
    results = data.get("metasploit_results") or session.get("metasploit_results") or {}
    return results if isinstance(results, dict) else {}


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

    mapping_results = active.get("mapping") or {}
    if not (
        isinstance(mapping_results, dict)
        and mapping_results.get("cve_source_of_truth") == "scanner_official_index"
        and mapping_results.get("cve_contract_version") == "scanner-canonical-v4"
    ):
        mapping_results = {}
    operation_results = active.get("operation_results") or _active_operation_results()
    validation_results = active.get("validation_results") or _active_validation_results()
    pivot_results = active.get("pivot_assessment") or {}
    attack_advice = active.get("attack_advice") or _active_attack_advice()
    metasploit_results = active.get("metasploit_results") or _active_metasploit_results()
    if isinstance(validation_results, dict) and attack_advice:
        validation_results = {
            **validation_results,
            "attack_advice": attack_advice,
        }
    if isinstance(validation_results, dict) and metasploit_results:
        validation_results = {
            **validation_results,
            "metasploit_results": metasploit_results,
        }
    risk = {}
    remediations = []

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
        pivot=pivot_results,
    )

    return {
        "scan": scan,
        "mapping": mapping_results,
        "operation": operation_results,
        "validation": validation_results,
        "pivot": pivot_results,
        "attack_advice": attack_advice,
        "metasploit_results": metasploit_results,
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
    if not (
        isinstance(mapping_results, dict)
        and mapping_results.get("cve_source_of_truth") == "scanner_official_index"
        and mapping_results.get("cve_contract_version") == "scanner-canonical-v4"
    ):
        try:
            from scanners.enumerator import _canonicalise_downstream_mapping
            mapping_results = map_vulnerabilities(parsed_results)
            mapping_results = _canonicalise_downstream_mapping(
                mapping_results,
                results.get("cve_matches") or [],
                results.get("relevant_cve_information") or [],
            )
            data["mapping"] = mapping_results
            data["ai_plan"] = {}
            data["attack_plan"] = {}
            changed = True
        except Exception:
            log.exception("Could not build vulnerability mapping for stored scan")
            mapping_results = mapping_results if isinstance(mapping_results, dict) else {}

    mode = data.get("technique_mode") or session.get("technique_mode", "hybrid")

    ai_plan = data.get("ai_plan")
    if not isinstance(ai_plan, dict) or not ai_plan.get("selected_technique_ids"):
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
    if risk:
        data["risk"] = {}
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
    active_scan = _active_scan_record()
    parsed_results = _load_current_scan_results() or {}

    selected = (
        active_scan.get("selected_internal_target")
        or session.get("selected_internal_target")
    )

    external_target = (
        active_scan.get("external_target")
        or active_scan.get("target")
        or session.get("external_target_ip")
        or session.get("target_ip")
        or parsed_results.get("target_ip")
        or "Unknown"
    )

    if isinstance(selected, dict) and selected.get("ip"):
        target = selected["ip"]
        os_name = selected.get("os") or "Unknown"
        source = "pivot_scan"
    else:
        target = external_target
        os_name = (
            parsed_results.get("os")
            or session.get("target_os")
            or "Unknown"
        )
        source = "external_scan"

    return {
        "target": target,
        "os": os_name,
        "platform": (
            "windows"
            if "win" in str(os_name).lower()
            else "linux"
        ),
        "source": source,
        "external_target": external_target,
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


def _build_detected_cve_rows(ai_plan=None, mapping_result=None, results=None):
    # Completed scanner runs have a canonical CVE contract produced only from
    # official index records and captured service evidence. Do not reconstruct
    # those rows from downstream mapping or AI content.
    if isinstance(results, dict) and (
        "canonical_cve_contract" in results or "cve_matches" in results
    ):
        rows = []
        # Primary vulnerability mapping contains validated applicability only.
        # Analyst-review records are rendered in their own report section and
        # never flow into downstream risk, ATT&CK, AI or execution consumers.
        canonical_rows = list(results.get("cve_matches") or [])
        for match in canonical_rows:
            cve_id = str(match.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            ports = match.get("observed_ports") or []
            if not ports:
                port = match.get("port")
                protocol = match.get("protocol")
                ports = [f"{port}/{protocol}"] if port else []
            service = str(match.get("service") or "Unidentified service")
            endpoint = ", ".join(str(value) for value in ports if value)
            rows.append({
                "cve_id": cve_id,
                "port": endpoint or "Port unavailable",
                "service": service,
                "product": str(match.get("product") or ""),
                "version": str(match.get("version") or ""),
                "severity": match.get("source_cvss_severity") or "Unavailable",
                "cvss_score": match.get("source_cvss_score"),
                "cvss_vector": match.get("source_cvss_vector") or "",
                "cvss_version": match.get("source_cvss_version") or (results.get("vulnerability_scoring") or {}).get("version") or "",
                "cvss_source": match.get("source_cvss_source") or "",
                "cvss_metric_integrity": match.get("source_cvss_metric_integrity") or "",
                "cvss_record_url": match.get("source_cvss_record_url") or "",
                "cvss_record_last_modified": match.get("source_cvss_record_last_modified") or "",
                "cvss_status": match.get("cvss_status") or ("published" if match.get("source_cvss_score") is not None else "not_provided_for_selected_version"),
                "confidence": match.get("classification") or "Evidence-linked",
                "applicability_reason": match.get("classification_reason") or "",
                "match_basis": match.get("match_basis") or "",
                "service_port": f"{service}/{endpoint or 'port unavailable'}",
                "description": match.get("vulnerability") or "No official description available.",
                "official_cve_url": _official_cve_url(cve_id),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "linked_techniques": [],
            })
        return rows

    # Legacy mapping and AI objects are not authoritative vulnerability sources.
    # Without a canonical scanner result, emit no CVE rows.
    return []
