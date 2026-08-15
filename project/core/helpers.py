# HELPERS
import logging
import socket
import re

from flask import session

from config import Config

from ai.technique_planner import generate_ai_technique_plan
from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from reports.report_generator import build_report_summary
from scanners.nmap_parser import parse_nmap_xml
from storage import scan_store

from automation.mission_service import get_mission_service
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
        log.warning(f"Risk score fallback triggered: {e}")
        return {
            "score": 50,
            "label": "Medium",
            "colour": "orange",
             "badge": "warning",
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
    """Adapt persisted scanner results without converting hypotheses into facts."""
    scan_record = scan_record or {}
    services = results.get("service_inventory") or []
    workflow = results.get("workflow") or scan_record.get("workflow") or {}

    assessment_target = (
        workflow.get("assessment_target")
        or results.get("target_input")
        or scan_record.get("target")
        or scan_record.get("target_ip")
        or "Unknown"
    )

    established_os = "Unresolved"
    target_text = str(assessment_target or "")
    target_parts = {part.strip() for part in target_text.split(",") if part.strip()}
    for host_row in results.get("host_identity_inventory") or []:
        if not isinstance(host_row, dict):
            continue
        host = str(host_row.get("host") or "")
        if target_parts and host not in target_parts:
            continue
        if str(host_row.get("identity_state") or "") != "established":
            continue
        best = host_row.get("best") or {}
        product = str(best.get("product") or best.get("name") or best.get("family") or "").strip()
        version = str(best.get("build") or best.get("version") or best.get("release") or "").strip()
        if product:
            established_os = product + (f" {version}" if version and version not in product else "")
            break

    hosts = []
    grouped: dict[str, list[dict]] = {}
    for service in services:
        host = str(service.get("host") or assessment_target or "Unknown")
        grouped.setdefault(host, []).append({
            "port": service.get("port"),
            "protocol": service.get("protocol", "tcp"),
            "state": service.get("state", "open"),
            "service": service.get("service", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "extrainfo": service.get("extrainfo", service.get("extra", "")),
            "cpe": service.get("cpe", []),
            "scripts": service.get("scripts", []),
            "service_attributes": service.get("service_attributes", {}),
            "transport_security": service.get("transport_security", ""),
        })

    for host, port_findings in grouped.items():
        hosts.append({
            "address": {"primary": host},
            "os": {"name": established_os if host in target_parts else "Unresolved"},
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
            "extrainfo": service.get("extrainfo", service.get("extra", "")),
            "service_attributes": service.get("service_attributes", {}),
            "transport_security": service.get("transport_security", ""),
        })

    return {
        **results,
        "target_ip": assessment_target,
        "os": established_os,
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


def _fallback_remediations(parsed_results: dict, mapping_results: dict) -> list[dict]:
    """Create useful remediation guidance even when CALDERA has not run."""
    rows: list[dict] = []
    seen: set[tuple] = set()
    cves = parsed_results.get("cve_matches") or []
    for finding in cves:
        if not isinstance(finding, dict):
            continue
        host = finding.get("host") or parsed_results.get("target_ip") or "Unknown"
        port = finding.get("port") or "N/A"
        cve_id = finding.get("cve_id") or "Vulnerability finding"
        key = (host, str(port), cve_id)
        if key in seen:
            continue
        seen.add(key)
        fix = finding.get("remediation_direction") or (
            f"Apply the vendor security update for {cve_id}, verify the affected service version, "
            "and rerun the safe validation check."
        )
        rows.append({
            "type": "vulnerability",
            "severity": finding.get("source_cvss_severity") or finding.get("severity") or "High",
            "title": cve_id,
            "affected_host": host,
            "affected_port": port,
            "summary": finding.get("vulnerability") or finding.get("description") or "Review and remediate the matched vulnerability.",
            "fixes": [fix],
        })

    for port in parsed_results.get("ports") or []:
        if not isinstance(port, dict) or str(port.get("state", "")).lower() != "open":
            continue
        service = str(port.get("service") or "unknown")
        number = port.get("port") or "N/A"
        key = ("service", str(number), service)
        if key in seen:
            continue
        seen.add(key)
        fixes = ["Restrict access to authorised management hosts and network segments."]
        lowered = service.lower()
        if lowered in {"microsoft-ds", "netbios-ssn", "smb"}:
            fixes = ["Disable SMBv1 where supported, update the device firmware or SMB implementation, require SMB signing where supported, and restrict ports 139/445 to trusted network segments."]
        elif lowered in {"msrpc", "epmap"}:
            fixes = ["Restrict RPC exposure to trusted administration networks and apply supported operating-system security updates."]
        rows.append({
            "type": "vulnerability",
            "severity": "Medium",
            "title": f"Exposed {service} service",
            "affected_host": parsed_results.get("target_ip") or "Unknown",
            "affected_port": number,
            "summary": f"{service} is reachable on port {number} and should be reviewed against business need.",
            "fixes": fixes,
        })
    return rows[:20]


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
    pivot_results = active.get("pivot_assessment") or session.get("pivot_assessment", {})
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
    risk = active.get("risk") or session.get("risk_score", {})
    remediations = active.get("remediations") or session.get("remediations", [])
    if not remediations:
        remediations = _fallback_remediations(parsed_results, mapping_results if isinstance(mapping_results, dict) else {})

    try:
        missions = get_mission_service().list_missions(limit=10)
    except Exception:
        log.warning("Could not load missions for report context", exc_info=True)
        missions = []

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
        pivot=pivot_results,
        results=parsed_results,
    )

    return {
        "scan": scan,
        "results": parsed_results,
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


def _normalise_target_os(os_value) -> dict:
    """
    Convert Nmap/pivot OS evidence into a consistent deployment platform.

    Returns:
        {
            "name": original human-readable OS name,
            "platform": windows | windows_legacy | linux | darwin | unknown,
            "confidence": optional accuracy value
        }
    """
    confidence = ""

    if isinstance(os_value, dict):
        os_name = str(
            os_value.get("name")
            or os_value.get("family")
            or os_value.get("os")
            or "Unknown"
        ).strip()

        confidence = str(
            os_value.get("accuracy")
            or os_value.get("confidence")
            or ""
        ).strip()
    else:
        os_name = str(os_value or "Unknown").strip()

    lowered = os_name.lower()

    if not lowered or lowered in {"unknown", "none", "n/a"}:
        platform = "unknown"

    elif any(token in lowered for token in (
        "windows xp",
        "windows 2000",
        "windows server 2003",
        "windows vista",
    )):
        platform = "windows_legacy"

    elif "windows" in lowered or "microsoft" in lowered:
        platform = "windows"

    elif any(token in lowered for token in (
        "linux",
        "ubuntu",
        "debian",
        "kali",
        "centos",
        "red hat",
        "fedora",
        "arch",
    )):
        platform = "linux"

    elif any(token in lowered for token in (
        "mac os",
        "macos",
        "darwin",
        "os x",
    )):
        platform = "darwin"

    else:
        platform = "unknown"

    return {
        "name": os_name or "Unknown",
        "platform": platform,
        "confidence": confidence,
    }


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
        raw_os = selected.get("os") or "Unknown"
        source = "pivot_scan"
    else:
        target = external_target
        raw_os = (
            parsed_results.get("os")
            or session.get("target_os")
            or "Unknown"
        )
        source = "external_scan"

        # Fall back to the first host's OS evidence.
        if (
            raw_os in {"Unknown", "", None}
            and isinstance(parsed_results.get("hosts"), list)
            and parsed_results["hosts"]
        ):
            raw_os = parsed_results["hosts"][0].get("os") or "Unknown"

    os_context = _normalise_target_os(raw_os)

    return {
        "target": target,
        "os": os_context["name"],
        "os_confidence": os_context["confidence"],
        "platform": os_context["platform"],
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


def _build_detected_cve_rows(ai_plan=None, mapping_result=None, parsed_results=None):
    """Build the user-facing CVE/CVSS review from scanner-owned evidence.

    Mapping/AI data may contribute linked ATT&CK context, but CVSS metadata and
    match evidence are taken from canonical scanner CVE rows whenever present.
    """
    cve_lookup: dict[str, dict] = {}

    def humanise_match_basis(basis: str, fallback: str = "") -> str:
        raw = str(basis or "").strip()
        if not raw:
            return fallback or "Published affected data matched the observed service evidence."
        name, _, detail = raw.partition(":")
        labels = {
            "structured_exact_version": "Observed version exactly matches a published affected version",
            "structured_affected_range": "Observed version falls within a published affected range using the record's declared version scheme",
            "structured_range_lower_endpoint": "Observed version exactly matches the published lower endpoint of an affected range",
            "structured_range_inclusive_upper_endpoint": "Observed version exactly matches the published inclusive upper endpoint of an affected range",
            "structured_default_status_affected": "The matched product record explicitly defines otherwise-unlisted versions as affected",
            "exact_application_cpe": "Observed application CPE and version exactly match a published affected application CPE",
            "exact_os_cpe": "Observed operating-system CPE and version exactly match a published affected OS CPE",
            "exact_structured_version": "Exact observed version is explicitly listed as affected",
            "exact_cpe_match": "Observed application CPE matches a published affected CPE",
            "exact_observed_version_in_record_text": "Observed version is explicitly referenced in the CVE record",
            "structured_same_product_range": "Observed version falls within a published affected version range",
            "structured_min_version": "Observed version matches a published affected branch or version range",
            "named_branch_before": "Observed version is earlier than the published upper bound in the matching product branch",
            "explicit_same_product_text_range": "Observed version falls within an explicit affected range in the CVE record",
            "wildcard_version_match": "The CVE record marks the matched product branch as affected without a narrower version bound",
        }
        text = labels.get(name, raw.replace("_", " ").strip().capitalize())
        if detail:
            text += f": {detail}"
        return text

    def ensure(cve_id: str) -> dict:
        row = cve_lookup.setdefault(cve_id, {
            "cve_id": cve_id,
            "severity": "Unknown",
            "classification": "Candidate CVE",
            "candidate_status": "candidate",
            "candidate_basis": "",
            "candidate_evidence_note": "",
            "affected_services": [],
            "service_port": "Unknown",
            "description": "No CVE description available.",
            "match_evidence": "Published CVE reference linked to observed evidence.",
            "raw_match_basis": "",
            "match_reason": "",
            "product_match_basis": "",
            "cvss_metrics": {},
            "cve_publisher": "CVE Program CNA",
            "cve_publisher_id": "",
            "observed_hosts": [],
            "observed_products": [],
            "observed_versions": [],
            "observed_endpoints": [],
            "evidence_sources": [],
            "evidence_references": [],
            "match_scopes": [],
            "affected_assets": [],
            "patch_states": [],
            "applicability_state": "candidate_unvalidated",
            "patch_state_status": "unknown",
            "validation_state": "not_performed",
            "identity_qualities": [],
            "matched_product_tokens": [],
            "matched_version_tokens": [],
            "affected_vendors": [],
            "affected_products": [],
            "affected_versions": [],
            "affected_entries": [],
            "affected_cpes": [],
            "applicability_context": {},
            "references": [],
            "official_cve_url": _official_cve_url(cve_id),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "nvd_cvss_enrichment": {},
            "linked_techniques": [],
            "candidate_sources": [],
            "source_agreement": "",
            "nvd_applicability": {},
        })
        return row

    def add_service(row: dict, service: str, product: str, version: str, port, protocol: str = "tcp") -> None:
        identity = " ".join(x for x in (str(product or "").strip(), str(version or "").strip()) if x).strip()
        if not identity:
            identity = str(service or "Unknown")
        if str(port).lower() == "host" or str(protocol).lower() == "host":
            endpoint = "host operating system"
        else:
            endpoint = f"{port}/{protocol}" if port not in (None, "") else "port unknown"
        label = f"{identity} ({endpoint})"
        if label not in row["affected_services"]:
            row["affected_services"].append(label)
        row["service_port"] = ", ".join(row["affected_services"])

    def humanise_publisher(row: dict) -> str:
        raw = str(row.get("cve_publisher") or "CVE Program CNA").strip()
        raw_norm = re.sub(r"[^a-z0-9]+", "", raw.lower())
        vendors = [str(v).strip() for v in row.get("affected_vendors") or [] if str(v).strip()]
        for vendor in vendors:
            vendor_norm = re.sub(r"[^a-z0-9]+", "", vendor.lower())
            if raw_norm and (raw_norm == vendor_norm or raw_norm in vendor_norm or vendor_norm in raw_norm):
                return vendor
        return raw

    def humanise_metric_source(metric: dict, row: dict) -> str:
        if not metric:
            return ""
        provider_name = str(metric.get("cvss_provider_name") or "").strip()
        role = str(metric.get("cvss_provider_role") or "").strip().upper()
        raw = str(metric.get("cvss_source") or "").strip()
        raw_lower = raw.lower()
        if provider_name:
            label = provider_name
        elif raw_lower == "nvd" or "nist.gov" in raw_lower:
            label = "NVD"
        elif raw and raw == str(row.get("cve_publisher_id") or ""):
            label = humanise_publisher(row)
        elif re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", raw):
            label = f"{role} provider" if role else "Published provider"
        else:
            label = raw or (f"{role} provider" if role else "Published source")
        if role and role not in {"NVD"} and role.lower() not in label.lower() and not label.lower().endswith("provider"):
            label = f"{label} ({role})"
        return label

    def flatten_metrics(row: dict) -> None:
        metrics = row.get("cvss_metrics") or {}
        for version, prefix in (("3.1", "cvss_31"), ("4.0", "cvss_40")):
            metric = metrics.get(version) if isinstance(metrics, dict) else None
            metric = metric if isinstance(metric, dict) else {}
            row[f"{prefix}_score"] = metric.get("cvss_score")
            row[f"{prefix}_severity"] = metric.get("cvss_severity") or "Not published"
            row[f"{prefix}_vector"] = metric.get("cvss_vector") or ""
            row[f"{prefix}_source_raw"] = metric.get("cvss_source") or ""
            row[f"{prefix}_source"] = humanise_metric_source(metric, row)
            row[f"{prefix}_verified"] = bool(metric.get("cvss_verified"))
            row[f"{prefix}_verification"] = metric.get("cvss_verification") or (
                "Not published" if not metric else "Published metric retained"
            )

        available = []
        for version in ("3.1", "4.0"):
            metric = metrics.get(version, {}) if isinstance(metrics, dict) else {}
            try:
                available.append((float(metric.get("cvss_score")), str(metric.get("cvss_severity") or "Unknown")))
            except (TypeError, ValueError):
                pass
        if available:
            row["severity"] = max(available, key=lambda item: item[0])[1].title()

        publishers = []
        verified = []
        for version in ("3.1", "4.0"):
            metric = metrics.get(version, {}) if isinstance(metrics, dict) else {}
            if not metric:
                continue
            source = humanise_metric_source(metric, row) or "Published source"
            publisher = f"CVSS {version}: {source}"
            if publisher not in publishers:
                publishers.append(publisher)
            if metric.get("cvss_verified"):
                verified.append(f"CVSS {version}: vector recomputed, matches")
            else:
                verified.append(f"CVSS {version}: not independently verified")
        # Table 1 publication provenance belongs to the CVE record/CNA, not
        # to the CVSS metric.  CVSS publisher/source stays separate for Table 2.
        row["published_by"] = humanise_publisher(row)
        row["score_sources"] = "; ".join(publishers) if publishers else "Not published"
        row["verified_by"] = "; ".join(verified) if verified else "Not published"

    # Mapping contributes technique relationships and a fallback service label.
    for vuln in (mapping_result or {}).get("vulnerabilities", []):
        for cve_id in vuln.get("cve_ids", []) or []:
            if not cve_id:
                continue
            row = ensure(str(cve_id))
            add_service(row, vuln.get("service", "Unknown"), "", "", vuln.get("port"), vuln.get("protocol", "tcp"))
            for match in vuln.get("cve_matches", []) or []:
                if str(match.get("cve_id") or "") == str(cve_id) and match.get("cvss_metrics"):
                    row["cvss_metrics"] = match.get("cvss_metrics") or {}
                    raw_basis = str(match.get("match_basis") or "")
                    row["raw_match_basis"] = raw_basis or row.get("raw_match_basis", "")
                    row["match_evidence"] = humanise_match_basis(raw_basis, row["match_evidence"])
            for tech in vuln.get("attack_techniques", []) or []:
                technique_id = tech.get("id")
                if technique_id and not any(item.get("id") == technique_id for item in row["linked_techniques"]):
                    row["linked_techniques"].append({
                        "id": technique_id,
                        "name": tech.get("name", ""),
                        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    })

    # Scanner results are canonical for CVE identity, applicability evidence and CVSS.
    parsed_results = parsed_results or {}
    scanner_rows = list(parsed_results.get("cve_review_candidates") or parsed_results.get("cve_matches") or [])
    for finding in scanner_rows:
        if not isinstance(finding, dict):
            continue
        cve_id = str(finding.get("cve_id") or "").strip()
        if not cve_id:
            continue
        row = ensure(cve_id)
        row["classification"] = "Candidate CVE"
        row["candidate_status"] = str(finding.get("candidate_status") or "candidate")
        row["candidate_basis"] = str(finding.get("candidate_basis") or row.get("candidate_basis") or "")
        row["candidate_evidence_note"] = str(finding.get("candidate_evidence_note") or row.get("candidate_evidence_note") or "")
        row["description"] = finding.get("vulnerability") or finding.get("description") or row["description"]
        raw_basis = str(finding.get("match_basis") or "").strip()
        row["raw_match_basis"] = raw_basis or row.get("raw_match_basis", "")
        row["match_evidence"] = finding.get("display_match_reason") or humanise_match_basis(
            raw_basis,
            finding.get("classification_reason") or finding.get("match_reason") or row["match_evidence"],
        )
        row["match_reason"] = finding.get("classification_reason") or finding.get("match_reason") or row.get("match_reason", "")
        row["product_match_basis"] = finding.get("product_match_basis") or row.get("product_match_basis", "")
        row["cvss_metrics"] = finding.get("effective_cvss_metrics") or finding.get("source_cvss_metrics") or finding.get("cvss_metrics") or row["cvss_metrics"]
        row["cve_program_cvss_metrics"] = finding.get("cve_program_cvss_metrics") or finding.get("source_cvss_metrics") or {}
        row["nvd_cvss_metrics"] = finding.get("nvd_cvss_metrics") or {}
        row["nvd_cvss_enrichment"] = finding.get("nvd_cvss_enrichment") or row.get("nvd_cvss_enrichment") or {}
        row["applicability_context"] = finding.get("applicability_context") or row.get("applicability_context") or {}
        row["cve_publisher"] = finding.get("cve_publisher") or row.get("cve_publisher") or "CVE Program CNA"
        row["cve_publisher_id"] = finding.get("cve_publisher_id") or row.get("cve_publisher_id", "")
        row["applicability_state"] = str(finding.get("applicability_state") or "candidate_unvalidated")
        row["patch_state_status"] = str(finding.get("patch_state_status") or "unknown")
        row["validation_state"] = str(finding.get("validation_state") or "not_performed")
        row["source_agreement"] = str(finding.get("source_agreement") or row.get("source_agreement") or "")
        row["nvd_applicability"] = finding.get("nvd_applicability") or row.get("nvd_applicability") or {}
        for source in finding.get("candidate_sources") or [finding.get("match_source")]:
            source = str(source or "").strip()
            if source and source not in row["candidate_sources"]:
                row["candidate_sources"].append(source)

        for key in ("affected_vendors", "affected_products", "affected_versions", "affected_entries", "affected_cpes", "matched_product_tokens", "matched_version_tokens", "references", "evidence_sources", "evidence_references"):
            values = finding.get(key) or []
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if value not in row[key]:
                    row[key].append(value)

        for key, value in (
            ("match_scopes", str(finding.get("match_scope") or "application_service")),
            ("affected_assets", str(finding.get("affected_asset") or "")),
            ("patch_states", str(finding.get("patch_state") or "")),
            ("identity_qualities", str(finding.get("identity_quality") or "")),
        ):
            if value and value not in row[key]:
                row[key].append(value)

        host = str(finding.get("host") or "").strip()
        product = str(finding.get("product") or "").strip()
        version = str(finding.get("version") or "").strip()
        port = finding.get("port")
        protocol = str(finding.get("protocol") or "tcp")
        endpoint = f"{port}/{protocol}" if port not in (None, "") else ""
        for key, value in (("observed_hosts", host), ("observed_products", product), ("observed_versions", version), ("observed_endpoints", endpoint)):
            if value and value not in row[key]:
                row[key].append(value)

        add_service(
            row,
            finding.get("service", "Unknown"),
            finding.get("product", ""),
            finding.get("version", ""),
            finding.get("port"),
            finding.get("protocol", "tcp"),
        )

    # AI may enrich linked technique context only; it must not invent CVSS data.
    for tech in (ai_plan or {}).get("allowed_techniques", []):
        technique_id = tech.get("id") or tech.get("technique_id")
        technique_name = tech.get("name") or tech.get("technique_name", "")
        mitre_url = tech.get("mitre_url", "")
        for cve in tech.get("linked_cves", []) or []:
            cve_id = str(cve.get("id") or "").strip()
            if not cve_id or cve_id not in cve_lookup:
                continue
            row = cve_lookup[cve_id]
            if technique_id and not any(item.get("id") == technique_id for item in row["linked_techniques"]):
                row["linked_techniques"].append({"id": technique_id, "name": technique_name, "mitre_url": mitre_url})

    for row in cve_lookup.values():
        flatten_metrics(row)

    def sort_key(row: dict):
        scores = [row.get("cvss_31_score"), row.get("cvss_40_score")]
        numeric = []
        for score in scores:
            try:
                numeric.append(float(score))
            except (TypeError, ValueError):
                pass
        return (-max(numeric) if numeric else 1.0, row.get("cve_id", ""))

    return sorted(cve_lookup.values(), key=sort_key)
