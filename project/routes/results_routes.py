import os
import copy
import re

from flask import (
    jsonify,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from config import Config
from caldera.api_client import CalderaClient

from scanners.mitre_cve import status as mitre_status
from scanners.nmap_parser import parse_nmap_xml
from storage import scan_store

from core.helpers import (
    _active_mapping_results,
    _build_active_report_context,
    _build_detected_cve_rows,
    _ensure_scan_analysis,
    _safe_risk_calculate,
    _stored_results_to_parsed_results,
)

from core.services import db



def _sanitise_client_evidence_paths(value):
    """Hide local project storage prefixes on client-facing appendix pages."""
    if not isinstance(value, str):
        return value
    pattern = re.compile(r'/(?:[^\s"\']+/)*storage/(?:scans|results)/([^\s"\']+)')
    return pattern.sub(lambda match: f'evidence/{os.path.basename(match.group(1))}', value)


def _client_safe_scan_record(data):
    safe = copy.deepcopy(data or {})
    for entry in safe.get('command_log') or []:
        if not isinstance(entry, dict):
            continue
        for key in ('command', 'output', 'output_file', 'result'):
            if key in entry:
                entry[key] = _sanitise_client_evidence_paths(entry.get(key))
    return safe




def _append_scan_cve_rows(rows, parsed_results):
    """Expose only scanner-owned, evidence-backed CVE matches."""
    output = list(rows or [])
    seen = {
        (
            str(item.get("host") or ""),
            str(item.get("service_port") or ""),
            str(item.get("cve_id") or ""),
        )
        for item in output
        if isinstance(item, dict)
    }
    for item in parsed_results.get("cve_matches") or []:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cve_id") or "").strip()
        service_port = f"{item.get('service', 'Unknown')}/{item.get('port', 'host')}"
        key = (str(item.get("host") or ""), service_port, cve_id)
        if not cve_id or key in seen:
            continue
        seen.add(key)
        severity = (
            item.get("source_cvss_severity")
            or item.get("cvss_severity")
            or item.get("severity")
            or "Unknown"
        )
        output.append({
            "cve_id": cve_id,
            "host": item.get("host"),
            "severity": severity,
            "cvss_score": item.get("source_cvss_score")
            if item.get("source_cvss_score") is not None
            else item.get("cvss_score"),
            "cvss_version": item.get("source_cvss_version")
            or item.get("cvss_version"),
            "cvss_vector": item.get("source_cvss_vector")
            or item.get("cvss_vector"),
            "match_basis": item.get("match_basis") or "",
            "service_port": service_port,
            "description": item.get("vulnerability")
            or item.get("description")
            or "Structured CVE record linked to observed identity evidence.",
            "official_cve_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "linked_techniques": [],
        })
    return output


def _fallback_result_remediations(parsed_results):
    text = str(parsed_results or {}).lower()
    fixes = []
    if any(x in text for x in ("microsoft-ds", "netbios-ssn", "smb", "445", "139")):
        fixes.extend([
            "Disable SMBv1 where possible and apply supported Microsoft security updates.",
            "Restrict ports 139 and 445 to trusted network segments.",
            "Require SMB signing and strong unique credentials.",
        ])
    if any(x in text for x in ("ms-wbt-server", "rdp", "3389")):
        fixes.append("Restrict RDP to approved management paths and enable NLA/MFA where supported.")
    if any(x in text for x in ("winrm", "5985", "wsman")):
        fixes.append("Restrict WinRM to administration hosts and prefer HTTPS transport.")
    if "windows xp" in text:
        fixes.insert(0, "Replace the unsupported Windows XP system with a supported operating system.")
    fixes.append("Re-test after remediation and compare against the current scan baseline.")
    return [{"type":"baseline","technique_id":"HARDENING","technique_name":"Service hardening","tactic":"remediation","summary":"Generated from current scan evidence.","fixes":list(dict.fromkeys(fixes))}]


def register_routes(app):
    @app.route("/results")
    def results():
        scan_id = session.get("scan_id")

        if scan_id:
            data = scan_store.load(scan_id)

            if data:
                data = _ensure_scan_analysis(data)

                ai_plan = data.get("ai_plan") or {}
                mapping_result = data.get("mapping") or {}

                parsed_for_view = _stored_results_to_parsed_results(data.get("results") or {}, data)
                detected_cves = _build_detected_cve_rows(ai_plan, mapping_result, parsed_for_view)

                return render_template(
                    "results.html",
                    scan=data,
                    results=parsed_for_view,
                    mapping=data.get("mapping") or {},
                    ai_plan=ai_plan,
                    detected_cves=detected_cves,
                    selected_mode=data.get("technique_mode") or session.get("technique_mode", "hybrid"),
                    attack_plan=data.get("attack_plan"),
                    validation_results=data.get("validation_results"),
                    operation_results=data.get("operation_results"),
                    risk=data.get("risk"),
                    remediations=data.get("remediations") or _fallback_result_remediations(parsed_for_view),
                )

        scan = {
            "target_ip": session.get("target_ip", ""),
            "port_range": session.get("port_range", "1-1024"),
            "output_file": session.get("scan_output_file", ""),
            "scan_id": session.get("scan_id", ""),
        }

        parsed_results = None
        mapping_results = _active_mapping_results() or session.get("mapping_results", [])
        risk = session.get("risk_score")

        if scan["output_file"]:
            try:
                parsed_results = parse_nmap_xml(scan["output_file"])
                scan["os"] = parsed_results.get("os", "Unknown")
                scan["ports"] = parsed_results.get("ports", [])

            except Exception:
                scan["os"] = "Unknown"
                scan["ports"] = []

        else:
            scan["os"] = "Unknown"
            scan["ports"] = []

        if not risk and isinstance(mapping_results, dict):
            risk = _safe_risk_calculate(
                mapping_results.get("vulnerabilities", []),
                {}
            )
            session["risk_score"] = risk

        ai_plan = session.get("ai_plan", {})

        detected_cves = _build_detected_cve_rows(ai_plan, mapping_results, parsed_results or {})

        return render_template(
            "results.html",
            scan=scan,
            results=parsed_results or {
                "os": scan["os"],
                "ports": scan["ports"],
            },
            mapping=mapping_results,
            ai_plan=ai_plan,
            detected_cves=detected_cves,
            selected_mode=session.get("technique_mode", "hybrid"),
            attack_plan=session.get("attack_plan"),
            validation_results=session.get("validation_results"),
            operation_results=session.get("operation_results"),
            risk=risk,
            remediations=session.get("remediations", []),
        )

    @app.route("/technical-appendix")
    def technical_appendix():
        scan_id = session.get("scan_id")

        if not scan_id:
            return render_template(
                "error.html",
                error_message="Technical appendix requires an active scan."
            ), 404

        data = scan_store.load(scan_id) or {}

        if not data:
            return render_template(
                "error.html",
                error_message="Technical appendix data not found."
            ), 404

        results = data.get("results") or {}
        mapping_results = data.get("mapping") or session.get("mapping_results", [])

        data["scan_id"] = scan_id
        safe_scan = _client_safe_scan_record(data)

        return render_template(
            "technical_appendix.html",
            scan=safe_scan,
            results=results,
            mapping=mapping_results,
            mitre_status=mitre_status(),
            caldera_status=CalderaClient(
                Config.CALDERA_URL,
                Config.CALDERA_KEY
            ).status(),
        )

    @app.route("/generate_report", methods=["POST"])
    def generate_report():
        context = _build_active_report_context()

        return jsonify({
            "ok": True,
            "report": context["report"],
            "pivot": context["pivot"],
            "report_url": url_for("report_view"),
            "download_url": url_for("export_report"),
        })

    @app.route("/report/view", methods=["GET"])
    def report_view():
        context = _build_active_report_context()

        return render_template("report_view.html", **context)

    @app.route("/scan/save", methods=["POST"])
    def save_scan():
        scan_results = request.get_json(silent=True) or {}

        target_ip = session.get("target_ip")
        port_range = session.get("port_range", "1-1024")

        if not target_ip:
            return jsonify({
                "success": False,
                "error": "No target_ip in session"
            }), 400

        scan_id = db.save_scan(target_ip, scan_results, port_range)
        session["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "scan_id": scan_id
        })

    @app.route("/vulnerabilities/save", methods=["POST"])
    def save_vulnerabilities():
        data = request.get_json(silent=True) or {}

        vulns = data.get("vulnerabilities", [])
        scan_id = session.get("scan_id")

        if not scan_id:
            return jsonify({
                "success": False,
                "error": "No scan_id in session"
            }), 400

        db.save_vulnerabilities(scan_id, vulns)
        session["vulnerabilities"] = vulns

        return jsonify({
            "success": True,
            "count": len(vulns)
        })


    @app.route("/report/export/pdf", methods=["GET"])
    def export_report_pdf():
        from reports.report_generator import generate_pdf_report

        context = _build_active_report_context()
        report_path = generate_pdf_report(
            scan_id=session.get("scan_id", ""),
            scan=context["scan"],
            mapping=context["mapping"],
            validation=context["validation"],
            operation=context["operation"],
            risk=context["risk"],
            remediations=context["remediations"],
            pivot=context["pivot"],
            missions=context.get("missions", []),
        )
        mimetype = "application/pdf" if str(report_path).lower().endswith(".pdf") else "text/plain"
        return send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path),
            mimetype=mimetype,
        )

    @app.route("/report/export", methods=["GET"])
    def export_report():
        from reports.report_generator import generate_text_report

        context = _build_active_report_context()

        report_path = generate_text_report(
            scan=context["scan"],
            mapping=context["mapping"],
            operation=context["operation"],
            risk=context["risk"],
            remediations=context["remediations"],
            validation=context["validation"],
            pivot=context["pivot"],
            missions=context.get("missions", []),
        )

        return send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path),
            mimetype="text/plain",
        )
