# app.py - FIXED VERSION
# Main Flask application for vulnerability assessment + attack simulation.

# edited
from ai.technique_planner import generate_ai_technique_plan
from ai.llm_client import ask_llm_text
from ai.safety import SAFE_REFUSAL, is_unsafe_user_request, sanitize_llm_reply
import json
import os
import socket
import threading
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    send_file,
    make_response,
    flash,
)
import logging

from config import Config

from mapping.technique_mapper import map_vulnerabilities
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.coverage_checker import CoverageChecker

from caldera.risk_scorer import RiskScorer
from exploitation.validator import ExploitabilityValidator
from reports.report_generator import build_report_summary
from storage.db import Database
from storage import scan_store
from scanners.enumerator import run_pipeline
from scanners.targets import expand_target_input
from scanners.mitre_cve import status as mitre_status
from scanners.scan_profiles import TOOL_OPTIONS, normalise_scan_options

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = getattr(Config, "SECRET_KEY", "change-me")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

@app.template_filter("status_label")
def status_label(value):
    return scan_store.LABELS.get(str(value), str(value or "Queued"))

@app.template_filter("status_class")
def status_class(value):
    s = str(value or "")
    lowered = s.lower()
    if s in {"queued"}:
        return "queued"
    if s in {"running"}:
        return "running"
    if s in {"success"} or lowered == "completed" or lowered.startswith("completed"):
        return "done"
    if (
        s in {"empty"}
        or "no evidence" in lowered
        or "no web paths" in lowered
        or "not applicable" in lowered
        or "input missing" in lowered
        or "input invalid" in lowered
        or "tool unavailable" in lowered
        or "unavailable" in lowered
        or "disabled" in lowered
    ):
        return "empty"
    if (
        s in {"failed"}
        or "timed out" in lowered
        or "failed" in lowered
        or "incomplete" in lowered
    ):
        return "failed"
    return "queued"

# ---------------------------------------------------
# INIT SERVICES
# ---------------------------------------------------

caldera_client = CalderaClient(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY,
)

operation_manager = OperationManager(caldera_client)
coverage_checker = CoverageChecker(caldera_client)
risk_scorer = RiskScorer()
exploitability_validator = ExploitabilityValidator()

db = Database(
    host=Config.MYSQL_HOST,
    user=Config.MYSQL_USER,
    password=Config.MYSQL_PASS,
    database=Config.MYSQL_DB,
)

try:
    db.init_schema()
except Exception:
    log.exception("Database schema initialization skipped or failed")


# ---------------------------------------------------
# HELPERS
# ---------------------------------------------------

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
        return None
    try:
        return parse_nmap_xml(output_file)
    except Exception:
        log.exception("Could not reload scan results for validation")
        return None


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


# ---------------------------------------------------
# ROUTES
# ---------------------------------------------------
# edited ai route
@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    try:
        data = request.get_json(silent=True) or {}
        user_message = data.get("message", "").strip()

        if not user_message:
            return jsonify({
                "ok": False,
                "reply": "Please enter a question."
            }), 400

        if is_unsafe_user_request(user_message):
            return jsonify({
                "ok": False,
                "reply": SAFE_REFUSAL
            }), 400

        mapping_results = session.get("mapping_results", {})
        ai_plan = session.get("ai_plan", {})
        attack_plan = session.get("attack_plan", {})
        operation_results = session.get("operation_results", {})
        validation_results = session.get("validation_results", {})
        risk_score = session.get("risk_score", {})

        safe_context = {
            "mapping_summary": {
                "severity_counts": mapping_results.get("severity_counts", {}),
                "top_risks": mapping_results.get("top_risks", []),
                "recommended_techniques": [
                    {
                        "id": tech.get("id"),
                        "name": tech.get("name"),
                        "count": tech.get("count"),
                        "max_severity": tech.get("max_severity"),
                        "mitre_url": (
                            f"https://attack.mitre.org/techniques/{tech.get('id').replace('.', '/')}/"
                            if tech.get("id") else ""
                        )
                    }
                    for tech in mapping_results.get("recommended_techniques", [])
                ],
                "attack_chain": mapping_results.get("attack_chain", []),
            },
            "ai_plan": ai_plan,
            "attack_plan": attack_plan,
            "operation_summary": {
                "total": operation_results.get("total", 0),
                "success_count": operation_results.get("success_count", 0),
                "fail_count": operation_results.get("fail_count", 0),
                "techniques_run": operation_results.get("techniques_run", []),
            },
            "exploitability_validation": {
                "mode": validation_results.get("mode"),
                "target": validation_results.get("target"),
                "confirmed": validation_results.get("confirmed", 0),
                "potential": validation_results.get("potential", 0),
                "findings": validation_results.get("findings", []),
            },
            "risk_score": risk_score,
        }

        message_lower = user_message.lower().strip()

        simple_greetings = {
            "hello", "hi", "hey", "yo", "sup",
            "hello!", "hi!", "hey!"
        }

        if message_lower in simple_greetings:
            return jsonify({
                "ok": True,
                "reply": (
                    "Hello. You can ask me about the scan findings, MITRE techniques, "
                    "CALDERA validation, CVEs, risk score, or general cybersecurity concepts."
                )
            })

        prompt = f"""
You are AutoPenTest's AI assistant for an authorised cybersecurity Final Year Project dashboard.

You can answer in two modes:

1. Normal chat / concept mode:
If the user asks a greeting, general cybersecurity concept, or basic technical question,
answer naturally and directly. Do not force MITRE ATT&CK mapping.

2. Project context mode:
If the user asks about scan findings, open ports, vulnerabilities, CVEs, MITRE ATT&CK,
CALDERA, selected techniques, risk score, or report output, use the project context.

Safety rules:
- Do not provide exploit commands, payloads, credential theft steps, malware instructions, bypass steps, or intrusion walkthroughs.
- Keep guidance focused on authorised lab validation, explanation, prioritisation, reporting, and remediation.
- If the project context does not contain enough information, say what is missing instead of inventing facts.
- For normal definitions like "what is SMB", answer using general cybersecurity knowledge.
- Only recommend MITRE ATT&CK technique IDs that appear in the project context.
- Reply in normal plain text, not JSON.
- Keep replies concise and useful.

Formatting rules:
- For normal chat or definitions, answer naturally in 1 to 3 short paragraphs.
- For project-specific technique questions, use this structure only when useful:
  Observation:
  Risk meaning:
  Recommended next step:
- Do not include MITRE ATT&CK mapping unless the user asks about techniques, attack mapping, scan findings, or validation.
- Do not force every answer into a report format.

Current project context:
{json.dumps(safe_context, indent=2, default=str)}

User question:
{user_message}

Reply:
"""

        reply = sanitize_llm_reply(ask_llm_text(prompt))

        return jsonify({
            "ok": True,
            "reply": reply
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "reply": f"AI chat error: {e}"
        }), 500
# edited


@app.route("/")
def index():
    return render_template("index.html", tool_options=TOOL_OPTIONS)


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        return render_template("error.html", error_message="No target provided"), 400

    profile = (request.form.get("scan_profile") or "fast").strip().lower()
    enabled_tools = request.form.getlist("tools")
    technique_mode = request.form.get("technique_mode")
    if technique_mode not in {"auto", "hybrid", "manual"}:
        technique_mode = "hybrid"

    scan_options = normalise_scan_options(profile, enabled_tools if enabled_tools else None)
    scan_id = scan_store.new_scan(
        target,
        request.remote_addr or "",
        request.headers.get("User-Agent", ""),
        scan_options=scan_options,
    )

    session.clear()
    session["scan_id"] = scan_id
    session["target_ip"] = target
    session["technique_mode"] = technique_mode

    threading.Thread(target=run_pipeline, args=(scan_id, target, scan_options), daemon=True).start()

    return render_template(
        "scanning.html",
        scan_id=scan_id,
        target=target,
        scan_options=scan_options,
    )


@app.route("/scan/status/<scan_id>")
def scan_status(scan_id):
    data = scan_store.progress(scan_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/scan/results/<scan_id>")
def results(scan_id):
    data = scan_store.load(scan_id)
    if not data:
        return render_template("error.html", error_message="Scan not found"), 404
    if data.get("status") == "running":
        return render_template(
            "scanning.html",
            scan_id=scan_id,
            target=data.get("target", ""),
            scan_options=data.get("scan_options") or {},
        )
    return render_template(
        "results.html",
        scan=data,
        results=data.get("results") or {},
        mitre_status=mitre_status(),
        caldera_status=CalderaClient(Config.CALDERA_URL, Config.CALDERA_KEY).status(),
    )


@app.route("/latest")
def latest():
    sid = session.get("scan_id")
    return redirect(url_for("results", scan_id=sid)) if sid else redirect(url_for("index"))


@app.route("/download/handoff/<scan_id>")
def handoff(scan_id):
    data = scan_store.load(scan_id) or {}
    path = (data.get("results") or {}).get("handoff_file")
    if not path or not Path(path).exists():
        return "Handoff package not found", 404
    return send_file(path, as_attachment=True)


@app.route("/download/pdf/<scan_id>")
def pdf_report(scan_id):
    data = scan_store.load(scan_id) or {}
    if not data:
        return "Scan not found", 404
    results = data.get("results") or {}
    html = ""
    try:
        html = render_template("pdf_report.html", scan=data, results=results, mitre_status=mitre_status())
        from weasyprint import HTML
        pdf_bytes = HTML(string=html, base_url=str(Path.cwd())).write_pdf()
    except Exception:
        try:
            from scanners.pdf_export import build_pdf_report
            pdf_bytes = build_pdf_report(data, results)
        except Exception as fallback_exc:
            text = "Recon report export failed. Handoff JSON is still available. Error: " + str(fallback_exc)
            response = make_response(text)
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            response.headers["Content-Disposition"] = f'attachment; filename="recon_report_{scan_id}_export_error.txt"'
            return response
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="recon_report_{scan_id}.pdf"'
    return response


@app.route("/caldera/handoff/<scan_id>")
def caldera_handoff(scan_id):
    data = scan_store.load(scan_id) or {}
    return jsonify((data.get("results") or {}).get("caldera_handoff") or {})


# ---------------------------------------------------
# CALDERA
# ---------------------------------------------------

@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    target_context = _current_target_context()
    status = operation_manager.check_readiness(target=target_context["target"])
    status["target"] = target_context["target"]
    status["target_os"] = target_context["os"]
    if not status.get("agent_ready"):
        status["deploy_command"] = operation_manager.get_deploy_command(
            kali_ip=_caldera_agent_server_host(),
            group=getattr(Config, "AGENT_GROUP", "red"),
            platform=target_context["platform"],
        )
    return jsonify(status)


@app.route("/caldera/deploy-command", methods=["GET"])
def caldera_deploy_command():
    target_context = _current_target_context()
    return jsonify({
        "ok": True,
        "target": target_context["target"],
        "os": target_context["os"],
        "group": getattr(Config, "AGENT_GROUP", "red"),
        "deploy_command": operation_manager.get_deploy_command(
            kali_ip=_caldera_agent_server_host(),
            group=getattr(Config, "AGENT_GROUP", "red"),
            platform=target_context["platform"],
        ),
    })


@app.route("/caldera/agent/delete", methods=["POST"])
def caldera_agent_delete():
    try:
        data = request.get_json(silent=True) or {}
        paw = data.get("paw")
        result = operation_manager.delete_agent(paw)
        return jsonify(result), 200 if result.get("ok") else 400
    except Exception as e:
        log.error(f"Agent delete failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/caldera/agents/remove-stale", methods=["POST"])
def caldera_agents_remove_stale():
    try:
        target_context = _current_target_context()
        result = operation_manager.remove_stale_agents(target=target_context["target"])
        return jsonify(result), 200 if result.get("ok") else 500
    except Exception as e:
        log.error(f"Remove stale agents failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/caldera/agent/select", methods=["POST"])
def caldera_agent_select():
    data = request.get_json(silent=True) or {}
    paw = data.get("paw")
    if not paw:
        return jsonify({"ok": False, "error": "Missing paw"}), 400
    session["selected_agent_paw"] = paw
    return jsonify({"ok": True, "selected_agent_paw": paw})

@app.route("/caldera/operation/status", methods=["GET"])
def operation_status():
    return jsonify(session.get("operation_results", {}))


@app.route("/exploitation/run", methods=["POST"])
def exploitation_run():
    try:
        parsed_results = _load_current_scan_results()
        if not parsed_results:
            return jsonify({
                "ok": False,
                "error": "No scan results available. Run a scan before validation."
            }), 400

        mapping_results = session.get("mapping_results", {})
        validation_results = exploitability_validator.validate(parsed_results, mapping_results)
        session["validation_results"] = validation_results
        session["risk_score"] = _safe_risk_calculate(
            mapping_results.get("vulnerabilities", []),
            {
                **(session.get("operation_results", {}) or {}),
                "validation_results": validation_results,
            },
        )

        return jsonify(validation_results)

    except Exception as e:
        log.error(f"Exploitability validation failed: {e}")
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500

@app.route("/api/caldera/check-coverage", methods=["POST"])
def check_coverage():
    """
    Check CALDERA ability coverage for given technique IDs.
    
    Request:
    {
        "technique_ids": ["T1046", "T1110", "T1078"]
    }
    
    Response:
    {
        "ok": True,
        "total": 3,
        "supported": 2,
        "unsupported": 1,
        "techniques": {
            "T1046": {
                "supported": True,
                "ability_count": 2,
                "abilities": [...]
            },
            "T1110": {
                "supported": False,
                "ability_count": 0,
                "abilities": []
            }
        }
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        technique_ids = data.get("technique_ids", [])
        
        if not technique_ids:
            return jsonify({
                "ok": False,
                "error": "technique_ids list is required"
            }), 400
        
        coverage = coverage_checker.check_technique_coverage(technique_ids)
        
        return jsonify({
            "ok": True,
            **coverage,
        })
    
    except Exception as e:
        log.error(f"Coverage check failed: {e}")
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500
    
@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    try:
        data = request.get_json(silent=True) or {}

        selected_techniques = data.get("selected_techniques", [])

        if not selected_techniques:
            return jsonify({
                "ok": False,
                "error": "No techniques selected"
            }), 400

        # Check coverage first
        coverage = coverage_checker.check_technique_coverage(selected_techniques)
        supported_techniques = coverage_checker.get_supported_techniques(selected_techniques)
        unsupported_count = coverage["unsupported"]

        if unsupported_count > 0:
            log.warning(
                f"User requested {len(selected_techniques)} techniques; "
                f"{unsupported_count} not supported by CALDERA. "
                f"Will execute only {len(supported_techniques)} supported techniques."
            )

        if not supported_techniques:
            mapping_results = session.get("mapping_results", {})
            unsupported_results = operation_manager.build_unsupported_results(
                selected_techniques,
                {
                    "vulnerabilities": mapping_results.get("vulnerabilities", []),
                    "scan_context": {"os": session.get("target_os", "Unknown")},
                },
            )
            result = {
                "success": True,
                "operation_id": "",
                "operation_name": "No CALDERA operation created",
                "state": "unsupported",
                "techniques_run": unsupported_results,
                "total": len(unsupported_results),
                "success_count": 0,
                "fail_count": 0,
                "running_count": 0,
                "discarded_count": 0,
                "unsupported_count": len(unsupported_results),
                "timed_out": False,
                "agent_host": "",
                "agent_paw": "",
                "coverage": coverage,
                "coverage_info": {
                    "requested": selected_techniques,
                    "supported": [],
                    "unsupported": selected_techniques,
                    "unsupported_count": len(selected_techniques),
                    "coverage_details": coverage,
                },
            }
            result["validation_results"] = session.get("validation_results", {})
            risk = _safe_risk_calculate(mapping_results.get("vulnerabilities", []), result)
            session["operation_results"] = result
            session["risk_score"] = risk
            return jsonify({
                "ok": True,
                **result,
                "risk": risk,
                "message": "No selected techniques are supported by CALDERA. Unsupported techniques were recorded for external validation.",
            })

        result = operation_manager.run_operation(
            technique_ids=supported_techniques,
            group=data.get("group", getattr(Config, "AGENT_GROUP", "red")),
            timeout=getattr(Config, "OPERATION_TIMEOUT", 180),
            target=session.get("target_ip"),
            selected_paw=session.get("selected_agent_paw"),
            unsupported_techniques=[t for t in selected_techniques if t not in supported_techniques],
            unsupported_context={
                "vulnerabilities": session.get("mapping_results", {}).get("vulnerabilities", []),
                "scan_context": {"os": session.get("target_os", "Unknown")},
            },
        )

        if not isinstance(result, dict):
            return jsonify({
                "ok": False,
                "error": "Invalid response from operation manager"
            }), 500

        if not result.get("success", True):
            return jsonify(result), 500

        # Risk score
        mapping_results = session.get("mapping_results", {})
        vulns = data.get("vulnerabilities") or session.get("vulnerabilities") or mapping_results.get("vulnerabilities", [])
        session["vulnerabilities"] = vulns
        result["validation_results"] = session.get("validation_results", {})
        risk = _safe_risk_calculate(vulns, result)

        # Remediation
        vulnerability_remediations = []
        try:
            vulnerability_remediations = risk_scorer.get_vulnerability_remediations(mapping_results) or []
        except Exception:
            vulnerability_remediations = []

        technique_remediations = []
        try:
            technique_remediations = risk_scorer.get_all_remediations(result) or []
        except Exception:
            technique_remediations = []

        remediations = vulnerability_remediations + technique_remediations

        # Add coverage info to results for display
        result["coverage_info"] = {
            "requested": selected_techniques,
            "supported": supported_techniques,
            "unsupported": [t for t in selected_techniques if t not in supported_techniques],
            "unsupported_count": unsupported_count,
            "coverage_details": coverage,
        }

        session["operation_results"] = result
        session["risk_score"] = risk
        session["remediations"] = remediations

        return jsonify({
            "ok": True,
            "success": True,
            **result,
            "risk": risk,
            "remediations": remediations,
        })

    except Exception as e:
        log.error(f"CALDERA execution failed: {e}")
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500


@app.route("/caldera/operation/<operation_id>", methods=["GET"])
def caldera_operation(operation_id):
    return jsonify(operation_manager.poll_operation(operation_id))


# ---------------------------------------------------
# RESULTS PAGE
# ---------------------------------------------------

@app.route("/results")
def results():
    scan = {
        "target_ip": session.get("target_ip", ""),
        "port_range": session.get("port_range", "1-1024"),
        "output_file": session.get("scan_output_file", ""),
    }

    parsed_results = None
    mapping_results = session.get("mapping_results", [])
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
        risk = _safe_risk_calculate(mapping_results.get("vulnerabilities", []), {})
        session["risk_score"] = risk

    return render_template(
        "results_full_dashboard.html",
        scan=scan,
        results=parsed_results or {
            "os": scan["os"],
            "ports": scan["ports"],
        },
        mapping=mapping_results,
        ai_plan=session.get("ai_plan"), ##edited
        selected_mode=session.get("technique_mode", "hybrid"), #edited
        attack_plan=session.get("attack_plan"),
        validation_results=session.get("validation_results"),
        operation_results=session.get("operation_results"),
        risk=risk,
        remediations=session.get("remediations", []),
    )


@app.route("/generate_report", methods=["POST"])
def generate_report():
    data = request.get_json(silent=True) or {}

    scan = {
        "target_ip": session.get("target_ip", data.get("target") or "Unknown"),
        "port_range": session.get("port_range", data.get("port_range") or "1-1024"),
        "output_file": session.get("scan_output_file", ""),
    }
    parsed_results = _load_current_scan_results() or {}
    scan["os"] = parsed_results.get("os", session.get("target_os", "Unknown"))
    scan["ports"] = parsed_results.get("ports", [])

    mapping_results = session.get("mapping_results", {})
    operation_results = session.get("operation_results", {})
    validation_results = session.get("validation_results", {})
    risk = session.get("risk_score", {})
    remediations = session.get("remediations", [])

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
    )

    return jsonify({
        "ok": True,
        "report": report,
        "download_url": url_for("export_report") if operation_results else None,
    })


# ---------------------------------------------------
# SAVE DATA
# ---------------------------------------------------

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


# ---------------------------------------------------
# REPORT EXPORT
# ---------------------------------------------------

@app.route("/report/export", methods=["GET"])
def export_report():
    from reports.report_generator import generate_text_report

    scan = {
        "target_ip": session.get("target_ip", "Unknown"),
        "port_range": session.get("port_range", "1-1024"),
        "output_file": session.get("scan_output_file", ""),
    }
    parsed_results = _load_current_scan_results() or {}
    scan["os"] = parsed_results.get("os", session.get("target_os", "Unknown"))
    scan["ports"] = parsed_results.get("ports", [])
    mapping_results = session.get("mapping_results", {})
    op_results = session.get("operation_results")
    validation_results = session.get("validation_results", {})
    risk = session.get("risk_score", {})
    remediations = session.get("remediations", [])

    if not op_results:
        return "No results to export", 400

    report_path = generate_text_report(
        scan=scan,
        mapping=mapping_results,
        operation=op_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
    )

    return send_file(
        report_path,
        as_attachment=True,
        download_name=os.path.basename(report_path),
        mimetype="text/plain",
    )


# ---------------------------------------------------
# RUN
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
