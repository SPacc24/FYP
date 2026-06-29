# app.py - FIXED VERSION
# Main Flask application for vulnerability assessment + attack simulation.

# edited
import sys
import os as _os_for_path
# Ensure the project directory is on sys.path so local top-level packages (ai, scanners, etc.) import correctly when running as a module
sys.path.insert(0, _os_for_path.path.dirname(__file__))

from ai.technique_planner import generate_ai_technique_plan
from ai.llm_client import ask_llm_text, get_llm_settings
from ai.safety import SAFE_REFUSAL, is_unsafe_user_request, sanitize_llm_reply
import json
import re
import os
import socket
import threading
from pathlib import Path
from urllib.parse import urlparse, urlunparse
import requests

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

from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.coverage_checker import CoverageChecker

from caldera.risk_scorer import RiskScorer
from exploitation.validator import ExploitabilityValidator
from proof_of_access import ProofTicketError, ProofTicketManager
from reports.report_generator import build_report_summary
from storage.db import Database
from storage import scan_store
from scanners.enumerator import TASKS, run_pipeline
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
proof_ticket_manager = ProofTicketManager(
    secret=Config.PROOF_OF_ACCESS_SECRET,
    enabled=Config.PROOF_OF_ACCESS_ENABLED,
    ttl_seconds=Config.PROOF_OF_ACCESS_TTL,
)

if Config.PROOF_OF_ACCESS_ENABLED and not proof_ticket_manager.active:
    log.warning(
        "Proof-of-access is enabled but PROOF_OF_ACCESS_SECRET is shorter "
        "than 32 bytes; ticket issuance is disabled."
    )

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


def _as_list(value):
    return value if isinstance(value, list) else []


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
    risk = active.get("risk") or session.get("risk_score", {})
    remediations = active.get("remediations") or session.get("remediations", [])

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
        validation=validation_results,
    )

    return {
        "scan": scan,
        "mapping": mapping_results,
        "operation": operation_results,
        "validation": validation_results,
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

        mapping_results = _active_mapping_results()
        ai_plan = _active_ai_plan()
        attack_plan = _active_attack_plan()
        operation_results = _active_operation_results()
        validation_results = _active_validation_results()
        risk_score = (_active_scan_record().get("risk") or session.get("risk_score", {}))

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


@app.route("/ai/status", methods=["GET"])
def ai_status():
    settings = get_llm_settings()
    parsed = urlparse(settings["url"])
    tags_url = urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))
    try:
        response = requests.get(tags_url, timeout=2)
        response.raise_for_status()
        models = response.json().get("models", [])
        model_names = [item.get("name") for item in models if item.get("name")]
        return jsonify({
            "ok": True,
            "available": True,
            "url": settings["url"],
            "model": settings["model"],
            "model_installed": settings["model"] in model_names,
            "models": model_names,
        })
    except Exception as exc:
        return jsonify({
            "ok": True,
            "available": False,
            "url": settings["url"],
            "model": settings["model"],
            "error": str(exc),
        })


@app.route("/")
def index():
    return render_template("index.html", tool_options=TOOL_OPTIONS)


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        return render_template("error.html", error_message="No target provided"), 400

    profile = (request.form.get("profile") or request.form.get("scan_profile") or "full").strip().lower()
    enabled_tools = request.form.getlist("enabled_tools") or request.form.getlist("tools")
    technique_mode = request.form.get("technique_mode")
    if technique_mode not in {"auto", "hybrid", "manual"}:
        technique_mode = "hybrid"

    scan_options = normalise_scan_options(profile, enabled_tools if profile == "custom" or enabled_tools else None)
    scan_options["technique_mode"] = technique_mode
    scan_id = scan_store.new_scan(
        target,
        request.remote_addr or "",
        request.headers.get("User-Agent", ""),
        scan_options=scan_options,
    )
    # Debug: record session start and scan id
    log.info(f"[scan] new_scan created: {scan_id} target={target} profile={profile} technique_mode={technique_mode} enabled_tools={enabled_tools}")
    scan_store.log(scan_id, f"Scan requested: target={target} profile={profile} technique_mode={technique_mode}")

    session.clear()
    session["scan_id"] = scan_id
    session["target_ip"] = target
    session["technique_mode"] = technique_mode

    # Start pipeline in background thread
    if os.getenv('PIPELINE_STUB') == '1':
        # Use a safe stub that initialises tasks and simulates progress for debugging
        def _stub_pipeline(sid, tgt, opts):
            log.info(f"[stub_pipeline] init tasks for {sid}")
            scan_store.init_tasks(sid, TASKS or ['Target Preparation', 'TCP Service Discovery', 'CVE Review', 'Report Preparation'])
            # simulate progression
            import time
            for t in list(scan_store.get(sid).get('tasks', [])):
                scan_store.set_task(sid, t['name'], scan_store.STATUS_RUNNING, summary='Simulated run')
                time.sleep(0.3)
                scan_store.set_task(sid, t['name'], scan_store.STATUS_SUCCESS, summary='Simulated complete')
            scan_store.update(sid, status='success', completed_at='simulated')

        threading.Thread(target=_stub_pipeline, args=(scan_id, target, scan_options), daemon=True).start()
        log.info(f"[scan] stub pipeline thread started for scan_id={scan_id}")
    else:
        threading.Thread(target=run_pipeline, args=(scan_id, target, scan_options), daemon=True).start()
        log.info(f"[scan] pipeline thread started for scan_id={scan_id}")

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
def scan_results(scan_id):
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

    session["scan_id"] = scan_id
    session["target_ip"] = data.get("target", "")
    session["scan_options"] = data.get("scan_options") or {}
    data = _ensure_scan_analysis(data)

    return render_template(
        "results.html",
        scan=data,
        results=_stored_results_to_parsed_results(data.get("results") or {}, data),
        mapping=data.get("mapping") or {},
        ai_plan=data.get("ai_plan"),
        selected_mode=data.get("technique_mode") or session.get("technique_mode", "hybrid"),
        attack_plan=data.get("attack_plan"),
        validation_results=data.get("validation_results"),
        operation_results=data.get("operation_results"),
        risk=data.get("risk"),
        remediations=data.get("remediations") or [],
    )


@app.route("/latest")
def latest():
    sid = session.get("scan_id")
    return redirect(url_for("scan_results", scan_id=sid)) if sid else redirect(url_for("index"))


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
    return jsonify(_active_operation_results())


@app.route("/proof-of-access/redeem", methods=["POST"])
def redeem_proof_of_access():
    data = request.get_json(silent=True) or {}

    try:
        proof = proof_ticket_manager.redeem(
            ticket=data.get("ticket", ""),
            observed_host=data.get("observed_host", ""),
            observed_ip=request.remote_addr or "",
        )
    except ProofTicketError:
        return jsonify({
            "ok": False,
            "error": "Proof ticket is invalid, expired, already used, or for another host.",
        }), 400

    return jsonify({
        "ok": True,
        "proof": proof,
    })


@app.route("/exploitation/run", methods=["POST"])
def exploitation_run():
    try:
        parsed_results = _load_current_scan_results()
        if not parsed_results:
            return jsonify({
                "ok": False,
                "error": "No scan results available. Run a scan before validation."
            }), 400

        mapping_results = _active_mapping_results()
        validation_results = exploitability_validator.validate(parsed_results, mapping_results)
        session["validation_results"] = validation_results
        session["risk_score"] = _safe_risk_calculate(
            mapping_results.get("vulnerabilities", []),
            {
                **(_active_operation_results() or {}),
                "validation_results": validation_results,
            },
        )
        _save_active_scan_fields(
            validation_results=validation_results,
            risk=session["risk_score"],
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
            mapping_results = _active_mapping_results()
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
            result["validation_results"] = _active_validation_results()
            proof_tickets = proof_ticket_manager.issue_for_operation(result)
            result["proof_of_access"] = {
                "enabled": proof_ticket_manager.active,
                "issued_count": len(proof_tickets),
                "tickets": proof_tickets,
            }
            risk = _safe_risk_calculate(mapping_results.get("vulnerabilities", []), result)
            session["operation_results"] = result
            session["risk_score"] = risk
            _save_active_scan_fields(operation_results=result, risk=risk)
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
                "vulnerabilities": _active_mapping_results().get("vulnerabilities", []),
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
        mapping_results = _active_mapping_results()
        vulns = data.get("vulnerabilities") or session.get("vulnerabilities") or mapping_results.get("vulnerabilities", [])
        session["vulnerabilities"] = vulns
        result["validation_results"] = _active_validation_results()
        proof_tickets = proof_ticket_manager.issue_for_operation(result)
        result["proof_of_access"] = {
            "enabled": proof_ticket_manager.active,
            "issued_count": len(proof_tickets),
            "tickets": proof_tickets,
        }
        risk = _safe_risk_calculate(vulns, result)

        # Remediation
        vulnerability_remediations = []
        try:
            vulnerability_remediations = _as_list(
                risk_scorer.get_vulnerability_remediations(mapping_results)
            )
        except Exception:
            vulnerability_remediations = []

        technique_remediations = []
        try:
            technique_remediations = _as_list(
                risk_scorer.get_all_remediations(result)
            )
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
        _save_active_scan_fields(
            operation_results=result,
            risk=risk,
            remediations=remediations,
        )

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
    scan_id = session.get("scan_id")
    if scan_id:
        data = scan_store.load(scan_id)
        if data:
            data = _ensure_scan_analysis(data)
            return render_template(
                "results.html",
                scan=data,
                results=_stored_results_to_parsed_results(data.get("results") or {}, data),
                mapping=data.get("mapping") or {},
                ai_plan=data.get("ai_plan"),
                selected_mode=data.get("technique_mode") or session.get("technique_mode", "hybrid"),
                attack_plan=data.get("attack_plan"),
                validation_results=data.get("validation_results"),
                operation_results=data.get("operation_results"),
                risk=data.get("risk"),
                remediations=data.get("remediations") or [],
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
        risk = _safe_risk_calculate(mapping_results.get("vulnerabilities", []), {})
        session["risk_score"] = risk

    return render_template(
        "results.html",
        scan=scan,
        results=parsed_results or {
            "os": scan["os"],
            "ports": scan["ports"],
        },
        mapping=mapping_results,
        ai_plan=session.get("ai_plan"),
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
        return render_template("error.html", error_message="Technical appendix requires an active scan."), 404

    data = scan_store.load(scan_id) or {}
    if not data:
        return render_template("error.html", error_message="Technical appendix data not found."), 404

    results = data.get("results") or {}
    mapping_results = data.get("mapping") or session.get("mapping_results", [])

    data["scan_id"] = scan_id

    return render_template(
        "technical_appendix.html",
        scan=data,
        results=results,
        mapping=mapping_results,
        mitre_status=mitre_status(),
        caldera_status=CalderaClient(Config.CALDERA_URL, Config.CALDERA_KEY).status(),
    )


@app.route("/generate_report", methods=["POST"])
def generate_report():
    context = _build_active_report_context()
    return jsonify({
        "ok": True,
        "report": context["report"],
        "report_url": url_for("report_view"),
        "download_url": url_for("export_report"),
    })


@app.route("/report/view", methods=["GET"])
def report_view():
    context = _build_active_report_context()
    return render_template("report_view.html", **context)


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
    context = _build_active_report_context()

    report_path = generate_text_report(
        scan=context["scan"],
        mapping=context["mapping"],
        operation=context["operation"],
        risk=context["risk"],
        remediations=context["remediations"],
        validation=context["validation"],
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
    port = int(os.getenv('PORT', '5000'))
    # Bind to all interfaces by default so the dashboard is reachable from the
    # host browser and other lab VMs at http://<kali-ip>:5000.
    # Override with APP_HOST=127.0.0.1 if you only want local access.
    host = os.getenv("APP_HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=True)
