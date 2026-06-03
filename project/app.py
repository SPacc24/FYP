# app.py - FIXED VERSION
# Main Flask application for vulnerability assessment + attack simulation.

# edited
from ai.technique_planner import generate_ai_technique_plan
from ai.llm_client import ask_llm_text
from ai.safety import SAFE_REFUSAL, is_unsafe_user_request, sanitize_llm_reply
import json
import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    send_file,
    flash,
)
import logging

from config import Config

from mapping.technique_mapper import map_vulnerabilities
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager

from caldera.risk_scorer import RiskScorer
from reports.report_generator import build_report_summary
from storage.db import Database

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = getattr(Config, "SECRET_KEY", "change-me")

SERVER_STATE = {}
HEAVY_STATE_KEYS = {
    "mapping_results",
    "ai_plan",
    "attack_plan",
    "operation_results",
    "risk_score",
    "remediations",
    "vulnerabilities",
}

# ---------------------------------------------------
# INIT SERVICES
# ---------------------------------------------------

caldera_client = CalderaClient(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY,
)

operation_manager = OperationManager(caldera_client)
risk_scorer = RiskScorer()

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
        return risk_scorer.calculate(vulns, op_results)
    except Exception as e:
        log.warning(f"Risk score fallback triggered: {e}")
        return {
            "score": 50,
            "label": "Medium",
            "colour": "orange",
             "badge": "warning",
        }


def _drop_client_side_heavy_state():
    for key in HEAVY_STATE_KEYS:
        session.pop(key, None)


def _get_assessment_state():
    state_id = session.get("assessment_state_id")

    if not state_id:
        state_id = uuid.uuid4().hex
        session["assessment_state_id"] = state_id

    _drop_client_side_heavy_state()
    return SERVER_STATE.setdefault(state_id, {})


def _replace_assessment_state(**values):
    old_state_id = session.get("assessment_state_id")

    if old_state_id:
        SERVER_STATE.pop(old_state_id, None)

    state_id = uuid.uuid4().hex
    session["assessment_state_id"] = state_id
    SERVER_STATE[state_id] = dict(values)
    _drop_client_side_heavy_state()


def _state_get(key, default=None):
    return _get_assessment_state().get(key, default)


def _state_set(**values):
    _get_assessment_state().update(values)


def _technique_id_from_mapping_item(item):
    if not isinstance(item, dict):
        return ""

    return str(item.get("id") or item.get("technique_id") or "").strip()


def _mapped_technique_ids(mapping_results):
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


def _normalise_selected_techniques(value):
    if not isinstance(value, list):
        return []

    selected = []

    for item in value:
        technique_id = str(item).strip()

        if technique_id and technique_id not in selected:
            selected.append(technique_id)

    return selected


def _allowed_technique_ids_for_mode(mode, mapping_results, ai_plan):
    mapped_ids = _mapped_technique_ids(mapping_results)

    if mode == "auto":
        ai_selected_ids = {
            str(technique_id).strip()
            for technique_id in ai_plan.get("selected_technique_ids", [])
            if str(technique_id).strip()
        }

        return ai_selected_ids & mapped_ids

    return mapped_ids


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

        mapping_results = _state_get("mapping_results", {})
        ai_plan = _state_get("ai_plan", {})
        attack_plan = _state_get("attack_plan", {})
        operation_results = _state_get("operation_results", {})
        risk_score = _state_get("risk_score", {})

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
            "risk_score": risk_score,
        }

        prompt = f"""
You are an AI assistant inside an authorised cybersecurity Final Year Project dashboard.

You help the student understand scan findings, ATT&CK technique recommendations,
CALDERA planning, risk scoring, and report interpretation.

Rules:
- Do not provide exploit commands, payloads, or step-by-step exploitation instructions.
- Do not tell the user how to bypass security.
- Explain at a high level using the provided project data.
- If asked what to run, recommend MITRE ATT&CK technique IDs only from the provided context.
- Keep replies concise and useful.
- Reply in normal plain text, not JSON.
- When mentioning MITRE ATT&CK techniques, include the technique ID, name, and MITRE URL if available.
- Explain reasoning in this structure: Observation -> Risk meaning -> Recommended next step.
- Keep next steps safe and high-level.
- Do not provide exploit commands or payloads.

Reply using this format when relevant:

Observation:
...

MITRE ATT&CK Mapping:
- Technique ID:
- Technique Name:
- MITRE Link:

Reasoning:
...

Recommended Next Steps:
1.
2.
3.

Current project context:
{json.dumps(safe_context, indent=2)}

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
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    ports = request.form.get("ports")
    intensity = request.form.get("intensity")
    profile = request.form.get("profile")

    #edited
    technique_mode = request.form.get("technique_mode")

    if technique_mode not in {"auto", "hybrid", "manual"}:
        technique_mode = "hybrid"
    #edited
    
    try:
        scan_result = run_nmap_scan(target, ports, intensity, profile)
        parsed_results = parse_nmap_xml(scan_result["output_file"])
        mapping_results = map_vulnerabilities(parsed_results) ##edited
        ai_plan = generate_ai_technique_plan(mapping_results, preferred_mode=technique_mode) ##edited
        risk = _safe_risk_calculate(mapping_results.get("vulnerabilities", []), {})

        session["target_ip"] = target
        session["port_range"] = ports or "1-1024"
        session["scan_output_file"] = scan_result.get("output_file", "")

        #edited
        session["technique_mode"] = technique_mode

        _replace_assessment_state(
            mapping_results=mapping_results,
            ai_plan=ai_plan,
            risk_score=risk,
        )

        return render_template(
            "results_full_dashboard.html",
            scan=_scan_summary(scan_result, parsed_results),
            results=parsed_results,
            mapping=mapping_results,
            ai_plan=ai_plan,  #edited
            selected_mode=technique_mode,  #edited
            attack_plan=None,
            operation_results=None,
            risk=risk,
            remediations=[],
        )

    except (NmapScanError, NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


# ---------------------------------------------------
# CALDERA
# ---------------------------------------------------

@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    return jsonify(operation_manager.check_readiness())

@app.route("/caldera/operation/status", methods=["GET"])
def operation_status():
    return jsonify(_state_get("operation_results", {}))
    
@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    try:
        data = request.get_json(silent=True) or {}

        selected_techniques = _normalise_selected_techniques(
            data.get("selected_techniques", [])
        )

        if not selected_techniques:
            return jsonify({
                "ok": False,
                "error": "No techniques selected"
            }), 400

        mapping_results = _state_get("mapping_results", {})
        ai_plan = _state_get("ai_plan", {})
        technique_mode = session.get("technique_mode", "hybrid")
        allowed_ids = _allowed_technique_ids_for_mode(
            technique_mode,
            mapping_results,
            ai_plan,
        )
        invalid_techniques = [
            technique_id
            for technique_id in selected_techniques
            if technique_id not in allowed_ids
        ]

        if invalid_techniques:
            return jsonify({
                "ok": False,
                "error": (
                    "One or more selected techniques are not allowed for the "
                    "current scan and technique mode."
                ),
                "invalid_techniques": invalid_techniques,
                "allowed_techniques": sorted(allowed_ids),
            }), 400

        result = operation_manager.run_operation(
            technique_ids=selected_techniques,
            group=data.get("group", "red"),
        )

        if not isinstance(result, dict):
            return jsonify({
                "ok": False,
                "error": "Invalid response from operation manager"
            }), 500

        if not result.get("success", True):
            return jsonify(result), 500

        # Risk score
        vulns = (
            data.get("vulnerabilities")
            or _state_get("vulnerabilities")
            or mapping_results.get("vulnerabilities", [])
        )
        risk = _safe_risk_calculate(vulns, result)

        # Remediation
        vulnerability_remediations = []
        try:
            vulnerability_remediations = risk_scorer.get_vulnerability_remediations(mapping_results)
        except Exception:
            vulnerability_remediations = []

        technique_remediations = []
        try:
            technique_remediations = risk_scorer.get_all_remediations(result)
        except Exception:
            technique_remediations = []

        remediations = vulnerability_remediations + technique_remediations

        _state_set(
            operation_results=result,
            risk_score=risk,
            remediations=remediations,
            vulnerabilities=vulns,
        )

        return jsonify({
            "ok": True,
            "success": True,
            **result,
            "risk": risk,
            "remediations": remediations,
        })

    except Exception as e:
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
    mapping_results = _state_get("mapping_results", [])
    risk = _state_get("risk_score")

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
        _state_set(risk_score=risk)

    return render_template(
        "results_full_dashboard.html",
        scan=scan,
        results=parsed_results or {
            "os": scan["os"],
            "ports": scan["ports"],
        },
        mapping=mapping_results,
        ai_plan=_state_get("ai_plan"), ##edited
        selected_mode=session.get("technique_mode", "hybrid"), #edited
        attack_plan=_state_get("attack_plan"),
        operation_results=_state_get("operation_results"),
        risk=risk,
        remediations=_state_get("remediations", []),
    )


@app.route("/generate_report", methods=["POST"])
def generate_report():
    data = request.get_json(silent=True) or {}

    scan = {
        "target_ip": session.get("target_ip", data.get("target") or "Unknown"),
        "port_range": session.get("port_range", data.get("port_range") or "1-1024"),
        "output_file": session.get("scan_output_file", ""),
    }

    mapping_results = _state_get("mapping_results", {})
    operation_results = _state_get("operation_results", {})
    risk = _state_get("risk_score", {})
    remediations = _state_get("remediations", [])

    report = build_report_summary(
        scan=scan,
        mapping=mapping_results,
        operation=operation_results,
        risk=risk,
        remediations=remediations,
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
    _state_set(vulnerabilities=vulns)

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
    mapping_results = _state_get("mapping_results", {})
    op_results = _state_get("operation_results")
    risk = _state_get("risk_score", {})
    remediations = _state_get("remediations", [])

    if not op_results:
        return "No results to export", 400

    report_path = generate_text_report(
        scan=scan,
        mapping=mapping_results,
        operation=op_results,
        risk=risk,
        remediations=remediations,
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
