# app.py - FIXED VERSION
# Main Flask application for vulnerability assessment + attack simulation.

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

from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager

from caldera.risk_scorer import RiskScorer
from storage.db import Database

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = getattr(Config, "SECRET_KEY", "change-me")

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


# ---------------------------------------------------
# ROUTES
# ---------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    ports = request.form.get("ports")
    intensity = request.form.get("intensity")
    profile = request.form.get("profile")

    try:
        scan_result = run_nmap_scan(target, ports, intensity, profile)
        parsed_results = parse_nmap_xml(scan_result["output_file"])
        mapping_results = map_vulnerabilities(parsed_results)

        session["target_ip"] = target
        session["port_range"] = ports or "1-1024"
        session["scan_output_file"] = scan_result.get("output_file", "")
        session["mapping_results"] = mapping_results

        return render_template(
            "results_full_dashboard.html",
            scan=_scan_summary(scan_result, parsed_results),
            results=parsed_results,
            mapping=mapping_results,
            attack_plan=None,
            operation_results=None,
            risk=None,
            remediations=[],
        )

    except (NmapScanError, NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


# ---------------------------------------------------
# CONFIRM PLAN (ONLY ONE VERSION - FIXED)
# ---------------------------------------------------

@app.route("/confirm-plan", methods=["POST"])
def confirm_attack_plan():
    scan_file = request.form.get("scan_file")
    mode = request.form.get("mode", "hybrid")
    selected_ids = request.form.getlist("selected_techniques")

    if not selected_ids:
        flash("No techniques selected.")
        return redirect(url_for("results"))

    try:
        parsed_results = parse_nmap_xml(scan_file)
        mapping_results = map_vulnerabilities(parsed_results)

        attack_plan = select_attack_mode(
            mapping_results,
            mode=mode,
            selected_ids=selected_ids,
        )

        session["attack_plan"] = attack_plan
        session["selected_technique_ids"] = selected_ids

        return render_template(
            "results_full_dashboard.html",
            scan={
                "target_ip": session.get("target_ip", ""),
                "port_range": session.get("port_range", "1-1024"),
                "output_file": scan_file,
                "os": parsed_results.get("os", "Unknown"),
                "ports": parsed_results.get("ports", []),
            },
            results=parsed_results,
            mapping=mapping_results,
            attack_plan=attack_plan,
            operation_results=session.get("operation_results"),
            risk=session.get("risk_score"),
            remediations=session.get("remediations", []),
        )

    except (NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


# ---------------------------------------------------
# CALDERA
# ---------------------------------------------------

@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    return jsonify(operation_manager.check_readiness())

@app.route("/caldera/operation/status", methods=["GET"])
def operation_status():
    return jsonify(session.get("operation_results", {}))
    
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
        vulns = data.get("vulnerabilities") or session.get("vulnerabilities", [])
        risk = _safe_risk_calculate(vulns, result)

        # Remediation
        try:
            remediations = risk_scorer.get_all_remediations(result)
        except Exception:
            remediations = []

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

    return render_template(
        "results_full_dashboard.html",
        scan=scan,
        results=parsed_results or {
            "os": scan["os"],
            "ports": scan["ports"],
        },
        mapping=mapping_results,
        attack_plan=session.get("attack_plan"),
        operation_results=session.get("operation_results"),
        risk=session.get("risk_score"),
        remediations=session.get("remediations", []),
    )


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
    from reports.report_generator import generate_pdf_report

    scan_id = session.get("scan_id")
    op_results = session.get("operation_results")
    risk = session.get("risk_score")
    remediations = session.get("remediations", [])

    if not op_results:
        return "No results to export", 400

    pdf_path = generate_pdf_report(
        scan_id=scan_id,
        operation=op_results,
        risk=risk,
        remediations=remediations,
    )

    return send_file(pdf_path, as_attachment=True)


# ---------------------------------------------------
# RUN
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)