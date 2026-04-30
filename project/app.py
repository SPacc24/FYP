from flask import Flask, render_template, request, jsonify

from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager

app = Flask(__name__)


def get_operation_manager():
    client = CalderaClient()
    return OperationManager(client)


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

        return render_template(
            "results.html",
            scan=scan_result,
            results=parsed_results,
            mapping=mapping_results,
        )
    except (NmapScanError, NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


@app.route("/confirm-plan", methods=["POST"])
def confirm_attack_plan():
    scan_file = request.form.get("scan_file")
    mode = request.form.get("mode")
    selected_ids = request.form.getlist("selected_techniques")

    try:
        parsed_results = parse_nmap_xml(scan_file)
        mapping_results = map_vulnerabilities(parsed_results)

        attack_plan = select_attack_mode(
            mapping_results,
            mode=mode,
            selected_ids=selected_ids,
        )

        return render_template(
            "attack_plan.html",
            mapping=mapping_results,
            attack_plan=attack_plan,
        )
    except (NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    manager = get_operation_manager()
    return jsonify(manager.check_readiness())


@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    data = request.get_json() or {}

    adversary_id = data.get("adversary_id")
    selected_techniques = data.get("selected_techniques", [])
    group = data.get("group", "red")
    planner_id = data.get("planner_id")

    if not adversary_id:
        return jsonify({
            "ok": False,
            "message": "Missing adversary_id."
        }), 400

    manager = get_operation_manager()
    result = manager.start_operation(
        adversary_id=adversary_id,
        selected_techniques=selected_techniques,
        group=group,
        planner_id=planner_id
    )

    status_code = 200 if result.get("ok") else 400
    return jsonify(result), status_code


@app.route("/caldera/operation/<operation_id>", methods=["GET"])
def caldera_operation(operation_id):
    manager = get_operation_manager()
    return jsonify(manager.poll_operation(operation_id))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
