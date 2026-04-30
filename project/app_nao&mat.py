from __future__ import annotations

from flask import Flask, render_template, request

from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

app = Flask(__name__)


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
            selected_ids=selected_ids
        )

        return render_template(
            "attack_plan.html",
            mapping=mapping_results,
            attack_plan=attack_plan,
        )

    except (NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

