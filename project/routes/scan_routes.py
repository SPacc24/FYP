import logging
import os
import threading
from pathlib import Path

from flask import (
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from scanners.enumerator import TASKS, run_pipeline
from scanners.mitre_cve import status as mitre_status
from scanners.scan_profiles import TOOL_OPTIONS, normalise_scan_options
from storage import scan_store

from core.helpers import (
    _build_detected_cve_rows,
    _ensure_scan_analysis,
    _stored_results_to_parsed_results,
)

log = logging.getLogger(__name__)


def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html", tool_options=TOOL_OPTIONS)

    @app.route("/scan", methods=["POST"])
    def scan():
        target = (request.form.get("target") or "").strip()

        if not target:
            return render_template(
                "error.html",
                error_message="No target provided"
            ), 400

        profile = (request.form.get("scan_profile") or "fast").strip().lower()
        enabled_tools = request.form.getlist("tools")
        technique_mode = request.form.get("technique_mode")

        if technique_mode not in {"auto", "hybrid", "manual"}:
            technique_mode = "hybrid"

        scan_options = normalise_scan_options(
            profile,
            enabled_tools if enabled_tools else None
        )
        scan_options["technique_mode"] = technique_mode

        scan_id = scan_store.new_scan(
            target,
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
            scan_options=scan_options,
        )

        log.info(
            "[scan] new_scan created: %s target=%s profile=%s technique_mode=%s enabled_tools=%s",
            scan_id,
            target,
            profile,
            technique_mode,
            enabled_tools,
        )

        scan_store.log(
            scan_id,
            f"Scan requested: target={target} profile={profile} technique_mode={technique_mode}"
        )

        session.clear()
        session["scan_id"] = scan_id
        session["target_ip"] = target
        session["technique_mode"] = technique_mode

        if os.getenv("PIPELINE_STUB") == "1":
            def _stub_pipeline(sid, tgt, opts):
                log.info("[stub_pipeline] init tasks for %s", sid)

                scan_store.init_tasks(
                    sid,
                    TASKS or [
                        "Target Preparation",
                        "TCP Service Discovery",
                        "CVE Review",
                        "Report Preparation",
                    ]
                )

                import time

                for task in list(scan_store.get(sid).get("tasks", [])):
                    scan_store.set_task(
                        sid,
                        task["name"],
                        scan_store.STATUS_RUNNING,
                        summary="Simulated run"
                    )
                    time.sleep(0.3)
                    scan_store.set_task(
                        sid,
                        task["name"],
                        scan_store.STATUS_SUCCESS,
                        summary="Simulated complete"
                    )

                scan_store.update(
                    sid,
                    status="success",
                    completed_at="simulated"
                )

            threading.Thread(
                target=_stub_pipeline,
                args=(scan_id, target, scan_options),
                daemon=True
            ).start()

            log.info("[scan] stub pipeline thread started for scan_id=%s", scan_id)

        else:
            threading.Thread(
                target=run_pipeline,
                args=(scan_id, target, scan_options),
                daemon=True
            ).start()

            log.info("[scan] pipeline thread started for scan_id=%s", scan_id)

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
            return render_template(
                "error.html",
                error_message="Scan not found"
            ), 404

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

        ai_plan = data.get("ai_plan") or {}
        mapping_result = data.get("mapping") or {}

        detected_cves = _build_detected_cve_rows(
            ai_plan,
            mapping_result
        )

        return render_template(
            "results.html",
            scan=data,
            results=_stored_results_to_parsed_results(data.get("results") or {}, data),
            mapping=data.get("mapping") or {},
            ai_plan=ai_plan,
            detected_cves=detected_cves,
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

        if sid:
            return redirect(url_for("scan_results", scan_id=sid))

        return redirect(url_for("index"))

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

        try:
            html = render_template(
                "pdf_report.html",
                scan=data,
                results=results,
                mitre_status=mitre_status()
            )

            from weasyprint import HTML

            pdf_bytes = HTML(
                string=html,
                base_url=str(Path.cwd())
            ).write_pdf()

        except Exception:
            try:
                from scanners.pdf_export import build_pdf_report

                pdf_bytes = build_pdf_report(data, results)

            except Exception as fallback_exc:
                text = (
                    "Recon report export failed. Handoff JSON is still available. Error: "
                    + str(fallback_exc)
                )

                response = make_response(text)
                response.headers["Content-Type"] = "text/plain; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    f'attachment; filename="recon_report_{scan_id}_export_error.txt"'
                )

                return response

        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="recon_report_{scan_id}.pdf"'
        )

        return response

    @app.route("/caldera/handoff/<scan_id>")
    def caldera_handoff(scan_id):
        data = scan_store.load(scan_id) or {}

        return jsonify(
            (data.get("results") or {}).get("caldera_handoff") or {}
        )