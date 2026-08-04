import ipaddress
import json
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
from scanners.phase_discovery import (
    DISCOVERY_TASKS,
    continue_discovery_with_subnet,
    run_discovery_pipeline,
    validate_external_target,
)
from scanners.scan_profiles import TOOL_OPTIONS, collector_ui_context, normalise_scan_options
from storage import scan_store

from core.helpers import (
    _build_detected_cve_rows,
    _ensure_scan_analysis,
    _stored_results_to_parsed_results,
)

log = logging.getLogger(__name__)


def _collector_template_context() -> dict:
    ui = collector_ui_context()
    return {
        "tool_options": TOOL_OPTIONS,
        "collector_catalog": ui.get("catalog") or [],
        "collector_groups": ui.get("groups") or [],
        "collection_presets": ui.get("presets") or {},
        "collector_policy_status": ui.get("policy_status"),
        "collector_policy_sha256": ui.get("policy_sha256"),
    }


def _detected_cve_groups_by_host(parsed_results: dict) -> dict[str, list[dict]]:
    """Build host-first UI rows without collapsing identical CVEs across targets."""

    canonical_groups = parsed_results.get("cve_matches_by_host") or {}
    if not isinstance(canonical_groups, dict) or not canonical_groups:
        canonical_groups = {}
        for row in parsed_results.get("cve_matches") or []:
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or "unattributed").strip() or "unattributed"
            canonical_groups.setdefault(host, []).append(row)

    grouped: dict[str, list[dict]] = {}
    for host, rows in canonical_groups.items():
        host_rows = [row for row in rows or [] if isinstance(row, dict)]
        host_results = dict(parsed_results)
        host_results["cve_matches"] = host_rows
        display_rows = _build_detected_cve_rows(None, None, host_results)
        for row in display_rows:
            row["target_host"] = str(host)
        grouped[str(host)] = display_rows

    def sort_key(item: tuple[str, list[dict]]):
        host = item[0]
        try:
            address = ipaddress.ip_address(host)
            return (0, address.version, int(address))
        except ValueError:
            return (1, 0, host)

    return dict(sorted(grouped.items(), key=sort_key))


def _json_form(name: str) -> dict:
    raw = (request.form.get(name) or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _scan_options_from_form() -> tuple[dict, str, str, list[str]]:
    profile = (
        request.form.get("profile")
        or request.form.get("scan_profile")
        or "full"
    ).strip().lower()
    enabled_tools = (
        request.form.getlist("enabled_tools")
        or request.form.getlist("tools")
    )
    technique_mode = request.form.get("technique_mode")
    if technique_mode not in {"auto", "hybrid", "manual"}:
        technique_mode = "hybrid"

    collector_plan = _json_form("collector_plan_json")
    host_discovery_settings = _json_form("host_discovery_json")
    service_identity_settings = _json_form("service_identity_json")
    collection_preset = (request.form.get("collection_preset") or "custom").strip().lower()

    scan_options = normalise_scan_options(
        profile,
        enabled_tools if (not collector_plan and (profile == "custom" or enabled_tools)) else None,
        tcp_port_mode=request.form.get("tcp_port_mode"),
        tcp_custom_ports=request.form.get("tcp_custom_ports"),
        udp_port_mode=request.form.get("udp_port_mode"),
        udp_custom_ports=request.form.get("udp_custom_ports"),
        advanced_settings={
            "command_timeout_seconds": request.form.get("command_timeout_seconds"),
            "retry_failed_batches": "retry_failed_batches" in request.form,
            "retry_count": request.form.get("retry_count"),
            "ports_per_batch": request.form.get("ports_per_batch"),
            "parallel_scanning": "parallel_scanning" in request.form,
            "parallel_workers": request.form.get("parallel_workers"),
        },
        collection_preset=collection_preset,
        collector_plan=collector_plan or None,
        host_discovery_settings=host_discovery_settings or None,
        service_identity_settings=service_identity_settings or None,
    )
    scan_options["technique_mode"] = technique_mode
    return scan_options, technique_mode, profile, enabled_tools


def _preserve_operator_session() -> None:
    security_session = {
        key: session[key]
        for key in ("operator_authenticated", "_csrf_token")
        if key in session
    }
    session.clear()
    session.update(security_session)


def _stub_discovery(scan_id: str, external_target: str) -> None:
    """Development stub using only explicitly supplied test-network context."""
    import ipaddress
    import time

    configured_subnet = str(os.getenv("AUTOPENTEST_STUB_SUBNET") or "").strip()
    configured_host = str(os.getenv("AUTOPENTEST_STUB_HOST") or "").strip()
    configured_interface = str(os.getenv("AUTOPENTEST_STUB_INTERFACE") or "stub0").strip()
    if not configured_subnet or not configured_host:
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_FAILED,
            error=(
                "PIPELINE_STUB requires AUTOPENTEST_STUB_SUBNET and "
                "AUTOPENTEST_STUB_HOST; no target or CIDR is invented."
            ),
            completed_at=scan_store.now(),
        )
        scan_store.persist(scan_id)
        return

    subnet = ipaddress.ip_network(configured_subnet, strict=False)
    host_ip = ipaddress.ip_address(configured_host)
    if host_ip not in subnet:
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_FAILED,
            error="AUTOPENTEST_STUB_HOST must be inside AUTOPENTEST_STUB_SUBNET.",
            completed_at=scan_store.now(),
        )
        scan_store.persist(scan_id)
        return

    scan_store.init_tasks(scan_id, DISCOVERY_TASKS, phase="discovery")
    for task in DISCOVERY_TASKS:
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING, summary="Simulated run")
        time.sleep(0.05)
        scan_store.set_task(scan_id, task, scan_store.STATUS_SUCCESS, summary="Simulated complete")

    host = {
        "ip": str(host_ip),
        "address": str(host_ip),
        "status": "up",
        "hostname": "stub-target",
        "mac": "",
        "mac_vendor": "",
        "role": "host",
        "is_scanner": False,
        "selectable": True,
        "discovered_by": ["stub"],
    }
    network_context = {
        "interface": configured_interface,
        "scanner_ip": "",
        "gateway": "",
        "internal_subnet": str(subnet),
        "access_mode": "stub",
        "candidate_subnets": [str(subnet)],
        "subnet_candidates": [{
            "subnet": str(subnet),
            "interface": configured_interface,
            "gateway": "",
            "access_mode": "stub",
            "relationship": "explicit_stub_configuration",
            "evidence_source": "environment",
            "route": {},
        }],
    }
    phase_results = {
        "external": {"status": "completed", "target": external_target, "reachable": True},
        "internal": {
            "status": "completed",
            "subnet": str(subnet),
            "host_count": 1,
            "selectable_host_count": 1,
            "hosts": [host],
        },
        "assessment": {"status": "awaiting_configuration", "targets": []},
    }
    workflow = {
        "mode": "external_internal_assessment",
        "continuous": True,
        "external_target": external_target,
        "internal_subnet": str(subnet),
        "access_mode": "stub",
        "network_context": network_context,
        "discovered_hosts": [host],
        "assessment_targets": [],
        "assessment_target": None,
        "phase_results": phase_results,
    }
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_CONFIGURATION,
        workflow_stage="awaiting_assessment_configuration",
        workflow=workflow,
        results={
            "workflow": workflow,
            "phase_results": phase_results,
            "hosts": [str(host_ip)],
            "internal_host_inventory": [host],
        },
        current_task="Waiting for Phase 3 configuration",
        next_task="Select one or more discovered hosts and configure the assessment",
    )
    scan_store.persist(scan_id)

def _stub_assessment(scan_id: str, target_input: str, scan_options: dict) -> None:
    import time

    from scanners.targets import expand_target_input

    assessment_targets = expand_target_input(target_input)
    scan_store.append_tasks(scan_id, TASKS, phase="assessment")
    for task in TASKS:
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING, summary="Simulated run")
        time.sleep(0.05)
        scan_store.set_task(scan_id, task, scan_store.STATUS_SUCCESS, summary="Simulated complete")

    current = scan_store.get(scan_id) or {}
    workflow = dict(current.get("workflow") or {})
    phase_results = dict(workflow.get("phase_results") or {})
    phase_results["assessment"] = {
        "status": "completed",
        "targets": assessment_targets,
        "service_count": 0,
        "cve_count": 0,
    }
    workflow["assessment_targets"] = assessment_targets
    workflow["assessment_target"] = target_input
    workflow["phase_results"] = phase_results
    results = {
        "workflow": workflow,
        "phase_results": phase_results,
        "internal_host_inventory": workflow.get("discovered_hosts") or [],
        "hosts": assessment_targets,
        "service_inventory": [],
        "cve_matches": [],
        "cve_matches_by_host": {},
        "scan_options": scan_options,
    }
    scan_store.update(
        scan_id,
        target=target_input,
        status=scan_store.STATUS_SUCCESS,
        workflow_stage="completed",
        workflow=workflow,
        results=results,
        completed_at=scan_store.now(),
    )
    scan_store.persist(scan_id)

def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/scan/discover", methods=["POST"])
    def scan_discover():
        try:
            external_target = validate_external_target(
                request.form.get("external_target") or request.form.get("target") or ""
            )
        except Exception as exc:
            return render_template("error.html", error_message=str(exc)), 400

        scan_id = scan_store.new_scan(
            external_target,
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
            scan_options={},
        )
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_EXTERNAL_DISCOVERY,
            workflow_stage="external",
            workflow={
                "mode": "external_internal_assessment",
                "continuous": True,
                "external_target": external_target,
                "assessment_target": None,
            },
        )
        scan_store.log(scan_id, f"Phase 1 requested for external target={external_target}")
        scan_store.audit_event(
            scan_id,
            "operator",
            "external_discovery_requested",
            {"external_target": external_target},
        )

        _preserve_operator_session()
        session["scan_id"] = scan_id
        session["external_target"] = external_target

        worker = _stub_discovery if os.getenv("PIPELINE_STUB") == "1" else run_discovery_pipeline
        threading.Thread(
            target=worker,
            args=(scan_id, external_target),
            daemon=True,
        ).start()

        return render_template(
            "scanning.html",
            scan_id=scan_id,
            target=external_target,
            scan_options={},
            workflow_stage="discovery",
        )

    @app.route("/scan/select-subnet/<scan_id>", methods=["GET", "POST"])
    def scan_select_subnet(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan mission not found"), 404

        if request.method == "GET":
            if data.get("status") != scan_store.STATUS_AWAITING_SUBNET_SELECTION:
                if data.get("status") == scan_store.STATUS_AWAITING_CONFIGURATION:
                    return redirect(url_for("scan_configure", scan_id=scan_id))
                if data.get("status") in {
                    scan_store.STATUS_EXTERNAL_DISCOVERY,
                    scan_store.STATUS_INTERNAL_DISCOVERY,
                    scan_store.STATUS_ASSESSMENT_RUNNING,
                    scan_store.STATUS_RUNNING,
                }:
                    return redirect(url_for("scan_results", scan_id=scan_id))
                return render_template(
                    "error.html",
                    error_message="This mission is not waiting for an internal subnet selection.",
                ), 409

            workflow = data.get("workflow") or {}
            context = workflow.get("network_context") or {}
            candidates = [
                item
                for item in context.get("subnet_candidates") or []
                if isinstance(item, dict) and item.get("subnet")
            ]
            if not candidates:
                return render_template(
                    "error.html",
                    error_message="No route-derived internal subnet candidate is available.",
                ), 409
            session["scan_id"] = scan_id
            return render_template(
                "subnet_selection.html",
                scan_id=scan_id,
                workflow=workflow,
                candidates=candidates,
            )

        selected_subnet = (request.form.get("internal_subnet") or "").strip()
        workflow = dict(data.get("workflow") or {})
        context = dict(workflow.get("network_context") or {})
        allowed_subnets = {
            str(item.get("subnet") or "")
            for item in context.get("subnet_candidates") or []
            if isinstance(item, dict) and item.get("subnet")
        }
        if not selected_subnet:
            return render_template(
                "error.html", error_message="Select one discovered internal subnet."
            ), 400
        if selected_subnet not in allowed_subnets:
            return render_template(
                "error.html",
                error_message=(
                    "The selected subnet was not one of the route-derived Phase 1 candidates."
                ),
            ), 400

        transitioned = scan_store.transition_status(
            scan_id,
            {scan_store.STATUS_AWAITING_SUBNET_SELECTION},
            scan_store.STATUS_INTERNAL_DISCOVERY,
            workflow_stage="internal",
            completed_at=None,
            error=None,
        )
        if not transitioned:
            return render_template(
                "error.html",
                error_message="The internal subnet selection has already been submitted.",
            ), 409

        scan_store.audit_event(
            scan_id,
            "operator",
            "internal_subnet_selected",
            {"internal_subnet": selected_subnet},
        )
        threading.Thread(
            target=continue_discovery_with_subnet,
            args=(scan_id, selected_subnet),
            daemon=True,
        ).start()
        return render_template(
            "scanning.html",
            scan_id=scan_id,
            target=workflow.get("external_target") or data.get("target", ""),
            scan_options={},
            workflow_stage="internal",
        )

    @app.route("/scan/configure/<scan_id>")
    def scan_configure(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan mission not found"), 404
        if data.get("status") != scan_store.STATUS_AWAITING_CONFIGURATION:
            if data.get("status") == scan_store.STATUS_AWAITING_SUBNET_SELECTION:
                return redirect(url_for("scan_select_subnet", scan_id=scan_id))
            if data.get("status") in {
                scan_store.STATUS_EXTERNAL_DISCOVERY,
                scan_store.STATUS_INTERNAL_DISCOVERY,
                scan_store.STATUS_ASSESSMENT_RUNNING,
                scan_store.STATUS_RUNNING,
            }:
                return redirect(url_for("scan_results", scan_id=scan_id))
            return render_template(
                "error.html",
                error_message="This scan mission is not waiting for Phase 3 configuration.",
            ), 409

        workflow = data.get("workflow") or {}
        discovered_hosts = [
            host
            for host in workflow.get("discovered_hosts") or []
            if isinstance(host, dict) and host.get("selectable") and host.get("ip")
        ]
        if not discovered_hosts:
            return render_template(
                "error.html",
                error_message="No discovered host is available for assessment.",
            ), 409

        initial_scan_options = data.get("scan_options") or {}
        clone_scan_id = (request.args.get("clone_scan") or "").strip()
        if clone_scan_id:
            previous = scan_store.load(clone_scan_id) or {}
            initial_scan_options = previous.get("scan_options") or initial_scan_options

        session["scan_id"] = scan_id
        context = _collector_template_context()
        return render_template(
            "assessment_config.html",
            scan_id=scan_id,
            workflow=workflow,
            discovered_hosts=discovered_hosts,
            initial_scan_options=initial_scan_options,
            clone_scan_id=clone_scan_id,
            **context,
        )

    @app.route("/scan/assess/<scan_id>", methods=["POST"])
    def scan(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan mission not found"), 404

        submitted_targets = [
            value.strip()
            for value in request.form.getlist("assessment_targets")
            if value.strip()
        ]
        assessment_targets = list(dict.fromkeys(submitted_targets))
        workflow = dict(data.get("workflow") or {})
        discovered_hosts = {
            str(host.get("ip") or host.get("address") or "")
            for host in workflow.get("discovered_hosts") or []
            if isinstance(host, dict) and host.get("selectable")
        }
        if not assessment_targets:
            return render_template(
                "error.html",
                error_message="Select at least one discovered host.",
            ), 400

        invalid_targets = [
            target for target in assessment_targets if target not in discovered_hosts
        ]
        if invalid_targets:
            return render_template(
                "error.html",
                error_message=(
                    "One or more selected assessment targets were not discovered "
                    "during Phase 2."
                ),
            ), 400

        internal_subnet = str(workflow.get("internal_subnet") or "").strip()
        try:
            internal_network = ipaddress.ip_network(internal_subnet, strict=False)
            outside_scope = [
                target
                for target in assessment_targets
                if ipaddress.ip_address(target) not in internal_network
            ]
        except ValueError:
            return render_template(
                "error.html",
                error_message="The persisted Phase 2 internal subnet is invalid.",
            ), 409
        if outside_scope:
            return render_template(
                "error.html",
                error_message=(
                    "One or more selected assessment targets are outside the "
                    "persisted Phase 2 subnet."
                ),
            ), 400

        scan_options, technique_mode, profile, enabled_tools = _scan_options_from_form()
        if scan_options.get("validation_errors"):
            return render_template(
                "error.html",
                error_message="; ".join(scan_options["validation_errors"]),
            ), 400

        network_context = dict(workflow.get("network_context") or {})
        scan_options["workflow_context"] = {
            "route_interface": str(network_context.get("interface") or ""),
            "scanner_ip": str(network_context.get("scanner_ip") or ""),
            "gateway": str(network_context.get("gateway") or ""),
            "internal_subnet": internal_subnet,
            "access_mode": str(
                workflow.get("access_mode")
                or network_context.get("access_mode")
                or ""
            ),
            "assessment_targets": assessment_targets,
        }

        target_input = ",".join(assessment_targets)
        phase_results = dict(workflow.get("phase_results") or {})
        assessment_phase = dict(phase_results.get("assessment") or {})
        assessment_phase.update({
            "status": "running",
            "targets": assessment_targets,
            "target_count": len(assessment_targets),
        })
        phase_results["assessment"] = assessment_phase
        workflow.update({
            "assessment_targets": assessment_targets,
            "assessment_target": target_input,
            "phase_results": phase_results,
        })

        transitioned = scan_store.transition_status(
            scan_id,
            {scan_store.STATUS_AWAITING_CONFIGURATION},
            scan_store.STATUS_ASSESSMENT_RUNNING,
            target=target_input,
            workflow_stage="assessment",
            workflow=workflow,
            scan_options=scan_options,
            completed_at=None,
            error=None,
        )
        if not transitioned:
            return render_template(
                "error.html",
                error_message="Phase 3 has already started or this mission is no longer configurable.",
            ), 409

        log.info(
            "[scan] phase3 started: %s targets=%s profile=%s technique_mode=%s enabled_tools=%s ports=%s advanced=%s",
            scan_id,
            assessment_targets,
            profile,
            technique_mode,
            enabled_tools,
            scan_options.get("port_selection"),
            scan_options.get("advanced_settings"),
        )
        scan_store.log(
            scan_id,
            f"Phase 3 requested: targets={target_input} profile={profile} "
            f"technique_mode={technique_mode} "
            f"tcp={scan_options.get('port_selection', {}).get('tcp', {}).get('mode')} "
            f"udp={scan_options.get('port_selection', {}).get('udp', {}).get('mode')}",
        )
        scan_store.audit_event(
            scan_id,
            "operator",
            "assessment_configuration_submitted",
            {
                "assessment_targets": assessment_targets,
                "target_count": len(assessment_targets),
                "profile": profile,
                "technique_mode": technique_mode,
            },
        )

        session["scan_id"] = scan_id
        session["target_ip"] = target_input
        session["assessment_targets"] = assessment_targets
        session["technique_mode"] = technique_mode
        session["scan_options"] = scan_options

        worker = _stub_assessment if os.getenv("PIPELINE_STUB") == "1" else run_pipeline
        threading.Thread(
            target=worker,
            args=(scan_id, target_input, scan_options),
            daemon=True,
        ).start()

        return render_template(
            "scanning.html",
            scan_id=scan_id,
            target=target_input,
            scan_options=scan_options,
            workflow_stage="assessment",
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

        status = str(data.get("status") or "")
        if status == scan_store.STATUS_AWAITING_SUBNET_SELECTION:
            return redirect(url_for("scan_select_subnet", scan_id=scan_id))
        if status == scan_store.STATUS_AWAITING_CONFIGURATION:
            return redirect(url_for("scan_configure", scan_id=scan_id))
        if status in {
            scan_store.STATUS_RUNNING,
            scan_store.STATUS_EXTERNAL_DISCOVERY,
            scan_store.STATUS_INTERNAL_DISCOVERY,
            scan_store.STATUS_ASSESSMENT_RUNNING,
        }:
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=data.get("target", ""),
                scan_options=data.get("scan_options") or {},
                workflow_stage=data.get("workflow_stage") or "",
            )

        session["scan_id"] = scan_id
        session["target_ip"] = data.get("target", "")
        session["scan_options"] = data.get("scan_options") or {}

        data = _ensure_scan_analysis(data)
        ai_plan = data.get("ai_plan") or {}
        mapping_result = data.get("mapping") or {}
        parsed_for_view = _stored_results_to_parsed_results(data.get("results") or {}, data)
        detected_cves = _build_detected_cve_rows(ai_plan, mapping_result, parsed_for_view)
        detected_cves_by_host = _detected_cve_groups_by_host(parsed_for_view)
        detected_cves_grouped = [
            row
            for host_rows in detected_cves_by_host.values()
            for row in host_rows
        ]

        return render_template(
            "results.html",
            scan=data,
            results=parsed_for_view,
            mapping=data.get("mapping") or {},
            ai_plan=ai_plan,
            detected_cves=detected_cves,
            detected_cves_by_host=detected_cves_by_host,
            detected_cves_grouped=detected_cves_grouped,
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
                mitre_status=mitre_status(),
            )
            from weasyprint import HTML

            pdf_bytes = HTML(string=html, base_url=str(Path.cwd())).write_pdf()
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
        return jsonify((data.get("results") or {}).get("caldera_handoff") or {})
