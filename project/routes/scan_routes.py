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
    continue_discovery_with_topology_path,
    discover_next_networks_from_device,
    prepare_assessment_from_current_layer,
    revisit_discovered_segment,
    retry_current_layer,
    run_discovery_pipeline,
    stop_discovery,
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
    # The port preview is derived through the same normalisation path used by
    # Phase 3 submission.  The frontend therefore does not maintain a second,
    # hard-coded definition of the Essentials profiles.
    preview_options = normalise_scan_options(
        "custom",
        None,
        tcp_port_mode="essentials",
        udp_port_mode="essentials",
    )
    port_selection = preview_options.get("port_selection") or {}
    return {
        "tool_options": TOOL_OPTIONS,
        "collector_catalog": ui.get("catalog") or [],
        "collector_groups": ui.get("groups") or [],
        "collection_presets": ui.get("presets") or {},
        "collector_policy_status": ui.get("policy_status"),
        "collector_policy_sha256": ui.get("policy_sha256"),
        "essential_tcp_ports": list((port_selection.get("tcp") or {}).get("ports") or []),
        "essential_udp_ports": list((port_selection.get("udp") or {}).get("ports") or []),
    }


def _device_presentation(host: dict) -> dict:
    """Build conservative Phase 2 device labels from already-retained evidence.

    This is presentation/classification only.  It does not run another probe and
    does not turn an unknown host into infrastructure merely because the operator
    selected it.
    """
    row = dict(host or {})
    role = str(row.get("role") or "").strip().lower()
    device_type = str(row.get("device_type") or "").strip()
    hostname = str(row.get("hostname") or "").strip()
    vendor = str(row.get("mac_vendor") or "").strip()

    generic_types = {"", "host", "observed device", "observed host", "endpoint"}
    if device_type.lower() not in generic_types:
        label = device_type
        quality = "Role established from retained discovery evidence"
    elif role in {"router", "router_or_switch", "gateway", "firewall", "network_device", "layer3", "layer_3"}:
        label = role.replace("_", " ").title()
        quality = "Role established from retained discovery evidence"
    else:
        label = "Device Role Not Established"
        quality = "Hostname/MAC/vendor identify the asset, but no retained evidence establishes its network role"

    if row.get("infrastructure_topology_queried") and not row.get("network_evidence_observed"):
        quality = "Network evidence checked; no additional network prefix was established"
    elif row.get("network_evidence_observed"):
        quality = "Network continuation evidence observed from this device"

    row["device_identity_label"] = label
    row["device_identity_quality"] = quality
    row["device_identity_hostname"] = hostname
    row["device_identity_vendor"] = vendor
    return row


def _discovery_identity_for_result(workflow: dict, target_text: str) -> dict:
    """Return retained discovery identity for one results-page target."""

    targets = [part.strip() for part in str(target_text or "").split(",") if part.strip()]
    if len(targets) != 1:
        return {}
    target = targets[0]
    asset = next(
        (
            dict(row)
            for row in (workflow or {}).get("asset_inventory")
            or (workflow or {}).get("discovered_hosts")
            or []
            if isinstance(row, dict)
            and str(row.get("ip") or row.get("address") or "").strip() == target
        ),
        {},
    )
    if not asset:
        return {}
    presented = _device_presentation(asset)
    hostname = str(presented.get("device_identity_hostname") or "").strip()
    vendor = str(presented.get("device_identity_vendor") or "").strip()
    device_label = str(presented.get("device_identity_label") or "Discovered Asset").strip()
    return {
        "target": target,
        "hostname": hostname,
        "vendor": vendor,
        "mac": str(asset.get("mac") or "").strip(),
        "device_label": device_label,
        "primary_label": hostname or device_label,
    }


def _assessment_segment_contexts(
    host: dict,
    segments: dict,
) -> list[dict]:
    """Return retained Phase 1/2 network contexts for one assessment target.

    Phase 3 must inherit the interface/source evidence that was already retained
    for the segment containing the target.  This helper deliberately uses only
    persisted discovery state; it does not consult the Kali kernel route table or
    execute any new network command.
    """

    host = dict(host or {})
    target = str(host.get("ip") or host.get("address") or "").strip()
    segment_ids = [str(value) for value in host.get("segment_ids") or [] if str(value).strip()]
    contexts: list[dict] = []

    for segment_id in segment_ids:
        segment = dict((segments or {}).get(segment_id) or {})
        if not segment:
            continue

        network_text = str(segment.get("network") or "").strip()
        contains_target = False
        if target and network_text:
            try:
                contains_target = ipaddress.ip_address(target) in ipaddress.ip_network(
                    network_text,
                    strict=False,
                )
            except ValueError:
                contains_target = False

        contexts.append({
            "segment_id": str(segment.get("segment_id") or segment_id),
            "network": network_text,
            "scope_kind": str(segment.get("scope_kind") or ""),
            "layer_index": int(segment.get("layer_index") or 0),
            "interface": str(segment.get("interface") or "").strip(),
            "scanner_ip": str(segment.get("source_address") or "").strip(),
            "gateway": str(segment.get("next_hop") or "").strip(),
            "route_table": str(segment.get("route_table") or "").strip(),
            "route_type": str(segment.get("route_type") or "").strip(),
            "access_mode": str(segment.get("access_mode") or "").strip(),
            "access_transport": str(
                segment.get("access_transport") or segment.get("access_mode") or ""
            ).strip(),
            "layer2_connected": bool(segment.get("layer2_connected")),
            "source_device_ip": str(segment.get("source_device_ip") or "").strip(),
            "contains_target": contains_target,
        })

    # Prefer the actual network layer containing the target, then a context
    # carrying an explicit interface/source, then the deepest retained layer.
    contexts.sort(
        key=lambda row: (
            0 if row.get("contains_target") else 1,
            0 if row.get("scope_kind") != "entry_host" else 1,
            0 if row.get("interface") else 1,
            0 if row.get("scanner_ip") else 1,
            -int(row.get("layer_index") or 0),
        )
    )
    return contexts


def _shared_assessment_network_context(target_contexts: dict[str, list[dict]]) -> dict:
    """Resolve a safe shared Phase 3 interface context when one exists.

    Existing Phase 3 collectors accept one workflow-level interface.  For a
    single target, or multiple targets retained on the same network segment, we
    preserve that exact Phase 2 interface/source.  If selected targets span
    different interfaces, the shared fields stay blank instead of binding every
    target to the wrong NIC; the per-target contexts remain retained for audit
    and future transport-specific handling.
    """

    primary = [contexts[0] for contexts in target_contexts.values() if contexts]
    if not primary or len(primary) != len(target_contexts):
        return {
            "route_interface": "",
            "scanner_ip": "",
            "gateway": "",
            "internal_subnet": "",
            "route_table": "",
            "route_type": "",
            "layer2_connected": False,
            "context_state": "per_target_or_unresolved",
        }

    def shared_value(key: str) -> str:
        values = {str(row.get(key) or "").strip() for row in primary}
        values.discard("")
        return next(iter(values)) if len(values) == 1 else ""

    interface = shared_value("interface")
    scanner_ip = shared_value("scanner_ip")
    network = shared_value("network")
    gateway = shared_value("gateway")
    route_table = shared_value("route_table")
    route_type = shared_value("route_type")

    # A global Layer-2 binding is valid only when every selected target shares
    # the same explicit interface and every primary context is directly attached.
    layer2_connected = bool(interface) and all(
        bool(row.get("layer2_connected")) for row in primary
    )

    return {
        "route_interface": interface,
        "scanner_ip": scanner_ip,
        "gateway": gateway,
        "internal_subnet": network,
        "route_table": route_table,
        "route_type": route_type,
        "layer2_connected": layer2_connected,
        "context_state": "shared_segment" if interface else "per_target_or_unresolved",
    }


def _detected_cve_groups_by_host(parsed_results: dict) -> dict[str, list[dict]]:
    """Build host-first UI rows without collapsing identical CVEs across targets."""

    canonical_groups = parsed_results.get("cve_review_candidates_by_host") or parsed_results.get("cve_matches_by_host") or {}
    if not isinstance(canonical_groups, dict) or not canonical_groups:
        canonical_groups = {}
        for row in parsed_results.get("cve_review_candidates") or parsed_results.get("cve_matches") or []:
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or "unattributed").strip() or "unattributed"
            canonical_groups.setdefault(host, []).append(row)

    grouped: dict[str, list[dict]] = {}
    for host, rows in canonical_groups.items():
        host_rows = [row for row in rows or [] if isinstance(row, dict)]
        host_results = dict(parsed_results)
        host_results["cve_review_candidates"] = host_rows
        host_results["cve_matches"] = [row for row in host_rows if str(row.get("applicability_state") or "matched") == "matched"]
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
                "AUTOPENTEST_STUB_HOST; no target or network is invented."
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
        time.sleep(0.02)
        scan_store.set_task(scan_id, task, scan_store.STATUS_SUCCESS, summary="Simulated complete")

    segment_id = "segment_stub"
    host = {
        "host_id": "host_stub",
        "segment_id": segment_id,
        "ip": str(host_ip),
        "address": str(host_ip),
        "status": "up",
        "reachability_state": "responsive",
        "hostname": "stub-target",
        "hostname_observations": [{"value": "stub-target", "source": "stub"}],
        "mac": "",
        "mac_vendor": "",
        "role": "host",
        "is_scanner": False,
        "selectable": True,
        "record_type": "stub_target",
        "origin": "explicit_stub_configuration",
        "origins": ["explicit_stub_configuration"],
        "independently_discovered": False,
        "discovered_by": ["explicit_stub_configuration"],
        "verification_methods": ["explicit_stub_configuration"],
    }
    segment = {
        "segment_id": segment_id,
        "layer_index": 0,
        "scope_kind": "route_network",
        "network": str(subnet),
        "enumeration_target": str(subnet),
        "interface": configured_interface,
        "source_address": "",
        "next_hop": "",
        "route_table": "stub",
        "route_type": "stub",
        "access_mode": "stub",
        "layer2_connected": False,
        "verification_state": "verified_reachable",
        "created_at": scan_store.now(),
        "last_enumerated_at": scan_store.now(),
        "hosts": [host],
        "path_ids": [],
        "discovery_execution": {
            "nmap_host_discovery": {
                "requested": True,
                "tool_available": True,
                "executed": True,
                "success": True,
                "evidence_produced": True,
            }
        },
        "route": {},
        "evidence": [{"type": "explicit_stub_configuration"}],
    }
    workflow = {
        "mode": "layered_network_discovery",
        "continuous": True,
        "entry_target": external_target,
        "external_target": external_target,
        "entry_result": {"target": external_target, "reachable": True, "reachability_state": "responsive", "evidence": []},
        "segments": {segment_id: segment},
        "paths": {},
        "route_observations": [],
        "baseline_route_signatures": [],
        "authorized_route_signatures": [],
        "authorized_route_networks": [],
        "authorized_route_records": {},
        "segment_order": [segment_id],
        "visited_segment_ids": [segment_id],
        "pending_path_ids": [],
        "current_segment_id": segment_id,
        "current_segment": segment,
        "operator_decisions": [],
        "assessment_targets": [],
        "assessment_target": None,
        "internal_subnet": str(subnet),
        "access_mode": "stub",
        "network_context": {
            "segment_id": segment_id,
            "interface": configured_interface,
            "scanner_ip": "",
            "gateway": "",
            "internal_subnet": str(subnet),
            "access_mode": "stub",
            "route_table": "stub",
            "route_type": "stub",
            "layer2_connected": False,
        },
        "discovered_hosts": [host],
        "phase_results": {
            "external": {"status": "completed", "target": external_target, "reachable": True},
            "entry": {"status": "completed", "target": external_target, "reachable": True},
            "internal": {"status": "completed", "subnet": str(subnet), "scope_kind": "route_network", "host_count": 1, "entry_target_count": 0, "independently_discovered_host_count": 0, "selectable_host_count": 1, "hosts": [host]},
            "traversal": {"status": "awaiting_operator_decision", "visited_segment_count": 1, "current_segment_id": segment_id, "pending_path_count": 0, "segments": [segment]},
            "assessment": {"status": "not_started", "targets": []},
        },
    }
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        results={
            "workflow": workflow,
            "phase_results": workflow["phase_results"],
            "hosts": [str(host_ip)],
            "internal_host_inventory": [host],
        },
        current_task="Waiting for operator decision",
        next_task="Assess this scope, refresh, retry, or stop",
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
        "cve_review_candidates": [],
        "cve_review_candidates_by_host": {},
        "cve_review_summary": {},
        "cve_matcher_audit": [],
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

def _network_discovery_multi_worker(scan_id: str, device_ips: list[str]) -> None:
    """Inspect selected Phase 2 devices sequentially and merge their branches.

    Sequential processing avoids multiple workers racing while they update the
    same mission JSON.  A failure on one selected device is retained without
    discarding evidence already collected from the others.
    """
    selected = list(dict.fromkeys(str(value).strip() for value in device_ips if str(value).strip()))
    failures: dict[str, str] = {}
    completed: list[str] = []
    for index, device_ip in enumerate(selected, start=1):
        scan_store.update(
            scan_id,
            current_task=f"Checking selected device {index}/{len(selected)} · {device_ip}",
            next_task="Present discovered device-to-network relationships",
            error=None,
        )
        scan_store.persist(scan_id)
        try:
            discover_next_networks_from_device(scan_id, device_ip)
            completed.append(device_ip)
        except Exception as exc:
            failures[device_ip] = str(exc)
            scan_store.log(
                scan_id,
                f"Selected-device network evidence collection failed for {device_ip}: {exc}",
                "ERROR",
            )

    data = scan_store.load(scan_id) or {}
    workflow = dict(data.get("workflow") or {})
    continuation = dict(workflow.get("topology_continuation") or {})
    continuation["selected_device_ips"] = selected
    continuation["completed_device_ips"] = completed
    continuation["device_failures"] = failures
    continuation["updated_at"] = scan_store.now()

    current_segment = dict(
        (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
    )
    current_paths = [
        path_id
        for path_id in current_segment.get("path_ids") or []
        if (workflow.get("paths") or {}).get(path_id)
        and (workflow.get("paths") or {}).get(path_id, {}).get("path_kind") == "infrastructure_topology"
    ]
    if current_paths:
        continuation["state"] = "network_evidence_observed"
        continuation["message"] = (
            f"Checked {len(selected)} selected device(s) and retained "
            f"{len(current_paths)} continuation network relationship(s)."
        )
    elif completed:
        continuation["state"] = "no_continuation_observed"
        continuation["message"] = (
            f"Checked {len(completed)} selected device(s); no additional continuation "
            "network was established from the observable evidence."
        )
    else:
        continuation["state"] = "discovery_failed"
        continuation["message"] = "Network evidence collection failed for every selected device."

    workflow["topology_continuation"] = continuation
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        current_task="Waiting for operator decision",
        next_task="Continue to a discovered network, inspect more devices, or finish Phase 2",
        error=("; ".join(f"{ip}: {message}" for ip, message in failures.items()) if failures and not completed else None),
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [
                str(host.get("ip") or host.get("address") or "")
                for host in workflow.get("asset_inventory") or []
                if isinstance(host, dict) and (host.get("ip") or host.get("address"))
            ],
            "internal_host_inventory": workflow.get("asset_inventory") or [],
        },
    )
    scan_store.persist(scan_id)


def _network_discovery_worker(scan_id: str, device_ip: str) -> None:
    """Compatibility wrapper for older one-device callers."""
    _network_discovery_multi_worker(scan_id, [device_ip])

def _command_output_for_operator(entry: dict) -> str:
    """Return console output without inlining a retained evidence file.

    Some scanner records append the full generated XML/text artefact after an
    ``[evidence file: ...]`` marker.  The persisted record remains unchanged;
    the UI shows the tool console output and exposes the artefact separately by
    filename.
    """
    output = str((entry or {}).get("output") or "")
    marker = "[evidence file:"
    position = output.lower().find(marker)
    if position >= 0:
        return output[:position].rstrip()
    return output


def _command_evidence_file(entry: dict) -> Path | None:
    raw = str((entry or {}).get("output_file") or "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = scan_store.SCANS_DIR / candidate.name
    try:
        resolved = candidate.resolve(strict=True)
        allowed_root = scan_store.SCANS_DIR.resolve(strict=True)
    except (OSError, FileNotFoundError):
        return None
    if resolved != allowed_root and allowed_root not in resolved.parents:
        return None
    return resolved if resolved.is_file() else None


def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/scan/discover", methods=["POST"])
    def scan_discover():
        try:
            entry_target = validate_external_target(
                request.form.get("external_target") or request.form.get("target") or ""
            )
        except Exception as exc:
            return render_template("error.html", error_message=str(exc)), 400

        scan_id = scan_store.new_scan(
            entry_target,
            request.remote_addr or "",
            request.headers.get("User-Agent", ""),
            scan_options={},
        )
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_ENTRY_DISCOVERY,
            workflow_stage="entry_discovery",
            workflow={
                "mode": "layered_network_discovery",
                "continuous": True,
                "entry_target": entry_target,
                "external_target": entry_target,
                "assessment_target": None,
                "segments": {},
                "paths": {},
            },
        )
        scan_store.log(scan_id, f"Entry discovery requested for target={entry_target}")
        scan_store.audit_event(
            scan_id,
            "operator",
            "entry_discovery_requested",
            {"entry_target": entry_target},
        )
        scan_store.persist(scan_id)

        _preserve_operator_session()
        session["scan_id"] = scan_id
        session["external_target"] = entry_target

        worker = _stub_discovery if os.getenv("PIPELINE_STUB") == "1" else run_discovery_pipeline
        threading.Thread(
            target=worker,
            args=(scan_id, entry_target),
            daemon=True,
        ).start()

        return render_template(
            "scanning.html",
            scan_id=scan_id,
            target=entry_target,
            scan_options={},
            workflow_stage="entry_discovery",
        )

    @app.route("/scan/select-subnet/<scan_id>", methods=["GET", "POST"])
    def scan_select_subnet(scan_id):
        """Compatibility endpoint for bookmarks from the earlier phased build."""
        return redirect(url_for("scan_layer_decision", scan_id=scan_id))

    @app.route("/scan/layer/<scan_id>", methods=["GET", "POST"])
    def scan_layer_decision(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan mission not found"), 404

        status = str(data.get("status") or "")
        if request.method == "GET":
            if status == scan_store.STATUS_AWAITING_CONFIGURATION:
                return redirect(url_for("scan_configure", scan_id=scan_id))
            if status != scan_store.STATUS_AWAITING_LAYER_DECISION:
                if status in {
                    scan_store.STATUS_ENTRY_DISCOVERY,
                    scan_store.STATUS_LAYER_ENUMERATION,
                    scan_store.STATUS_PATH_VERIFICATION,
                    scan_store.STATUS_ASSESSMENT_RUNNING,
                    scan_store.STATUS_RUNNING,
                }:
                    return redirect(url_for("scan_results", scan_id=scan_id))
                return render_template(
                    "error.html",
                    error_message="This mission is not waiting for a Phase 2 discovery decision.",
                ), 409

            workflow = dict(data.get("workflow") or {})
            current_segment = dict(
                (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
            )
            if not current_segment:
                return render_template(
                    "error.html",
                    error_message="The current discovery-layer record is unavailable.",
                ), 409

            path_rows = [
                dict((workflow.get("paths") or {}).get(path_id) or {})
                for path_id in current_segment.get("path_ids") or []
                if (workflow.get("paths") or {}).get(path_id)
                and (workflow.get("paths") or {}).get(path_id, {}).get("path_kind") == "infrastructure_topology"
            ]
            path_rows.sort(key=lambda row: str(row.get("destination_network") or ""))
            current_hosts = [
                dict(host)
                for host in current_segment.get("hosts") or []
                if isinstance(host, dict) and not host.get("is_scanner") and (host.get("ip") or host.get("address"))
            ]
            continuation_state = dict(workflow.get("topology_continuation") or {})
            selected_device_ip = str(continuation_state.get("selected_device_ip") or "")
            selected_device_ips = [
                str(value)
                for value in continuation_state.get("selected_device_ips") or ([selected_device_ip] if selected_device_ip else [])
                if str(value)
            ]
            selected_device_set = set(selected_device_ips)
            for host in current_hosts:
                host_ip = str(host.get("ip") or host.get("address") or "")
                host["topology_selected"] = bool(host_ip and host_ip in selected_device_set)
            inventory = [
                dict(host)
                for host in workflow.get("asset_inventory") or workflow.get("discovered_hosts") or []
                if isinstance(host, dict) and (host.get("ip") or host.get("address"))
            ]
            # Current-segment host rows are the raw discovery observations.
            # Overlay the accumulated inventory classification so MAC/vendor,
            # hostname and infrastructure hints discovered earlier are visible
            # when the operator chooses a continuation device.
            inventory_by_ip = {
                str(host.get("ip") or host.get("address") or ""): host
                for host in inventory
            }
            for host in current_hosts:
                host_ip = str(host.get("ip") or host.get("address") or "")
                retained = inventory_by_ip.get(host_ip) or {}
                for key in (
                    "hostname",
                    "mac",
                    "mac_vendor",
                    "role",
                    "device_type",
                    "infrastructure_candidate_state",
                    "infrastructure_candidate_reason",
                    "infrastructure_topology_queried",
                    "network_evidence_checked",
                    "network_evidence_observed",
                    "topology_platform",
                    "device_interfaces",
                ):
                    if retained.get(key) not in (None, "", [], {}):
                        host[key] = retained.get(key)
            current_hosts = [_device_presentation(host) for host in current_hosts]
            inventory_by_ip = {
                str(host.get("ip") or host.get("address") or ""): host
                for host in inventory
            }
            for path in path_rows:
                source_ip = str(path.get("source_device_ip") or "")
                source_host = _device_presentation(inventory_by_ip.get(source_ip) or {"ip": source_ip})
                path["source_device_label"] = source_host.get("device_identity_label") or "Device role not established"
                path["source_device_hostname"] = source_host.get("hostname") or ""

            inconclusive_operator_targets = [
                host
                for host in inventory
                if str(host.get("record_type") or "") == "entry_target"
                and str(host.get("origin") or "") == "operator_supplied"
                and not host.get("is_scanner")
                and not host.get("selectable")
            ]
            visited_segments = [
                dict((workflow.get("segments") or {}).get(segment_id) or {})
                for segment_id in workflow.get("segment_order") or []
                if (workflow.get("segments") or {}).get(segment_id)
            ]
            session["scan_id"] = scan_id
            return render_template(
                "layer_decision.html",
                scan_id=scan_id,
                workflow=workflow,
                current_segment=current_segment,
                current_hosts=current_hosts,
                all_discovered_hosts=inventory,
                continuation_paths=path_rows,
                topology_continuation=continuation_state,
                selected_device_ip=selected_device_ip,
                selected_device_ips=selected_device_ips,
                inconclusive_operator_targets=inconclusive_operator_targets,
                visited_segments=visited_segments,
                mission_error=data.get("error"),
            )

        if status != scan_store.STATUS_AWAITING_LAYER_DECISION:
            return render_template(
                "error.html",
                error_message="The Phase 2 decision has already been submitted.",
            ), 409

        action = str(request.form.get("action") or "").strip().lower()

        if action in {"finish_phase2", "assess_current"}:
            try:
                prepare_assessment_from_current_layer(
                    scan_id,
                    allow_inconclusive_operator_targets=(
                        str(request.form.get("allow_inconclusive_operator_targets") or "")
                        .strip()
                        .lower()
                        in {"1", "true", "yes", "on"}
                    ),
                )
            except Exception as exc:
                return render_template("error.html", error_message=str(exc)), 400
            return redirect(url_for("scan_configure", scan_id=scan_id))

        if action in {"discover_device", "query_device"}:
            raw_device_ips = request.form.getlist("device_ips") or request.form.getlist("device_ip")
            device_ips = list(
                dict.fromkeys(str(value).strip() for value in raw_device_ips if str(value).strip())
            )
            if not device_ips:
                return render_template(
                    "error.html", error_message="Select one or more discovered devices to inspect."
                ), 400

            workflow = dict(data.get("workflow") or {})
            current_segment = dict(
                (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
            )
            current_host_ips = {
                str(host.get("ip") or host.get("address") or "").strip()
                for host in current_segment.get("hosts") or []
                if isinstance(host, dict) and not host.get("is_scanner")
            }
            invalid = [device_ip for device_ip in device_ips if device_ip not in current_host_ips]
            if invalid:
                return render_template(
                    "error.html",
                    error_message="Every selected device must be retained in the current discovery layer.",
                ), 400

            continuation_state = dict(workflow.get("topology_continuation") or {})
            continuation_state.update({
                "selected_device_ip": device_ips[-1],
                "selected_device_ips": device_ips,
                "state": "collecting_network_evidence",
                "access_source": "observed_network_evidence",
                "message": f"Checking {len(device_ips)} selected device(s) for network continuation evidence.",
                "selected_at": scan_store.now(),
                "updated_at": scan_store.now(),
            })
            workflow["topology_continuation"] = continuation_state
            workflow.setdefault("operator_decisions", []).append(
                {
                    "decision": "select_discovery_devices",
                    "segment_id": workflow.get("current_segment_id"),
                    "device_ips": device_ips,
                    "timestamp": scan_store.now(),
                }
            )

            transitioned = scan_store.transition_status(
                scan_id,
                {scan_store.STATUS_AWAITING_LAYER_DECISION},
                scan_store.STATUS_LAYER_ENUMERATION,
                workflow_stage="network_evidence_discovery",
                workflow=workflow,
                current_task=f"Checking {len(device_ips)} selected device(s) for network continuation",
                next_task="Present discovered device-to-network relationships",
                completed_at=None,
                error=None,
            )
            if not transitioned:
                return render_template("error.html", error_message="The Phase 2 decision was already submitted."), 409
            scan_store.persist(scan_id)
            threading.Thread(
                target=_network_discovery_multi_worker,
                args=(scan_id, device_ips),
                daemon=True,
            ).start()
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=(data.get("workflow") or {}).get("entry_target") or data.get("target", ""),
                scan_options={},
                workflow_stage="network_evidence_discovery",
            )

        if action in {"continue_path", "follow_path"}:
            path_id = str(request.form.get("path_id") or "").strip()
            access_transport = str(request.form.get("access_transport") or "direct").strip().lower()
            workflow = dict(data.get("workflow") or {})
            path = dict((workflow.get("paths") or {}).get(path_id) or {})
            if not path_id or not path or path.get("path_kind") != "infrastructure_topology":
                return render_template(
                    "error.html", error_message="Select one discovered continuation network."
                ), 400
            if path.get("from_segment_id") != workflow.get("current_segment_id"):
                return render_template(
                    "error.html", error_message="The selected network does not start from the current layer."
                ), 400
            if not path.get("enumeration_eligible"):
                return render_template(
                    "error.html", error_message="The selected network is not eligible for bounded enumeration."
                ), 400
            if access_transport not in {"direct"}:
                return render_template("error.html", error_message="Choose a supported access method."), 400
            transitioned = scan_store.transition_status(
                scan_id,
                {scan_store.STATUS_AWAITING_LAYER_DECISION},
                scan_store.STATUS_PATH_VERIFICATION,
                workflow_stage="path_verification",
                current_task="Verifying selected network branch",
                next_task="Enumerate the approved network layer",
                completed_at=None,
                error=None,
            )
            if not transitioned:
                return render_template("error.html", error_message="The Phase 2 decision was already submitted."), 409
            scan_store.persist(scan_id)
            threading.Thread(
                target=continue_discovery_with_topology_path,
                args=(scan_id, path_id),
                kwargs={"access_transport": access_transport},
                daemon=True,
            ).start()
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=workflow.get("entry_target") or data.get("target", ""),
                scan_options={},
                workflow_stage="path_verification",
            )

        if action == "retry_layer":
            transitioned = scan_store.transition_status(
                scan_id,
                {scan_store.STATUS_AWAITING_LAYER_DECISION},
                scan_store.STATUS_LAYER_ENUMERATION,
                workflow_stage="layer_enumeration",
                current_task="Repeating current-layer enumeration",
                next_task="Return to operator decision",
                completed_at=None,
                error=None,
            )
            if not transitioned:
                return render_template("error.html", error_message="The Phase 2 decision was already submitted."), 409
            scan_store.persist(scan_id)
            threading.Thread(target=retry_current_layer, args=(scan_id,), daemon=True).start()
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=(data.get("workflow") or {}).get("entry_target") or data.get("target", ""),
                scan_options={},
                workflow_stage="layer_enumeration",
            )

        if action == "revisit_segment":
            segment_id = str(request.form.get("segment_id") or "").strip()
            workflow = dict(data.get("workflow") or {})
            if not segment_id or segment_id not in set(workflow.get("visited_segment_ids") or []):
                return render_template("error.html", error_message="Select one previously discovered layer."), 400
            if segment_id == str(workflow.get("current_segment_id") or ""):
                return redirect(url_for("scan_layer_decision", scan_id=scan_id))
            transitioned = scan_store.transition_status(
                scan_id,
                {scan_store.STATUS_AWAITING_LAYER_DECISION},
                scan_store.STATUS_LAYER_ENUMERATION,
                workflow_stage="layer_revisit",
                current_task="Returning to selected discovery layer",
                next_task="Return to operator decision",
                completed_at=None,
                error=None,
            )
            if not transitioned:
                return render_template("error.html", error_message="The Phase 2 decision was already submitted."), 409
            scan_store.persist(scan_id)
            threading.Thread(target=revisit_discovered_segment, args=(scan_id, segment_id), daemon=True).start()
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=workflow.get("entry_target") or data.get("target", ""),
                scan_options={},
                workflow_stage="layer_revisit",
            )

        if action == "stop":
            try:
                stop_discovery(scan_id)
            except Exception as exc:
                return render_template("error.html", error_message=str(exc)), 400
            return redirect(url_for("scan_configure", scan_id=scan_id))

        return render_template(
            "error.html",
            error_message="Choose Continue Discovery, Finish Phase 2, Retry, or a visited layer.",
        ), 400

    @app.route("/scan/configure/<scan_id>")
    def scan_configure(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan mission not found"), 404
        if data.get("status") != scan_store.STATUS_AWAITING_CONFIGURATION:
            if data.get("status") == scan_store.STATUS_AWAITING_LAYER_DECISION:
                return redirect(url_for("scan_layer_decision", scan_id=scan_id))
            if data.get("status") in {
                scan_store.STATUS_ENTRY_DISCOVERY,
                scan_store.STATUS_LAYER_ENUMERATION,
                scan_store.STATUS_PATH_VERIFICATION,
                scan_store.STATUS_ASSESSMENT_RUNNING,
                scan_store.STATUS_RUNNING,
            }:
                return redirect(url_for("scan_results", scan_id=scan_id))
            return render_template(
                "error.html",
                error_message="This scan mission is not waiting for Phase 3 configuration.",
            ), 409

        workflow = dict(data.get("workflow") or {})
        current_segment = dict(
            (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
        )
        discovered_hosts = [
            dict(host)
            for host in workflow.get("asset_inventory") or workflow.get("discovered_hosts") or []
            if isinstance(host, dict)
            and host.get("selectable")
            and not host.get("is_scanner")
            and (host.get("ip") or host.get("address"))
        ]
        if not discovered_hosts:
            return render_template(
                "error.html",
                error_message="No selectable target is available in the retained Phase 1/2 inventory.",
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
            current_segment=current_segment,
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
        current_segment = dict(
            (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
        )
        retained_host_records = {
            str(host.get("ip") or host.get("address") or ""): dict(host)
            for host in workflow.get("asset_inventory") or workflow.get("discovered_hosts") or []
            if isinstance(host, dict)
            and host.get("selectable")
            and not host.get("is_scanner")
            and str(host.get("ip") or host.get("address") or "")
        }
        if not assessment_targets:
            return render_template(
                "error.html",
                error_message="Select at least one retained target.",
            ), 400

        invalid_targets = [target for target in assessment_targets if target not in retained_host_records]
        if invalid_targets:
            return render_template(
                "error.html",
                error_message=(
                    "One or more selected assessment targets were not retained during Phase 1/2 discovery."
                ),
            ), 400

        scanner_sources = {
            str(segment.get("source_address") or "").strip()
            for segment in (workflow.get("segments") or {}).values()
            if isinstance(segment, dict) and str(segment.get("source_address") or "").strip()
        }
        scanner_sources.update(
            str(host.get("ip") or host.get("address") or "").strip()
            for host in workflow.get("asset_inventory") or []
            if isinstance(host, dict) and host.get("is_scanner")
        )
        if any(target in scanner_sources for target in assessment_targets):
            return render_template(
                "error.html",
                error_message="A scanner/controller address cannot be selected for assessment.",
            ), 400

        scan_options, technique_mode, profile, enabled_tools = _scan_options_from_form()
        if scan_options.get("validation_errors"):
            return render_template(
                "error.html",
                error_message="; ".join(scan_options["validation_errors"]),
            ), 400

        selected_host_records = {
            target: retained_host_records[target]
            for target in assessment_targets
            if target in retained_host_records
        }
        override_targets = [
            target
            for target, host in selected_host_records.items()
            if host.get("assessment_discovery_bypass")
        ]
        if override_targets:
            host_discovery = dict(scan_options.get("host_discovery") or {})
            host_discovery["assume_single_target_live"] = True
            host_discovery["operator_override_targets"] = override_targets
            host_discovery["operator_override_reason"] = (
                "operator_authorized_inconclusive_reachability"
            )
            scan_options["host_discovery"] = host_discovery

        target_contexts = {}
        target_assets = {
            target: {
                "ip": target,
                "hostname": str((retained_host_records.get(target) or {}).get("hostname") or ""),
                "mac": str((retained_host_records.get(target) or {}).get("mac") or ""),
                "mac_vendor": str((retained_host_records.get(target) or {}).get("mac_vendor") or ""),
                "device_type": str((retained_host_records.get(target) or {}).get("device_type") or ""),
                "role": str((retained_host_records.get(target) or {}).get("role") or ""),
                "origin": str((retained_host_records.get(target) or {}).get("origin") or ""),
                "discovery_layers": list((retained_host_records.get(target) or {}).get("discovery_layers") or []),
                "topology_platform": str((retained_host_records.get(target) or {}).get("topology_platform") or ""),
                "infrastructure_candidate_state": str((retained_host_records.get(target) or {}).get("infrastructure_candidate_state") or ""),
            }
            for target in assessment_targets
        }
        segments = workflow.get("segments") or {}
        for target in assessment_targets:
            host = retained_host_records.get(target) or {}
            target_contexts[target] = _assessment_segment_contexts(host, segments)

        shared_network_context = _shared_assessment_network_context(target_contexts)

        pivot_assessment_targets = []
        for target, contexts in target_contexts.items():
            transports = {
                str(context.get("access_transport") or context.get("access_mode") or "").strip().lower()
                for context in contexts
                if isinstance(context, dict)
            }
            direct_known = bool(transports & {"direct", "entry_target", "routed", "directly_connected"})
            if "pivot" in transports and not direct_known:
                pivot_assessment_targets.append(target)

        scan_options["workflow_context"] = {
            "segment_id": "multi_segment_inventory",
            "route_interface": shared_network_context.get("route_interface", ""),
            "scanner_ip": shared_network_context.get("scanner_ip", ""),
            "gateway": shared_network_context.get("gateway", ""),
            "internal_subnet": shared_network_context.get("internal_subnet", ""),
            "access_mode": "retained_inventory",
            "route_table": shared_network_context.get("route_table", ""),
            "route_type": shared_network_context.get("route_type", ""),
            "layer2_connected": bool(shared_network_context.get("layer2_connected")),
            "network_context_state": shared_network_context.get("context_state", ""),
            "assessment_targets": assessment_targets,
            "target_contexts": target_contexts,
            "target_assets": target_assets,
            "pivot_targets": pivot_assessment_targets,
            "inconclusive_reachability_override_targets": override_targets,
        }

        target_input = ",".join(assessment_targets)
        assessment_started_at = scan_store.now()
        phase_results = dict(workflow.get("phase_results") or {})
        assessment_phase = dict(phase_results.get("assessment") or {})
        assessment_phase.update({
            "status": "running",
            "targets": assessment_targets,
            "target_count": len(assessment_targets),
            "segment_id": "multi_segment_inventory",
            "network": "multiple_retained_scopes",
            "started_at": assessment_started_at,
            "inconclusive_reachability_override_targets": override_targets,
        })
        phase_results["assessment"] = assessment_phase
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "select_assessment_targets",
                "segment_id": "multi_segment_inventory",
                "network": "multiple_retained_scopes",
                "targets": assessment_targets,
                "target_count": len(assessment_targets),
                "inconclusive_reachability_override_targets": override_targets,
                "state_before": scan_store.STATUS_AWAITING_CONFIGURATION,
                "state_after": scan_store.STATUS_ASSESSMENT_RUNNING,
                "timestamp": scan_store.now(),
            }
        )
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
            assessment_started_at=assessment_started_at,
            completed_at=None,
            error=None,
        )
        if not transitioned:
            return render_template(
                "error.html",
                error_message="Phase 3 has already started or this mission is no longer configurable.",
            ), 409
        scan_store.persist(scan_id)

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
                "segment_id": "multi_segment_inventory",
                "network": "multiple_retained_scopes",
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

    @app.route("/scan/status-lite/<scan_id>")
    def scan_status_lite(scan_id):
        """Lightweight live status for Phase 3 presentation.

        The existing /scan/status endpoint is intentionally preserved for
        compatibility.  This endpoint omits raw command output and the full
        assessment result package so browser polling cannot grow with evidence
        volume.
        """
        data = scan_store.progress_summary(scan_id)
        if not data:
            return jsonify({"error": "not found"}), 404
        response = make_response(jsonify(data))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.route("/scan/command-evidence/<scan_id>/<int:command_index>")
    def scan_command_evidence(scan_id, command_index):
        """Fetch one completed command's retained evidence on demand."""
        data = scan_store.load(scan_id)
        if not data:
            return jsonify({"error": "not found"}), 404
        command_log = data.get("command_log") or [
            entry
            for entry in data.get("activity_log", [])
            if isinstance(entry, dict) and entry.get("command")
        ]
        if command_index < 0 or command_index >= len(command_log):
            return jsonify({"error": "command evidence not found"}), 404
        entry = command_log[command_index]
        if not isinstance(entry, dict):
            return jsonify({"error": "command evidence not found"}), 404
        response = make_response(jsonify({
            "command_index": command_index,
            "time": entry.get("time") or "",
            "timestamp": entry.get("timestamp") or "",
            "status": entry.get("status") or entry.get("level") or "",
            "command": entry.get("command") or "",
            "purpose": entry.get("purpose") or entry.get("description") or entry.get("message") or "",
            "output": _command_output_for_operator(entry),
            "output_summary": entry.get("output_summary") or "",
            "exit_code": entry.get("exit_code", ""),
            "output_file": Path(str(entry.get("output_file") or "")).name if entry.get("output_file") else "",
            "output_file_url": (
                url_for("scan_evidence_file", scan_id=scan_id, command_index=command_index)
                if _command_evidence_file(entry) is not None
                else ""
            ),
            "output_truncated": bool(entry.get("output_truncated")),
            "started_at": entry.get("started_at") or "",
            "ended_at": entry.get("ended_at") or "",
            "target": entry.get("target") or "",
        }))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.route("/scan/evidence-file/<scan_id>/<int:command_index>")
    def scan_evidence_file(scan_id, command_index):
        """Open one retained evidence artefact by filename, never by caller path."""
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan not found"), 404
        command_log = data.get("command_log") or [
            entry
            for entry in data.get("activity_log", [])
            if isinstance(entry, dict) and entry.get("command")
        ]
        if command_index < 0 or command_index >= len(command_log):
            return render_template("error.html", error_message="Evidence file not found"), 404
        entry = command_log[command_index]
        if not isinstance(entry, dict):
            return render_template("error.html", error_message="Evidence file not found"), 404
        evidence_path = _command_evidence_file(entry)
        if evidence_path is None:
            return render_template("error.html", error_message="Evidence file is unavailable"), 404
        return send_file(
            evidence_path,
            as_attachment=False,
            download_name=evidence_path.name,
            max_age=0,
        )

    @app.route("/scan/results/<scan_id>")
    def scan_results(scan_id):
        data = scan_store.load(scan_id)
        if not data:
            return render_template("error.html", error_message="Scan not found"), 404

        status = str(data.get("status") or "")
        if status in {scan_store.STATUS_AWAITING_SUBNET_SELECTION, scan_store.STATUS_AWAITING_LAYER_DECISION}:
            return redirect(url_for("scan_layer_decision", scan_id=scan_id))
        if status == scan_store.STATUS_AWAITING_CONFIGURATION:
            return redirect(url_for("scan_configure", scan_id=scan_id))
        if status in {
            scan_store.STATUS_RUNNING,
            scan_store.STATUS_EXTERNAL_DISCOVERY,
            scan_store.STATUS_INTERNAL_DISCOVERY,
            scan_store.STATUS_ENTRY_DISCOVERY,
            scan_store.STATUS_LAYER_ENUMERATION,
            scan_store.STATUS_PATH_VERIFICATION,
            scan_store.STATUS_ASSESSMENT_RUNNING,
        }:
            return render_template(
                "scanning.html",
                scan_id=scan_id,
                target=data.get("target", ""),
                scan_options=data.get("scan_options") or {},
                workflow_stage=data.get("workflow_stage") or "",
            )

        if str(data.get("workflow_stage") or "") == "discovery_stopped":
            return render_template(
                "discovery_summary.html",
                scan=data,
                workflow=data.get("workflow") or {},
                results=data.get("results") or {},
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
            discovery_identity=_discovery_identity_for_result(
                data.get("workflow") or {},
                data.get("target") or "",
            ),
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
