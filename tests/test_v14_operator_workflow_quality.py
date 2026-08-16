from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "project"


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_phase1_intro_is_concise_and_old_continuation_copy_removed():
    text = read("project/templates/index.html")
    assert "PHASE 1 · ENTRY DISCOVERY" in text
    assert "Start from one authorised IP address" in text
    assert "OPERATOR-CONTROLLED CONTINUATION" not in text
    assert "Operator Path Decision" not in text
    assert "Existing Phase 3" not in text


def test_phase2_uses_multiselect_and_evidence_based_device_labels():
    template = read("project/templates/layer_decision.html")
    routes = read("project/routes/scan_routes.py")
    assert 'type="checkbox" name="device_ips"' in template
    assert 'request.form.getlist("device_ips")' in routes
    assert "_network_discovery_multi_worker" in routes
    assert "Devices Discovered on Current Subnet" in template
    assert "Find Next Networks" in template
    assert "Device Role Not Established" in template
    assert "Possible infrastructure candidate" not in template
    assert "Continuation branches are created only" not in template
    assert "RULE" not in template


def test_phase2_selected_devices_are_processed_sequentially():
    routes = read("project/routes/scan_routes.py")
    start = routes.index("def _network_discovery_multi_worker")
    end = routes.index("def _network_discovery_worker", start)
    body = routes[start:end]
    assert "for index, device_ip in enumerate(selected" in body
    assert "discover_next_networks_from_device(scan_id, device_ip)" in body
    assert "threading.Thread" not in body


def test_selected_host_is_not_automatically_classified_as_network_device():
    source = read("project/scanners/phase_discovery.py")
    start = source.index("def _update_asset_device_classification")
    end = source.index("def _retain_topology_interface_assets", start)
    body = source[start:end]
    assert "network_evidence_observed" in body
    assert "role_established = bool(network_evidence_observed)" in body
    assert "if role_established:" in body


def test_active_phase2_snapshot_does_not_read_kernel_route_table():
    source = read("project/scanners/phase_discovery.py")
    start = source.index("def collect_local_observation_snapshot")
    end = source.index("def _asset_ip", start)
    body = source[start:end]
    assert "ip -j route" not in body
    assert "ip route" not in body
    assert '"routes": []' in body

    topology = read("project/scanners/topology_evidence.py")
    assert "kernel_route_evidence" not in topology
    assert "kernel_route_table" not in topology

    run_start = source.index("def run_discovery_pipeline")
    run_end = source.index("def retry_current_layer", run_start)
    run_body = source[run_start:run_end]
    assert '"kernel_route_discovery": False' in run_body
    assert "_route_get(" not in run_body


def test_phase3_flow_and_exact_port_previews_are_present():
    template = read("project/templates/assessment_config.html")
    for label in (
        "Port &amp; Service Enumeration",
        "Service &amp; Host Identification",
        "Service-Specific Enumeration",
        "Evidence Recovery",
        "Per-Target Consolidation",
    ):
        assert label in template
    assert "essential_tcp_ports" in template
    assert "essential_udp_ports" in template
    assert "parsePortSpecPreview" in template
    assert "Selected TCP ports" in template
    assert "Selected UDP ports" in template
    assert "1–65535" in template
    assert "addEventListener('input'" in template


def test_essentials_preview_uses_the_same_backend_normalisation():
    sys.path.insert(0, str(PROJECT))
    try:
        from scanners.scan_profiles import normalise_scan_options, parse_port_spec
        options = normalise_scan_options(
            "custom", None, tcp_port_mode="essentials", udp_port_mode="essentials"
        )
        assert len(options["port_selection"]["tcp"]["ports"]) == 81
        assert len(options["port_selection"]["udp"]["ports"]) == 22
        assert parse_port_spec("22,80,443,8000-8005") == [22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
    finally:
        sys.path.pop(0)


def test_command_logs_use_copy_and_on_demand_view_evidence():
    scanning = read("project/templates/scanning.html")
    appendix = read("project/templates/technical_appendix.html")
    scan_routes = read("project/routes/scan_routes.py")
    assert "Copy Command" in scanning
    assert "View Evidence" in scanning
    assert "View Raw Evidence" not in scanning
    assert "Copy Command" in appendix
    assert "View Evidence" in appendix
    assert "entry.output or entry.result" not in appendix
    assert "/scan/command-evidence/" in scanning
    assert "/scan/command-evidence/" in appendix
    assert 'Path(str(entry.get("output_file") or "")).name' in scan_routes
    assert "_command_output_for_operator" in scan_routes
    assert "output_file_url" in scan_routes
    assert "/scan/evidence-file/" in scan_routes


def test_client_facing_command_records_keep_exact_command_but_omit_raw_output():
    source = read("project/routes/results_routes.py")
    start = source.index("def _client_safe_scan_record")
    end = source.index("def _client_safe_results_record", start)
    body = source[start:end]
    assert "entry['command_index'] = index" in body
    assert "entry.pop('output', None)" in body
    assert "entry.pop('result', None)" in body
    assert "entry['command']" not in body
    assert "os.path.basename" in body


def test_results_summary_uses_retained_host_identity_and_precise_metric_label():
    template = read("project/templates/results.html")
    assert "host_identity_inventory" in template
    assert "overview_identity" in template
    assert "Versioned service endpoints" in template
    assert "Route Observations" not in template
    assert "Authorised Routes" not in template
    assert "Continuation Networks" in template


def test_stale_route_and_readonly_ui_copy_is_absent():
    combined = "\n".join(
        read(path)
        for path in (
            "project/templates/index.html",
            "project/templates/layer_decision.html",
            "project/templates/scanning.html",
            "project/templates/assessment_config.html",
            "project/templates/results.html",
            "project/templates/technical_appendix.html",
        )
    )
    for stale in (
        "Read-only topology access",
        "ON-DEMAND READ-ONLY TOPOLOGY ACCESS",
        "Workflow State",
        "local subnet enumeration",
        "Query Infrastructure Topology",
        "Kernel-selected",
    ):
        assert stale not in combined
