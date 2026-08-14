from __future__ import annotations

from pathlib import Path

from scanners import phase_discovery
from scanners.infrastructure_discovery import parse_topology_output
from storage import scan_store


def test_cisco_interface_query_reveals_other_connected_network():
    text = """Interface              IP-Address      OK? Method Status                Protocol
Vlan10                  192.168.50.2    YES manual up                    up
Vlan20                  198.18.20.1     YES manual up                    up
C    192.168.50.0/24 is directly connected, Vlan10
C    198.18.20.0/24 is directly connected, Vlan20
"""
    interfaces, routes = parse_topology_output("cisco_ios", "ssh", text)
    assert {row["address"] for row in interfaces} == {"192.168.50.2", "198.18.20.1"}
    assert {row["network"] for row in routes} >= {"192.168.50.0/24", "198.18.20.0/24"}


def test_topology_query_excludes_current_facing_network_and_builds_operator_path(monkeypatch):
    scan_id = scan_store.new_scan("192.168.50.2")
    segment = {
        "segment_id": "segment_entry",
        "layer_index": 0,
        "scope_kind": "entry_host",
        "network": "192.168.50.2/32",
        "hosts": [{"ip": "192.168.50.2", "selectable": True, "role": "entry_target"}],
        "path_ids": [],
    }
    workflow = {
        "entry_target": "192.168.50.2",
        "entry_result": {"reachable": True},
        "segments": {segment["segment_id"]: segment},
        "segment_order": [segment["segment_id"]],
        "visited_segment_ids": [segment["segment_id"]],
        "current_segment_id": segment["segment_id"],
        "paths": {},
        "asset_inventory": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    phase_discovery._accumulate_assets(workflow, segment["hosts"], segment=segment)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_LAYER_DECISION, workflow=workflow)

    monkeypatch.setattr(
        "scanners.infrastructure_discovery.collect_device_topology",
        lambda *_args, **_kwargs: {
            "observation_id": "infraobs_test",
            "device_ip": "192.168.50.2",
            "profile_ref": "lab-ro",
            "platform": "cisco_ios",
            "transport": "ssh",
            "interfaces": [],
            "routes": [],
            "networks": [
                {
                    "destination_network": "192.168.50.0/24",
                    "device_interface": "Vlan10",
                    "device_interface_ip": "192.168.50.2",
                    "enumeration_eligible": True,
                    "evidence_sources": ["device_interface"],
                },
                {
                    "destination_network": "10.20.30.0/24",
                    "device_interface": "Vlan20",
                    "device_interface_ip": "10.20.30.1",
                    "enumeration_eligible": True,
                    "evidence_sources": ["device_interface"],
                },
            ],
        },
    )
    monkeypatch.setattr(
        "scanners.enterprise_readiness.validate_scope",
        lambda *_args, **_kwargs: {"scope_mode": "test"},
    )
    monkeypatch.setattr(
        phase_discovery,
        "_discovery_network_scope_state",
        lambda _network: (True, "test"),
    )

    phase_discovery.discover_next_networks_from_device(scan_id, "192.168.50.2", profile_ref="lab-ro")
    data = scan_store.get(scan_id)
    paths = list(data["workflow"]["paths"].values())
    assert [row["destination_network"] for row in paths] == ["10.20.30.0/24"]
    assert paths[0]["path_kind"] == "infrastructure_topology"
    assert paths[0]["authorization_state"] == "operator_selection_required"
    assert data["workflow"]["asset_inventory"][0]["device_type"] == "Cisco network device"


def test_finish_phase2_exposes_assets_from_multiple_layers():
    scan_id = scan_store.new_scan("192.168.50.2")
    entry = {
        "segment_id": "entry",
        "layer_index": 0,
        "scope_kind": "entry_host",
        "network": "192.168.50.2/32",
        "hosts": [{"ip": "192.168.50.2", "selectable": True, "role": "router"}],
    }
    internal = {
        "segment_id": "internal",
        "layer_index": 1,
        "scope_kind": "topology_network",
        "network": "10.20.30.0/24",
        "hosts": [
            {"ip": "10.20.30.1", "selectable": True, "role": "firewall"},
            {"ip": "10.20.30.25", "selectable": True, "role": "host"},
        ],
    }
    workflow = {
        "entry_target": "192.168.50.2",
        "entry_result": {"reachable": True},
        "segments": {"entry": entry, "internal": internal},
        "segment_order": ["entry", "internal"],
        "visited_segment_ids": ["entry", "internal"],
        "current_segment_id": "internal",
        "paths": {},
        "asset_inventory": [],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    for segment in (entry, internal):
        phase_discovery._accumulate_assets(workflow, segment["hosts"], segment=segment)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_LAYER_DECISION, workflow=workflow)

    phase_discovery.prepare_assessment_from_current_layer(scan_id)
    data = scan_store.get(scan_id)
    assert data["status"] == scan_store.STATUS_AWAITING_CONFIGURATION
    assert {row["ip"] for row in data["workflow"]["asset_inventory"] if row.get("selectable")} == {
        "192.168.50.2",
        "10.20.30.1",
        "10.20.30.25",
    }
    assert data["workflow"]["phase_results"]["assessment"]["inventory_scope"] == "all_discovered_assets"


def test_live_pipeline_definition_does_not_use_kernel_route_discovery():
    source = Path(phase_discovery.__file__).read_text(encoding="utf-8")
    # The active v6 definition appears after the compatibility implementation.
    active = source[source.rfind("def run_discovery_pipeline"):]
    assert "collect_network_snapshot" not in active
    assert "discover_network_context" not in active
    assert "collect_local_observation_snapshot" in active
    assert '"kernel_route_discovery": False' in active


def test_palo_alto_parser_retains_direct_interfaces_and_networks():
    text = """Name: ethernet1/1
Ip: 203.0.113.2/24
Name: ethernet1/3
Ip: 172.16.0.1/30
203.0.113.0/24 0.0.0.0 connect ethernet1/1
172.16.0.0/30 0.0.0.0 connect ethernet1/3
"""
    interfaces, routes = parse_topology_output("palo_alto", "ssh", text)
    assert {row["address"] for row in interfaces} == {"203.0.113.2", "172.16.0.1"}
    assert {row["network"] for row in routes} >= {"203.0.113.0/24", "172.16.0.0/30"}


def test_large_control_plane_network_is_retained_but_not_enumeration_eligible(monkeypatch):
    from scanners import infrastructure_discovery

    monkeypatch.setattr(infrastructure_discovery.Config, "MAX_EXPANDED_TARGETS", 256)
    interfaces, routes = parse_topology_output(
        "generic",
        "ssh",
        "2: eth9 inet 10.40.0.1/16 scope global eth9\n10.40.0.0/16 dev eth9\n",
    )
    rows = infrastructure_discovery._network_records("192.0.2.10", interfaces, routes)
    assert len(rows) == 1
    assert rows[0]["destination_network"] == "10.40.0.0/16"
    assert rows[0]["enumeration_eligible"] is False


def test_querying_multiple_devices_preserves_all_current_layer_branches(monkeypatch):
    scan_id = scan_store.new_scan("192.168.50.10")
    segment = {
        "segment_id": "segment_branch",
        "layer_index": 1,
        "scope_kind": "topology_network",
        "network": "192.168.50.0/24",
        "hosts": [
            {"ip": "192.168.50.10", "selectable": True},
            {"ip": "192.168.50.20", "selectable": True},
        ],
        "path_ids": [],
    }
    workflow = {
        "entry_target": "192.168.50.10",
        "entry_result": {"reachable": True},
        "segments": {segment["segment_id"]: segment},
        "segment_order": [segment["segment_id"]],
        "visited_segment_ids": [segment["segment_id"]],
        "current_segment_id": segment["segment_id"],
        "paths": {},
        "asset_inventory": [],
        "topology_observations": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    phase_discovery._accumulate_assets(workflow, segment["hosts"], segment=segment)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_LAYER_DECISION, workflow=workflow)

    def fake_collect(_scan_id, device_ip, profile_ref=""):
        network = "10.10.10.0/24" if device_ip.endswith(".10") else "10.20.20.0/24"
        interface_ip = "10.10.10.1" if device_ip.endswith(".10") else "10.20.20.1"
        return {
            "observation_id": f"infraobs_{device_ip}",
            "device_ip": device_ip,
            "profile_ref": profile_ref or "ro",
            "platform": "cisco_ios",
            "transport": "ssh",
            "interfaces": [],
            "routes": [],
            "networks": [{
                "destination_network": network,
                "device_interface": "Vlan20",
                "device_interface_ip": interface_ip,
                "enumeration_eligible": True,
                "evidence_sources": ["device_interface"],
            }],
        }

    monkeypatch.setattr("scanners.infrastructure_discovery.collect_device_topology", fake_collect)
    monkeypatch.setattr("scanners.enterprise_readiness.validate_scope", lambda *_a, **_k: {})
    monkeypatch.setattr(phase_discovery, "_discovery_network_scope_state", lambda _n: (True, "test"))

    phase_discovery.discover_next_networks_from_device(scan_id, "192.168.50.10", profile_ref="ro")
    phase_discovery.discover_next_networks_from_device(scan_id, "192.168.50.20", profile_ref="ro")
    data = scan_store.get(scan_id)
    current = data["workflow"]["segments"][segment["segment_id"]]
    retained = {
        data["workflow"]["paths"][path_id]["destination_network"]
        for path_id in current["path_ids"]
    }
    assert retained == {"10.10.10.0/24", "10.20.20.0/24"}


def test_topology_interface_ips_are_retained_as_phase3_candidates(monkeypatch):
    workflow = {"asset_inventory": []}
    topology = {
        "observation_id": "infraobs_interfaces",
        "platform": "palo_alto",
        "interfaces": [
            {"interface": "ethernet1/1", "address": "203.0.113.2", "network": "203.0.113.0/24"},
            {"interface": "ethernet1/3", "address": "172.16.0.1", "network": "172.16.0.0/30"},
        ],
    }
    monkeypatch.setattr(phase_discovery, "_discovery_network_scope_state", lambda _n: (True, "test"))
    phase_discovery._retain_topology_interface_assets(
        workflow,
        device_ip="203.0.113.2",
        topology=topology,
    )
    assert {row["ip"] for row in workflow["asset_inventory"]} == {"203.0.113.2", "172.16.0.1"}
    assert all(row["selectable"] for row in workflow["asset_inventory"])
    assert all(row["discovery_phase"] == "Phase 2" for row in workflow["asset_inventory"])


def test_asset_inventory_deduplicates_topology_and_network_enumeration(monkeypatch):
    workflow = {"asset_inventory": []}
    topology = {
        "observation_id": "infraobs_dup",
        "platform": "cisco_ios",
        "interfaces": [
            {"interface": "Vlan20", "address": "10.30.40.1", "network": "10.30.40.0/24"},
        ],
    }
    monkeypatch.setattr(phase_discovery, "_discovery_network_scope_state", lambda _n: (True, "test"))
    phase_discovery._retain_topology_interface_assets(workflow, device_ip="192.0.2.1", topology=topology)
    segment = {
        "segment_id": "seg_dup",
        "layer_index": 2,
        "scope_kind": "topology_network",
        "network": "10.30.40.0/24",
    }
    phase_discovery._accumulate_assets(
        workflow,
        [{"ip": "10.30.40.1", "selectable": True, "reachability_state": "responsive", "origin": "network_enumeration"}],
        segment=segment,
    )
    rows = [row for row in workflow["asset_inventory"] if row["ip"] == "10.30.40.1"]
    assert len(rows) == 1
    assert rows[0]["reachability_state"] == "responsive"
    assert rows[0]["selectable"] is True
    assert "Phase 2 / Topology" in rows[0]["discovery_layers"]
    assert "Phase 2 / Layer 2" in rows[0]["discovery_layers"]


def test_password_backed_ssh_does_not_log_secret(monkeypatch):
    import subprocess
    from scanners import infrastructure_discovery

    captured = {}
    monkeypatch.setenv("TEST_INFRA_PASSWORD", "super-secret-value")
    monkeypatch.setattr(
        infrastructure_discovery.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"ssh", "sshpass"} else None,
    )
    monkeypatch.setattr(
        infrastructure_discovery.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        infrastructure_discovery.scan_store,
        "log_command",
        lambda _scan_id, **kwargs: captured.update(kwargs),
    )
    infrastructure_discovery._collect_ssh(
        "scan-redaction",
        "192.0.2.5",
        "ro",
        {
            "profile_ref": "ro",
            "platform": "cisco_ios",
            "transport": "ssh",
            "username": "readonly",
            "secret_env": "TEST_INFRA_PASSWORD",
        },
    )
    assert "super-secret-value" not in captured.get("command", "")
    assert "super-secret-value" not in captured.get("output", "")
    assert "<read-only topology commands via stdin>" in captured.get("command", "")


def test_infrastructure_candidate_hint_is_conservative_and_operator_controlled():
    likely = phase_discovery._apply_infrastructure_hint({
        "ip": "192.0.2.10",
        "role": "gateway",
        "selectable": True,
        "is_scanner": False,
    })
    unknown = phase_discovery._apply_infrastructure_hint({
        "ip": "192.0.2.20",
        "role": "host",
        "selectable": True,
        "is_scanner": False,
    })
    assert likely["infrastructure_candidate_state"] == "likely"
    assert unknown["infrastructure_candidate_state"] == "possible"
    assert unknown["selectable"] is True


def test_local_connected_scope_comes_from_interface_address_not_routes(monkeypatch):
    snapshot = {
        "interfaces": [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"family": "inet", "local": "192.168.1.49", "prefixlen": 24, "scope": "global"}
                ],
            },
            {
                "ifname": "eth1",
                "addr_info": [
                    {"family": "inet", "local": "192.168.80.128", "prefixlen": 24, "scope": "global"}
                ],
            },
        ],
        # A deliberately unrelated route-like field must not influence selection.
        "routes": [{"dst": "10.99.0.0/16", "dev": "eth1"}],
        "neighbours": [],
    }
    monkeypatch.setattr(phase_discovery, "_discovery_network_scope_state", lambda _n: (True, "test"))
    scope = phase_discovery._local_connected_scope_for_entry(snapshot, "192.168.1.1")
    assert scope is not None
    assert scope["network"] == "192.168.1.0/24"
    assert scope["interface"] == "eth0"
    assert scope["scanner_ip"] == "192.168.1.49"
    assert scope["evidence_source"] == "scanner_interface_address"


def test_live_pipeline_enumerates_connected_subnet_before_topology_query(monkeypatch):
    scan_id = scan_store.new_scan("192.168.1.1")

    monkeypatch.setattr(
        phase_discovery,
        "check_external_reachability",
        lambda *_a, **_k: {
            "target": "192.168.1.1",
            "reachable": True,
            "reachability_state": "responsive",
            "evidence": [{"method": "test", "response_observed": True}],
            "statement": "test response observed",
        },
    )
    monkeypatch.setattr(
        phase_discovery,
        "collect_local_observation_snapshot",
        lambda *_a, **_k: {
            "captured_at": scan_store.now(),
            "interfaces": [
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {"family": "inet", "local": "192.168.1.49", "prefixlen": 24, "scope": "global"}
                    ],
                },
                {
                    "ifname": "eth1",
                    "addr_info": [
                        {"family": "inet", "local": "192.168.80.128", "prefixlen": 24, "scope": "global"}
                    ],
                },
            ],
            "interface_index": {},
            "routes": [],
            "neighbours": [],
            "route_signatures": [],
        },
    )
    monkeypatch.setattr(phase_discovery, "_discovery_network_scope_state", lambda _n: (True, "test"))
    monkeypatch.setattr("scanners.enterprise_readiness.validate_scope", lambda *_a, **_k: {})

    def fake_discover(_scan_id, subnet, **kwargs):
        assert subnet == "192.168.1.0/24"
        assert kwargs["interface"] == "eth0"
        assert kwargs["scanner_ip"] == "192.168.1.49"
        assert kwargs["layer2_connected"] is True
        return [
            {
                "ip": "192.168.1.1",
                "address": "192.168.1.1",
                "selectable": True,
                "reachability_state": "responsive",
                "role": "host",
                "record_type": "discovered_host",
                "origin": "nmap_host_discovery",
                "origins": ["nmap_host_discovery"],
                "independently_discovered": True,
                "discovered_by": ["nmap_host_discovery"],
                "verification_methods": ["nmap_host_discovery"],
                "is_scanner": False,
            },
            {
                "ip": "192.168.1.42",
                "address": "192.168.1.42",
                "selectable": True,
                "reachability_state": "responsive",
                "role": "host",
                "record_type": "discovered_host",
                "origin": "nmap_host_discovery",
                "origins": ["nmap_host_discovery"],
                "independently_discovered": True,
                "discovered_by": ["nmap_host_discovery"],
                "verification_methods": ["nmap_host_discovery"],
                "is_scanner": False,
            },
            {
                "ip": "192.168.1.49",
                "address": "192.168.1.49",
                "selectable": False,
                "reachability_state": "responsive",
                "role": "scanner",
                "record_type": "scanner",
                "origin": "scanner_interface",
                "origins": ["scanner_interface"],
                "independently_discovered": False,
                "discovered_by": [],
                "verification_methods": ["scanner_interface"],
                "is_scanner": True,
            },
        ], {"nmap_host_discovery": {"executed": True, "success": True, "evidence_produced": True}}

    monkeypatch.setattr(phase_discovery, "discover_internal_hosts", fake_discover)

    phase_discovery.run_discovery_pipeline(scan_id, "192.168.1.1")
    data = scan_store.get(scan_id)
    workflow = data["workflow"]
    current = workflow["segments"][workflow["current_segment_id"]]

    assert data["status"] == scan_store.STATUS_AWAITING_LAYER_DECISION
    assert current["scope_kind"] == "local_connected_network"
    assert current["network"] == "192.168.1.0/24"
    assert current["interface"] == "eth0"
    assert current["source_address"] == "192.168.1.49"
    assert current["layer2_connected"] is True
    assert "192.168.1.42" in {row["ip"] for row in workflow["asset_inventory"]}
    assert workflow["discovery_stages"]["local_subnet"] == "interface_address_prefix"
    assert workflow["discovery_stages"]["topology_continuation"] == "operator_selected_device_observable_evidence"
    # The Phase 1 address remains operator supplied even when it is observed again in the /24.
    entry = next(row for row in workflow["asset_inventory"] if row["ip"] == "192.168.1.1")
    assert entry["origin"] == "operator_supplied"
    assert entry["record_type"] == "entry_target"


def test_finish_phase2_records_explicit_stop_reason_after_local_discovery():
    scan_id = scan_store.new_scan("192.168.1.1")
    entry = {
        "segment_id": "entry_local_stop",
        "layer_index": 0,
        "scope_kind": "entry_host",
        "network": "192.168.1.1/32",
        "hosts": [{"ip": "192.168.1.1", "selectable": True, "record_type": "entry_target", "origin": "operator_supplied"}],
    }
    local = {
        "segment_id": "local_stop",
        "layer_index": 1,
        "scope_kind": "local_connected_network",
        "network": "192.168.1.0/24",
        "hosts": [
            {"ip": "192.168.1.1", "selectable": True, "record_type": "entry_target", "origin": "operator_supplied"},
            {"ip": "192.168.1.42", "selectable": True, "record_type": "discovered_host", "origin": "nmap_host_discovery"},
        ],
    }
    workflow = {
        "entry_target": "192.168.1.1",
        "entry_result": {"reachable": True},
        "segments": {entry["segment_id"]: entry, local["segment_id"]: local},
        "segment_order": [entry["segment_id"], local["segment_id"]],
        "visited_segment_ids": [entry["segment_id"], local["segment_id"]],
        "current_segment_id": local["segment_id"],
        "paths": {},
        "topology_observations": [],
        "asset_inventory": [],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    for segment in (entry, local):
        phase_discovery._accumulate_assets(workflow, segment["hosts"], segment=segment)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_LAYER_DECISION, workflow=workflow)

    phase_discovery.prepare_assessment_from_current_layer(scan_id)
    data = scan_store.get(scan_id)
    reason = data["workflow"]["phase2_stop_reason"]
    assert "no further network layer was discovered or authorised" in reason.lower()
    assert data["workflow"]["phase2_stop"]["code"] == "operator_finished_after_local_discovery_no_topology_continuation"
    assert data["workflow"]["phase_results"]["traversal"]["status"] == "completed"


def test_phase2_ui_separates_local_discovery_from_topology_continuation():
    template = (Path(phase_discovery.__file__).resolve().parents[1] / "templates/layer_decision.html").read_text(encoding="utf-8")
    assert "Enumerate Current Subnet" in template
    assert "Inspect Selected Devices" in template
    assert "Continuation Networks" in template
    assert "infrastructure profile" not in template.lower()
    assert "Device labels are based only on retained discovery evidence" in template


def test_reports_include_phase2_stop_reason():
    project_root = Path(phase_discovery.__file__).resolve().parents[1]
    for name in ("results.html", "pdf_report.html", "technical_appendix.html"):
        template = (project_root / "templates" / name).read_text(encoding="utf-8")
        assert "phase2_stop_reason" in template
