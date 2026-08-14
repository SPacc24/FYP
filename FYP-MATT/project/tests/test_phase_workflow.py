from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from scanners.phase_discovery import (
    DiscoveryWorkflowError,
    _candidate_network_records,
    _candidate_networks,
    _entry_target_observation,
    _find_route_for_path,
    _parse_host_inventory,
    _path_records_from_snapshot,
    _route_signature,
    _segment_from_entry,
    _segment_identifier,
    prepare_assessment_from_current_layer,
    _set_current_aliases,
    _usable_internal_network,
    authorize_observed_route,
    validate_external_target,
    revoke_authorized_route,
)
from storage import scan_store


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent


def test_phase1_accepts_one_ip_only():
    assert validate_external_target("10.10.10.1") == "10.10.10.1"
    for value in ("", "10.10.10.0/24", "10.10.10.1 10.10.10.2", "gateway.local"):
        with pytest.raises(DiscoveryWorkflowError):
            validate_external_target(value)


def test_network_bounding_does_not_assume_private_address_space():
    assert _usable_internal_network(ipaddress.ip_network("198.51.100.0/24"))
    assert _usable_internal_network(ipaddress.ip_network("10.10.10.0/24"))
    assert not _usable_internal_network(ipaddress.ip_network("0.0.0.0/0"))
    assert not _usable_internal_network(ipaddress.ip_network("127.0.0.0/24"))


def test_specific_connected_route_is_observed_without_automatic_selection():
    external = ipaddress.ip_address("10.10.10.1")
    routes = [{"dst": "10.10.10.0/24", "dev": "eth1", "scope": "link"}]
    addresses = [
        {
            "ifname": "eth1",
            "addr_info": [{"family": "inet", "local": "10.10.10.5", "prefixlen": 24}],
        }
    ]
    candidates, _ = _candidate_networks(external, "eth1", routes, addresses)
    assert [str(network) for network in candidates] == ["10.10.10.0/24"]


def test_default_route_does_not_become_a_layer_candidate():
    external = ipaddress.ip_address("8.8.8.8")
    routes = [{"dst": "default", "dev": "eth0", "gateway": "192.168.1.1"}]
    addresses = [
        {
            "ifname": "eth0",
            "addr_info": [{"family": "inet", "local": "192.168.1.20", "prefixlen": 24}],
        }
    ]
    candidates, _ = _candidate_networks(external, "eth0", routes, addresses)
    assert candidates == []


def test_route_candidates_do_not_infer_tunnel_semantics_from_interface_names():
    external = ipaddress.ip_address("198.51.100.10")
    routes = [
        {"dst": "default", "dev": "uplink0", "gateway": "192.0.2.1"},
        {"dst": "10.30.40.0/24", "dev": "anything7"},
    ]
    records, _ = _candidate_network_records(external, "uplink0", routes, [])
    assert [item["subnet"] for item in records] == ["10.30.40.0/24"]
    assert records[0]["interface"] == "anything7"
    assert records[0]["access_mode"] == "directly_connected"
    assert records[0]["verification_state"] == "observed"


def test_specific_route_via_entry_is_retained_without_cidr_guessing():
    external = ipaddress.ip_address("198.51.100.10")
    routes = [{"dst": "10.20.30.0/24", "dev": "route0", "gateway": "198.51.100.10"}]
    records, _ = _candidate_network_records(external, "route0", routes, [])
    assert [item["subnet"] for item in records] == ["10.20.30.0/24"]
    assert records[0]["relationship"] == "specific_route_via_external_target"


def test_multiple_routes_are_retained_for_operator_choice():
    external = ipaddress.ip_address("10.0.0.1")
    routes = [
        {"dst": "10.20.30.0/24", "dev": "route0", "gateway": "10.0.0.1"},
        {"dst": "10.20.40.0/24", "dev": "route0", "gateway": "10.0.0.1"},
    ]
    records, _ = _candidate_network_records(external, "route0", routes, [])
    assert {item["subnet"] for item in records} == {"10.20.30.0/24", "10.20.40.0/24"}


def test_path_inventory_is_current_layer_scoped_and_marks_visited_destinations():
    current_id = _segment_identifier("192.0.2.10/32", "ifA", "192.0.2.20", "192.0.2.1", "main", "entry_host")
    visited_id = _segment_identifier("10.0.1.0/24", "ifB", "10.0.1.5", "", "main", "route_network")
    route_a = {"dst": "10.0.0.0/24", "dev": "ifA", "gateway": "192.0.2.1"}
    route_b = {"dst": "10.0.1.0/24", "dev": "ifB", "prefsrc": "10.0.1.5"}
    signatures = [_route_signature(route_a), _route_signature(route_b)]
    workflow = {
        "paths": {},
        "visited_segment_ids": [current_id, visited_id],
        "last_route_signatures": [],
        "authorized_route_signatures": signatures,
        "authorized_route_records": {
            signature: {"authorized_by": "operator", "authorized_at": "now"}
            for signature in signatures
        },
    }
    current = {
        "segment_id": current_id,
        "network": "192.0.2.10/32",
        "interface": "ifA",
        "source_address": "192.0.2.20",
        "next_hop": "192.0.2.1",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": [route_a, route_b],
        "interface_index": {
            "ifA": {"addresses": [{"address": "192.0.2.20", "prefixlen": 24}]},
            "ifB": {"addresses": [{"address": "10.0.1.5", "prefixlen": 24}]},
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    assert len(paths) == 2
    assert len(pending) == 1
    states = {row["destination_network"]: row["verification_state"] for row in paths.values()}
    assert states["10.0.0.0/24"] == "authorized_pending_verification"
    assert states["10.0.1.0/24"] == "previously_visited"


def test_large_route_is_retained_as_evidence_but_not_followable(monkeypatch):
    monkeypatch.setattr("scanners.phase_discovery.Config.MAX_EXPANDED_TARGETS", 256)
    current_id = _segment_identifier(
        "192.0.2.10/32", "ifA", "192.0.2.20", "192.0.2.1", "main", "entry_host"
    )
    route = {"dst": "10.0.0.0/16", "dev": "ifA", "gateway": "192.0.2.1"}
    signature = _route_signature(route)
    workflow = {
        "paths": {},
        "visited_segment_ids": [current_id],
        "last_route_signatures": [],
        "authorized_route_signatures": [signature],
        "authorized_route_records": {
            signature: {"authorized_by": "operator", "authorized_at": "now"}
        },
    }
    current = {
        "segment_id": current_id,
        "network": "192.0.2.10/32",
        "interface": "ifA",
        "source_address": "192.0.2.20",
        "next_hop": "192.0.2.1",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": [route],
        "interface_index": {
            "ifA": {"addresses": [{"address": "192.0.2.20", "prefixlen": 24}]}
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    assert len(paths) == 1
    row = next(iter(paths.values()))
    assert row["destination_network"] == "10.0.0.0/16"
    assert row["verification_state"] == "scope_exceeds_discovery_limit"
    assert row["enumeration_eligible"] is False
    assert pending == []


def test_path_route_matching_respects_route_table():
    path = {
        "destination_network": "10.20.30.0/24",
        "interface": "ifA",
        "next_hop": "192.0.2.1",
        "route_table": "200",
    }
    snapshot = {
        "routes": [
            {"dst": "10.20.30.0/24", "dev": "ifA", "gateway": "192.0.2.1", "table": "main"},
            {"dst": "10.20.30.0/24", "dev": "ifA", "gateway": "192.0.2.1", "table": "200"},
        ]
    }
    match = _find_route_for_path(path, snapshot)
    assert match is not None
    assert str(match.get("table")) == "200"


def test_phase2_inventory_marks_scanner_unselectable(tmp_path: Path):
    xml = tmp_path / "hosts.xml"
    xml.write_text(
        """<?xml version='1.0'?>
<nmaprun>
  <host><status state='up'/><address addr='10.10.10.5' addrtype='ipv4'/><hostnames><hostname name='kali'/></hostnames></host>
  <host><status state='up'/><address addr='10.10.10.20' addrtype='ipv4'/><address addr='00:11:22:33:44:55' addrtype='mac' vendor='Lab Vendor'/><hostnames><hostname name='server01'/></hostnames></host>
</nmaprun>""",
        encoding="utf-8",
    )
    hosts = _parse_host_inventory(
        xml,
        scanner_ip="10.10.10.5",
        gateway="10.10.10.1",
        segment_id="segment_test",
    )
    assert hosts[0]["is_scanner"] is True
    assert hosts[0]["selectable"] is False
    assert hosts[1]["ip"] == "10.10.10.20"
    assert hosts[1]["hostname"] == "server01"
    assert hosts[1]["mac_vendor"] == "Lab Vendor"
    assert hosts[1]["selectable"] is True


def test_current_aliases_keep_phase3_compatibility_without_flattening_history():
    segment = {
        "segment_id": "segment_a",
        "network": "10.0.0.0/24",
        "interface": "ifA",
        "source_address": "10.0.0.5",
        "next_hop": "",
        "route_table": "main",
        "route_type": "unicast",
        "access_mode": "directly_connected",
        "layer2_connected": True,
        "hosts": [{"ip": "10.0.0.20", "selectable": True}],
    }
    workflow = {
        "entry_result": {},
        "segments": {"segment_a": segment},
        "paths": {},
        "segment_order": ["segment_a"],
        "visited_segment_ids": ["segment_a"],
        "pending_path_ids": [],
        "current_segment_id": "segment_a",
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    _set_current_aliases(workflow)
    assert workflow["internal_subnet"] == "10.0.0.0/24"
    assert workflow["discovered_hosts"][0]["ip"] == "10.0.0.20"
    assert workflow["network_context"]["segment_id"] == "segment_a"
    assert workflow["segment_order"] == ["segment_a"]


def test_scan_store_appends_assessment_without_erasing_discovery():
    scan_id = scan_store.new_scan("10.10.10.1")
    scan_store.init_tasks(scan_id, ["Entry", "Layer"], phase="discovery")
    scan_store.set_task(scan_id, "Entry", scan_store.STATUS_SUCCESS)
    scan_store.set_task(scan_id, "Layer", scan_store.STATUS_SUCCESS)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_CONFIGURATION)
    assert scan_store.transition_status(
        scan_id,
        {scan_store.STATUS_AWAITING_CONFIGURATION},
        scan_store.STATUS_ASSESSMENT_RUNNING,
    )
    scan_store.append_tasks(scan_id, ["TCP Service Discovery"], phase="assessment")
    data = scan_store.get(scan_id)
    assert [task["name"] for task in data["tasks"]] == ["Entry", "Layer", "TCP Service Discovery"]
    assert data["tasks"][-1]["phase"] == "assessment"


def test_phase3_template_keeps_existing_customisation_controls():
    template = (PROJECT_ROOT / "templates/assessment_config.html").read_text(encoding="utf-8")
    assert 'name="assessment_targets"' in template
    assert 'type="checkbox"' in template
    assert "Select at least one retained target" in template
    assert 'name="target"' not in template
    for control in (
        'name="tcp_port_mode"',
        'name="udp_port_mode"',
        'name="technique_mode"',
        'name="collector_plan_json"',
        'name="host_discovery_json"',
        'name="service_identity_json"',
        'name="command_timeout_seconds"',
        'name="ports_per_batch"',
    ):
        assert control in template


def test_layer_decision_ui_uses_simplified_topology_control_loop():
    template = (PROJECT_ROOT / "templates/layer_decision.html").read_text(encoding="utf-8")
    assert 'type="checkbox" name="device_ips"' in template
    assert 'type="radio" name="path_id"' in template
    assert 'value="discover_device"' in template
    assert 'value="continue_path"' in template
    assert 'value="finish_phase2"' in template
    assert 'value="retry_layer"' in template
    assert 'value="revisit_segment"' in template
    assert 'name="allow_inconclusive_operator_targets"' in template
    assert "Device labels are based only on retained discovery evidence" in template
    assert 'value="authorize_route"' not in template
    assert 'name="route_observation_id"' not in template


def test_phase3_backend_accepts_complete_retained_inventory():
    source = (PROJECT_ROOT / "routes/scan_routes.py").read_text(encoding="utf-8")
    assert 'request.form.getlist("assessment_targets")' in source
    assert 'workflow.get("asset_inventory")' in source
    assert "target not in retained_host_records" in source
    assert '"target_contexts": target_contexts' in source
    assert 'target_input = ",".join(assessment_targets)' in source
    assert "outside the current verified scope" not in source


def test_interface_bound_commands_use_selected_interface():
    from scanners import command_builders

    arp = command_builders.arp_scan("/usr/bin/arp-scan", "10.10.10.0/24", interface="route7")
    nmap = command_builders.nmap_host_discovery(
        "/usr/bin/nmap", ["10.10.10.20"], Path("hosts.xml"), interface="route7"
    )
    assert "--interface" in arp and "route7" in arp
    assert "-e" in nmap and "route7" in nmap


def test_discovery_module_does_not_create_routes_or_addresses():
    source = (PROJECT_ROOT / "scanners/phase_discovery.py").read_text(encoding="utf-8")
    assert '"route", "add"' not in source
    assert '"addr", "add"' not in source
    assert "ip route add" not in source
    assert "ip addr add" not in source
    assert "_TUNNEL_INTERFACE_RE" not in source
    assert '"kernel_route_discovery": False' in source
    assert "path_observation_only" in source
    assert "revisit_discovered_segment" in source


def test_reports_render_layer_traversal_and_multiple_targets():
    results = (PROJECT_ROOT / "templates/results.html").read_text(encoding="utf-8")
    report = (PROJECT_ROOT / "templates/pdf_report.html").read_text(encoding="utf-8")
    appendix = (PROJECT_ROOT / "templates/technical_appendix.html").read_text(encoding="utf-8")
    for template in (results, report, appendix):
        assert "segment_order" in template
        assert "assessment_targets" in template
        assert "current_segment_id" in template
    assert "Scope Traversal Record" in report
    assert "operator_decisions" in appendix


def test_arp_capability_setup_uses_discovered_binary_path():
    installer = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'ARP_SCAN_BIN="$(command -v arp-scan || true)"' in installer
    assert 'setcap cap_net_raw,cap_net_admin=eip "$ARP_SCAN_BIN"' in installer
    assert "/usr/bin/arp-scan" not in installer



def test_entry_target_provenance_is_operator_supplied_and_not_discovered():
    segment = {
        "segment_id": "segment_entry",
        "enumeration_target": "203.0.113.25",
    }
    result = {
        "reachable": True,
        "evidence": [
            {
                "method": "nmap_host_discovery",
                "response_observed": True,
                "command": "nmap -sn 203.0.113.25",
                "returncode": 0,
            }
        ],
    }
    host = _entry_target_observation(segment, result)
    assert host["origin"] == "operator_supplied"
    assert host["record_type"] == "entry_target"
    assert host["independently_discovered"] is False
    assert host["verification_methods"] == ["nmap_host_discovery"]
    assert host["selectable"] is True


def test_baseline_unrelated_routes_are_observations_not_continuation_paths():
    current_id = _segment_identifier(
        "192.168.112.143/32",
        "routeA",
        "192.168.211.140",
        "192.168.211.2",
        "main",
        "entry_host",
    )
    routes = [
        {"dst": "192.168.1.0/24", "dev": "routeB", "scope": "link"},
        {"dst": "192.168.211.0/24", "dev": "routeA", "scope": "link"},
    ]
    signatures = [_route_signature(route) for route in routes]
    workflow = {
        "entry_target": "192.168.112.143",
        "paths": {},
        "visited_segment_ids": [current_id],
        "baseline_route_signatures": signatures,
    }
    current = {
        "segment_id": current_id,
        "scope_kind": "entry_host",
        "network": "192.168.112.143/32",
        "interface": "routeA",
        "source_address": "192.168.211.140",
        "next_hop": "192.168.211.2",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": routes,
        "interface_index": {
            "routeA": {"addresses": [{"address": "192.168.211.140", "prefixlen": 24}]},
            "routeB": {"addresses": [{"address": "192.168.1.2", "prefixlen": 24}]},
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    assert paths == {}
    assert pending == []
    assert len(workflow["route_observations"]) == 2
    assert all(not row["mission_related"] for row in workflow["route_observations"])


def test_connected_route_containing_entry_target_is_suggested_but_requires_authorization():
    current_id = _segment_identifier(
        "192.168.50.25/32", "routeA", "192.168.50.10", "", "main", "entry_host"
    )
    route = {"dst": "192.168.50.0/24", "dev": "routeA", "scope": "link"}
    signature = _route_signature(route)
    workflow = {
        "entry_target": "192.168.50.25",
        "paths": {},
        "visited_segment_ids": [current_id],
        "baseline_route_signatures": [signature],
    }
    current = {
        "segment_id": current_id,
        "scope_kind": "entry_host",
        "network": "192.168.50.25/32",
        "interface": "routeA",
        "source_address": "192.168.50.10",
        "next_hop": "",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": [route],
        "interface_index": {
            "routeA": {"addresses": [{"address": "192.168.50.10", "prefixlen": 24}]}
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    assert paths == {}
    assert pending == []
    observation = workflow["route_observations"][0]
    assert observation["destination_network"] == "192.168.50.0/24"
    assert observation["relationship"] == "route_contains_entry_target"
    assert observation["mission_related"] is True
    assert observation["operator_authorized"] is False

    workflow["authorized_route_signatures"] = [signature]
    workflow["authorized_route_records"] = {
        signature: {"authorized_by": "operator", "authorized_at": "now"}
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    row = next(iter(paths.values()))
    assert row["relationship"] == "operator_authorized"
    assert row["evidence_relationship"] == "route_contains_entry_target"
    assert row["verification_state"] == "authorized_pending_verification"
    assert pending == [row["path_id"]]


def test_new_route_after_baseline_is_suggested_then_operator_authorized():
    current_id = _segment_identifier(
        "198.51.100.20/32", "uplink", "192.0.2.10", "192.0.2.1", "main", "entry_host"
    )
    workflow = {
        "entry_target": "198.51.100.20",
        "paths": {},
        "visited_segment_ids": [current_id],
        "baseline_route_signatures": [],
    }
    current = {
        "segment_id": current_id,
        "scope_kind": "entry_host",
        "network": "198.51.100.20/32",
        "interface": "uplink",
        "source_address": "192.0.2.10",
        "next_hop": "192.0.2.1",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:05:00+00:00",
        "routes": [{"dst": "100.64.40.0/24", "dev": "device7", "gateway": "192.0.2.254"}],
        "interface_index": {
            "device7": {"addresses": [{"address": "100.64.0.5", "prefixlen": 24}]}
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    assert paths == {}
    assert pending == []
    observation = workflow["route_observations"][0]
    assert observation["relationship"] == "newly_observed_route"
    assert observation["interface"] == "device7"

    signature = observation["route_signature"]
    workflow["authorized_route_signatures"] = [signature]
    workflow["authorized_route_records"] = {
        signature: {"authorized_by": "operator", "authorized_at": "now"}
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    row = next(iter(paths.values()))
    assert row["relationship"] == "operator_authorized"
    assert row["evidence_relationship"] == "newly_observed_route"
    assert pending == [row["path_id"]]


def test_entry_segment_is_host_scope_not_network_layer():
    context = {
        "entry_target": "192.0.2.50",
        "interface": "route0",
        "scanner_ip": "192.0.2.10",
        "gateway": "192.0.2.1",
        "route_table": "main",
        "route_type": "default",
        "access_mode": "routed",
        "route": {},
        "matched_route": {},
    }
    segment = _segment_from_entry(context, {"reachable": True})
    assert segment["scope_kind"] == "entry_host"
    assert segment["network"] == "192.0.2.50/32"
    assert segment["enumeration_target"] == "192.0.2.50"



def test_operator_authorized_baseline_route_becomes_path_candidate():
    current_id = _segment_identifier(
        "198.51.100.20/32", "uplink", "192.0.2.10", "192.0.2.1", "main", "entry_host"
    )
    route = {"dst": "10.70.80.0/24", "dev": "rangeLink", "gateway": "192.0.2.254"}
    signature = _route_signature(route)
    workflow = {
        "entry_target": "198.51.100.20",
        "paths": {},
        "visited_segment_ids": [current_id],
        "baseline_route_signatures": [signature],
        "authorized_route_signatures": [signature],
        "authorized_route_records": {
            signature: {"authorized_by": "operator", "authorized_at": "now"}
        },
    }
    current = {
        "segment_id": current_id,
        "scope_kind": "entry_host",
        "network": "198.51.100.20/32",
        "interface": "uplink",
        "source_address": "192.0.2.10",
        "next_hop": "192.0.2.1",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": [route],
        "interface_index": {
            "rangeLink": {"addresses": [{"address": "10.70.0.5", "prefixlen": 24}]}
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    row = next(iter(paths.values()))
    assert row["relationship"] == "operator_authorized"
    assert row["evidence_relationship"] == "baseline_route_observation_only"
    assert row["authorization_state"] == "operator_authorized"
    assert row["verification_state"] == "authorized_pending_verification"
    assert pending == [row["path_id"]]



def test_baseline_route_via_gateway_in_current_network_is_segmented_path():
    current_id = _segment_identifier(
        "10.20.0.0/24", "range0", "10.20.0.10", "", "main", "route_network"
    )
    route = {"dst": "10.30.0.0/24", "dev": "range0", "gateway": "10.20.0.1"}
    signature = _route_signature(route)
    workflow = {
        "entry_target": "198.51.100.20",
        "paths": {},
        "visited_segment_ids": [current_id],
        "baseline_route_signatures": [signature],
        "authorized_route_signatures": [signature],
        "authorized_route_records": {
            signature: {"authorized_by": "operator", "authorized_at": "now"}
        },
    }
    current = {
        "segment_id": current_id,
        "scope_kind": "route_network",
        "network": "10.20.0.0/24",
        "interface": "range0",
        "source_address": "10.20.0.10",
        "next_hop": "",
    }
    snapshot = {
        "captured_at": "2026-08-06T00:00:00+00:00",
        "routes": [route],
        "interface_index": {
            "range0": {"addresses": [{"address": "10.20.0.10", "prefixlen": 24}]}
        },
    }
    paths, pending = _path_records_from_snapshot(workflow, current, snapshot)
    row = next(iter(paths.values()))
    assert row["relationship"] == "operator_authorized"
    assert row["evidence_relationship"] == "next_hop_on_current_scope"
    assert row["destination_network"] == "10.30.0.0/24"
    assert pending == [row["path_id"]]



def test_responsive_operator_entry_target_can_enter_existing_phase3_configuration():
    scan_id = scan_store.new_scan("203.0.113.25")
    segment = {
        "segment_id": "segment_entry_assess",
        "scope_kind": "entry_host",
        "network": "203.0.113.25/32",
        "interface": "route0",
        "source_address": "192.0.2.10",
        "next_hop": "192.0.2.1",
        "route_table": "main",
        "route_type": "default",
        "access_mode": "routed",
        "layer2_connected": False,
        "hosts": [
            {
                "ip": "203.0.113.25",
                "address": "203.0.113.25",
                "record_type": "entry_target",
                "origin": "operator_supplied",
                "independently_discovered": False,
                "selectable": True,
            }
        ],
    }
    workflow = {
        "entry_target": "203.0.113.25",
        "segments": {segment["segment_id"]: segment},
        "paths": {},
        "segment_order": [segment["segment_id"]],
        "visited_segment_ids": [segment["segment_id"]],
        "pending_path_ids": [],
        "current_segment_id": segment["segment_id"],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow=workflow,
    )
    prepare_assessment_from_current_layer(scan_id)
    data = scan_store.get(scan_id)
    assert data["status"] == scan_store.STATUS_AWAITING_CONFIGURATION
    assert data["workflow"]["phase_results"]["assessment"]["segment_id"] == segment["segment_id"]


def test_inconclusive_operator_entry_requires_explicit_override_for_phase3():
    scan_id = scan_store.new_scan("203.0.113.40")
    segment = {
        "segment_id": "segment_entry_inconclusive",
        "scope_kind": "entry_host",
        "network": "203.0.113.40/32",
        "interface": "route0",
        "source_address": "192.0.2.10",
        "next_hop": "192.0.2.1",
        "route_table": "main",
        "route_type": "default",
        "access_mode": "routed",
        "layer2_connected": False,
        "hosts": [
            {
                "ip": "203.0.113.40",
                "address": "203.0.113.40",
                "record_type": "entry_target",
                "origin": "operator_supplied",
                "independently_discovered": False,
                "reachability_state": "reachability_not_established",
                "selectable": False,
            }
        ],
    }
    workflow = {
        "entry_target": "203.0.113.40",
        "segments": {segment["segment_id"]: segment},
        "paths": {},
        "segment_order": [segment["segment_id"]],
        "visited_segment_ids": [segment["segment_id"]],
        "pending_path_ids": [],
        "current_segment_id": segment["segment_id"],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow=workflow,
    )

    with pytest.raises(DiscoveryWorkflowError):
        prepare_assessment_from_current_layer(scan_id)

    prepare_assessment_from_current_layer(
        scan_id,
        allow_inconclusive_operator_targets=True,
    )
    data = scan_store.get(scan_id)
    host = data["workflow"]["segments"][segment["segment_id"]]["hosts"][0]
    assert data["status"] == scan_store.STATUS_AWAITING_CONFIGURATION
    assert host["selectable"] is True
    assert host["reachability_state"] == "reachability_not_established"
    assert host["assessment_discovery_bypass"] is True
    assert data["workflow"]["phase_results"]["assessment"]["override_targets"] == [
        "203.0.113.40"
    ]


def test_authorize_and_revoke_observed_route_preserves_kernel_configuration(monkeypatch):
    scan_id = scan_store.new_scan("198.51.100.30")
    route = {"dst": "10.80.90.0/24", "dev": "range0", "gateway": "192.0.2.1"}
    signature = _route_signature(route)
    segment_id = _segment_identifier(
        "198.51.100.30/32",
        "uplink0",
        "192.0.2.10",
        "192.0.2.1",
        "main",
        "entry_host",
    )
    observation_id = "routeobs_test_authorize"
    segment = {
        "segment_id": segment_id,
        "scope_kind": "entry_host",
        "network": "198.51.100.30/32",
        "interface": "uplink0",
        "source_address": "192.0.2.10",
        "next_hop": "192.0.2.1",
        "route_observation_ids": [observation_id],
        "path_ids": [],
        "hosts": [],
    }
    workflow = {
        "entry_target": "198.51.100.30",
        "segments": {segment_id: segment},
        "current_segment_id": segment_id,
        "segment_order": [segment_id],
        "visited_segment_ids": [segment_id],
        "paths": {},
        "route_observations": [
            {
                "observation_id": observation_id,
                "route_signature": signature,
                "destination_network": "10.80.90.0/24",
                "interface": "range0",
                "source_address": "10.80.0.5",
                "next_hop": "192.0.2.1",
                "route_table": "main",
                "route_type": "unicast",
                "route_scope": "",
                "route_protocol": "",
                "address_count": 256,
                "enumeration_eligible": True,
                "route": route,
                "baseline": True,
                "mission_related": False,
                "relationship": "baseline_route_observation_only",
            }
        ],
        "baseline_route_signatures": [signature],
        "authorized_route_signatures": [],
        "authorized_route_networks": [],
        "authorized_route_records": {},
        "pending_path_ids": [],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_LAYER_ENUMERATION,
        workflow=workflow,
    )

    snapshot = {
        "captured_at": "2026-08-07T00:00:00+00:00",
        "routes": [route],
        "route_signatures": [signature],
        "interface_index": {
            "range0": {"addresses": [{"address": "10.80.0.5", "prefixlen": 24}]}
        },
    }
    monkeypatch.setattr(
        "scanners.phase_discovery.collect_network_snapshot",
        lambda *_args, **_kwargs: snapshot,
    )

    authorize_observed_route(scan_id, observation_id)
    data = scan_store.get(scan_id)
    assert data["status"] == scan_store.STATUS_AWAITING_LAYER_DECISION
    assert signature in data["workflow"]["authorized_route_signatures"]
    assert data["workflow"]["authorized_route_records"][signature]["authorized_by"] == "operator"
    path_id = data["workflow"]["segments"][segment_id]["path_ids"][0]
    path = data["workflow"]["paths"][path_id]
    assert path["verification_state"] == "authorized_pending_verification"
    assert path["authorization_state"] == "operator_authorized"

    revoke_authorized_route(scan_id, path_id)
    data = scan_store.get(scan_id)
    assert signature not in data["workflow"]["authorized_route_signatures"]
    assert path_id not in data["workflow"]["segments"][segment_id]["path_ids"]
    assert data["workflow"]["paths"][path_id]["authorization_state"] == "authorization_revoked"
