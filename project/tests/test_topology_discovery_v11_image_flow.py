from __future__ import annotations

from pathlib import Path

from scanners import phase_discovery
from storage import scan_store


def _mission(device_ip: str = "198.18.10.2") -> tuple[str, dict]:
    scan_id = scan_store.new_scan(device_ip)
    segment = {
        "segment_id": "seg_current",
        "layer_index": 1,
        "scope_kind": "local_connected_network",
        "network": "198.18.10.0/24",
        "interface": "eth0",
        "source_address": "198.18.10.50",
        "hosts": [{"ip": device_ip, "selectable": True, "role": "router"}],
        "path_ids": [],
    }
    workflow = {
        "entry_target": device_ip,
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
    return scan_id, workflow


def test_authenticated_topology_is_primary_and_supplemental_cannot_create_extra_branch(monkeypatch):
    scan_id, _workflow = _mission()
    monkeypatch.setenv("INFRA_TOPOLOGY_SUPPLEMENTAL_EVIDENCE", "1")
    monkeypatch.setattr(
        "scanners.enterprise_readiness.validate_scope",
        lambda *_args, **_kwargs: {"scope_mode": "test"},
    )
    monkeypatch.setattr(
        phase_discovery,
        "_discovery_network_scope_state",
        lambda _network: (True, "test"),
    )
    monkeypatch.setattr(
        "scanners.infrastructure_discovery.collect_device_topology",
        lambda *_args, **_kwargs: {
            "observation_id": "auth_obs",
            "device_ip": "198.18.10.2",
            "profile_ref": "lab-readonly",
            "access_source": "configured_profile",
            "platform": "cisco_ios",
            "transport": "ssh",
            "interfaces": [],
            "routes": [],
            "networks": [
                {
                    "destination_network": "198.18.20.0/24",
                    "device_interface": "Vlan20",
                    "device_interface_ip": "198.18.20.1",
                    "enumeration_eligible": True,
                    "evidence_sources": ["device_interface"],
                }
            ],
        },
    )
    monkeypatch.setattr(
        "scanners.topology_evidence.collect_device_topology_evidence",
        lambda *_args, **_kwargs: {
            "device_ip": "198.18.10.2",
            "candidate_networks": [
                {
                    "network": "198.18.20.0/24",
                    "source": "passive_routing_advertisement",
                    "confidence": "medium",
                    "evidence": [{"type": "test_corroboration"}],
                },
                {
                    # This network exists only in supplemental evidence and must
                    # never become a continuation branch by itself.
                    "network": "198.18.99.0/24",
                    "source": "management_plane_disclosure",
                    "confidence": "medium",
                    "evidence": [{"type": "supplement_only"}],
                },
            ],
            "collectors": {},
            "boundary_state": "continuation_candidates_observed",
        },
    )

    phase_discovery.discover_next_networks_from_device(
        scan_id, "198.18.10.2", profile_ref="lab-readonly"
    )
    data = scan_store.get(scan_id)
    paths = list(data["workflow"]["paths"].values())
    assert [row["destination_network"] for row in paths] == ["198.18.20.0/24"]
    assert paths[0]["reachability_state"] == "unknown"
    assert paths[0]["evidence_source_label"].startswith("Configured device")
    assert "supplemental:passive_routing_advertisement" in paths[0]["evidence_sources"]
    observation = data["workflow"]["topology_observations"][0]
    assert observation["supplemental_topology_evidence"]["boundary_state"] == "continuation_candidates_observed"


def test_stop_phase2_hands_full_inventory_to_phase3_instead_of_closing_mission():
    scan_id, workflow = _mission()
    second = {
        "segment_id": "seg_second",
        "layer_index": 2,
        "scope_kind": "topology_network",
        "network": "198.18.20.0/24",
        "hosts": [{"ip": "198.18.20.25", "selectable": True, "role": "host"}],
    }
    workflow["segments"][second["segment_id"]] = second
    workflow["segment_order"].append(second["segment_id"])
    workflow["visited_segment_ids"].append(second["segment_id"])
    workflow["current_segment_id"] = second["segment_id"]
    phase_discovery._accumulate_assets(workflow, second["hosts"], segment=second)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_LAYER_DECISION, workflow=workflow)

    phase_discovery.stop_discovery(scan_id)
    data = scan_store.get(scan_id)
    assert data["status"] == scan_store.STATUS_AWAITING_CONFIGURATION
    retained = {row.get("ip") or row.get("address") for row in data["workflow"]["asset_inventory"]}
    assert {"198.18.10.2", "198.18.20.25"}.issubset(retained)
    assert data["workflow"]["phase_results"]["assessment"]["inventory_scope"] == "all_discovered_assets"


def test_phase2_template_matches_operator_controlled_loop_design():
    project_root = Path(phase_discovery.__file__).resolve().parents[1]
    template = (project_root / "templates/layer_decision.html").read_text(encoding="utf-8")
    for phrase in (
        "Enumerate Current Subnet",
        "Identify Devices",
        "Inspect Selected Devices",
        "Link Networks",
        "Continue or Finish",
        "Devices Discovered on Current Subnet",
        "Continuation Networks",
        "EVIDENCE SOURCE",
        "Continue Discovery",
        "Stop Phase 2 · Proceed to Phase 3",
        "Reachable · verified",
        "Unknown · not yet tested",
        "Unreachable · blocked/failed",
    ):
        assert phrase in template
    assert 'name="device_ips"' in template
    assert 'value="query_device"' not in template
    assert 'value="query_device_runtime"' not in template
    assert 'value="discover_device"' in template
    assert 'name="path_id"' in template
    assert 'value="continue_path"' in template
    assert 'value="finish_phase2"' in template


def test_phase2_code_contains_no_demo_network_constants():
    project_root = Path(phase_discovery.__file__).resolve().parents[1]
    files = [
        project_root / "scanners/phase_discovery.py",
        project_root / "scanners/infrastructure_discovery.py",
        project_root / "scanners/topology_evidence.py",
        project_root / "routes/scan_routes.py",
        project_root / "templates/layer_decision.html",
    ]
    source = "\n".join(path.read_text(encoding="utf-8") for path in files)
    for value in ("192.168.1.42", "203.0.113.0/24", "172.16.0.0/24", "10.10.10.0/24"):
        assert value not in source
