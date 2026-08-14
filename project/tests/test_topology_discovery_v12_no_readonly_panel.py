from pathlib import Path


def test_phase2_template_has_no_readonly_topology_access_panel():
    template = (Path(__file__).resolve().parents[1] / "templates" / "layer_decision.html").read_text(encoding="utf-8")
    forbidden = [
        "Read-only topology access",
        "ON-DEMAND READ-ONLY TOPOLOGY ACCESS",
        "runtimePlatform",
        "runtimeTransport",
        "runtimeUsername",
        "runtimeSecret",
        'value="query_device_runtime"',
    ]
    for value in forbidden:
        assert value not in template
    assert 'value="discover_device"' in template
    assert "Find Next Network" in template


def test_phase2_route_does_not_collect_runtime_topology_credentials():
    source = (Path(__file__).resolve().parents[1] / "routes" / "scan_routes.py").read_text(encoding="utf-8")
    assert 'action in {"discover_device", "query_device"}' in source
    assert "runtime_username" not in source
    assert "runtime_secret" not in source
    assert "public_profile_catalog" not in source
    assert "profile_selection_context" not in source


def test_phase2_default_discovery_uses_observed_evidence_not_infrastructure_profile_source():
    source = (Path(__file__).resolve().parents[1] / "scanners" / "phase_discovery.py").read_text(encoding="utf-8")
    assert 'legacy_profile_mode = bool(str(profile_ref or "").strip() or runtime_profile is not None)' in source
    assert 'collect_device_topology_evidence' in source
    assert 'evidence_mode = "observed_network_evidence"' in source



def test_default_device_discovery_creates_branch_from_observed_prefix(monkeypatch):
    from scanners import phase_discovery
    from storage import scan_store

    scan_id = scan_store.new_scan("198.18.10.2")
    segment = {
        "segment_id": "seg_current",
        "layer_index": 1,
        "scope_kind": "local_connected_network",
        "network": "198.18.10.0/24",
        "interface": "eth0",
        "source_address": "198.18.10.50",
        "hosts": [{"ip": "198.18.10.2", "selectable": True, "role": "router"}],
        "path_ids": [],
    }
    workflow = {
        "entry_target": "198.18.10.2",
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
        "scanners.enterprise_readiness.validate_scope",
        lambda *_args, **_kwargs: {"scope_mode": "test"},
    )
    monkeypatch.setattr(
        phase_discovery,
        "_discovery_network_scope_state",
        lambda _network: (True, "test"),
    )
    monkeypatch.setattr(
        phase_discovery,
        "collect_local_observation_snapshot",
        lambda *_args, **_kwargs: {"routes": [], "interfaces": []},
    )
    monkeypatch.setattr(
        "scanners.topology_evidence.collect_device_topology_evidence",
        lambda *_args, **_kwargs: {
            "device_ip": "198.18.10.2",
            "captured_at": "2026-08-12T00:00:00Z",
            "candidate_networks": [
                {
                    "network": "198.18.20.0/24",
                    "interface": "eth0",
                    "source": "passive_routing_advertisement",
                    "confidence": "medium",
                    "evidence_sources": ["passive_routing_advertisement"],
                    "evidence": [{"type": "test_prefix"}],
                    "enumeration_eligible": True,
                }
            ],
            "collectors": {},
            "boundary_state": "continuation_candidates_observed",
        },
    )

    phase_discovery.discover_next_networks_from_device(scan_id, "198.18.10.2")
    data = scan_store.get(scan_id)
    paths = list(data["workflow"]["paths"].values())
    assert len(paths) == 1
    assert paths[0]["destination_network"] == "198.18.20.0/24"
    assert paths[0]["evidence_source_label"] == "Observed network evidence from selected device"
    continuation = data["workflow"]["topology_continuation"]
    assert continuation["access_source"] == "observed_network_evidence"
    assert continuation["state"] == "network_evidence_observed"
