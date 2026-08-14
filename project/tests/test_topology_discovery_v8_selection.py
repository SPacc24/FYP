from __future__ import annotations

from pathlib import Path

from scanners import phase_discovery
from scanners.infrastructure_discovery import profile_selection_context
from storage import scan_store


def _local_workflow() -> dict:
    segment = {
        "segment_id": "local_v8",
        "layer_index": 1,
        "scope_kind": "local_connected_network",
        "network": "192.168.1.0/24",
        "hosts": [
            {
                "ip": "192.168.1.1",
                "address": "192.168.1.1",
                "selectable": True,
                "reachability_state": "responsive",
                "role": "host",
                "hostname": "Linksys03374",
                "mac_vendor": "Belkin International",
            },
            {
                "ip": "192.168.1.32",
                "address": "192.168.1.32",
                "selectable": True,
                "reachability_state": "responsive",
                "role": "host",
            },
            {
                "ip": "192.168.1.42",
                "address": "192.168.1.42",
                "selectable": True,
                "reachability_state": "responsive",
                "role": "host",
                "mac_vendor": "Cisco Systems",
            },
        ],
        "path_ids": [],
    }
    workflow = {
        "entry_target": "192.168.1.1",
        "entry_result": {"reachable": True},
        "segments": {segment["segment_id"]: segment},
        "segment_order": [segment["segment_id"]],
        "visited_segment_ids": [segment["segment_id"]],
        "current_segment_id": segment["segment_id"],
        "paths": {},
        "asset_inventory": [],
        "operator_decisions": [],
        "phase_results": {"assessment": {"status": "not_started", "targets": []}},
    }
    phase_discovery._accumulate_assets(workflow, segment["hosts"], segment=segment)
    phase_discovery._set_current_aliases(workflow)
    return workflow


def test_profile_context_preserves_device_selection_when_no_profile(monkeypatch):
    monkeypatch.delenv("INFRA_TOPOLOGY_PROFILES_JSON", raising=False)
    monkeypatch.delenv("INFRA_TOPOLOGY_DEFAULT_PROFILE", raising=False)
    context = profile_selection_context("192.168.1.42")
    assert context["ready"] is False
    assert context["state"] == "profile_required"
    assert "selected successfully" in context["message"]


def test_profile_context_auto_matches_selected_device(monkeypatch):
    monkeypatch.setenv(
        "INFRA_TOPOLOGY_PROFILES_JSON",
        '{"cisco-router":{"label":"Cisco Internet Router","platform":"cisco_ios","transport":"ssh","username":"readonly","secret_env":"CISCO_TOPOLOGY_PASSWORD","match_hosts":["192.168.1.42"]}}',
    )
    monkeypatch.delenv("INFRA_TOPOLOGY_DEFAULT_PROFILE", raising=False)
    context = profile_selection_context("192.168.1.42")
    assert context["ready"] is True
    assert context["resolved_profile_ref"] == "cisco-router"
    assert context["selection_source"] == "device_match"




def test_scoped_profile_does_not_auto_enable_other_hosts(monkeypatch):
    monkeypatch.setenv(
        "INFRA_TOPOLOGY_PROFILES_JSON",
        '{"cisco-router":{"label":"Cisco Internet Router","platform":"cisco_ios","transport":"ssh","username":"readonly","secret_env":"CISCO_TOPOLOGY_PASSWORD","match_hosts":["192.168.1.42"]}}',
    )
    monkeypatch.delenv("INFRA_TOPOLOGY_DEFAULT_PROFILE", raising=False)
    matching = profile_selection_context("192.168.1.42")
    other = profile_selection_context("192.168.1.32")
    assert matching["ready"] is True
    assert other["ready"] is False
    assert other["state"] == "profile_not_matched"

def test_profile_context_requires_explicit_choice_when_multiple_profiles_do_not_match(monkeypatch):
    monkeypatch.setenv(
        "INFRA_TOPOLOGY_PROFILES_JSON",
        '{"router-a":{"platform":"cisco_ios","transport":"ssh","username":"ro","match_hosts":["10.0.0.1"]},"router-b":{"platform":"palo_alto","transport":"ssh","username":"ro","match_hosts":["10.0.0.2"]}}',
    )
    monkeypatch.delenv("INFRA_TOPOLOGY_DEFAULT_PROFILE", raising=False)
    context = profile_selection_context("192.168.1.42")
    assert context["ready"] is False
    assert context["state"] == "profile_selection_required"


def test_phase2_post_accepts_device_selection_without_profile_and_preserves_it(monkeypatch):
    monkeypatch.delenv("INFRA_TOPOLOGY_PROFILES_JSON", raising=False)
    monkeypatch.delenv("INFRA_TOPOLOGY_DEFAULT_PROFILE", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE_OPERATOR_ACCESS", "1")

    import pytest
    pytest.importorskip("flask")
    from config import Config
    monkeypatch.setattr(Config, "OPERATOR_TOKEN", "")
    monkeypatch.setattr(Config, "ALLOW_INSECURE_OPERATOR_ACCESS", True)
    from app import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    scan_id = scan_store.new_scan("192.168.1.1")
    workflow = _local_workflow()
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        results={"workflow": workflow},
    )
    scan_store.persist(scan_id)

    response = client.post(
        f"/scan/layer/{scan_id}",
        data={"action": "query_device", "device_ip": "192.168.1.42"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    data = scan_store.get(scan_id)
    assert data["status"] == scan_store.STATUS_AWAITING_LAYER_DECISION
    continuation = data["workflow"]["topology_continuation"]
    assert continuation["selected_device_ip"] == "192.168.1.42"
    assert continuation["state"] == "profile_required"
    assert "profile" in str(data.get("error") or "").lower()

    page = client.get(f"/scan/layer/{scan_id}")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert 'value="192.168.1.42" checked' in html
    assert 'id="continueDiscoveryBtn"' in html
    # The server-side lock must no longer depend on profile availability.
    assert "not current_hosts or not infrastructure_profiles" not in html
    assert "Selected Continuation Device" in html


def test_generic_host_is_low_unconfirmed_guidance_but_still_selectable():
    workflow = _local_workflow()
    inventory = {row["ip"]: row for row in workflow["asset_inventory"]}
    assert inventory["192.168.1.42"]["infrastructure_candidate_state"] == "likely"
    assert inventory["192.168.1.1"]["infrastructure_candidate_state"] == "likely"
    assert inventory["192.168.1.32"]["infrastructure_candidate_state"] == "possible"
    assert inventory["192.168.1.32"]["selectable"] is True


def test_stop_reason_distinguishes_no_observed_continuation_from_no_deeper_network_claim():
    workflow = _local_workflow()
    workflow["topology_continuation"] = {
        "selected_device_ip": "192.168.1.42",
        "state": "no_continuation_observed",
    }
    stop = phase_discovery._phase2_stop_summary(workflow)
    assert stop["code"] == "operator_finished_without_observed_continuation"
    assert "does not prove that no deeper network exists" in stop["message"]


def test_phase2_template_allows_selection_without_global_profile_lock():
    project_root = Path(phase_discovery.__file__).resolve().parents[1]
    template = (project_root / "templates/layer_decision.html").read_text(encoding="utf-8")
    route_source = (project_root / "routes/scan_routes.py").read_text(encoding="utf-8")
    assert "not current_hosts or not infrastructure_profiles" not in template
    assert "continueDiscoveryBtn" in template
    assert "inspect their network evidence" in template.lower()
    assert "Continue to Selected Network" in template
    assert 'workflow["topology_continuation"] = continuation_state' in route_source
    assert "profile_context" not in route_source
    assert "_network_discovery_worker" in route_source
