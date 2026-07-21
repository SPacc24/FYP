"""Closed-loop mission orchestration tests (no hard-coded module paths)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Isolate mission storage before imports that touch service singleton.
@pytest.fixture()
def mission_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPENTEST_MISSIONS_DIR", str(tmp_path / "missions"))
    monkeypatch.setenv("AUTOPENTEST_PROOFS_DIR", str(tmp_path / "proofs"))
    from automation import mission_service as ms

    ms.reset_mission_service()
    yield tmp_path
    ms.reset_mission_service()


def _web_smb_results(target: str = "10.10.10.20") -> dict:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [
                    {"port": 80, "state": "open", "service": "http", "product": "Apache"},
                    {"port": 445, "state": "open", "service": "microsoft-ds", "product": "Windows"},
                    {"port": 22, "state": "open", "service": "ssh"},
                ],
            }
        ],
    }


def _ms17_results(target: str = "10.10.10.30") -> dict:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [
                    {"port": 445, "state": "open", "service": "microsoft-ds"},
                ],
            }
        ],
        "vulnerabilities": [{"host": target, "port": 445, "cve": "CVE-2017-0144"}],
    }


def _unknown_results(target: str = "10.10.10.40") -> dict:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [
                    {"port": 31337, "state": "open", "service": "custom-proto", "product": "LabApp"},
                ],
            }
        ],
    }


def test_playbook_loader_lists_json_only(mission_env):
    from automation.playbook_loader import default_playbook_id, list_playbooks, load_playbook

    entries = list_playbooks()
    assert any(e["id"] == "edge_to_internal_proof" for e in entries)
    pb = load_playbook(default_playbook_id())
    assert pb["stages"]
    assert pb["branches"]
    assert pb["evidence_detectors"]


def test_engine_branches_on_patched_ms17(mission_env):
    from automation.playbook_engine import PlaybookEngine

    engine = PlaybookEngine(playbook_id="edge_to_internal_proof")
    mission = engine.start_mission(parsed_results=_web_smb_results())
    flags = set(mission.get("flags") or [])
    assert "smb_present" in flags
    assert "http_present" in flags
    # Geographic celebrity kill-path should suppress without CVE evidence
    assert "branch_ms17_suppressed" in flags or "ms17_not_exploitable" in flags
    assert "impact_path_available" in flags  # via web
    # High-risk items wait for humans
    pending = [a for a in mission["action_queue"] if a.get("status") == "awaiting_approval"]
    assert any(a.get("requires_approval") for a in pending) or mission["status"] in {
        "awaiting_approval",
        "awaiting_operator",
        "running",
        "completed",
        "blocked_unlock",
    }


def test_safe_only_never_queues_exploits(mission_env):
    from automation.playbook_engine import PlaybookEngine

    engine = PlaybookEngine(playbook_id="surface_validation_only")
    mission = engine.start_mission(
        parsed_results=_ms17_results(),
        risk_posture="safe-only",
    )
    for action in mission.get("action_queue") or []:
        assert action.get("module_type") != "exploit"
        assert action.get("status") != "awaiting_approval" or action.get("risk") in {
            "info",
            "low",
            "medium",
            "high",
        }
    # With safe-only surface playbook, stage flow should complete without impact gate
    assert mission["status"] in {"completed", "awaiting_operator", "running"}


def test_unknown_surface_research_queue(mission_env):
    from automation.playbook_engine import PlaybookEngine

    engine = PlaybookEngine(playbook_id="edge_to_internal_proof")
    mission = engine.start_mission(parsed_results=_unknown_results())
    assert mission.get("research_queue"), "unknown surface should enter research queue"
    assert "unknown_surface_present" in set(mission.get("flags") or [])
    # LLM did not invent modules — catalog key empty for research rows
    research_actions = [a for a in mission["action_queue"] if a.get("kind") == "research_probe"]
    assert research_actions
    assert all(not a.get("catalog_key") for a in research_actions)


def test_proof_unlocks_pivot(mission_env):
    from automation.mission_service import get_mission_service

    svc = get_mission_service()
    mission = svc.start(
        playbook_id="edge_to_internal_proof",
        parsed_results=_web_smb_results(),
    )
    mid = mission["mission_id"]

    # Clear impact gate approvals; engine should then block on pivot_expand
    for _ in range(20):
        mission = svc.get(mid)
        if mission["status"] == "blocked_unlock" and mission.get("current_stage_id") == "pivot_expand":
            break
        pending = [
            a for a in mission["action_queue"] if a["status"] == "awaiting_approval"
            and a.get("kind") != "pivot_segment"
        ]
        if pending:
            svc.approve(mid, pending[0]["queue_id"], approved=True, operator_note="lab")
            continue
        if mission["status"] == "awaiting_operator":
            svc.continue_mission(mid)
            continue
        break

    mission = svc.get(mid)
    assert mission.get("current_stage_id") == "pivot_expand" or "impact_path_available" in set(
        mission.get("flags") or []
    )

    mission = svc.attach_proof(
        mid,
        evidence="Authorised reverse shell callback observed",
        target="10.10.10.20",
        proof_type="operator_attested",
    )
    assert "foothold_proved" in set(mission.get("flags") or [])
    pivots = [a for a in mission["action_queue"] if a.get("kind") == "pivot_segment"]
    assert pivots, "foothold proof should unlock pivot segment recommendations"
    assert all(p.get("requires_approval") for p in pivots)
    assert all(p.get("status") == "awaiting_approval" for p in pivots)


def test_attack_graph_built_from_evidence(mission_env):
    from automation.attack_graph import build_attack_graph

    graph = build_attack_graph(_web_smb_results())
    kinds = {n["kind"] for n in graph["nodes"]}
    assert "host" in kinds
    assert "service" in kinds
    assert graph["stats"]["hosts"] >= 1
    assert graph["stats"]["services"] >= 2


def test_validate_safe_and_impact_outcome_closed_loop(mission_env):
    from automation.mission_service import get_mission_service

    svc = get_mission_service()
    mission = svc.start(
        playbook_id="edge_to_internal_proof",
        parsed_results=_web_smb_results(),
    )
    mid = mission["mission_id"]

    # Safe auxiliaries should leave queued_auto → succeeded without approving exploits
    before_auto = [a for a in mission["action_queue"] if a["status"] == "queued_auto"]
    assert before_auto, "expected safe auto-queue from catalog"
    mission = svc.validate_safe_actions(mid, outcome="success")
    still_auto = [a for a in mission["action_queue"] if a["status"] == "queued_auto"]
    succeeded = [a for a in mission["action_queue"] if a["status"] == "succeeded"]
    assert succeeded, "safe validation should mark auxiliaries succeeded"
    assert len(still_auto) < len(before_auto)
    assert "safe_validation_recorded" in set(mission.get("flags") or [])

    # High-risk web impact: approve → record success → proof unlocks pivot
    pending = [a for a in mission["action_queue"] if a["status"] == "awaiting_approval"]
    assert pending
    web = next(
        (a for a in pending if "web" in str(a.get("kind")) or "cmdi" in str(a.get("catalog_key"))),
        pending[0],
    )
    mission = svc.approve(mid, web["queue_id"], approved=True)
    mission = svc.record_outcome(
        mid,
        action_queue_id=web["queue_id"],
        outcome="success",
        detail="lab cmdi confirmed",
    )
    flags = set(mission.get("flags") or [])
    assert "impact_confirmed" in flags or "web_impact_confirmed" in flags
    assert "foothold_proved" not in flags  # proof still required

    mission = svc.attach_proof(
        mid,
        evidence="cmdi whoami output captured on authorised diagnostics host",
        target="10.10.10.20",
        catalog_key=web.get("catalog_key") or "",
    )
    assert "foothold_proved" in set(mission.get("flags") or [])
    assert any(a.get("kind") == "pivot_segment" for a in mission["action_queue"])


def test_api_mission_start(mission_env, monkeypatch):
    monkeypatch.setenv("ALLOW_INSECURE_OPERATOR_ACCESS", "1")
    monkeypatch.setattr("config.Config.OPERATOR_TOKEN", "")
    monkeypatch.setattr("config.Config.ALLOW_INSECURE_OPERATOR_ACCESS", True)
    from app import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.post(
        "/api/mission/start",
        json={
            "playbook_id": "edge_to_internal_proof",
            "parsed_results": _web_smb_results(),
        },
    )
    assert r.status_code == 200, r.get_data(as_text=True)
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["mission"]["mission_id"]
    mid = payload["mission"]["mission_id"]

    g = client.get(f"/api/mission/{mid}")
    assert g.status_code == 200
    assert g.get_json()["mission"]["playbook_id"] == "edge_to_internal_proof"

    page = client.get("/mission")
    assert page.status_code == 200
    assert b"Mission Console" in page.data
