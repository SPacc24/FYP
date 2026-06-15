import json

import pytest

from proof_of_access.gate import ProofTicketError, ProofTicketManager
from proof_of_access.record_proof import write_marker


def operation_result(
    *,
    technique_id="T1190",
    status="success",
    timed_out=False,
):
    return {
        "success": True,
        "operation_id": "op-123",
        "operation_name": "controlled-test",
        "timed_out": timed_out,
        "agent_host": "client01",
        "agent_paw": "paw-123",
        "agent_ip_addrs": ["192.0.2.10"],
        "techniques_run": [
            {
                "technique_id": technique_id,
                "technique_name": "Controlled validation",
                "tactic": "initial-access",
                "status": status,
                "timestamp": "2026-06-16T12:00:00Z",
                "link_id": "link-123",
            }
        ],
    }


def test_issues_one_time_host_bound_ticket_after_qualifying_success():
    manager = ProofTicketManager(
        secret="test-secret-that-is-at-least-32-bytes",
        enabled=True,
        ttl_seconds=60,
        clock=lambda: 1000,
    )

    tickets = manager.issue_for_operation(operation_result())

    assert len(tickets) == 1
    proof = manager.redeem(
        tickets[0]["ticket"],
        "CLIENT01.example.test",
        "192.0.2.10",
    )
    assert proof["operation_id"] == "op-123"
    assert proof["technique_id"] == "T1190"

    with pytest.raises(ProofTicketError):
        manager.redeem(tickets[0]["ticket"], "client01", "192.0.2.10")


@pytest.mark.parametrize(
    ("technique_id", "status", "timed_out"),
    [
        ("T1082", "success", False),
        ("T1190", "failed", False),
        ("T1110", "success", True),
    ],
)
def test_refuses_non_qualifying_or_uncertain_results(
    technique_id,
    status,
    timed_out,
):
    manager = ProofTicketManager(
        secret="test-secret-that-is-at-least-32-bytes",
        enabled=True,
        clock=lambda: 1000,
    )

    tickets = manager.issue_for_operation(operation_result(
        technique_id=technique_id,
        status=status,
        timed_out=timed_out,
    ))

    assert tickets == []


def test_rejects_ticket_on_the_wrong_host():
    manager = ProofTicketManager(
        secret="test-secret-that-is-at-least-32-bytes",
        enabled=True,
        clock=lambda: 1000,
    )
    ticket = manager.issue_for_operation(operation_result())[0]["ticket"]

    with pytest.raises(ProofTicketError):
        manager.redeem(ticket, "different-host", "192.0.2.10")


def test_rejects_ticket_from_the_wrong_source_address():
    manager = ProofTicketManager(
        secret="test-secret-that-is-at-least-32-bytes",
        enabled=True,
        clock=lambda: 1000,
    )
    ticket = manager.issue_for_operation(operation_result())[0]["ticket"]

    with pytest.raises(ProofTicketError):
        manager.redeem(ticket, "client01", "192.0.2.99")


def test_short_signing_secret_keeps_feature_inactive():
    manager = ProofTicketManager(
        secret="too-short",
        enabled=True,
        clock=lambda: 1000,
    )

    assert manager.active is False
    assert manager.issue_for_operation(operation_result()) == []


def test_flask_redemption_endpoint_enforces_one_time_use(monkeypatch):
    import app as app_module

    manager = ProofTicketManager(
        secret="test-secret-that-is-at-least-32-bytes",
        enabled=True,
        clock=lambda: 1000,
    )
    result = operation_result()
    result["agent_ip_addrs"] = ["127.0.0.1"]
    ticket = manager.issue_for_operation(result)[0]["ticket"]
    monkeypatch.setattr(app_module, "proof_ticket_manager", manager)

    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    response = client.post(
        "/proof-of-access/redeem",
        json={
            "ticket": ticket,
            "observed_host": "client01",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["proof"]["link_id"] == "link-123"

    replay = client.post(
        "/proof-of-access/redeem",
        json={
            "ticket": ticket,
            "observed_host": "client01",
        },
    )
    assert replay.status_code == 400


def test_writes_minimal_tamper_evident_marker(tmp_path):
    proof = {
        "nonce": "nonce-123",
        "operation_id": "op-123",
        "link_id": "link-123",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "initial-access",
        "agent_host": "client01",
        "completed_at": "2026-06-16T12:00:00Z",
    }

    marker_path = write_marker(proof, tmp_path, "client01")
    marker = json.loads(marker_path.read_text(encoding="utf-8"))

    assert marker["proof_type"] == "controlled-access-validation"
    assert marker["operation_id"] == "op-123"
    assert len(marker["sha256"]) == 64
    assert "command" not in marker
    assert "output" not in marker
    assert "credential" not in marker
