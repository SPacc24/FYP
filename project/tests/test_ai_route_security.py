import app as app_module
import routes.caldera_routes as caldera_routes
from storage import scan_store


def _unlocked_client():
    client = app_module.app.test_client()
    unlock = client.post(
        "/operator/unlock",
        json={"operator_token": "test-operator-token"},
    )
    return client, unlock.get_json()["csrf_token"]


def test_caldera_agent_select_validates_paw_against_available_agents(monkeypatch):
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(app_module.Config, "OPERATOR_TOKEN", "test-operator-token")
    monkeypatch.setattr(app_module.Config, "AGENT_GROUP", "red")

    def check_agent(group, target, selected_paw):
        assert group == "red"
        assert target == "10.0.0.5"
        assert selected_paw == "abc123"
        return True, {"paw": "abc123", "host": "victim-win10"}

    monkeypatch.setattr(caldera_routes.operation_manager, "check_agent", check_agent)

    client, csrf_token = _unlocked_client()

    with client.session_transaction() as flask_session:
        flask_session["target_ip"] = "10.0.0.5"

    response = client.post(
        "/caldera/agent/select",
        json={"paw": " abc123 "},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["selected_agent_paw"] == "abc123"
    assert data["agent"]["paw"] == "abc123"
    assert data["target"] == "10.0.0.5"

    with client.session_transaction() as flask_session:
        assert flask_session["selected_agent_paw"] == "abc123"


def test_caldera_agent_select_rejects_unknown_paw(monkeypatch):
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(app_module.Config, "OPERATOR_TOKEN", "test-operator-token")

    monkeypatch.setattr(
        caldera_routes.operation_manager,
        "check_agent",
        lambda **kwargs: (False, "No trusted online agents found."),
    )

    client, csrf_token = _unlocked_client()

    response = client.post(
        "/caldera/agent/select",
        json={"paw": "missing"},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 400
    data = response.get_json()
    assert data["ok"] is False
    assert data["error"] == "No trusted online agents found."


def test_caldera_run_requires_execution_gate_and_approval(monkeypatch):
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(app_module.Config, "OPERATOR_TOKEN", "test-operator-token")
    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", False)

    client, csrf_token = _unlocked_client()

    disabled = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1046"], "approved": True},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert disabled.status_code == 403
    assert disabled.get_json()["error"] == "CALDERA execution is disabled."

    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", True)

    missing_approval = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1046"], "approved": False},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert missing_approval.status_code == 400
    assert missing_approval.get_json()["error"] == (
        "Explicit operator approval is required."
    )

    extra_field = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1046"], "approved": True, "group": "blue"},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert extra_field.status_code == 400
    assert extra_field.get_json()["error"] == (
        "Only selected_techniques and approved are accepted."
    )


def test_caldera_run_uses_configured_group_and_target_context(monkeypatch):
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(app_module.Config, "OPERATOR_TOKEN", "test-operator-token")
    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", True)
    monkeypatch.setattr(app_module.Config, "AGENT_GROUP", "red")
    monkeypatch.setattr(app_module.Config, "OPERATION_TIMEOUT", 45)

    scan_id = scan_store.new_scan("192.168.56.20")
    scan_store.update(
        scan_id,
        selected_internal_target={
            "ip": "10.0.0.5",
            "os": "Windows",
        },
        external_target="192.168.56.20",
        mapping={
            "recommended_techniques": [
                {"id": "T1046", "name": "Network Service Discovery"}
            ],
            "vulnerabilities": [],
        },
        ai_plan={"selected_technique_ids": ["T1046"]},
    )

    monkeypatch.setattr(
        caldera_routes.coverage_checker,
        "check_technique_coverage",
        lambda technique_ids: {"unsupported": 0},
    )
    monkeypatch.setattr(
        caldera_routes.coverage_checker,
        "get_supported_techniques",
        lambda technique_ids: list(technique_ids),
    )
    monkeypatch.setattr(
        caldera_routes.proof_ticket_manager,
        "issue_for_operation",
        lambda result: [],
    )
    monkeypatch.setattr(
        caldera_routes.risk_scorer,
        "get_vulnerability_remediations",
        lambda mapping_results: [],
    )
    monkeypatch.setattr(
        caldera_routes.risk_scorer,
        "get_all_remediations",
        lambda result: [],
    )

    def run_operation(**kwargs):
        assert kwargs["technique_ids"] == ["T1046"]
        assert kwargs["group"] == "red"
        assert kwargs["timeout"] == 45
        assert kwargs["target"] == "10.0.0.5"
        assert kwargs["selected_paw"] == "abc123"
        return {
            "success": True,
            "operation_id": "op001",
            "techniques_run": [],
        }

    monkeypatch.setattr(caldera_routes.operation_manager, "run_operation", run_operation)

    try:
        client, csrf_token = _unlocked_client()

        with client.session_transaction() as flask_session:
            flask_session["scan_id"] = scan_id
            flask_session["technique_mode"] = "auto"
            flask_session["selected_agent_paw"] = "abc123"

        response = client.post(
            "/caldera/run",
            json={"selected_techniques": ["T1046"], "approved": True},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["ok"] is True
        assert data["target"] == "10.0.0.5"
        assert data["target_source"] == "pivot_scan"
        assert data["external_target"] == "192.168.56.20"
    finally:
        with scan_store._lock:
            scan_store._store.pop(scan_id, None)


def test_caldera_run_rejects_unmapped_technique(monkeypatch):
    app_module.app.config["TESTING"] = True
    old_token = app_module.Config.OPERATOR_TOKEN
    old_caldera_execution = app_module.Config.ENABLE_CALDERA_EXECUTION
    app_module.Config.OPERATOR_TOKEN = "test-operator-token"
    app_module.Config.ENABLE_CALDERA_EXECUTION = True

    scan_id = scan_store.new_scan("192.0.2.10")
    scan_store.update(
        scan_id,
        mapping={
            "recommended_techniques": [
                {"id": "T1046", "name": "Network Service Discovery"}
            ],
            "vulnerabilities": [],
        },
        ai_plan={"selected_technique_ids": ["T1046"]},
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("CALDERA should not be called for unmapped techniques")

    monkeypatch.setattr(
        caldera_routes.operation_manager,
        "run_operation",
        fail_if_called,
    )

    try:
        client, csrf_token = _unlocked_client()

        with client.session_transaction() as flask_session:
            flask_session["scan_id"] = scan_id
            flask_session["technique_mode"] = "auto"

        response = client.post(
            "/caldera/run",
            json={"selected_techniques": ["T1059"], "approved": True},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 400
        data = response.get_json()
        assert data["ok"] is False
        assert data["invalid_techniques"] == ["T1059"]
        assert data["allowed_techniques"] == ["T1046"]
    finally:
        app_module.Config.OPERATOR_TOKEN = old_token
        app_module.Config.ENABLE_CALDERA_EXECUTION = old_caldera_execution
        with scan_store._lock:
            scan_store._store.pop(scan_id, None)