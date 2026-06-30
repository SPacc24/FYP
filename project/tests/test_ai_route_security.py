import app as app_module


def test_caldera_run_rejects_unmapped_technique(monkeypatch):
    state_id = "test-ai-route-security"

    app_module.app.config["TESTING"] = True
    app_module.SERVER_STATE[state_id] = {
        "mapping_results": {
            "recommended_techniques": [
                {"id": "T1046", "name": "Network Service Discovery"}
            ],
            "vulnerabilities": [],
        },
        "ai_plan": {
            "selected_technique_ids": ["T1046"]
        },
    }

    def fail_if_called(*args, **kwargs):
        raise AssertionError("CALDERA should not be called for unmapped techniques")

    monkeypatch.setattr(app_module.operation_manager, "run_operation", fail_if_called)

    client = app_module.app.test_client()

    with client.session_transaction() as flask_session:
        flask_session["assessment_state_id"] = state_id
        flask_session["technique_mode"] = "auto"

    response = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1059"]},
    )

    assert response.status_code == 400

    data = response.get_json()
    assert data["ok"] is False
    assert data["invalid_techniques"] == ["T1059"]
    assert data["allowed_techniques"] == ["T1046"]

    app_module.SERVER_STATE.pop(state_id, None)
