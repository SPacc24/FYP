import app as app_module
import routes.caldera_routes as caldera_routes
from storage import scan_store


def test_caldera_run_rejects_unmapped_technique(monkeypatch):
    app_module.app.config["TESTING"] = True
    old_token = app_module.Config.OPERATOR_TOKEN
    app_module.Config.OPERATOR_TOKEN = "test-operator-token"

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
        client = app_module.app.test_client()
        unlock = client.post(
            "/operator/unlock",
            json={"operator_token": "test-operator-token"},
        )
        csrf_token = unlock.get_json()["csrf_token"]

        with client.session_transaction() as flask_session:
            flask_session["scan_id"] = scan_id
            flask_session["technique_mode"] = "auto"

        response = client.post(
            "/caldera/run",
            json={"selected_techniques": ["T1059"]},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 400
        data = response.get_json()
        assert data["ok"] is False
        assert data["invalid_techniques"] == ["T1059"]
        assert data["allowed_techniques"] == ["T1046"]
    finally:
        app_module.Config.OPERATOR_TOKEN = old_token
        with scan_store._lock:
            scan_store._store.pop(scan_id, None)
