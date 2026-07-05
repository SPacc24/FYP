import app as app_module


def test_operator_token_locks_sensitive_routes_until_unlocked():
    old_token = app_module.Config.OPERATOR_TOKEN
    app_module.Config.OPERATOR_TOKEN = "test-operator-token"
    app_module.app.config["TESTING"] = True

    try:
        client = app_module.app.test_client()

        locked = client.get("/scan/status/not-a-scan")
        assert locked.status_code == 403
        assert locked.get_json()["ok"] is False

        token_header = client.get(
            "/scan/status/not-a-scan",
            headers={"X-Operator-Token": "test-operator-token"},
        )
        assert token_header.status_code == 403
        assert token_header.get_json()["ok"] is False

        unlock = client.post(
            "/operator/unlock",
            json={"operator_token": "test-operator-token"},
        )
        assert unlock.status_code == 200
        assert unlock.get_json()["ok"] is True
        csrf_token = unlock.get_json()["csrf_token"]

        allowed = client.get("/scan/status/not-a-scan")
        assert allowed.status_code == 200
        assert allowed.get_json()["task_total"] == 0

        missing_csrf = client.post("/pentest/advice", json={})
        assert missing_csrf.status_code == 403
        assert "CSRF" in missing_csrf.get_json()["error"]

        with_csrf = client.post(
            "/pentest/advice",
            json={},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert with_csrf.status_code == 400
        assert "No scan results" in with_csrf.get_json()["error"]
    finally:
        app_module.Config.OPERATOR_TOKEN = old_token
