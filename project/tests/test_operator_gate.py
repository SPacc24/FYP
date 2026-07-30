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


def test_starting_scan_preserves_operator_and_csrf_session(monkeypatch):
    import routes.scan_routes as scan_routes

    class NoStartThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    old_token = app_module.Config.OPERATOR_TOKEN
    app_module.Config.OPERATOR_TOKEN = "test-operator-token"
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(scan_routes.threading, "Thread", NoStartThread)
    monkeypatch.setattr(scan_routes.scan_store, "new_scan", lambda *args, **kwargs: "test-scan")
    monkeypatch.setattr(scan_routes.scan_store, "log", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scan_routes.scan_store,
        "progress",
        lambda scan_id: {"scan_id": scan_id, "task_total": 0},
    )

    try:
        client = app_module.app.test_client()
        unlock = client.post(
            "/operator/unlock",
            json={"operator_token": "test-operator-token"},
        )
        csrf_token = unlock.get_json()["csrf_token"]

        started = client.post(
            "/scan",
            data={
                "target": "192.0.2.10",
                "scan_profile": "fast",
                "technique_mode": "hybrid",
                "_csrf_token": csrf_token,
            },
        )
        assert started.status_code == 200

        with client.session_transaction() as browser_session:
            assert browser_session["operator_authenticated"] is True
            assert browser_session["_csrf_token"] == csrf_token

        progress = client.get("/scan/status/test-scan")
        assert progress.status_code == 200
        assert progress.get_json()["scan_id"] == "test-scan"
    finally:
        app_module.Config.OPERATOR_TOKEN = old_token
