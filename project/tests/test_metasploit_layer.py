from exploitation.metasploit_policy import authorize_metasploit_action, build_metasploit_actions
from exploitation.metasploit_client import MetasploitRpcClient
from exploitation.metasploit_service import MetasploitService


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
    assert "msf_smb_version:445" in action_ids
    assert "msf_http_title:80" in action_ids
    assert all(action["target"] == "192.168.56.20" for action in actions)
    assert all(action["module_type"] == "auxiliary" for action in actions)

    smb_action = next(action for action in actions if action["action_id"] == "msf_smb_version:445")
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


def test_policy_rejects_arbitrary_or_unscoped_action():
    result = authorize_metasploit_action(
        "exploit/windows/smb/not-in-allowlist:445",
        _scan(),
    )

    assert result["ok"] is False
    assert "not allowed" in result["error"]


class FakeMetasploitClient:
    def __init__(self):
        self.executed = []

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


def test_service_executes_only_policy_authorized_action():
    client = FakeMetasploitClient()
    service = MetasploitService(client)

    result = service.run_action("msf_smb_version:445", _scan())

    assert result["ok"] is True
    assert result["action"]["module_name"] == "scanner/smb/smb_version"
    assert result["rpc_result"]["job_id"] == 7
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

    result = service.run_action("msf_smb_version:445", _scan())

    assert result["ok"] is False
    assert result["error"] == "connection refused"
    assert client.executed == []
