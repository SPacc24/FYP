import app as app_module
import routes.caldera_routes as caldera_routes
from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from storage import scan_store


def _agent(
    paw="paw-1",
    *,
    host="victim-win10",
    ip_addresses=None,
    platform="windows",
    group="red",
    trusted=True,
    alive=True,
    lifecycle="online",
):
    ip_addresses = ip_addresses if ip_addresses is not None else ["10.0.0.5"]
    return {
        "paw": paw,
        "host": host,
        "hostname": host,
        "ip_addresses": ip_addresses,
        "host_ip_addrs": ip_addresses,
        "ip": ", ".join(ip_addresses),
        "platform": platform,
        "group": group,
        "trusted": trusted,
        "alive": alive,
        "lifecycle": lifecycle,
        "status": lifecycle.title(),
    }


class FakeCalderaClient:
    def __init__(self, agents):
        self._agents = agents

    def get_agents_normalized(self):
        return list(self._agents)

    def get_online_agents(self):
        return [
            agent for agent in self._agents
            if agent.get("trusted") and agent.get("alive") and agent.get("paw")
        ]


def _manager(agents, tmp_path):
    return OperationManager(FakeCalderaClient(agents), log_dir=tmp_path)


def _unlocked_client(monkeypatch):
    app_module.app.config["TESTING"] = True
    monkeypatch.setattr(app_module.Config, "OPERATOR_TOKEN", "test-operator-token")
    client = app_module.app.test_client()
    unlock = client.post(
        "/operator/unlock",
        json={"operator_token": "test-operator-token"},
    )
    return client, unlock.get_json()["csrf_token"]


def _scan_with_internal_target(target="10.0.0.5", external="192.168.56.20"):
    scan_id = scan_store.new_scan(external)
    scan_store.update(
        scan_id,
        selected_internal_target={
            "ip": target,
            "os": "Windows",
        },
        external_target=external,
        mapping={
            "recommended_techniques": [
                {"id": "T1046", "name": "Network Service Discovery"}
            ],
            "vulnerabilities": [],
        },
        ai_plan={"selected_technique_ids": ["T1046"]},
    )
    return scan_id


def test_unknown_agent_lifecycle_is_unknown():
    client = CalderaClient(base_url="http://caldera.test", api_key="TESTKEY")

    assert client._agent_lifecycle({"alive": "maybe"}) == "unknown"
    assert client._normalise_agent({"paw": "abc", "alive": "maybe"})["alive"] is False


def test_online_agent_lifecycle():
    client = CalderaClient(base_url="http://caldera.test", api_key="TESTKEY")

    assert client._agent_lifecycle({"alive": True}) == "online"
    assert client._agent_lifecycle({"alive": "running"}) == "online"
    assert client._normalise_agent({"paw": "abc", "alive": "online"})["alive"] is True


def test_invalid_agent_ips_are_removed():
    client = CalderaClient(base_url="http://caldera.test", api_key="TESTKEY")

    agent = client._normalise_agent({
        "host_ip_addrs": [
            "10.0.0.5",
            "999.999.999.999",
            "not-an-ip",
            "10.0.0.5",
        ],
    })

    assert agent["ip_addresses"] == ["10.0.0.5"]
    assert agent["host_ip_addrs"] == ["10.0.0.5"]
    assert agent["ip"] == "10.0.0.5"


def test_exact_ip_match_is_ready(tmp_path):
    manager = _manager([_agent(ip_addresses=["10.0.0.5"])], tmp_path)

    result = manager.check_readiness(target="10.0.0.5")

    assert result["agent_ready"] is True
    assert result["target_match_type"] == "ip"


def test_hostname_only_match_is_not_ready(tmp_path):
    manager = _manager([
        _agent(host="10.0.0.5", ip_addresses=["10.0.0.9"]),
    ], tmp_path)

    result = manager.check_readiness(target="10.0.0.5")

    assert result["agent_ready"] is False
    assert result["target_match_type"] == "hostname"


def test_platform_match_is_not_ready(tmp_path):
    manager = _manager([
        _agent(platform="windows-10.0.0.5", ip_addresses=["10.0.0.9"]),
    ], tmp_path)

    result = manager.check_readiness(target="10.0.0.5")

    assert result["agent_ready"] is False
    assert result["target_match_type"] == "platform"


def test_unrelated_agent_is_not_ready(tmp_path):
    manager = _manager([_agent(ip_addresses=["10.0.0.9"])], tmp_path)

    result = manager.check_readiness(target="10.0.0.5")

    assert result["agent_ready"] is False
    assert result["target_match_type"] == "none"


def test_untrusted_agent_is_rejected(tmp_path):
    manager = _manager([_agent(trusted=False)], tmp_path)

    available, message = manager.check_agent(group="red", target="10.0.0.5")

    assert available is False
    assert "No trusted online agents" in message


def test_offline_agent_is_rejected(tmp_path):
    manager = _manager([
        _agent(alive=False, lifecycle="offline"),
    ], tmp_path)

    available, message = manager.check_agent(group="red", target="10.0.0.5")

    assert available is False
    assert "No trusted online agents" in message


def test_unknown_agent_is_rejected(tmp_path):
    manager = _manager([
        _agent(alive=False, lifecycle="unknown"),
    ], tmp_path)

    available, message = manager.check_agent(group="red", target="10.0.0.5")

    assert available is False
    assert "No trusted online agents" in message


def test_wrong_group_is_rejected(tmp_path):
    manager = _manager([_agent(group="blue")], tmp_path)

    available, message = manager.check_agent(group="red", target="10.0.0.5")

    assert available is False
    assert "group 'red'" in message


def test_selected_paw_must_exist(tmp_path):
    manager = _manager([_agent(paw="paw-1")], tmp_path)

    available, message = manager.check_agent(
        group="red",
        target="10.0.0.5",
        selected_paw="missing",
    )

    assert available is False
    assert "Selected agent 'missing' is not available" in message


def test_selected_paw_must_match_target(tmp_path):
    manager = _manager([
        _agent(paw="paw-1", ip_addresses=["10.0.0.9"]),
    ], tmp_path)

    available, message = manager.check_agent(
        group="red",
        target="10.0.0.5",
        selected_paw="paw-1",
    )

    assert available is False
    assert "does not match target '10.0.0.5'" in message


def test_multiple_exact_agents_require_selection(tmp_path):
    manager = _manager([
        _agent(paw="paw-1", ip_addresses=["10.0.0.5"]),
        _agent(paw="paw-2", ip_addresses=["10.0.0.5"]),
    ], tmp_path)

    available, message = manager.check_agent(group="red", target="10.0.0.5")

    assert available is False
    assert "Multiple trusted online agents match target" in message

    selected_available, selected = manager.check_agent(
        group="red",
        target="10.0.0.5",
        selected_paw="paw-2",
    )
    assert selected_available is True
    assert selected["paw"] == "paw-2"


def test_arbitrary_agent_selection_route_is_rejected(monkeypatch, tmp_path):
    client, csrf_token = _unlocked_client(monkeypatch)
    monkeypatch.setattr(app_module.Config, "AGENT_GROUP", "red")
    monkeypatch.setattr(
        caldera_routes,
        "operation_manager",
        _manager([_agent(paw="paw-1", ip_addresses=["10.0.0.9"])], tmp_path),
    )

    with client.session_transaction() as flask_session:
        flask_session["target_ip"] = "10.0.0.5"

    response = client.post(
        "/caldera/agent/select",
        json={"paw": "paw-1"},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 400
    assert "does not match target" in response.get_json()["error"]


def test_caldera_execution_disabled(monkeypatch):
    client, csrf_token = _unlocked_client(monkeypatch)
    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", False)

    response = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1046"], "approved": True},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "CALDERA execution is disabled."


def test_caldera_execution_requires_approval(monkeypatch):
    client, csrf_token = _unlocked_client(monkeypatch)
    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", True)

    response = client.post(
        "/caldera/run",
        json={"selected_techniques": ["T1046"], "approved": False},
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Explicit operator approval is required."


def test_caldera_run_uses_selected_internal_target(monkeypatch):
    client, csrf_token = _unlocked_client(monkeypatch)
    monkeypatch.setattr(app_module.Config, "ENABLE_CALDERA_EXECUTION", True)
    monkeypatch.setattr(app_module.Config, "AGENT_GROUP", "red")
    monkeypatch.setattr(app_module.Config, "OPERATION_TIMEOUT", 60)

    scan_id = _scan_with_internal_target()

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
        assert kwargs["target"] == "10.0.0.5"
        assert kwargs["group"] == "red"
        assert kwargs["selected_paw"] == "paw-1"
        return {
            "success": True,
            "operation_id": "op001",
            "techniques_run": [],
        }

    monkeypatch.setattr(caldera_routes.operation_manager, "run_operation", run_operation)

    try:
        with client.session_transaction() as flask_session:
            flask_session["scan_id"] = scan_id
            flask_session["selected_agent_paw"] = "paw-1"
            flask_session["technique_mode"] = "auto"

        response = client.post(
            "/caldera/run",
            json={"selected_techniques": ["T1046"], "approved": True},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["target"] == "10.0.0.5"
        assert data["target_source"] == "pivot_scan"
        assert data["external_target"] == "192.168.56.20"
    finally:
        with scan_store._lock:
            scan_store._store.pop(scan_id, None)


def test_target_change_clears_selected_paw(monkeypatch):
    client, csrf_token = _unlocked_client(monkeypatch)
    scan_id = scan_store.new_scan("192.168.56.20")
    scan_store.update(
        scan_id,
        external_target="192.168.56.20",
        internal_targets=[
            {
                "ip": "10.0.0.5",
                "os": "Windows",
            }
        ],
        selected_agent_paw="paw-1",
    )

    try:
        with client.session_transaction() as flask_session:
            flask_session["scan_id"] = scan_id
            flask_session["target_ip"] = "192.168.56.20"
            flask_session["selected_agent_paw"] = "paw-1"

        response = client.post(
            "/pivot/target/select",
            json={"target_ip": "10.0.0.5"},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert response.get_json()["selected_agent_paw"] is None

        with client.session_transaction() as flask_session:
            assert "selected_agent_paw" not in flask_session

        assert scan_store.load(scan_id)["selected_agent_paw"] is None
    finally:
        with scan_store._lock:
            scan_store._store.pop(scan_id, None)
