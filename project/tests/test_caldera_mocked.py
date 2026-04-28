import responses

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager


@responses.activate
def test_readiness_with_online_agent(tmp_path):
    base_url = "http://caldera.test"

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/agents",
        json=[
            {
                "paw": "abc123",
                "host": "victim-win10",
                "platform": "windows",
                "group": "red",
                "trusted": True,
                "last_seen": "2026-04-28T10:00:00"
            }
        ],
        status=200
    )

    client = CalderaClient(base_url=base_url, api_key="TESTKEY")
    manager = OperationManager(client, log_dir=tmp_path)

    result = manager.check_readiness()

    assert result["ok"] is True
    assert result["caldera_reachable"] is True
    assert result["agent_ready"] is True
    assert len(result["online_agents"]) == 1


@responses.activate
def test_readiness_with_no_agent(tmp_path):
    base_url = "http://caldera.test"

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/agents",
        json=[],
        status=200
    )

    client = CalderaClient(base_url=base_url, api_key="TESTKEY")
    manager = OperationManager(client, log_dir=tmp_path)

    result = manager.check_readiness()

    assert result["ok"] is True
    assert result["caldera_reachable"] is True
    assert result["agent_ready"] is False

@responses.activate
def test_start_operation_success(tmp_path):
    base_url = "http://caldera.test"

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/agents",
        json=[
            {
                "paw": "abc123",
                "host": "victim-win10",
                "platform": "windows",
                "group": "red",
                "trusted": True
            }
        ],
        status=200
    )

    responses.add(
        responses.POST,
        f"{base_url}/api/v2/operations",
        json={
            "id": "op001",
            "name": "AutoPenTest-test",
            "state": "running"
        },
        status=200
    )

    client = CalderaClient(base_url=base_url, api_key="TESTKEY")
    manager = OperationManager(client, log_dir=tmp_path)

    result = manager.start_operation(
        adversary_id="test-adversary-id",
        selected_techniques=["T1059", "T1087"]
    )

    assert result["ok"] is True
    assert result["stage"] == "operation_started"
    assert result["operation"]["id"] == "op001"