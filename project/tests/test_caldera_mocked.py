import json

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


@responses.activate
def test_custom_adversary_contains_all_selected_technique_abilities(tmp_path):
    base_url = "http://caldera.test"

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/abilities",
        json=[
            {
                "ability_id": "ab-t1046",
                "name": "Network Service Discovery scan",
                "technique_id": "T1046",
                "platforms": {"windows": {"cmd": {"command": "scan"}}},
            },
            {
                "ability_id": "ab-t1135",
                "name": "Network Share Discovery command prompt",
                "technique_id": "T1135",
                "platforms": {"windows": {"cmd": {"command": "net view"}}},
            },
            {
                "ability_id": "ab-t1021",
                "name": "Net use map admin share",
                "technique_id": "T1021.002",
                "platforms": {"windows": {"cmd": {"command": "net use"}}},
            },
        ],
        status=200,
    )

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/abilities",
        json=[
            {
                "ability_id": "ab-t1046",
                "name": "Network Service Discovery scan",
                "technique_id": "T1046",
                "platforms": {"windows": {"cmd": {"command": "scan"}}},
            },
            {
                "ability_id": "ab-t1135",
                "name": "Network Share Discovery command prompt",
                "technique_id": "T1135",
                "platforms": {"windows": {"cmd": {"command": "net view"}}},
            },
            {
                "ability_id": "ab-t1021",
                "name": "Net use map admin share",
                "technique_id": "T1021.002",
                "platforms": {"windows": {"cmd": {"command": "net use"}}},
            },
        ],
        status=200,
    )

    responses.add(
        responses.GET,
        f"{base_url}/api/v2/abilities",
        json=[
            {
                "ability_id": "ab-t1046",
                "name": "Network Service Discovery scan",
                "technique_id": "T1046",
                "platforms": {"windows": {"cmd": {"command": "scan"}}},
            },
            {
                "ability_id": "ab-t1135",
                "name": "Network Share Discovery command prompt",
                "technique_id": "T1135",
                "platforms": {"windows": {"cmd": {"command": "net view"}}},
            },
            {
                "ability_id": "ab-t1021",
                "name": "Net use map admin share",
                "technique_id": "T1021.002",
                "platforms": {"windows": {"cmd": {"command": "net use"}}},
            },
        ],
        status=200,
    )

    responses.add(
        responses.POST,
        f"{base_url}/api/v2/adversaries",
        json={"adversary_id": "adv001"},
        status=200,
    )

    client = CalderaClient(base_url=base_url, api_key="TESTKEY")
    manager = OperationManager(client, log_dir=tmp_path)

    adversary_id, selected_abilities = manager._create_custom_adversary(
        ["T1046", "T1135", "T1021.002"]
    )

    payload = json.loads(responses.calls[-1].request.body.decode("utf-8"))

    assert adversary_id == "adv001"
    assert [item["ability_id"] for item in selected_abilities] == [
        "ab-t1046",
        "ab-t1135",
        "ab-t1021",
    ]
    assert payload["atomic_ordering"] == ["ab-t1046", "ab-t1135", "ab-t1021"]
