from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager


def test_caldera_client_can_be_created():
    client = CalderaClient(
        base_url="http://127.0.0.1:8888",
        api_key="TESTKEY"
    )

    assert client.base_url == "http://127.0.0.1:8888"


def test_operation_manager_can_be_created(tmp_path):
    client = CalderaClient(
        base_url="http://127.0.0.1:8888",
        api_key="TESTKEY"
    )

    manager = OperationManager(client, log_dir=tmp_path)

    assert manager.log_dir.exists()