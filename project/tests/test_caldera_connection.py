import sys
from pathlib import Path

# Add the project root (parent of tests/) to sys.path so caldera can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager


def main():
    client = CalderaClient()
    manager = OperationManager(client)

    result = manager.check_readiness()

    print("=== Caldera Readiness Check ===")
    print(f"Caldera reachable: {result['caldera_reachable']}")
    print(f"Agent ready: {result['agent_ready']}")
    print(f"Message: {result['message']}")

    if result["online_agents"]:
        print("\nOnline agents:")
        for agent in result["online_agents"]:
            print(f"- {agent}")


if __name__ == "__main__":
    main()