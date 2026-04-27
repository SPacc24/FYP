import json
import time
from pathlib import Path

class OperationManager:
    def __init__(self, caldera_client):
        self.client = caldera_client
        self.log_dir = Path("storage/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def get_online_agents(self):
        agents = self.client.list_agents()
        return [
            agent for agent in agents
            if agent.get("trusted") is True
        ]

    def find_abilities_by_attack_ids(self, attack_ids):
        abilities = self.client.list_abilities()
        selected = []

        for ability in abilities:
            technique = ability.get("technique", {})
            attack_id = technique.get("attack_id")

            if attack_id in attack_ids:
                selected.append(ability)

        return selected

    def create_operation_payload(self, name, agent_group, adversary_id=None):
        return {
            "name": name,
            "group": agent_group,
            "adversary": adversary_id,
            "state": "running",
            "autonomous": 1
        }

    def run_operation(self, name, agent_group, adversary_id):
        payload = self.create_operation_payload(
            name=name,
            agent_group=agent_group,
            adversary_id=adversary_id
        )

        operation = self.client.create_operation(payload)
        return operation

    def save_operation_log(self, operation_id, data):
        path = self.log_dir / f"operation_{operation_id}.json"

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return str(path)

    def poll_operation(self, operation_id, max_attempts=30):
        for _ in range(max_attempts):
            operations = self.client.get("/api/v2/operations")

            for operation in operations:
                if operation.get("id") == operation_id:
                    self.save_operation_log(operation_id, operation)

                    if operation.get("state") in ["finished", "cleanup"]:
                        return operation

            time.sleep(3)

        return {"error": "Operation polling timed out"}