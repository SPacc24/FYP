import json
from datetime import datetime
from pathlib import Path

class OperationManager:
    def __init__(self, caldera_client, log_dir="storage/logs"):
        self.client = caldera_client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def verify_agent_ready(self):
        agents = self.client.get_online_agents()
        return {
            "ready": len(agents) > 0,
            "agents": agents
        }

    def run_operation(self, adversary_id, selected_techniques):
        agent_status = self.verify_agent_ready()
        if not agent_status["ready"]:
            return {
                "ok": False,
                "error": "No online Caldera Sandcat agent found."
            }

        op = self.client.create_operation(
            name=f"AutoPenTest-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            adversary_id=adversary_id
        )

        result = {
            "ok": True,
            "operation": op,
            "selected_techniques": selected_techniques,
            "agents": agent_status["agents"]
        }

        self._save_log(result)
        return result

    def poll_operation(self, operation_id):
        data = self.client.get_operation(operation_id)
        self._save_log(data, f"operation_{operation_id}.json")
        return data

    def _save_log(self, data, filename=None):
        if filename is None:
            filename = f"caldera_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = self.log_dir / filename
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(path)