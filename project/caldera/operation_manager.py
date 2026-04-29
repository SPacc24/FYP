import json
from datetime import datetime
from pathlib import Path

from caldera.api_client import CalderaAPIError


class OperationManager:
    def __init__(self, caldera_client, log_dir="storage/logs"):
        self.client = caldera_client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def check_readiness(self):
        """
        Checks whether Caldera is reachable and whether at least one trusted agent exists.
        """
        try:
            agents = self.client.get_online_agents()

            return {
                "ok": True,
                "caldera_reachable": True,
                "agent_ready": len(agents) > 0,
                "online_agents": agents,
                "message": "Caldera reachable. Agent found." if agents else "Caldera reachable. No trusted agent found."
            }

        except CalderaAPIError as e:
            return {
                "ok": False,
                "caldera_reachable": False,
                "agent_ready": False,
                "online_agents": [],
                "message": str(e)
            }

    def start_operation(self, adversary_id, selected_techniques=None, group="red", planner_id=None):
        """
        Starts a Caldera operation using a selected adversary profile.
        selected_techniques is saved for your app/reporting layer, even if Caldera uses adversary_id.
        """
        selected_techniques = selected_techniques or []

        readiness = self.check_readiness()

        if not readiness["ok"]:
            return {
                "ok": False,
                "stage": "connectivity",
                "message": readiness["message"]
            }

        if not readiness["agent_ready"]:
            return {
                "ok": False,
                "stage": "agent_check",
                "message": "No trusted Sandcat agent is currently online."
            }

        operation_name = f"AutoPenTest-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        try:
            operation = self.client.create_operation(
                name=operation_name,
                adversary_id=adversary_id,
                group=group,
                planner_id=planner_id
            )

            result = {
                "ok": True,
                "stage": "operation_started",
                "operation_name": operation_name,
                "operation": operation,
                "selected_techniques": selected_techniques,
                "online_agents": readiness["online_agents"]
            }

            self.save_log(result, f"{operation_name}.json")
            return result

        except CalderaAPIError as e:
            return {
                "ok": False,
                "stage": "operation_create",
                "message": str(e)
            }

    def poll_operation(self, operation_id):
        try:
            operation = self.client.get_operation(operation_id)

            result = {
                "ok": True,
                "operation": operation
            }

            self.save_log(result, f"operation_{operation_id}.json")
            return result

        except CalderaAPIError as e:
            return {
                "ok": False,
                "stage": "operation_poll",
                "message": str(e)
            }

    def save_log(self, data, filename):
        path = self.log_dir / filename
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(path)
