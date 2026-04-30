import os
import logging
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
class CalderaAPIError(Exception):
    """Raised when Caldera API returns an error or cannot be reached."""
    pass
class CalderaClient:
    def __init__(self, base_url=None, api_key=None, verify_ssl=False, timeout=10):
        self.base_url = (base_url or os.getenv("CALDERA_URL", "http://127.0.0.1:8888")).rstrip("/")
        self.api_key = api_key or os.getenv("CALDERA_API_KEY", "")
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "KEY": self.api_key,
                "Content-Type": "application/json"
            })

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            response.raise_for_status()

            if response.text:
                return response.json()

            return {}

        except requests.exceptions.RequestException as e:
            raise CalderaAPIError(f"Caldera API request failed: {e}")

        except ValueError:
            raise CalderaAPIError("Caldera returned a non-JSON response.")

    def health_check(self):
        """
        Checks whether the Caldera server is reachable.

        Note:
        Some Caldera versions may not expose /api/v2/health.
        If this endpoint fails, use list_agents() as the practical connectivity test.
        """
        return self._request("GET", "/api/v2/health")

    def list_agents(self):
        return self._request("GET", "/api/v2/agents")

    def get_online_agents(self):
        agents = self.list_agents()

        if isinstance(agents, dict):
            agents = agents.get("agents", [])

        online = []

        for agent in agents:
            trusted = agent.get("trusted")
            paw = agent.get("paw")
            host = agent.get("host") or agent.get("host_name")

            if trusted is True:
                online.append({
                    "paw": paw,
                    "host": host,
                    "platform": agent.get("platform"),
                    "group": agent.get("group"),
                    "last_seen": agent.get("last_seen")
                })

        return online

    def list_operations(self):
        return self._request("GET", "/api/v2/operations")

    def get_operation(self, operation_id):
        return self._request("GET", f"/api/v2/operations/{operation_id}")

    def create_operation(self, name, adversary_id, group="red", planner_id=None):
        payload = {
            "name": name,
            "group": group,
            "adversary": {
                "adversary_id": adversary_id
            },
            "state": "running",
            "autonomous": 1
        }

        if planner_id:
            payload["planner"] = {
                "planner_id": planner_id
            }

        return self._request("POST", "/api/v2/operations", json=payload)
    