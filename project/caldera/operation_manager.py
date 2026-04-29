""" import json
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
        return str(path) """

"""
caldera/operation_manager.py
High-level orchestration layer for Caldera operations.
Uses api_client.py as the engine. Handles the full attack lifecycle:
select adversary → run operation → poll results → parse → return clean data.
"""

import time
import logging
from caldera.api_client import CalderaClient

log = logging.getLogger(__name__)


# ── Caldera status codes ────────────────────────────────────────────────────
STATUS_MAP = {
    0:  'success',
    -2: 'failed',
    -3: 'discarded',
    1:  'running',
    -1: 'collect',  # collecting output
}

# ── Safe built-in adversary names to try (in order of preference) ───────────
SAFE_ADVERSARIES = [
    'discovery',
    'hunter',
    'basic',
    'initial'
]


class OperationManager:
    def __init__(self, base_url: str, api_key: str):
        self.client = CalderaClient(base_url, api_key)

    # ── Agent management ────────────────────────────────────────────────────

    def check_agent(self, group: str = 'red') -> tuple[bool, str | dict]:
        """
        Check if a Sandcat agent is online and trusted.
        Returns (True, agent_dict) or (False, error_message).
        """
        agents = self.client.get_agents_by_group(group)

        if not agents:
            return False, (
                "No agents found in group '{}'. "
                "Deploy Sandcat on the target machine first.".format(group)
            )

        # Prefer trusted agents
        trusted = [a for a in agents if a.get('trusted', False)]
        active  = trusted if trusted else agents

        agent = active[0]
        log.info(f"Agent found: {agent.get('host', 'unknown')} | paw: {agent.get('paw')}")
        return True, agent

    def get_deploy_command(self, kali_ip: str, group: str = 'red') -> str:
        """Return PowerShell command to deploy Sandcat on Windows victim."""
        return self.client.generate_sandcat_command(kali_ip, group)

    # ── Adversary selection ─────────────────────────────────────────────────

    def _find_builtin_adversary(self) -> str | None:
        """Try to find a safe built-in adversary for initial testing."""
        for name in SAFE_ADVERSARIES:
            adv = self.client.get_adversary_by_name(name)
            if adv:
                log.info(f"Using built-in adversary: {adv['name']} | {adv['adversary_id']}")
                return adv['adversary_id']
        return None

    def _create_custom_adversary(self, technique_ids: list) -> str | None:
        """
        Create a custom adversary profile from a list of ATT&CK technique IDs.
        Maps technique IDs → ability IDs → creates adversary.
        """
        ability_ids = []
        for tid in technique_ids:
            abilities = self.client.get_abilities_by_technique(tid)
            if abilities:
                # Take the first Windows-compatible ability for each technique
                windows_ab = [
                    ab for ab in abilities
                    if 'windows' in str(ab.get('platforms', {})).lower()
                ]
                chosen = windows_ab[0] if windows_ab else abilities[0]
                ability_ids.append(chosen['ability_id'])
                log.info(f"Technique {tid} → ability: {chosen.get('name')}")

        if not ability_ids:
            log.warning("No matching abilities found for given techniques.")
            return None

        name = f"autopentest-custom-{int(time.time())}"
        result = self.client.create_adversary(name, ability_ids)

        if 'error' in result:
            log.error(f"Failed to create adversary: {result['error']}")
            return None

        adv_id = result.get('adversary_id')
        log.info(f"Custom adversary created: {name} | {adv_id}")
        return adv_id

    def resolve_adversary(self, technique_ids: list) -> tuple[str | None, bool]:
        """
        Resolve the best adversary to use.
        Returns (adversary_id, is_custom).
        Tries custom first, falls back to built-in.
        """
        # Try to build custom adversary from techniques
        if technique_ids:
            custom_id = self._create_custom_adversary(technique_ids)
            if custom_id:
                return custom_id, True

        # Fallback: use a safe built-in
        builtin_id = self._find_builtin_adversary()
        return builtin_id, False

    # ── Full operation flow ─────────────────────────────────────────────────

    def run_operation(
        self,
        technique_ids: list,
        group: str = 'red',
        timeout: int = 180
    ) -> dict:
        """
        Full P4 operation flow:
        1. Verify agent is online
        2. Resolve adversary (custom or built-in)
        3. Create + start operation
        4. Poll until complete or timeout
        5. Parse + return clean results

        Returns a structured result dict ready for Flask + MySQL storage.
        """

        # ── 1. Check agent ───────────────────────────────────────────────
        available, agent_info = self.check_agent(group)
        if not available:
            return self._error_result(agent_info)

        agent_host = agent_info.get('host', 'unknown')
        agent_paw  = agent_info.get('paw', '')

        # ── 2. Resolve adversary ─────────────────────────────────────────
        adversary_id, is_custom = self.resolve_adversary(technique_ids)
        if not adversary_id:
            return self._error_result(
                "Could not find or create a suitable adversary profile. "
                "Check Caldera has abilities loaded."
            )

        # ── 3. Create operation ──────────────────────────────────────────
        op_name   = f"autopentest-{int(time.time())}"
        operation = self.client.create_operation(op_name, adversary_id, group)

        if isinstance(operation, dict) and 'error' in operation:
            return self._error_result(operation['error'])

        op_id = operation.get('id')
        if not op_id:
            return self._error_result(
                "Operation created but no ID returned. Check Caldera logs."
            )

        log.info(f"Operation started: {op_name} | id: {op_id}")

        # ── 4. Poll for results ──────────────────────────────────────────
        result = self._poll_until_done(op_id, timeout)

        # ── 5. Cleanup custom adversary ──────────────────────────────────
        if is_custom and adversary_id:
            self.client.delete_adversary(adversary_id)
            log.info(f"Cleaned up custom adversary: {adversary_id}")

        # Add agent info to result
        result['agent_host'] = agent_host
        result['agent_paw']  = agent_paw
        return result

    # ── Polling ─────────────────────────────────────────────────────────────

    def _poll_until_done(self, op_id: str, timeout: int = 180) -> dict:
        """
        Poll Caldera every 5 seconds until operation finishes or timeout.
        Returns parsed result dict.
        """
        start     = time.time()
        poll_interval = 5
        done_states   = {'finished', 'cleanup', 'complete', 'ran'}

        log.info(f"Polling operation {op_id} (timeout: {timeout}s)")

        while time.time() - start < timeout:
            op    = self.client.get_operation(op_id)
            state = op.get('state', 'unknown')

            log.info(f"  Operation state: {state}")

            if state in done_states:
                links = self.client.get_operation_links(op_id)
                return self._parse_results(op, links, timed_out=False)

            time.sleep(poll_interval)

        # Timeout — stop gracefully and return whatever we have
        log.warning(f"Operation {op_id} timed out after {timeout}s")
        self.client.stop_operation(op_id)
        time.sleep(2)

        op    = self.client.get_operation(op_id)
        links = self.client.get_operation_links(op_id)
        return self._parse_results(op, links, timed_out=True)

    # ── Result parsing ──────────────────────────────────────────────────────

    def _parse_results(
        self,
        operation: dict,
        links: list,
        timed_out: bool = False
    ) -> dict:
        """
        Convert raw Caldera output into a clean, structured result dict.
        Ready to be stored in MySQL and displayed on the Flask UI.
        """
        techniques_run = []

        for link in (links or []):
            status_code = link.get('status', -3)
            status      = STATUS_MAP.get(status_code, 'unknown')

            ability = link.get('ability', {})

            techniques_run.append({
                'technique_id':   ability.get('technique_id',   'N/A'),
                'technique_name': ability.get('name',           'Unknown'),
                'tactic':         ability.get('tactic',         'unknown'),
                'status':         status,
                'output':         link.get('output', ''),
                'command':        link.get('command', ''),
                'timestamp':      link.get('finish', link.get('decide', '')),
                'link_id':        link.get('id', '')
            })

        success_count = sum(1 for t in techniques_run if t['status'] == 'success')
        fail_count    = sum(1 for t in techniques_run if t['status'] == 'failed')
        total         = len(techniques_run)

        return {
            'success':        True,
            'operation_id':   operation.get('id',    ''),
            'operation_name': operation.get('name',  ''),
            'state':          'timed_out' if timed_out else operation.get('state', ''),
            'techniques_run': techniques_run,
            'total':          total,
            'success_count':  success_count,
            'fail_count':     fail_count,
            'timed_out':      timed_out,
            'agent_host':     '',   # filled in by run_operation
            'agent_paw':      ''
        }

    def _error_result(self, message: str) -> dict:
        """Standard error result format."""
        log.error(f"Operation error: {message}")
        return {
            'success':        False,
            'error':          message,
            'operation_id':   '',
            'operation_name': '',
            'state':          'error',
            'techniques_run': [],
            'total':          0,
            'success_count':  0,
            'fail_count':     0,
            'timed_out':      False,
            'agent_host':     '',
            'agent_paw':      ''
        }

    # ── Utility ─────────────────────────────────────────────────────────────

    def get_operation_history(self) -> list:
        """Get all past operations from Caldera."""
        return self.client.get_all_operations()

    def is_caldera_alive(self) -> bool:
        """Quick health check."""
        return self.client.ping()
