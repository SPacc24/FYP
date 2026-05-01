import json
import logging
import time
from datetime import datetime
from pathlib import Path

from caldera.api_client import CalderaAPIError


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

STATUS_MAP = {
    0: 'success',
    -2: 'failed',
    -3: 'discarded',
    1: 'running',
    -1: 'collect',
}

SAFE_ADVERSARIES = ['discovery', 'hunter', 'basic', 'initial']

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
        
    def check_agent(self, group='red'):
        agents = self.client.get_online_agents()
        group_agents = [a for a in agents if a.get('group') == group] if group else agents
        if not group_agents:
            return False, f"No agents found in group '{group}'. Deploy Sandcat on the target machine first."
        trusted = [a for a in group_agents if a.get('paw')]
        active = trusted if trusted else group_agents
        agent = active[0]
        log.info('Agent found: %s | paw: %s', agent.get('host', 'unknown'), agent.get('paw'))
        return True, agent

    def get_deploy_command(self, kali_ip, group='red'):
        return self.client.generate_sandcat_command(kali_ip, group)

    def _find_builtin_adversary(self):
        for name in SAFE_ADVERSARIES:
            adv = self.client.get_adversary_by_name(name)
            if adv:
                log.info('Using built-in adversary: %s | %s', adv.get('name'), adv.get('adversary_id'))
                return adv.get('adversary_id')
        return None

    def _create_custom_adversary(self, technique_ids):
        ability_ids = []
        for tid in technique_ids or []:
            abilities = self.client.get_abilities_by_technique(tid)
            if not abilities:
                continue
            windows_ab = [ab for ab in abilities if 'windows' in str(ab.get('platforms', {})).lower()]
            chosen = windows_ab[0] if windows_ab else abilities[0]
            ability_ids.append(chosen['ability_id'])
            log.info('Technique %s -> ability: %s', tid, chosen.get('name'))
        if not ability_ids:
            log.warning('No matching abilities found for given techniques.')
            return None
        name = f'autopentest-custom-{int(time.time())}'
        result = self.client.create_adversary(name, ability_ids)
        if isinstance(result, dict) and result.get('error'):
            log.error('Failed to create adversary: %s', result['error'])
            return None
        return result.get('adversary_id')

    def resolve_adversary(self, technique_ids):
        if technique_ids:
            custom_id = self._create_custom_adversary(technique_ids)
            if custom_id:
                return custom_id, True
        return self._find_builtin_adversary(), False

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

    def run_operation(self, technique_ids, group='red', timeout=180):
        available, agent_info = self.check_agent(group)
        if not available:
            return self._error_result(agent_info)
        agent_host = agent_info.get('host', 'unknown')
        agent_paw = agent_info.get('paw', '')
        adversary_id, is_custom = self.resolve_adversary(technique_ids)
        if not adversary_id:
            return self._error_result('Could not find or create a suitable adversary profile. Check Caldera has abilities loaded.')
        op_name = f'autopentest-{int(time.time())}'
        operation = self.client.create_operation(op_name, adversary_id, group)
        if isinstance(operation, dict) and operation.get('error'):
            return self._error_result(operation['error'])
        op_id = operation.get('id') or operation.get('operation_id')
        if not op_id:
            return self._error_result('Operation created but no ID returned. Check Caldera logs.')
        result = self._poll_until_done(op_id, timeout)
        if is_custom and adversary_id:
            self.client.delete_adversary(adversary_id)
        result['agent_host'] = agent_host
        result['agent_paw'] = agent_paw
        return result

    def _poll_until_done(self, op_id, timeout=180):
        start = time.time()
        poll_interval = 5
        done_states = {'finished', 'cleanup', 'complete', 'ran'}
        while time.time() - start < timeout:
            op = self.client.get_operation(op_id)
            state = op.get('state', 'unknown') if isinstance(op, dict) else 'unknown'
            if state in done_states:
                links = self.client.get_operation_links(op_id)
                return self._parse_results(op if isinstance(op, dict) else {}, links, timed_out=False)
            time.sleep(poll_interval)
        self.client.stop_operation(op_id)
        time.sleep(20)
        op = self.client.get_operation(op_id)
        links = self.client.get_operation_links(op_id)
        return self._parse_results(op if isinstance(op, dict) else {}, links, timed_out=True)

    def _parse_results(self, operation, links, timed_out=False):
        techniques_run = []
        for link in links or []:
            status_code = link.get('status', -3)
            status = STATUS_MAP.get(status_code, 'unknown')
            ability = link.get('ability', {}) or {}
            techniques_run.append({
                'technique_id': ability.get('technique_id', 'N/A'),
                'technique_name': ability.get('name', 'Unknown'),
                'tactic': ability.get('tactic', 'unknown'),
                'status': status,
                'output': link.get('output', ''),
                'command': link.get('command', ''),
                'timestamp': link.get('finish', link.get('decide', '')),
                'link_id': link.get('id', ''),
            })

        success_count = sum(1 for t in techniques_run if t['status'] == 'success')
        fail_count = sum(1 for t in techniques_run if t['status'] == 'failed')
        running_count = sum(1 for t in techniques_run if t['status'] == 'running')
        discarded_count = sum(1 for t in techniques_run if t['status'] == 'discarded')
        total = len(techniques_run)


        return {
            'success': True,
            'operation_id': operation.get('id', ''),
            'operation_name': operation.get('name', ''),
            'state': 'timed_out' if timed_out else operation.get('state', ''),
            'techniques_run': techniques_run,
            'total': total,
            'success_count': success_count,
            'fail_count': fail_count,
            'timed_out': timed_out,
            'agent_host': '',
            'agent_paw': ''
        }

    def _error_result(self, message):
        log.error('Operation error: %s', message)
        return {
            'success': False,
            'error': message,
            'operation_id': '',
            'operation_name': '',
            'state': 'error',
            'techniques_run': [],
            'total': 0,
            'success_count': 0,
            'fail_count': 0,
            'timed_out': False,
            'agent_host': '',
            'agent_paw': '',
        }

    def save_log(self, data, filename):
        path = self.log_dir / filename
        path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return str(path)

    def get_operation_history(self):
        return self.client.list_operations()

    def is_caldera_alive(self):
        return self.client.health_check() is not None

 