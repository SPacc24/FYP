
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

PREFERRED_ABILITY_TERMS = {
    'T1210': ['validation', 'validate', 'check', 'scan', 'winpwn', 'ms17-10'],
    'T1021.002': ['net use', 'admin share', 'map', 'share'],
    'T1135': ['network share', 'view remote shares', 'net view', 'share discovery'],
    'T1046': ['scan', 'service discovery', 'port scan', 'network service'],
    'T1059': ['powershell', 'command prompt', 'cmd'],
}

UNSAFE_ABILITY_TERMS = [
    'payload',
    'reverse shell',
    'meterpreter',
    'mimikatz',
    'credential dump',
    'exfil',
    'ransom',
    'delete',
    'destructive',
    'persistence',
]

class OperationManager:
    def __init__(self, caldera_client_or_url, api_key=None, log_dir="storage/logs"):
        """
        Backwards-compatible constructor.
        Accepts either a CalderaClient instance or (base_url, api_key) pair.
        """
        # Delay import to avoid circular import at module load time
        from caldera.api_client import CalderaClient

        if hasattr(caldera_client_or_url, "get_online_agents"):
            # Already a client-like object
            self.client = caldera_client_or_url
        elif isinstance(caldera_client_or_url, str):
            # base_url provided; create a CalderaClient
            self.client = CalderaClient(base_url=caldera_client_or_url, api_key=api_key)
        else:
            raise ValueError("OperationManager requires a CalderaClient instance or a base_url string")

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def check_readiness(self):
        """
        Checks whether Caldera is reachable and whether at least one trusted agent exists.
        """
        try:
            if hasattr(self.client, "get_agents_normalized"):
                all_agents = self.client.get_agents_normalized()
            else:
                all_agents = self.client.get_online_agents()
            agents = [
                agent for agent in all_agents
                if agent.get("trusted") and agent.get("alive") and agent.get("paw")
            ]

            return {
                "ok": True,
                "caldera_reachable": True,
                "agent_ready": len(agents) > 0,
                "agents": all_agents,
                "online_agents": agents,
                "message": (
                    "Ready - Trusted CALDERA agent available"
                    if agents
                    else "Caldera reachable - no trusted agent available"
                )
            }

        except CalderaAPIError as e:
            return {
                "ok": False,
                "caldera_reachable": False,
                "agent_ready": False,
                "agents": [],
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

    def get_deploy_command(self, kali_ip=None, group='red', platform='windows'):
        return self.client.generate_sandcat_command(kali_ip, group, platform)

    def _find_builtin_adversary(self):
        for name in SAFE_ADVERSARIES:
            adv = self.client.get_adversary_by_name(name)
            if adv:
                log.info('Using built-in adversary: %s | %s', adv.get('name'), adv.get('adversary_id'))
                return adv.get('adversary_id')
        return None

    def _ability_platform_text(self, ability):
        return json.dumps(ability.get('platforms', {}), default=str).lower()

    def _ability_search_text(self, ability):
        fields = [
            ability.get('name', ''),
            ability.get('description', ''),
            ability.get('tactic', ''),
            ability.get('executor', ''),
            ability.get('requirements', ''),
            ability.get('payloads', ''),
            ability.get('command', ''),
            self._ability_platform_text(ability),
        ]
        return ' '.join(str(field) for field in fields).lower()

    def _ability_is_unsafe(self, ability):
        text = self._ability_search_text(ability)
        return any(term in text for term in UNSAFE_ABILITY_TERMS)

    def _score_ability(self, technique_id, ability):
        text = self._ability_search_text(ability)
        score = 0

        if 'windows' in self._ability_platform_text(ability):
            score += 50
        if not self._ability_is_unsafe(ability):
            score += 30
        if 'cleanup' in text or 'deleter' in text:
            score -= 25

        for index, term in enumerate(PREFERRED_ABILITY_TERMS.get(technique_id, [])):
            if term in text:
                score += 40 - index

        name = str(ability.get('name', '')).lower()
        if name:
            score += max(0, 20 - len(name) // 10)

        return score

    def _choose_safe_ability(self, technique_id, abilities):
        ranked = sorted(
            abilities,
            key=lambda ability: (
                -self._score_ability(technique_id, ability),
                str(ability.get('name', '')).lower(),
                str(ability.get('ability_id') or ability.get('id') or ''),
            ),
        )
        for ability in ranked:
            if not self._ability_is_unsafe(ability):
                return ability
        return ranked[0] if ranked else None

    def _create_custom_adversary(self, technique_ids):
        ability_ids = []
        selected_abilities = []
        for tid in technique_ids or []:
            abilities = self.client.get_abilities_by_technique(tid)
            if not abilities:
                continue
            chosen = self._choose_safe_ability(tid, abilities)
            if not chosen:
                continue
            ability_id = chosen.get('ability_id') or chosen.get('id')
            if not ability_id or ability_id in ability_ids:
                continue
            ability_ids.append(ability_id)
            selected_abilities.append({
                'technique_id': tid,
                'ability_id': ability_id,
                'ability_name': chosen.get('name'),
            })
            log.info('Technique %s -> ability: %s | %s', tid, ability_id, chosen.get('name'))
        if not ability_ids:
            log.warning('No matching abilities found for given techniques.')
            return None
        name = f'autopentest-custom-{int(time.time())}'
        result = self.client.create_adversary(name, ability_ids)
        if isinstance(result, dict) and result.get('error'):
            log.error('Failed to create adversary: %s', result['error'])
            return None
        adversary_id = result.get('adversary_id') or result.get('id')
        return adversary_id, selected_abilities

    def resolve_adversary(self, technique_ids):
        if technique_ids:
            created = self._create_custom_adversary(technique_ids)
            if created:
                custom_id, selected_abilities = created
                return custom_id, True, selected_abilities
        return self._find_builtin_adversary(), False, []

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
        adversary_id, is_custom, selected_abilities = self.resolve_adversary(technique_ids)
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
        result['selected_abilities'] = selected_abilities
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
            'running_count': running_count,
            'discarded_count': discarded_count,
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
            'running_count': 0,
            'discarded_count': 0,
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

 
