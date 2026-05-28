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
PREFERRED_EXECUTORS = ("cmd", "psh", "powershell", "sh")
SAFE_NAME_HINTS = {
    "T1046": ("nmap", "port scan", "fingerprint", "network service"),
    "T1021.002": ("net use", "admin share", "smb", "windows admin"),
    "T1135": ("network share discovery", "net view", "command prompt", "share discovery"),
    "T1210": ("remote services", "smb", "test", "scan", "check"),
    "T1059": ("powershell", "command prompt", "cmd"),
}
RISKY_NAME_HINTS = (
    "dump",
    "credential",
    "mimikatz",
    "delete",
    "ransom",
    "exfil",
    "persistence",
    "disable",
)
BLOCKED_ABILITY_HINTS = (
    "ransom",
    "encrypt",
    "destructive",
    "mimikatz",
    "credential dump",
)

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

    def _normalise_technique_id(self, ability):
        technique = ability.get('technique_id') or ability.get('technique', {})
        if isinstance(technique, dict):
            technique = technique.get('attack_id')
        return str(technique or '').strip().upper()

    def _platforms(self, ability):
        platforms = ability.get('platforms') or {}
        return platforms if isinstance(platforms, dict) else {}

    def _platform_score(self, ability, agent_platform='windows'):
        platforms = self._platforms(ability)
        platform = str(agent_platform or 'windows').lower()

        if platform in platforms:
            score = 60
            executors = platforms.get(platform) or {}
        elif 'windows' in platforms:
            score = 45
            executors = platforms.get('windows') or {}
        elif not platforms:
            return 10
        else:
            return -100

        if isinstance(executors, dict):
            executor_names = [str(name).lower() for name in executors.keys()]
            for index, executor in enumerate(PREFERRED_EXECUTORS):
                if executor in executor_names:
                    score += len(PREFERRED_EXECUTORS) - index
                    break

        return score

    def _safety_score(self, ability):
        text = ' '.join([
            str(ability.get('name', '')),
            str(ability.get('description', '')),
            str(ability.get('tactic', '')),
        ]).lower()

        penalty = sum(20 for hint in RISKY_NAME_HINTS if hint in text)
        return -penalty

    def _is_blocked_ability(self, ability):
        text = ' '.join([
            str(ability.get('name', '')),
            str(ability.get('description', '')),
        ]).lower()
        return any(hint in text for hint in BLOCKED_ABILITY_HINTS)

    def _preference_score(self, ability, technique_id):
        name = str(ability.get('name', '')).lower()
        hints = SAFE_NAME_HINTS.get(str(technique_id).upper(), ())
        score = 0
        for index, hint in enumerate(hints):
            if hint in name:
                score += (len(hints) - index) * 5
        return score

    def _choose_ability(self, technique_id, abilities, agent_platform='windows'):
        valid = [
            ab for ab in abilities or []
            if ab.get('ability_id') and not self._is_blocked_ability(ab)
        ]
        if not valid:
            return None

        def score(ability):
            return (
                self._platform_score(ability, agent_platform),
                self._safety_score(ability),
                self._preference_score(ability, technique_id),
                str(ability.get('name', '')).lower(),
            )

        return sorted(valid, key=score, reverse=True)[0]

    def _create_custom_adversary(self, technique_ids):
        return self._create_custom_adversary_for_agent(technique_ids, agent_platform='windows')

    def _create_custom_adversary_for_agent(self, technique_ids, agent_platform='windows'):
        ability_ids = []
        chosen_abilities = []
        log.info('[CALDERA] Selected techniques: %s', technique_ids or [])

        for tid in technique_ids or []:
            abilities = self.client.get_abilities_by_technique(tid)
            if not abilities:
                log.warning('[CALDERA] No supported abilities found for %s', tid)
                continue

            chosen = self._choose_ability(tid, abilities, agent_platform)
            if not chosen:
                log.warning('[CALDERA] No compatible ability could be selected for %s', tid)
                continue

            ability_ids.append(chosen['ability_id'])
            chosen_abilities.append({
                'technique_id': tid,
                'ability_id': chosen.get('ability_id'),
                'ability_name': chosen.get('name'),
                'platforms': chosen.get('platforms', {}),
                'tactic': chosen.get('tactic'),
            })
            log.info(
                '[CALDERA] Chosen ability: %s -> %s | %s',
                tid,
                chosen.get('ability_id'),
                chosen.get('name'),
            )

        if not ability_ids:
            log.warning('No matching abilities found for given techniques.')
            return None, []

        name = f'autopentest-custom-{int(time.time())}'
        log.info('[CALDERA] Creating adversary %s with ability IDs: %s', name, ability_ids)
        result = self.client.create_adversary(name, ability_ids)
        if isinstance(result, dict) and result.get('error'):
            log.error('Failed to create adversary: %s', result['error'])
            return None, chosen_abilities

        adversary_id = None
        if isinstance(result, dict):
            adversary_id = result.get('adversary_id') or result.get('id')
        return adversary_id, chosen_abilities

    def resolve_adversary(self, technique_ids):
        if technique_ids:
            custom_id, _chosen = self._create_custom_adversary(technique_ids)
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
        agent_platform = agent_info.get('platform') or 'windows'
        adversary_id, chosen_abilities = self._create_custom_adversary_for_agent(
            technique_ids,
            agent_platform=agent_platform,
        )
        is_custom = bool(adversary_id)
        if not adversary_id:
            return self._error_result('Could not find or create a suitable adversary profile. Check Caldera has abilities loaded.')
        op_name = f'autopentest-{int(time.time())}'
        operation = self.client.create_operation(op_name, adversary_id, group)
        if isinstance(operation, dict) and operation.get('error'):
            return self._error_result(operation['error'])
        op_id = operation.get('id') or operation.get('operation_id')
        if not op_id:
            return self._error_result('Operation created but no ID returned. Check Caldera logs.')
        log.info('[CALDERA] Operation created: %s | adversary=%s | group=%s', op_id, adversary_id, group)
        result = self._poll_until_done(op_id, timeout, expected_abilities=chosen_abilities)
        if is_custom and adversary_id:
            self.client.delete_adversary(adversary_id)
        result['agent_host'] = agent_host
        result['agent_paw'] = agent_paw
        result['chosen_abilities'] = chosen_abilities
        result['selected_techniques'] = technique_ids
        return result

    def _poll_until_done(self, op_id, timeout=180, expected_abilities=None):
        start = time.time()
        poll_interval = 5
        done_states = {'finished', 'cleanup', 'complete', 'ran'}
        while time.time() - start < timeout:
            op = self.client.get_operation(op_id)
            state = op.get('state', 'unknown') if isinstance(op, dict) else 'unknown'
            log.info('[CALDERA] Operation %s state: %s', op_id, state)
            if state in done_states:
                links = self.client.get_operation_links(op_id)
                return self._parse_results(
                    op if isinstance(op, dict) else {},
                    links,
                    timed_out=False,
                    expected_abilities=expected_abilities,
                )
            time.sleep(poll_interval)
        self.client.stop_operation(op_id)
        time.sleep(20)
        op = self.client.get_operation(op_id)
        links = self.client.get_operation_links(op_id)
        return self._parse_results(
            op if isinstance(op, dict) else {},
            links,
            timed_out=True,
            expected_abilities=expected_abilities,
        )

    def _normalise_links(self, links):
        if isinstance(links, list):
            return links
        if not isinstance(links, dict):
            return []
        for key in ('links', 'steps', 'chain', 'facts'):
            value = links.get(key)
            if isinstance(value, list):
                return value
        return []

    def _link_output(self, link):
        output = link.get('output')
        if isinstance(output, dict):
            values = []
            for value in output.values():
                if isinstance(value, dict):
                    values.extend(str(v) for v in value.values() if v not in (None, ''))
                elif value not in (None, ''):
                    values.append(str(value))
            return '\n'.join(values)
        if isinstance(output, list):
            return '\n'.join(str(item) for item in output)
        return str(output or '')

    def _link_timestamp(self, link):
        for key in ('finish', 'completed', 'run', 'decide', 'collect'):
            value = link.get(key)
            if value:
                return value
        return ''

    def _classify_link(self, link, output, ability):
        tactic = str(ability.get('tactic') or '').lower()
        name = str(ability.get('name') or '').lower()
        if tactic == 'cleanup' or 'cleanup' in name:
            return 'discarded'

        status_code = link.get('status')
        status = STATUS_MAP.get(status_code)
        stderr = str(link.get('stderr') or link.get('error') or '')
        combined = f'{output}\n{stderr}'.lower()

        if status == 'discarded':
            return 'discarded'
        if status == 'failed' or stderr:
            return 'failed'
        if any(token in combined for token in ('traceback', 'exception', 'error:', 'failed', 'not recognized')):
            return 'failed'
        if status == 'success':
            return 'success'
        if self._link_timestamp(link) and (output.strip() or link.get('pid') or link.get('command')):
            return 'success'
        if status == 'running' or not self._link_timestamp(link):
            return 'running'
        return status or 'unknown'

    def _parse_results(self, operation, links, timed_out=False, expected_abilities=None):
        techniques_run = []
        normalised_links = self._normalise_links(links)
        log.info('[CALDERA] Returned links: %s', len(normalised_links))
        seen_ability_ids = set()

        for link in normalised_links:
            ability = link.get('ability', {}) or {}
            ability_id = ability.get('ability_id') or link.get('ability_id')
            if ability_id:
                seen_ability_ids.add(ability_id)
            output = self._link_output(link)
            status = self._classify_link(link, output, ability)
            techniques_run.append({
                'technique_id': self._normalise_technique_id(ability) or 'N/A',
                'technique_name': ability.get('name', 'Unknown'),
                'tactic': ability.get('tactic', 'unknown'),
                'status': status,
                'output': output,
                'command': link.get('command', ''),
                'timestamp': self._link_timestamp(link),
                'link_id': link.get('id', ''),
                'paw': link.get('paw', ''),
                'ability_id': ability_id or '',
                'status_code': link.get('status'),
            })

        for expected in expected_abilities or []:
            ability_id = expected.get('ability_id')
            if ability_id in seen_ability_ids:
                continue

            techniques_run.append({
                'technique_id': expected.get('technique_id', 'N/A'),
                'technique_name': expected.get('ability_name', 'Unknown'),
                'tactic': expected.get('tactic', 'unknown'),
                'status': 'discarded',
                'output': 'No CALDERA operation link was returned for this selected ability. It may have been skipped because of planner, platform, or fact requirements.',
                'command': '',
                'timestamp': '',
                'link_id': '',
                'paw': '',
                'ability_id': ability_id or '',
                'status_code': None,
            })

        success_count = sum(1 for t in techniques_run if t['status'] == 'success')
        fail_count = sum(1 for t in techniques_run if t['status'] == 'failed')
        running_count = sum(1 for t in techniques_run if t['status'] == 'running')
        discarded_count = sum(1 for t in techniques_run if t['status'] == 'discarded')
        total = len(techniques_run)

        log.info(
            '[CALDERA] Parsed results: %s success, %s failed, %s discarded, %s running',
            success_count,
            fail_count,
            discarded_count,
            running_count,
        )

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

 
