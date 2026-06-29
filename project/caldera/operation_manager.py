
import json
import logging
import re
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

    def _normalise_agent_ips(self, agent):
        raw = agent.get('ip') or agent.get('host_ip') or agent.get('host_ip_addrs') or ''
        if isinstance(raw, list):
            return {str(item).strip() for item in raw if item}
        found = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", str(raw))
        if found:
            return {item.strip() for item in found if item.strip()}
        return {item.strip() for item in str(raw).replace(';', ',').split(',') if item.strip()}

    def _agent_matches_target(self, agent, target):
        if not target or target == 'Unknown':
            return False
        target_norm = str(target).lower().strip()
        agent_hosts = {
            str(agent.get('host') or '').lower().strip(),
            str(agent.get('hostname') or '').lower().strip(),
            str(agent.get('paw') or '').lower().strip(),
        }
        agent_ips = {ip.lower() for ip in self._normalise_agent_ips(agent)}
        # Priority: exact IP match, then hostname/paw, then platform match
        if target_norm in agent_ips:
            return True
        if target_norm in agent_hosts:
            return True
        # Allow loose match against platform/OS strings if target appears to be an OS
        platform = str(agent.get('platform') or '').lower()
        if target_norm in platform or platform in target_norm:
            return True
        return False

    def _agent_sort_key(self, agent):
        raw = str(agent.get('last_seen') or '')
        try:
            parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
            return parsed.timestamp()
        except ValueError:
            return 0

    def check_readiness(self, target=None):
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

            # If no target provided, any trusted+alive+paw agent means readiness
            if not target:
                matching_agents = sorted(agents, key=self._agent_sort_key, reverse=True)
                ready = len(matching_agents) > 0
                message = "Ready - Trusted CALDERA agent available" if ready else "Caldera reachable - no trusted agent available"
                return {
                    "ok": True,
                    "caldera_reachable": True,
                    "agent_ready": ready,
                    "agents": all_agents,
                    "online_agents": matching_agents,
                    "trusted_online_agents": agents,
                    "target": target or "",
                    "message": message
                }

            # Prioritise exact IP matches when a target context is provided
            ip_matched = []
            host_matched = []
            os_matched = []
            for agent in agents:
                ips = self._normalise_agent_ips(agent)
                if target and str(target) in ips:
                    ip_matched.append(agent)
                    continue
                hosts = {str(agent.get('host') or '').lower(), str(agent.get('hostname') or '').lower(), str(agent.get('paw') or '').lower()}
                if target and str(target).lower() in hosts:
                    host_matched.append(agent)
                    continue
                platform = str(agent.get('platform') or '').lower()
                if target and str(target).lower() in platform:
                    os_matched.append(agent)

            # Choose which matching list to expose as "online_agents" (priority order)
            if ip_matched:
                matching_agents = sorted(ip_matched, key=self._agent_sort_key, reverse=True)
                ready = True
                message = "Ready - Trusted CALDERA agent available (IP match)"
            elif host_matched:
                matching_agents = sorted(host_matched, key=self._agent_sort_key, reverse=True)
                ready = False
                message = "Caldera reachable - trusted agents exist, matched by hostname but not by IP"
            elif os_matched:
                matching_agents = sorted(os_matched, key=self._agent_sort_key, reverse=True)
                ready = False
                message = "Caldera reachable - trusted agents exist, matched by platform/OS"
            else:
                # CALDERA does not always report target IPs consistently across
                # Sandcat/platform versions. When trusted agents exist but no IP
                # matches the scan target, keep the app usable and clearly mark
                # that the match is not confirmed.
                matching_agents = sorted(agents, key=self._agent_sort_key, reverse=True)
                ready = len(matching_agents) > 0
                message = (
                    "Trusted CALDERA agent available, but it did not expose an IP "
                    "matching the scanned target. Confirm the agent host before running."
                    if ready
                    else "Caldera reachable - trusted agents exist, but none match the scanned target"
                )

            return {
                "ok": True,
                "caldera_reachable": True,
                "agent_ready": ready,
                "agents": all_agents,
                "online_agents": matching_agents,
                "trusted_online_agents": agents,
                "target_match_confirmed": bool(ip_matched),
                "target": target or "",
                "message": message
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
        
    def check_agent(self, group='red', target=None, selected_paw=None):
        agents = self.client.get_online_agents()
        group_agents = [a for a in agents if a.get('group') == group] if group else agents
        if selected_paw:
            selected = [a for a in group_agents if a.get('paw') == selected_paw]
            if selected:
                return True, selected[0]
        original_group_agents = list(group_agents)
        if target:
            group_agents = [a for a in group_agents if self._agent_matches_target(a, target)]
            if not group_agents and original_group_agents:
                # Some CALDERA builds omit host_ip_addrs or report NAT/interface
                # addresses that do not equal the scanned IP. Falling back to the
                # newest trusted group agent prevents a false "not working" state;
                # the UI/runbook still tells the user to verify the host manually.
                group_agents = original_group_agents
        if not group_agents:
            target_note = f" for target '{target}'" if target else ""
            return False, f"No trusted online agents found in group '{group}'{target_note}. Deploy Sandcat on the target machine first."
        group_agents = sorted(group_agents, key=self._agent_sort_key, reverse=True)
        trusted = [a for a in group_agents if a.get('paw')]
        active = trusted if trusted else group_agents
        agent = active[0]
        log.info('Agent found: %s | paw: %s', agent.get('host', 'unknown'), agent.get('paw'))
        return True, agent

    def get_deploy_command(self, kali_ip=None, group='red', platform='windows'):
        return self.client.generate_sandcat_command(kali_ip, group, platform)

    def delete_agent(self, paw):
        if not paw:
            return {"ok": False, "message": "Missing agent paw."}
        self.client.delete_agent(paw)
        return {"ok": True, "deleted": paw}

    def remove_stale_agents(self, target=None, keep_newest=True):
        readiness = self.check_readiness(target=target)
        if not readiness.get("ok"):
            return readiness

        agents = readiness.get("agents", [])
        matching = [agent for agent in agents if self._agent_matches_target(agent, target)] if target else agents
        matching = sorted(matching, key=self._agent_sort_key, reverse=True)
        keep_paw = None
        if keep_newest:
            for agent in matching:
                if agent.get("trusted") and agent.get("alive") and agent.get("paw"):
                    keep_paw = agent.get("paw")
                    break

        deleted = []
        errors = []
        for agent in matching:
            paw = agent.get("paw")
            if not paw or paw == keep_paw:
                continue
            if agent.get("alive") and agent.get("trusted"):
                continue
            try:
                self.client.delete_agent(paw)
                deleted.append(paw)
            except CalderaAPIError as exc:
                errors.append({"paw": paw, "error": str(exc)})

        return {"ok": not errors, "deleted": deleted, "errors": errors, "kept": keep_paw}

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

        # De-prioritise container / docker specific abilities for non-container targets
        if any(tok in text for tok in ['container', 'docker', 'kubernetes']):
            score -= 40

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

    def run_operation(self, technique_ids, group='red', timeout=180, target=None, selected_paw=None, unsupported_techniques=None, unsupported_context=None):
        available, agent_info = self.check_agent(group, target=target, selected_paw=selected_paw)
        if not available:
            return self._error_result(agent_info)
        agent_host = agent_info.get('host', 'unknown')
        agent_paw = agent_info.get('paw', '')
        agent_ip_addrs = agent_info.get('host_ip_addrs', [])
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
        if unsupported_techniques:
            result['techniques_run'].extend(
                self._unsupported_results(unsupported_techniques, unsupported_context or {})
            )
            result['total'] = len(result['techniques_run'])
            result['unsupported_count'] = len(unsupported_techniques)
        result['agent_host'] = agent_host
        result['agent_paw'] = agent_paw
        result['agent_ip_addrs'] = agent_ip_addrs
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
            technique_id = self._extract_technique_id(ability)
            raw_output, stdout, stderr, command_completed = self._extract_link_output(link)
            command = self._extract_command(link, ability)
            facts = link.get('facts') or link.get('relationships') or []
            parsed_evidence = self._parse_evidence(technique_id, raw_output, facts)
            techniques_run.append({
                'technique_id': technique_id,
                'technique_name': ability.get('name', 'Unknown'),
                'tactic': ability.get('tactic', 'unknown'),
                'status': status,
                'output': raw_output,
                'stdout': stdout,
                'stderr': stderr,
                'parsed_evidence': parsed_evidence,
                'evidence_summary': self._evidence_summary(parsed_evidence, raw_output, command_completed),
                'command_completed': command_completed,
                'command': command,
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
            'agent_paw': '',
            'agent_ip_addrs': [],
        }

    def _extract_technique_id(self, ability):
        technique = ability.get('technique_id') or ability.get('technique') or {}
        if isinstance(technique, dict):
            return technique.get('attack_id') or technique.get('technique_id') or 'N/A'
        return technique or 'N/A'

    def _extract_command(self, link, ability):
        if link.get('command'):
            return link.get('command')
        executor = ability.get('executor') or {}
        if isinstance(executor, dict):
            return executor.get('command') or executor.get('psh') or executor.get('cmd') or ''
        return ''

    def _stringify_output(self, value):
        if value is None:
            return ''
        if isinstance(value, str):
            return value
        return json.dumps(value, indent=2, default=str)

    def _extract_link_output(self, link):
        output = link.get('output')
        stdout = ''
        stderr = ''
        command_completed = None

        if isinstance(output, dict):
            stdout = self._stringify_output(output.get('stdout') or output.get('output') or output.get('result'))
            stderr = self._stringify_output(output.get('stderr') or output.get('error'))
            raw_output = self._stringify_output(output)
        elif isinstance(output, bool):
            command_completed = output
            raw_output = self._stringify_output(link.get('result') or link.get('stdout') or '')
            stdout = self._stringify_output(link.get('stdout') or '')
            stderr = self._stringify_output(link.get('stderr') or link.get('error') or '')
        else:
            raw_output = self._stringify_output(output or link.get('result') or link.get('stdout') or '')
            stdout = self._stringify_output(link.get('stdout') or raw_output)
            stderr = self._stringify_output(link.get('stderr') or link.get('error') or '')

        # Normalize boolean-y outputs returned by some Caldera abilities
        try:
            if isinstance(stdout, str) and stdout.lower() in {'true', 'false'} and command_completed is not None:
                # boolean completion indicator, not useful as stdout
                stdout = ''
            if isinstance(raw_output, str) and raw_output.lower() in {'true', 'false'} and command_completed is not None:
                raw_output = ''
        except Exception:
            pass

        return raw_output, stdout, stderr, command_completed

    def _parse_evidence(self, technique_id, raw_output, facts=None):
        text = raw_output or ''
        evidence = []
        facts = facts or []

        for fact in facts:
            if not isinstance(fact, dict):
                continue
            trait = str(fact.get('trait') or fact.get('name') or fact.get('source') or '').lower()
            value = fact.get('value') or fact.get('target') or fact.get('edge') or ''
            if value and any(token in trait for token in ['share', 'service', 'port', 'host']):
                evidence.append(f"{trait}: {value}")

        if technique_id == 'T1135':
            share_names = set()
            try:
                parsed = json.loads(text)
                items = parsed if isinstance(parsed, list) else [parsed]
                for item in items:
                    if isinstance(item, dict):
                        name = item.get('Name') or item.get('name') or item.get('ShareName')
                        if name:
                            share_names.add(str(name))
            except (TypeError, ValueError):
                pass
            for match in re.findall(r'\b([A-Za-z][A-Za-z0-9_.-]*\$?)\b', text):
                if match.upper() in {'ADMIN$', 'C$', 'IPC$'}:
                    share_names.add(match)
                elif 'share' in text.lower() and match.lower() not in {'name', 'description', 'path', 'scope', 'false', 'true'}:
                    share_names.add(match)
            evidence.extend(f"SMB share observed: {name}" for name in sorted(share_names))

        elif technique_id == 'T1046':
            for port, service in re.findall(r'(\d{1,5})/(?:tcp|udp)\s+open\s+([^\s]+)', text, flags=re.IGNORECASE):
                evidence.append(f"Open service observed: {port} {service}")

        elif technique_id == 'T1021.002':
            lowered = text.lower()
            if 'success' in lowered or 'completed successfully' in lowered or 'the command completed successfully' in lowered:
                evidence.append('SMB admin share mapping reported success.')
            if 'access is denied' in lowered or 'logon failure' in lowered or 'system error 5' in lowered:
                evidence.append('SMB admin share mapping failed due to authentication or authorisation.')

        return evidence

    def _evidence_summary(self, parsed_evidence, raw_output, command_completed=None):
        if parsed_evidence:
            return '; '.join(parsed_evidence[:4])
        if raw_output:
            return 'Raw CALDERA output captured; review stdout/stderr.'
        if command_completed is True:
            return 'Command completed, but CALDERA returned no stdout/stderr evidence.'
        return 'Execution completed but no evidence returned.'

    def _unsupported_results(self, technique_ids, context):
        vulnerabilities = context.get('vulnerabilities', [])
        scan_context = context.get('scan_context', {})
        results = []
        for tid in technique_ids:
            evidence = self._unsupported_context_for(tid, vulnerabilities, scan_context)
            results.append({
                'technique_id': tid,
                'technique_name': 'Exploitation of Remote Services' if tid == 'T1210' else 'Unsupported Technique',
                'tactic': 'lateral-movement' if tid == 'T1210' else 'unknown',
                'status': 'unsupported',
                'output': '',
                'stdout': '',
                'stderr': '',
                'parsed_evidence': evidence,
                'evidence_summary': '; '.join(evidence) if evidence else 'Unsupported by CALDERA - requires external exploitability validation.',
                'command': '',
                'timestamp': '',
                'link_id': '',
            })
        return results

    def build_unsupported_results(self, technique_ids, context=None):
        return self._unsupported_results(technique_ids, context or {})

    def _unsupported_context_for(self, technique_id, vulnerabilities, scan_context=None):
        if technique_id != 'T1210':
            return ['Unsupported by CALDERA - requires external validation.']
        evidence = ['Unsupported by CALDERA - requires external exploitability validation.']
        os_name = (scan_context or {}).get('os')
        if os_name and os_name != 'Unknown':
            evidence.append(f"Detected OS context: {os_name}.")
        for vuln in vulnerabilities or []:
            service = str(vuln.get('service', '')).lower()
            title = str(vuln.get('title', ''))
            if service in {'microsoft-ds', 'netbios-ssn', 'smb'}:
                evidence.append(
                    f"{vuln.get('host', 'Unknown')}:{vuln.get('port', 'N/A')} {service} exposure detected: {title}"
                )
        return evidence

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
            'agent_ip_addrs': [],
        }

    def save_log(self, data, filename):
        path = self.log_dir / filename
        path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return str(path)

    def get_operation_history(self):
        return self.client.list_operations()

    def is_caldera_alive(self):
        return self.client.health_check() is not None
