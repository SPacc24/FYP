
"""
caldera/risk_scorer.py
Risk scoring engine for AutoPenTest.
Combines CVE CVSS scores from vulnerability mapping
with ATT&CK technique success/failure weights
to produce a final risk score (0.0 - 10.0).
"""

import logging
from typing import Any

log = logging.getLogger(__name__)

TACTIC_WEIGHTS = {
    'initial-access': 1.5,
    'execution': 1.5,
    'persistence': 2.0,
    'privilege-escalation': 2.5,
    'defense-evasion': 1.5,
    'credential-access': 2.5,
    'discovery': 0.5,
    'lateral-movement': 2.0,
    'collection': 1.5,
    'command-and-control': 2.0,
    'exfiltration': 2.5,
    'impact': 2.0,
}

DEFAULT_TACTIC_WEIGHT = 1.0


def get_risk_label(score: float) -> dict:
    if score >= 8.0:
        return {'label': 'CRITICAL', 'colour': '#e85555', 'badge': 'danger'}
    if score >= 6.0:
        return {'label': 'HIGH', 'colour': '#f5a623', 'badge': 'warning'}
    if score >= 4.0:
        return {'label': 'MEDIUM', 'colour': '#f0c040', 'badge': 'info'}
    if score >= 2.0:
        return {'label': 'LOW', 'colour': '#34d058', 'badge': 'success'}
    return {'label': 'MINIMAL', 'colour': '#8b949e', 'badge': 'secondary'}


class RiskScorer:
    def calculate(self, vulnerabilities: list, operation_results: dict) -> dict:
        cve_component = self._score_cve(vulnerabilities)
        attack_component = self._score_attack(operation_results)
        combined = self._combine(cve_component, attack_component)
        label_info = get_risk_label(combined)
        breakdown = {
            'cve_component': round(cve_component, 2),
            'attack_component': round(attack_component, 2),
            'final_score': round(combined, 2),
            'cve_count': len(vulnerabilities),
            'techniques_run': operation_results.get('total', 0),
            'techniques_success': operation_results.get('success_count', 0),
        }
        log.info('Risk score: %.2f | CVE=%.2f ATT&CK=%.2f', combined, cve_component, attack_component)
        return {
            'score': round(combined, 2),
            'label': label_info['label'],
            'colour': label_info['colour'],
            'badge': label_info['badge'],
            'breakdown': breakdown,
        }

    def _score_cve(self, vulnerabilities: list) -> float:
        if not vulnerabilities:
            return 0.0
        scores = sorted([float(v.get('cve_score', 0.0) or 0.0) for v in vulnerabilities], reverse=True)
        if not scores:
            return 0.0
        weights = [1 / (i + 1) for i in range(len(scores))]
        weighted = sum(s * w for s, w in zip(scores, weights))
        total_w = sum(weights)
        avg = weighted / total_w if total_w else 0.0
        return min(avg / 2.0, 5.0)

    def _score_attack(self, operation_results: dict) -> float:
        techniques = operation_results.get('techniques_run', [])
        if not techniques:
            return 0.0
        raw_score = 0.0
        max_possible = 0.0
        for t in techniques:
            tactic = str(t.get('tactic', '')).lower().replace(' ', '-')
            weight = TACTIC_WEIGHTS.get(tactic, DEFAULT_TACTIC_WEIGHT)
            max_possible += weight
            if t.get('status') == 'success':
                raw_score += weight
        if max_possible == 0:
            return 0.0
        return min((raw_score / max_possible) * 5.0, 5.0)

    def _combine(self, cve_score: float, attack_score: float) -> float:
        if attack_score == 0.0:
            return min(cve_score * 2.0, 10.0)
        return min((cve_score * 0.8) + (attack_score * 1.2), 10.0)

    def get_remediation_for_technique(self, technique_id: str) -> dict:
        remediation = {
            'T1003': {
                'title': 'Credential Dumping Detected',
                'summary': 'Attacker successfully dumped credentials from memory.',
                'fixes': [
                    'Enable Windows Credential Guard',
                    'Restrict SeDebugPrivilege to SYSTEM only',
                    'Deploy LAPS for local admin password management',
                    'Enable Protected Users security group in AD',
                    'Block LSASS access via Attack Surface Reduction rules',
                ],
                'mitre_defend': 'M1043, M1028, M1026',
            },
            'T1021': {
                'title': 'Remote Service Exploitation',
                'summary': 'Attacker used remote services (SMB/RDP/WMI) for lateral movement.',
                'fixes': [
                    'Disable SMBv1, enforce SMBv3 with signing',
                    'Restrict RDP access via firewall rules',
                    'Enable Network Level Authentication for RDP',
                    'Disable WMI remote execution where not needed',
                    'Implement network segmentation',
                ],
                'mitre_defend': 'M1035, M1030',
            },
            'T1082': {
                'title': 'System Discovery',
                'summary': 'Attacker enumerated system information.',
                'fixes': [
                    'Restrict access to system information commands',
                    'Enable Windows Firewall with strict inbound rules',
                    'Monitor for unusual enumeration activity in SIEM',
                ],
                'mitre_defend': 'M1018',
            },
            'T1087': {
                'title': 'Account Discovery',
                'summary': 'Attacker enumerated user accounts.',
                'fixes': [
                    'Restrict AD enumeration to authorised users only',
                    'Enable AD audit logging',
                    'Implement Just-In-Time access for privileged accounts',
                ],
                'mitre_defend': 'M1028',
            },
            'T1055': {
                'title': 'Process Injection',
                'summary': 'Attacker injected code into running processes.',
                'fixes': [
                    'Enable Attack Surface Reduction rules in Windows Defender',
                    'Deploy Endpoint Detection and Response (EDR) solution',
                    'Restrict which processes can be injected into',
                ],
                'mitre_defend': 'M1040',
            },
            'T1059': {
                'title': 'Command Execution via Scripting',
                'summary': 'Attacker executed code via PowerShell or cmd.',
                'fixes': [
                    'Enable PowerShell Constrained Language Mode',
                    'Deploy Application Whitelisting (AppLocker/WDAC)',
                    'Enable ScriptBlock logging for PowerShell',
                    'Disable cmd.exe for non-admin users where possible',
                ],
                'mitre_defend': 'M1038, M1042',
            },
            'T1547': {
                'title': 'Persistence via Registry/Startup',
                'summary': 'Attacker established persistence via registry run keys.',
                'fixes': [
                    'Monitor registry run keys for unauthorised changes',
                    'Enable Autoruns monitoring',
                    'Restrict registry write permissions for standard users',
                ],
                'mitre_defend': 'M1024',
            },
            'T1548': {
                'title': 'Bypass User Account Control',
                'summary': 'Attacker bypassed UAC to gain elevated privileges.',
                'fixes': [
                    'Set UAC to Always Notify',
                    'Remove users from local Administrators group',
                    'Enforce Least Privilege principle',
                ],
                'mitre_defend': 'M1051, M1026',
            },
        }
        for key, advice in remediation.items():
            if technique_id.startswith(key):
                return advice
        return {
            'title': f'Technique {technique_id} Succeeded',
            'summary': 'Review this technique and apply relevant mitigations.',
            'fixes': [
                'Review MITRE ATT&CK mitigations for this technique',
                'Enable enhanced logging and monitoring',
                'Apply Principle of Least Privilege',
            ],
            'mitre_defend': 'See https://attack.mitre.org',
        }

    def get_all_remediations(self, operation_results: dict) -> list:
        remediations = []
        seen = set()
        for t in operation_results.get('techniques_run', []):
            if t.get('status') == 'success':
                tid = t.get('technique_id', '')
                if tid and tid not in seen:
                    advice = self.get_remediation_for_technique(tid)
                    advice['technique_id'] = tid
                    advice['technique_name'] = t.get('technique_name', '')
                    advice['tactic'] = t.get('tactic', '')
                    remediations.append(advice)
                    seen.add(tid)
        return remediations
