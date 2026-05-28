
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


def build_mitre_url(technique_id: str) -> str:
    technique_id = str(technique_id or "").strip()
    if not technique_id:
        return "https://attack.mitre.org/"
    if "." in technique_id:
        main_id, sub_id = technique_id.split('.', 1)
        return f"https://attack.mitre.org/techniques/{main_id}/{sub_id}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"

# ── Tactic weights (how dangerous each ATT&CK tactic is) ───────────────────
# Based on MITRE ATT&CK impact assessment + industry standards
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
SEVERITY_SCORE = {
    'critical': 10.0,
    'high': 8.0,
    'medium': 5.0,
    'low': 2.0,
    'info': 0.0,
}

# Risk label thresholds 
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
    """
    Produces a final risk score (0.0 - 10.0) by combining:
    1. CVE CVSS scores from the vulnerability mapping step
    2. ATT&CK technique success weights from Caldera operation results
    """
    def calculate(
            self, 
            vulnerabilities: list, 
            operation_results: dict) -> dict:
        """
        Main scoring method.

        Args:
            vulnerabilities: List of CVE dicts from vulnerability mapping.
                             Each: {cve_id, cve_score, severity, port, service}
            operation_results: Parsed result dict from OperationManager.run_operation()

        Returns:
            {
              'score':       float (0.0-10.0),
              'label':       str,
              'colour':      str,
              'badge':       str,
              'breakdown':   dict  (for report transparency)
            }
        """
        cve_component = self._score_cve(vulnerabilities)
        exposure_component = self._score_exposure(vulnerabilities)
        attack_component = self._score_attack(operation_results)
        validation_component = self._score_validation(operation_results.get('validation_results', {}))
        combined = self._combine(cve_component, exposure_component, attack_component, validation_component)
        label_info = get_risk_label(combined)
        breakdown = {
            'cve_component': round(cve_component, 2),
            'exposure_component': round(exposure_component, 2),
            'attack_component': round(attack_component, 2),
            'validation_component': round(validation_component, 2),
            'final_score': round(combined, 2),
            'cve_count': len(vulnerabilities),
            'exposed_services': len([v for v in vulnerabilities if str(v.get('state', '')).lower() == 'open']),
            'techniques_run': operation_results.get('total', 0),
            'techniques_success': operation_results.get('success_count', 0),
            'unsupported_techniques': operation_results.get('unsupported_count', 0),
        }
        log.info('Risk score: %.2f | CVE=%.2f ATT&CK=%.2f', combined, cve_component, attack_component)
        return {
            'score': round(combined, 2),
            'label': label_info['label'],
            'colour': label_info['colour'],
            'badge': label_info['badge'],
            'breakdown': breakdown,
        }

    # CVE scoring
    def _score_cve(self, vulnerabilities: list) -> float:
        """
        Calculate risk contribution from CVE findings.

        Uses CVSS base score (0-10) from each vulnerability.
        Takes the weighted average, skewed toward the highest scores.
        """
        if not vulnerabilities:
            return 0.0

        scores = sorted([self._finding_score(v) for v in vulnerabilities], reverse=True)
        
        if not scores:
            return 0.0
        
        # Weighted average: highest score counts most
        weights = [1 / (i + 1) for i in range(len(scores))]
        weighted = sum(s * w for s, w in zip(scores, weights))
        total_w = sum(weights)
        avg = weighted / total_w if total_w else 0.0

        # Normalize to 0-5 (CVE contributes up to 50% of final score)
        return min(avg / 2.0, 5.0)

    def _finding_score(self, finding: dict) -> float:
        """
        Convert mapper findings into a 0-10 risk value.

        Older code expected cve_score only, but the mapper primarily emits
        severity and priority_score. Supporting both keeps scan-stage risk
        useful before any CALDERA operation runs.
        """
        for key in ('cve_score', 'cvss_score', 'priority_score'):
            try:
                score = float(finding.get(key, 0.0) or 0.0)
            except (TypeError, ValueError):
                score = 0.0

            if score > 0:
                return min(score, 10.0)

        cve_scores = []
        for match in finding.get('cve_matches', []) or []:
            try:
                cve_scores.append(float(match.get('score', 0.0) or match.get('cvss', 0.0) or 0.0))
            except (TypeError, ValueError):
                continue

        if cve_scores:
            return min(max(cve_scores), 10.0)

        severity = str(finding.get('severity', 'info')).lower()
        return SEVERITY_SCORE.get(severity, 0.0)

    def _score_exposure(self, vulnerabilities: list) -> float:
        if not vulnerabilities:
            return 0.0

        high_value_services = {
            'microsoft-ds',
            'netbios-ssn',
            'smb',
            'ms-wbt-server',
            'wsman',
            'ssh',
            'telnet',
            'mysql',
        }
        score = 0.0
        for finding in vulnerabilities:
            if str(finding.get('state', '')).lower() != 'open':
                continue
            score += 0.35
            if str(finding.get('service', '')).lower() in high_value_services:
                score += 0.55
            if finding.get('attack_techniques'):
                score += min(len(finding.get('attack_techniques', [])) * 0.12, 0.45)
        return min(score, 2.0)

    # ATT&CK technique scoring
    def _score_attack(self, operation_results: dict) -> float:
        """
        Calculate risk contribution from successful ATT&CK techniques.

        Each successful technique adds its tactic weight.
        Normalised to 0-5 (ATT&CK contributes up to 50% of final score).
        """
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

    def _score_validation(self, validation_results: dict) -> float:
        if not validation_results:
            return 0.0
        confirmed = int(validation_results.get('confirmed', 0) or 0)
        potential = int(validation_results.get('potential', 0) or 0)
        return min((confirmed * 0.8) + (potential * 0.45), 2.0)

     # Combination
    def _combine(self, cve_score: float, exposure_score: float, attack_score: float, validation_score: float) -> float:
        """
        Components are additive and capped at 10 so the report can explain why
        scan exposure, lab validation, and CALDERA evidence changed the score.
        """
        return min(cve_score + exposure_score + attack_score + validation_score, 10.0)

    # Remediation hints (rule-based advice for common techniques)
    def get_remediation_for_technique(self, technique_id: str) -> dict:
        """
        Rule-based remediation advice for common ATT&CK techniques.
        No API needed — pure rule engine.
        """
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

        # Match on partial technique ID
        for key, advice in remediation.items():
            if technique_id.startswith(key):
                advice_copy = advice.copy()
                advice_copy['mitre_url'] = build_mitre_url(technique_id)
                return advice_copy
            
        # Default generic advice
        return {
            'title': f'Technique {technique_id} Succeeded',
            'summary': 'Review this technique and apply relevant mitigations.',
            'fixes': [
                'Review MITRE ATT&CK mitigations for this technique',
                'Enable enhanced logging and monitoring',
                'Apply Principle of Least Privilege',
            ],
            'mitre_defend': 'See https://attack.mitre.org',
            'mitre_url': build_mitre_url(technique_id),
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
                    advice['type'] = 'technique'
                    remediations.append(advice)
                    seen.add(tid)
        return remediations

    def get_vulnerability_remediations(self, mapping_results: dict) -> list:
        remediations = []
        seen = set()

        for vuln in mapping_results.get('vulnerabilities', []):
            host = vuln.get('host', 'Unknown host')
            port = vuln.get('port', 'Unknown port')
            service = vuln.get('service', 'Unknown service')
            key = (host, port, service, vuln.get('title'))

            if key in seen:
                continue
            seen.add(key)

            remediations.append({
                'type': 'vulnerability',
                'title': vuln.get('title', 'Vulnerability finding'),
                'summary': vuln.get('cve_hint', vuln.get('recommendation', 'Review the finding and apply hardening.')),
                'fixes': [vuln.get('recommendation', 'Review configuration and patch software.')],
                'affected_host': host,
                'affected_port': port,
                'affected_service': service,
                'severity': vuln.get('severity', 'Unknown'),
            })

        return remediations
