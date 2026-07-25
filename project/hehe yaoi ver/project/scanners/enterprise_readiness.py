from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from storage import scan_store


class EnterprisePolicyError(RuntimeError):
    """Raised when an authorised engagement policy would be violated."""


def _first_existing(*paths: str) -> Path | None:
    for item in paths:
        path = Path(item)
        if path.exists():
            return path
    return None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise EnterprisePolicyError(f'Policy file could not be parsed: {path}: {exc}') from exc
    if not isinstance(data, dict):
        raise EnterprisePolicyError(f'Policy file must contain a JSON object: {path}')
    return data


def load_engagement_policy() -> dict[str, Any]:
    configured = os.getenv('ENGAGEMENT_POLICY_FILE', '').strip()
    path = Path(configured) if configured else _first_existing('project/policies/engagement_policy.json', 'policies/engagement_policy.json')
    if path is None:
        raise EnterprisePolicyError('Engagement policy is missing; scan refused rather than running without scope controls.')
    policy = _load_json(path)
    policy['_policy_file'] = str(path)
    return policy


def _parse_dt(value: str) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EnterprisePolicyError(f'Invalid engagement datetime: {value}') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _network_list(values: list[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values or []:
        networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
    return networks


def _address_in_any(addr: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip in net for net in networks)


def validate_scope(targets: list[str], target_input: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate targets against explicit engagement scope.

    The default policy supports private lab ranges for FYP demonstration, but the report
    still records that an enterprise pilot should replace it with a signed RoE policy.
    """
    policy = policy or load_engagement_policy()
    now = datetime.now(timezone.utc)
    start = _parse_dt(policy.get('engagement_start_utc', ''))
    expiry = _parse_dt(policy.get('engagement_expiry_utc', ''))
    if start and now < start:
        raise EnterprisePolicyError('Engagement window has not started; scan refused.')
    if expiry and now > expiry:
        raise EnterprisePolicyError('Engagement window has expired; scan refused.')

    controls = policy.get('scope_controls') or {}
    allow_private_lab = bool(controls.get('allow_private_lab_targets_without_signed_roe', False))
    allow_public = bool(controls.get('allow_public_targets', False))
    allowed = _network_list(controls.get('allowed_networks') or [])
    denied = _network_list(controls.get('denied_networks') or [])
    max_targets = int(controls.get('max_targets_per_scan') or len(targets) or 1)
    if len(targets) > max_targets:
        raise EnterprisePolicyError(f'Target expansion produced {len(targets)} host(s), above engagement policy limit {max_targets}.')

    violations: list[str] = []
    warnings: list[str] = []
    for target in targets:
        ip = ipaddress.ip_address(target)
        if denied and _address_in_any(target, denied):
            violations.append(f'{target} is inside an explicitly denied network')
        if allowed and not _address_in_any(target, allowed):
            violations.append(f'{target} is outside allowed engagement scope')
        if not allowed:
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                if allow_private_lab:
                    warnings.append(f'{target} allowed by private-lab fallback; replace with signed RoE allow-list before company review')
                else:
                    violations.append(f'{target} requires explicit allow-list scope')
            elif not allow_public:
                violations.append(f'{target} is public/non-private and public targeting is disabled')
    approvals = policy.get('approvals') or {}
    if approvals.get('require_reviewer_approval') and not approvals.get('reviewer_approval_record'):
        violations.append('reviewer approval required by policy but no approval record is configured')
    if approvals.get('require_manager_approval') and not approvals.get('manager_approval_record'):
        violations.append('manager approval required by policy but no approval record is configured')
    if violations:
        raise EnterprisePolicyError('; '.join(violations))
    return {
        'policy_file': policy.get('_policy_file', ''),
        'target_input': target_input,
        'targets': targets,
        'validated_at_utc': now.isoformat(timespec='seconds'),
        'engagement_id': policy.get('engagement_id', 'unspecified'),
        'engagement_name': policy.get('engagement_name', 'unspecified'),
        'scope_mode': 'explicit_allowlist' if allowed else ('private_lab_fallback' if allow_private_lab else 'restricted'),
        'warnings': sorted(set(warnings)),
        'approvals': approvals,
    }


def load_enterprise_review_policy() -> dict[str, Any]:
    path = _first_existing('project/policies/enterprise_review_policy.json', 'policies/enterprise_review_policy.json')
    if path is None:
        return {}
    data = _load_json(path)
    data['_policy_file'] = str(path)
    return data


def build_decision_register(services: list[dict[str, Any]], objectives: list[dict[str, Any]], environment_context_indicators: list[dict[str, Any]], evidence_gaps: list[dict[str, Any]], review_policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = review_policy or load_enterprise_review_policy()
    rules = policy.get('decision_rules') or {}
    register: list[dict[str, Any]] = []
    pause_reasons = []
    environment_notes = []
    if environment_context_indicators:
        environment_notes.append('environment_context_indicator_observed')
    if evidence_gaps:
        pause_reasons.append('identity_evidence_incomplete')
    for obj in objectives or []:
        register.append({
            'objective_id': obj.get('id'),
            'objective_label': obj.get('label'),
            'matched_ports': obj.get('matched_ports', []),
            'matched_services': obj.get('matched_services', []),
            'decision': 'collect_readiness_evidence_only' if not pause_reasons else 'continue_with_context_checkpoint',
            'basis': rules.get('readiness_basis', 'Evidence-first recon only; exploitation and credential validation remain downstream.'),
            'required_human_gate': bool(obj.get('matched_ports')),
            'pause_reasons': pause_reasons,
            'environment_notes': environment_notes,
        })
    if not register:
        register.append({
            'objective_id': 'surface_discovery',
            'objective_label': 'Attack surface discovery',
            'decision': 'no_service_objective_selected',
            'basis': 'No service objective matched the current evidence set.',
            'required_human_gate': False,
            'pause_reasons': pause_reasons,
            'environment_notes': environment_notes,
        })
    return register


def sha256_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build_evidence_manifest(scan_id: str, raw_evidence_index: list[dict[str, Any]], package_file: str | None = None) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_evidence_index or []:
        path = str(item.get('output_file') or item.get('file') or '').strip()
        if not path or path in seen:
            continue
        seen.add(path)
        p = Path(path)
        row = {
            'path': path,
            'exists': p.exists(),
            'source': item.get('tool') or item.get('source') or item.get('id') or '',
            'host': item.get('host', ''),
            'port': item.get('port', ''),
            'content_type': item.get('type') or item.get('content_type') or '',
        }
        if p.exists() and p.is_file():
            row['sha256'] = sha256_file(p)
            row['size_bytes'] = p.stat().st_size
        entries.append(row)
    manifest = {
        'scan_id': scan_id,
        'generated_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'hash_algorithm': 'sha256',
        'entries': entries,
    }
    if package_file:
        out = Path(package_file)
    else:
        out = scan_store.result_path(f'{scan_id}_evidence_manifest.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, default=str), encoding='utf-8')
    manifest['manifest_file'] = str(out)
    manifest['manifest_sha256'] = sha256_file(out)
    return manifest


def build_enterprise_readiness_summary(scope_validation: dict[str, Any], decision_register: list[dict[str, Any]], evidence_manifest: dict[str, Any], review_policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = review_policy or load_enterprise_review_policy()
    controls = policy.get('review_controls') or []
    implemented = []
    for control in controls:
        cid = control.get('id')
        if cid in {'scope_control', 'chain_of_custody', 'decision_register', 'environment_context'}:
            state = 'implemented_in_recon_scope'
        else:
            state = control.get('state', 'documented_for_company_review')
        implemented.append({**control, 'state': state})
    return {
        'scope_validation': scope_validation,
        'decision_register_count': len(decision_register or []),
        'evidence_manifest_file': evidence_manifest.get('manifest_file'),
        'evidence_manifest_sha256': evidence_manifest.get('manifest_sha256'),
        'company_review_controls': implemented,
        'limitations': policy.get('limitations', []),
        'standards_alignment': policy.get('standards_alignment', []),
    }
