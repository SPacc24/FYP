from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from storage import scan_store


def _norm(value: Any) -> str:
    return str(value or '').strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _service_key(row: dict[str, Any]) -> str:
    return f"{_norm(row.get('host'))}:{_norm(row.get('port'))}/{_norm(row.get('protocol') or 'tcp').lower()}"


def _service_signature(row: dict[str, Any]) -> str:
    parts = [row.get('service'), row.get('product'), row.get('version'), row.get('extrainfo')]
    return ' | '.join(_norm(p) for p in parts if _norm(p))


def _safe_json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _recent_handoff_files(results_dir: Path, current_scan_id: str, limit: int = 12) -> list[Path]:
    if not results_dir.exists():
        return []
    files = [p for p in results_dir.glob('*_handoff.json') if current_scan_id not in p.name]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def _latest_comparable_run(results_dir: Path, current_target: str, current_scan_id: str) -> dict[str, Any] | None:
    for path in _recent_handoff_files(results_dir, current_scan_id):
        data = _safe_json_load(path)
        if not isinstance(data, dict):
            continue
        if _norm(data.get('target_input')) == current_target:
            data['_source_file'] = str(path)
            return data
    return None


def build_enumeration_cache(scan_id: str, target_input: str, services: list[dict[str, Any]], modern_active_validation: dict[str, Any], passive_intelligence: dict[str, Any], cache_dir: str | Path | None = None) -> dict[str, Any]:
    """Create cache metadata for repeat scans.

    The current run is never skipped by this helper. It writes cache metadata so
    future runs can safely reuse stable low-noise observations when policy allows.
    """
    cache_path = Path(cache_dir) if cache_dir is not None else scan_store.storage_path('cache')
    cache_path.mkdir(parents=True, exist_ok=True)
    ttl_seconds = {
        'dns_context': 12 * 3600,
        'tls_intelligence': 12 * 3600,
        'http_security_context': 6 * 3600,
        'ldap_rootdse': 24 * 3600,
        'ldapsearch_rootdse': 24 * 3600,
        'kerberos_info': 24 * 3600,
        'snmp_targeted_oids': 24 * 3600,
        'service_inventory': 6 * 3600,
    }
    active_keys = [k for k, v in (modern_active_validation or {}).items() if isinstance(v, list) and v]
    reusable_collectors = [k for k in active_keys if k in ttl_seconds]
    # service inventory is always represented as a reusable low-noise comparison unit.
    reusable_collectors.append('service_inventory')
    service_rows = [
        {
            'key': _service_key(s),
            'signature': _service_signature(s),
            'host': s.get('host'),
            'port': s.get('port'),
            'protocol': s.get('protocol', 'tcp'),
            'service': s.get('service'),
            'product': s.get('product'),
            'version': s.get('version'),
        }
        for s in services or []
    ]
    cache = {
        'scan_id': scan_id,
        'target': target_input,
        'created_at': _now(),
        'policy': 'Reuse stable metadata only when target, network-path context and service signature remain consistent.',
        'reusable_collectors': [
            {'collector': c, 'ttl_seconds': ttl_seconds.get(c, 6 * 3600), 'reuse_boundary': 'metadata only; do not infer service absence from cached data'}
            for c in sorted(set(reusable_collectors))
        ],
        'service_signatures': service_rows,
        'passive_summary_count': len((passive_intelligence or {}).get('summary') or []),
        'summary': f"{len(service_rows)} service signature(s) and {len(set(reusable_collectors))} reusable metadata collector type(s) recorded.",
    }
    out = cache_path / f'{scan_id}_enumeration_cache.json'
    out.write_text(json.dumps(cache, indent=2, default=str), encoding='utf-8')
    cache['cache_file'] = str(out)
    return cache


def build_differential_recon(scan_id: str, target_input: str, current_services: list[dict[str, Any]], results_dir: str | Path | None = None) -> dict[str, Any]:
    """Compare current service inventory to the most recent comparable run.

    This is operational comparison only. It does not rank, prioritise or assign risk.
    """
    results_path = Path(results_dir) if results_dir is not None else scan_store.RESULTS_DIR
    previous = _latest_comparable_run(results_path, _norm(target_input), scan_id)
    current_map = {_service_key(s): _service_signature(s) for s in current_services or []}
    if not previous:
        return {
            'baseline_found': False,
            'summary': 'No previous comparable run found for this target. Current scan becomes the first comparison baseline.',
            'new_services': [],
            'removed_services': [],
            'changed_services': [],
        }
    previous_services = previous.get('service_inventory') or []
    previous_map = {_service_key(s): _service_signature(s) for s in previous_services if isinstance(s, dict)}
    new_keys = sorted(set(current_map) - set(previous_map))
    removed_keys = sorted(set(previous_map) - set(current_map))
    changed_keys = sorted(k for k in set(current_map) & set(previous_map) if current_map[k] != previous_map[k])
    return {
        'baseline_found': True,
        'baseline_file': previous.get('_source_file'),
        'baseline_scan_id': previous.get('scan_id'),
        'summary': f"Compared against previous run {previous.get('scan_id') or 'unknown'}: {len(new_keys)} new, {len(removed_keys)} removed, {len(changed_keys)} changed service item(s).",
        'new_services': [{'service_key': k, 'current_signature': current_map[k]} for k in new_keys[:50]],
        'removed_services': [{'service_key': k, 'previous_signature': previous_map[k]} for k in removed_keys[:50]],
        'changed_services': [{'service_key': k, 'previous_signature': previous_map[k], 'current_signature': current_map[k]} for k in changed_keys[:50]],
        'interpretation_boundary': 'Differences reflect observed recon evidence between runs only; scheduled rules, filtering and scan position can change visibility.',
    }


def build_service_confidence_breakdown(services: list[dict[str, Any]], enumeration_intelligence: dict[str, Any], modern_active_validation: dict[str, Any], passive_intelligence: dict[str, Any]) -> list[dict[str, Any]]:
    active_by_host: dict[str, set[str]] = {}
    for key, value in (modern_active_validation or {}).items():
        if not isinstance(value, list):
            continue
        for row in value:
            if isinstance(row, dict) and row.get('host'):
                active_by_host.setdefault(_norm(row.get('host')), set()).add(key)
    passive_hosts = set()
    for section in ['findings', 'reverse_dns', 'dns', 'tls']:
        for row in (passive_intelligence or {}).get(section) or []:
            if isinstance(row, dict) and row.get('host'):
                passive_hosts.add(_norm(row.get('host')))
    role_by_host: dict[str, list[str]] = {}
    for row in (enumeration_intelligence or {}).get('service_roles') or []:
        role_by_host.setdefault(_norm(row.get('host')), []).append(_norm(row.get('role')))
    rows = []
    for svc in services or []:
        host = _norm(svc.get('host'))
        sources = ['Service inventory']
        if _service_signature(svc):
            sources.append('Banner or version evidence')
        if active_by_host.get(host):
            sources.append('Validator evidence')
        if host in passive_hosts:
            sources.append('Passive or DNS/TLS evidence')
        if role_by_host.get(host):
            sources.append('Cross-service role inference')
        if 'Validator evidence' in sources and 'Banner or version evidence' in sources:
            confidence = 'Supported'
        elif 'Banner or version evidence' in sources:
            confidence = 'Observed'
        else:
            confidence = 'Unresolved'
        rows.append({
            'host': host,
            'port': svc.get('port'),
            'protocol': svc.get('protocol', 'tcp'),
            'service': svc.get('service') or 'unknown',
            'confidence': confidence,
            'evidence_sources': sorted(set(sources)),
            'role_context': sorted(set(role_by_host.get(host, []))),
            'boundary': 'Confidence describes evidence support for identification only; it is not severity or priority.',
        })
    return rows[:120]


def build_operational_metrics(scan_id: str, services: list[dict[str, Any]], raw_evidence_index: list[dict[str, Any]], modern_active_validation: dict[str, Any], started_at: str | None = None) -> dict[str, Any]:
    evidence_files = [r for r in raw_evidence_index or [] if isinstance(r, dict) and r.get('path')]
    validators = [k for k, v in (modern_active_validation or {}).items() if isinstance(v, list) and v]
    return {
        'scan_id': scan_id,
        'started_at': started_at,
        'completed_at': _now(),
        'service_records': len(services or []),
        'evidence_files': len(evidence_files),
        'validators_with_evidence': len(validators),
        'validator_names': sorted(validators),
        'summary': f"{len(services or [])} service record(s), {len(evidence_files)} evidence file reference(s), and {len(validators)} validator group(s) retained.",
        'boundary': 'Operational metrics describe collection volume and duration context only; they do not guide exploitation or downstream action selection.',
    }


def build_operational_maturity_package(scan_id: str, target_input: str, services: list[dict[str, Any]], raw_evidence_index: list[dict[str, Any]], modern_active_validation: dict[str, Any], passive_intelligence: dict[str, Any], enumeration_intelligence: dict[str, Any], started_at: str | None = None) -> dict[str, Any]:
    cache = build_enumeration_cache(scan_id, target_input, services, modern_active_validation, passive_intelligence)
    differential = build_differential_recon(scan_id, target_input, services)
    confidence_breakdown = build_service_confidence_breakdown(services, enumeration_intelligence, modern_active_validation, passive_intelligence)
    metrics = build_operational_metrics(scan_id, services, raw_evidence_index, modern_active_validation, started_at)
    package = {
        'enumeration_cache': cache,
        'differential_recon': differential,
        'service_confidence_breakdown': confidence_breakdown,
        'operational_metrics': metrics,
        'summary': [
            cache.get('summary', ''),
            differential.get('summary', ''),
            metrics.get('summary', ''),
            f"{len(confidence_breakdown)} service confidence row(s) retained.",
        ],
    }
    out = scan_store.result_path(f'{scan_id}_operational_maturity.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(package, indent=2, default=str), encoding='utf-8')
    package['operational_maturity_file'] = str(out)
    return package
