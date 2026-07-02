from __future__ import annotations
import json
from pathlib import Path
from typing import Any

class ObjectiveRegistryError(RuntimeError):
    pass

def _registry_path() -> Path:
    for candidate in (Path('project/policies/objective_registry.json'), Path('policies/objective_registry.json')):
        if candidate.exists():
            return candidate
    raise ObjectiveRegistryError('Objective registry missing; recon cannot infer objectives safely.')

def load_objective_registry() -> dict[str, Any]:
    try:
        data = json.loads(_registry_path().read_text(encoding='utf-8'))
    except Exception as exc:
        raise ObjectiveRegistryError(f'Objective registry could not be loaded: {exc}') from exc
    if not isinstance(data, dict) or not data:
        raise ObjectiveRegistryError('Objective registry is empty or invalid.')
    return data

def infer_objectives(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    registry = load_objective_registry()
    observed_services = {str(s.get('service') or '').lower() for s in services or []}
    observed_ports = {int(s.get('port') or 0) for s in services or [] if str(s.get('port') or '').isdigit()}
    selected: list[dict[str, Any]] = []
    for key, spec in registry.items():
        spec_services = {str(x).lower() for x in spec.get('services') or []}
        spec_ports = {int(x) for x in spec.get('ports') or []}
        matched_services = sorted(spec_services & observed_services)
        matched_ports = sorted(spec_ports & observed_ports)
        if matched_services or matched_ports:
            selected.append({
                'id': key,
                'label': spec.get('label') or key.replace('_', ' ').title(),
                'matched_services': matched_services,
                'matched_ports': matched_ports,
                'evidence_needed': list(spec.get('evidence_needed') or []),
            })
    return selected

def evidence_gaps_for_service(service: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    if not service.get('product'):
        gaps.append('product_identity')
    if not service.get('version'):
        gaps.append('version_identity')
    if not service.get('cpe'):
        gaps.append('cpe_identity')
    return gaps
