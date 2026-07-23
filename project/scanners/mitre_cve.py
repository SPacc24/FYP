
from __future__ import annotations

import copy
import json
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from .scoring_policy import (
    ScoringPolicyError,
    metric_keys_by_version,
    normalise_cvss_version,
    validate_published_metric,
)
from .cve_v5_matcher import search as search_cve_v5
from .cve_v5_matcher import SQLITE_INDEX, affected_identity_keys

BASE = Path('storage/mitre_cve')
REPO_DIR = BASE / 'cvelistV5'
INDEX = BASE / 'official_mitre_cve_index.jsonl'
OFFICIAL_CVE_REPO = 'https://github.com/CVEProject/cvelistV5.git'
OFFICIAL_CVE_SOURCE = 'Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)'
# Production applicability is data-driven. Product identity comes only from
# the observed fingerprint and machine-readable CVE List V5 fields.
# No product-specific alias table or description parser participates.

def status() -> dict[str, Any]:
    records = 0
    selection_schema_records = 0
    cvss_records = 0
    cvss_records_by_version = {version: 0 for version in metric_keys_by_version()}
    status_error = ''
    if INDEX.exists():
        try:
            with INDEX.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    records += 1
                    if '"index_schema_version": 4' in line:
                        selection_schema_records += 1
                    has_cvss = False
                    for version in cvss_records_by_version:
                        if '"cvss_metrics"' in line and f'"{version}":' in line:
                            cvss_records_by_version[version] += 1
                            has_cvss = True
                        elif f'"cvss_version": "{version}"' in line and '"cvss_score"' in line:
                            cvss_records_by_version[version] += 1
                            has_cvss = True
                    if has_cvss:
                        cvss_records += 1
        except Exception as exc:
            records = 0
            selection_schema_records = 0
            cvss_records = 0
            cvss_records_by_version = {version: 0 for version in metric_keys_by_version()}
            status_error = f'{type(exc).__name__}: {exc}'
    index_ready = (
        INDEX.exists()
        and SQLITE_INDEX.exists()
        and records > 0
        and selection_schema_records == records
        and not status_error
    )
    if records > 0 and not SQLITE_INDEX.exists() and not status_error:
        status_error = 'Local CVE List V5 SQLite index is missing; rebuild schema v4.'
    elif records > 0 and selection_schema_records != records and not status_error:
        status_error = 'Local CVE List V5 index schema is outdated; rebuild schema v4.'
    stale_cvss = index_ready and cvss_records == 0
    return {
        'source': OFFICIAL_CVE_SOURCE,
        'available': index_ready,
        'matcher_status': 'available' if index_ready else 'unavailable',
        'status_error': status_error,
        'records_indexed': records,
        'cvss_selection_ready': index_ready,
        'cvss_selection_schema_records': selection_schema_records,
        'records_with_cvss_metadata': cvss_records,
        'records_with_cvss_metadata_by_version': cvss_records_by_version,
        'cvss_metadata_stale': stale_cvss,
        'cvss_metadata_warning': 'CVE index is available, but CVSS metadata is missing. Run: python scripts/rebuild_mitre_cve_index.py' if stale_cvss else '',
        'rebuild_command': 'python scripts/rebuild_mitre_cve_index.py',
        'index_file': str(INDEX),
        'repo_dir': str(REPO_DIR),
        'matching_policy': 'Candidate requires a direct match to machine-readable CVE List V5 affected data using the record-defined version semantics. Confirmed requires separate target-specific validation evidence. CVSS severity never creates or confirms a finding.',
        'applicability_source': OFFICIAL_CVE_SOURCE,
    }


def _sort_key(row: dict[str, Any]) -> tuple[bool, float, str]:
    """Published technical severity order; unavailable metrics sort last."""
    score = row.get('cvss_score')
    return (score is None, -(float(score) if score is not None else 0.0), str(row.get('cve_id') or ''))


def _metric_for_version(record: dict[str, Any], selected_version: str) -> dict[str, Any]:
    """Return only the exact published metric selected by the operator."""
    metric = (record.get('cvss_metrics') or {}).get(selected_version)
    return dict(metric) if isinstance(metric, dict) else {}


def search(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    cvss_version: str | None = None,
    observed_environment_cpes: tuple[str, ...] = (),
    observed_platforms: tuple[str, ...] = (),
    observed_modules: tuple[str, ...] = (),
    observed_package_names: tuple[str, ...] = (),
    observed_program_files: tuple[str, ...] = (),
    observed_program_routines: tuple[str, ...] = (),
) -> tuple[dict[str, Any], ...]:
    candidates, _ = search_with_diagnostics(
        product,
        version,
        service,
        cpe,
        cvss_version=cvss_version,
        observed_environment_cpes=observed_environment_cpes,
        observed_platforms=observed_platforms,
        observed_modules=observed_modules,
        observed_package_names=observed_package_names,
        observed_program_files=observed_program_files,
        observed_program_routines=observed_program_routines,
    )
    return tuple(candidates)


def search_with_diagnostics(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    cvss_version: str | None = None,
    observed_environment_cpes: tuple[str, ...] = (),
    observed_platforms: tuple[str, ...] = (),
    observed_modules: tuple[str, ...] = (),
    observed_package_names: tuple[str, ...] = (),
    observed_program_files: tuple[str, ...] = (),
    observed_program_routines: tuple[str, ...] = (),
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Return Candidate findings and non-CVE operational diagnostics."""
    selected_version = normalise_cvss_version(cvss_version)
    service_cpes = tuple(value.strip() for value in str(cpe or '').splitlines() if value.strip())
    rows, diagnostics = search_cve_v5(
        product,
        version,
        selected_cvss=selected_version,
        service_cpes=service_cpes,
        environment_cpes=observed_environment_cpes,
        observed_platforms=observed_platforms,
        observed_modules=observed_modules,
        observed_package_names=observed_package_names,
        observed_program_files=observed_program_files,
        observed_program_routines=observed_program_routines,
    )
    return tuple(copy.deepcopy(sorted(rows, key=_sort_key))), tuple(copy.deepcopy(diagnostics))


def _extract_metrics_from_node(node: Any, provider_role: str) -> dict[str, dict[str, Any]]:
    if not isinstance(node, dict):
        return {}
    candidates = []
    metrics = node.get('metrics')
    if isinstance(metrics, list):
        candidates.extend(metrics)
    extracted: dict[str, dict[str, Any]] = {}
    metric_keys = metric_keys_by_version()
    for c in candidates:
        if not isinstance(c, dict):
            continue
        for version, key in metric_keys.items():
            if version in extracted:
                continue
            data = c.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get('baseScore')
            severity = data.get('baseSeverity') or data.get('severity')
            vector = data.get('vectorString')
            if score is not None:
                try:
                    published = validate_published_metric(version, score, severity, vector)
                except ScoringPolicyError:
                    continue
                extracted[version] = {
                    **published,
                    'cvss_source': c.get('source') or node.get('providerMetadata', {}).get('orgId') or '',
                    'cvss_provider_role': provider_role,
                }
    return extracted


def _extract_metrics(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    containers = data.get('containers', {}) if isinstance(data, dict) else {}
    cna = containers.get('cna') or {}
    metrics = _extract_metrics_from_node(cna, 'CNA')
    for adp in containers.get('adp') or []:
        for version, metric in _extract_metrics_from_node(adp, 'ADP').items():
            metrics.setdefault(version, metric)
    return metrics


def build_index() -> dict[str, Any]:
    BASE.mkdir(parents=True, exist_ok=True)
    if not REPO_DIR.exists():
        repo = OFFICIAL_CVE_REPO
        subprocess.run(['git', 'clone', '--depth', '1', repo, str(REPO_DIR)], check=True)
    else:
        subprocess.run(['git', '-C', str(REPO_DIR), 'pull', '--ff-only'], check=False)

    count = 0
    cvss_count = 0
    cvss_count_by_version = {version: 0 for version in metric_keys_by_version()}
    temp_index = INDEX.with_suffix(INDEX.suffix + '.tmp')
    temp_sqlite = SQLITE_INDEX.with_suffix(SQLITE_INDEX.suffix + '.tmp')
    temp_sqlite.unlink(missing_ok=True)
    database = sqlite3.connect(temp_sqlite)
    database.execute('CREATE TABLE affected_identities (cve_id TEXT NOT NULL, identity_key TEXT NOT NULL, record_json TEXT NOT NULL)')
    with temp_index.open('w', encoding='utf-8') as out:
        for path in REPO_DIR.rglob('CVE-*.json'):
            try:
                data = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            cve_id = data.get('cveMetadata', {}).get('cveId') or path.stem
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            record_containers = [('CNA', cna)]
            record_containers.extend(
                ('ADP', node) for node in (containers.get('adp') or []) if isinstance(node, dict)
            )
            descs = cna.get('descriptions') or []
            desc = ''
            for d in descs:
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break
            if not desc and descs:
                desc = descs[0].get('value', '')

            vendors: list[str] = []
            products: list[str] = []
            versions: list[str] = []
            affected_entries: list[dict[str, Any]] = []
            cpes: list[str] = []
            for container_role, container in record_containers:
                provider = container.get('providerMetadata') or {}
                for a in container.get('affected') or []:
                    if not isinstance(a, dict):
                        continue
                    vendor = str(a.get('vendor', '') or '')
                    product = str(a.get('product', '') or '')
                    if vendor:
                        vendors.append(vendor)
                    if product:
                        products.append(product)
                    entry_versions = []
                    for v in a.get('versions') or []:
                        if not isinstance(v, dict):
                            continue
                        entry = {
                            'version': str(v.get('version', '') or ''),
                            'status': str(v.get('status', '') or ''),
                            'lessThan': str(v.get('lessThan', '') or ''),
                            'lessThanOrEqual': str(v.get('lessThanOrEqual', '') or ''),
                            'versionType': str(v.get('versionType', '') or ''),
                            'changes': [
                                {
                                    'at': str(change.get('at', '') or ''),
                                    'status': str(change.get('status', '') or ''),
                                }
                                for change in (v.get('changes') or [])
                                if isinstance(change, dict)
                            ],
                        }
                        entry_versions.append(entry)
                        for fld in ('version', 'lessThan', 'lessThanOrEqual'):
                            if entry.get(fld):
                                versions.append(entry[fld])
                    entry_cpes = []
                    for c in a.get('cpes') or []:
                        if isinstance(c, str):
                            cpes.append(c)
                            entry_cpes.append(c)
                    affected_entries.append({
                        'container_role': container_role,
                        'provider_org_id': str(provider.get('orgId', '') or ''),
                        'provider_short_name': str(provider.get('shortName', '') or ''),
                        'vendor': vendor,
                        'product': product,
                        'collectionURL': str(a.get('collectionURL', '') or ''),
                        'packageName': str(a.get('packageName', '') or ''),
                        'repo': str(a.get('repo', '') or ''),
                        'defaultStatus': str(a.get('defaultStatus', '') or ''),
                        'versions': entry_versions,
                        'cpes': entry_cpes,
                        'platforms': [str(x) for x in (a.get('platforms') or []) if x],
                        'modules': [str(x) for x in (a.get('modules') or []) if x],
                        'programFiles': [str(x) for x in (a.get('programFiles') or []) if x],
                        'programRoutines': [x for x in (a.get('programRoutines') or []) if isinstance(x, (str, dict))],
                    })

            refs = []
            for _container_role, container in record_containers:
                for r in container.get('references') or []:
                    if not isinstance(r, dict):
                        continue
                    url = r.get('url')
                    if url:
                        refs.append(url)
            metrics = _extract_metrics(data)
            record_url = f'https://www.cve.org/CVERecord?id={cve_id}'
            record_updated = str(data.get('cveMetadata', {}).get('dateUpdated') or '')
            for metric in metrics.values():
                metric['cvss_record_url'] = record_url
                metric['cvss_record_last_modified'] = record_updated
            if metrics:
                cvss_count += 1
                for version in metrics:
                    if version in cvss_count_by_version:
                        cvss_count_by_version[version] += 1

            row = {
                'index_schema_version': 4,
                'state': str(data.get('cveMetadata', {}).get('state') or ''),
                'cve_id': cve_id,
                'description': desc,
                'affected_vendors': sorted(set(vendors)),
                'affected_products': sorted(set(products)),
                'affected_versions': sorted(set(versions)),
                'affected_entries': affected_entries,
                'cpes': sorted(set(cpes)),
                'references': list(dict.fromkeys(refs))[:10],
                'source': OFFICIAL_CVE_SOURCE,
                'cvss_metrics': metrics,
            }
            encoded = json.dumps(row, ensure_ascii=False)
            out.write(encoded + '\n')
            identity_keys = set()
            for affected_entry in affected_entries:
                identity_keys.update(affected_identity_keys(affected_entry))
            for identity_key in identity_keys:
                database.execute('INSERT INTO affected_identities VALUES (?, ?, ?)', (cve_id, identity_key, encoded))
            count += 1
    if count <= 0:
        database.close()
        temp_index.unlink(missing_ok=True)
        temp_sqlite.unlink(missing_ok=True)
        raise RuntimeError('Official CVE repository contained no indexable CVE records.')
    database.execute('CREATE INDEX affected_identity_key_idx ON affected_identities(identity_key)')
    database.execute('CREATE INDEX affected_identity_cve_idx ON affected_identities(cve_id)')
    database.commit()
    database.close()
    temp_index.replace(INDEX)
    temp_sqlite.replace(SQLITE_INDEX)
    return {'records_indexed': count, 'records_with_cvss_metadata': cvss_count, 'records_with_cvss_metadata_by_version': cvss_count_by_version, 'index_file': str(INDEX), 'sqlite_index': str(SQLITE_INDEX)}
