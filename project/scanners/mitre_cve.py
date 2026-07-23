
from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .scoring_policy import (
    ScoringPolicyError,
    metric_keys_by_version,
    normalise_cvss_version,
    validate_published_metric,
)
from .nvd_repository import (
    NVD_SOURCE,
    cpe_attributes,
    concrete_cpe23,
    evaluate_configurations,
    query_vulnerable_cpe,
)

BASE = Path('storage/mitre_cve')
REPO_DIR = BASE / 'cvelistV5'
INDEX = BASE / 'official_mitre_cve_index.jsonl'
OFFICIAL_CVE_REPO = 'https://github.com/CVEProject/cvelistV5.git'
OFFICIAL_CVE_SOURCE = 'Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)'
# Production applicability is data-driven. Product identity comes only from
# the observed fingerprint/CPE and machine-readable CVE List or NVD fields.
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
                    if '"index_schema_version": 2' in line:
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
    stale_cvss = INDEX.exists() and records > 0 and cvss_records == 0
    return {
        'source': OFFICIAL_CVE_SOURCE,
        # Runtime applicability uses the NVD CVE API and does not depend on a
        # complete local CVE List mirror. The index remains optional metadata.
        'available': True,
        'matcher_status': 'available',
        'status_error': status_error,
        'records_indexed': records,
        'cvss_selection_ready': records > 0 and selection_schema_records == records,
        'cvss_selection_schema_records': selection_schema_records,
        'records_with_cvss_metadata': cvss_records,
        'records_with_cvss_metadata_by_version': cvss_records_by_version,
        'cvss_metadata_stale': stale_cvss,
        'cvss_metadata_warning': 'CVE index is available, but CVSS metadata is missing. Run: python scripts/rebuild_mitre_cve_index.py' if stale_cvss else '',
        'rebuild_command': 'python scripts/rebuild_mitre_cve_index.py',
        'index_file': str(INDEX),
        'repo_dir': str(REPO_DIR),
        'matching_policy': 'Concrete observed CPE 2.3 Name queried through the official NVD CVE API using cpeName and isVulnerable, followed by NVD configuration-node evaluation. Product text, CVE descriptions, fuzzy names, aliases, confidence thresholds and CVE List affected-version guesses cannot emit candidates.',
        'applicability_source': NVD_SOURCE,
    }


def _sort_key(row: dict[str, Any]) -> tuple[int, str]:
    # Not a report ranking; just stable grouping by availability of source metadata.
    score = row.get('cvss_score')
    return (0 if score is not None else 1, str(row.get('cve_id') or ''))


def _observed_cpe_values(value: str) -> list[str]:
    """Preserve escaped whitespace inside formatted CPE attribute values."""
    return [item.strip() for item in re.split(r'[\r\n,]+', str(value or '')) if item.strip()]


def _nvd_candidates(
    cpe: str,
    selected_version: str,
    observed_environment_cpes: tuple[str, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from .nvd_enrichment import _extract_nvd_metrics

    rows: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    for raw_cpe in _observed_cpe_values(cpe):
        primary_cpe = concrete_cpe23(raw_cpe)
        if not primary_cpe:
            if raw_cpe.strip():
                diagnostics.append({
                    'matcher_status': 'not_evaluated',
                    'reason': 'cpe_not_query_eligible',
                    'cpe': raw_cpe.strip(),
                    'detail': 'NVD cpeName matching requires concrete part, vendor, product and version attributes.',
                })
            continue
        records, query_status = query_vulnerable_cpe(primary_cpe)
        diagnostics.append({'matcher_status': query_status.get('status'), **query_status})
        for rec in records:
            cve_id = str(rec.get('cve_id') or '').upper()
            if not cve_id:
                continue
            applicability = evaluate_configurations(
                rec.get('configurations') or [],
                primary_cpe,
                observed_environment_cpes,
                primary_query_verified=bool(query_status.get('authoritative_query_verified')),
            )
            metrics = _extract_nvd_metrics({'id': cve_id, **rec})
            metric = metrics.get(selected_version) or {}
            cpe_parts = cpe_attributes(primary_cpe)
            candidate = {
                'cve_id': cve_id,
                'description': rec.get('description') or '',
                'references': rec.get('references') or [],
                'source': OFFICIAL_CVE_SOURCE,
                'cvss_score': metric.get('cvss_score'),
                'cvss_severity': metric.get('cvss_severity') or '',
                'cvss_vector': metric.get('cvss_vector') or '',
                'cvss_source': metric.get('cvss_source') or '',
                'cvss_version': selected_version,
                'cvss_score_type': 'Base',
                'cvss_nomenclature': 'CVSS-B' if selected_version == '4.0' else 'CVSS Base',
                'cvss_provider_role': metric.get('cvss_provider_role') or '',
                'cvss_enrichment_source': metric.get('cvss_enrichment_source') or NVD_SOURCE,
                'cvss_record_url': metric.get('cvss_record_url') or f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'cvss_record_last_modified': metric.get('cvss_record_last_modified') or rec.get('last_modified') or '',
                'cvss_status': 'published' if metric.get('cvss_score') is not None else 'not_provided_for_selected_version',
                'cvss_available_versions': sorted(metrics),
                'matched_product_tokens': [primary_cpe],
                'matched_version_tokens': [cpe_parts[3]] if cpe_parts else [],
                'match_basis': applicability.get('basis'),
                'product_match_basis': 'nvd_cpe_name_is_vulnerable_query',
                'applicability_decision': applicability.get('decision'),
                'applicability_source': NVD_SOURCE,
                'applicability_record_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'required_conditions': applicability.get('required_conditions') or [],
                'contradictions': applicability.get('contradictions') or [],
                'configuration_truth': applicability.get('configuration_truth') or 'unknown',
                'official_description_source': NVD_SOURCE,
                'detection_status': 'not_tested',
                'applicability_only': True,
            }
            existing = rows.get(cve_id)
            if existing:
                precedence = {'rejected': 0, 'needs_context': 1, 'potentially_affected': 2}
                existing_decision = str(existing.get('applicability_decision') or 'needs_context')
                candidate_decision = str(candidate.get('applicability_decision') or 'needs_context')
                selected = candidate if precedence.get(candidate_decision, 1) > precedence.get(existing_decision, 1) else existing
                other = existing if selected is candidate else candidate
                selected = dict(selected)
                selected['references'] = list(dict.fromkeys((selected.get('references') or []) + (other.get('references') or [])))
                selected['matched_product_tokens'] = list(dict.fromkeys((selected.get('matched_product_tokens') or []) + (other.get('matched_product_tokens') or [])))
                selected['matched_version_tokens'] = list(dict.fromkeys((selected.get('matched_version_tokens') or []) + (other.get('matched_version_tokens') or [])))
                selected['required_conditions'] = sorted(set((selected.get('required_conditions') or []) + (other.get('required_conditions') or [])))
                selected['contradictions'] = sorted(set((selected.get('contradictions') or []) + (other.get('contradictions') or [])))
                rows[cve_id] = selected
            else:
                rows[cve_id] = candidate
    return list(rows.values()), diagnostics


def search(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    cvss_version: str | None = None,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
    observed_environment_cpes: tuple[str, ...] = (),
) -> tuple[dict[str, Any], ...]:
    confirmed, _ = search_with_held(
        product,
        version,
        service,
        cpe,
        cvss_version=cvss_version,
        confidence_score=confidence_score,
        recommended_for_cve=recommended_for_cve,
        observed_environment_cpes=observed_environment_cpes,
    )
    return tuple(confirmed)


def search_with_held(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    cvss_version: str | None = None,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
    observed_environment_cpes: tuple[str, ...] = (),
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Return only NVD CPE applicability results for concrete observed CPEs.

    Product, version and service strings are retained in the signature for
    caller compatibility, but cannot create CVE candidates. The former private
    numeric fingerprint gate is intentionally ignored: CPE query eligibility
    is now determined solely by the documented NVD ``cpeName`` requirements.
    """
    selected_version = normalise_cvss_version(cvss_version)
    nvd_rows, nvd_diagnostics = _nvd_candidates(
        cpe,
        selected_version,
        observed_environment_cpes,
    )
    if not any(concrete_cpe23(value) for value in _observed_cpe_values(cpe)):
        nvd_diagnostics.insert(0, {
            'reason': 'concrete_cpe_required',
            'matcher_status': 'not_evaluated',
            'detail': 'No CVE candidate was generated from product text, version text, service name or confidence score.',
        })
    return tuple(copy.deepcopy(sorted(nvd_rows, key=_sort_key))), tuple(copy.deepcopy(nvd_diagnostics))


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
    with temp_index.open('w', encoding='utf-8') as out:
        for path in REPO_DIR.rglob('CVE-*.json'):
            try:
                data = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            cve_id = data.get('cveMetadata', {}).get('cveId') or path.stem
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            record_containers = [cna]
            record_containers.extend(
                node for node in (containers.get('adp') or []) if isinstance(node, dict)
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
            for container in record_containers:
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
                    affected_entries.append({'vendor': vendor, 'product': product, 'versions': entry_versions, 'cpes': entry_cpes})

            refs = []
            for container in record_containers:
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
                'index_schema_version': 2,
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
            out.write(json.dumps(row, ensure_ascii=False) + '\n')
            count += 1
    if count <= 0:
        temp_index.unlink(missing_ok=True)
        raise RuntimeError('Official CVE repository contained no indexable CVE records.')
    temp_index.replace(INDEX)
    return {'records_indexed': count, 'records_with_cvss_metadata': cvss_count, 'records_with_cvss_metadata_by_version': cvss_count_by_version, 'index_file': str(INDEX)}
