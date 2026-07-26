
from __future__ import annotations

import copy
import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import nvd_client
from .scoring_policy import ScoringPolicyError, validate_published_metric

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE = PROJECT_ROOT / 'storage' / 'mitre_cve'
REPO_DIR = BASE / 'cvelistV5'
INDEX = BASE / 'official_mitre_cve_index.jsonl'
OFFICIAL_CVE_REPO = 'https://github.com/CVEProject/cvelistV5.git'
OFFICIAL_CVE_SOURCE = 'Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)'
MIN_FINGERPRINT_CONFIDENCE = 0.7


# v32-from-v31 principle: official CVE candidates only; report layer decides strict vs relevant information.
# The matcher does NOT use broad record-text search as proof. A visible CVE row
# needs exact CPE evidence, exact product identity plus exact observed version,
# or a clearly bounded affected-version range for the same product family.

def _load_product_alias_registry() -> dict[str, dict[str, Any]]:
    candidates = [Path('project/policies/product_alias_registry.json'), Path('policies/product_alias_registry.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        raise RuntimeError('Product alias registry missing; CVE matching cannot safely infer product families.')
    data = json.loads(path.read_text(encoding='utf-8'))
    out: dict[str, dict[str, Any]] = {}
    for key, spec in data.items():
        out[key] = {
            'detect': list(spec.get('detect') or []),
            'affected_products': set(spec.get('affected_products') or []),
            'desc_phrases': list(spec.get('desc_phrases') or []),
            'blocked': set(spec.get('blocked') or []),
        }
    return out

PRODUCTS: dict[str, dict[str, Any]] = _load_product_alias_registry()

GENERIC_TOKENS = {
    'linux','debian','ubuntu','windows','microsoft','server','daemon','service','protocol','tcp','udp',
    'ssl','tls','http','https','ssh','ftp','smtp','smtpd','dns','domain','netbios','rpcbind','unknown',
    'openbsd','solaris','gnu','classpath','root','shell','db','database','telnet','telnetd','vnc','rmi',
    'ruby','apache','samba','smb','mysql','postgres','postgresql','bind','isc'
}


def status() -> dict[str, Any]:
    records = 0
    cvss_records = 0
    by_version = {'3.1': 0, '4.0': 0}
    status_error = ''
    if INDEX.exists():
        try:
            with INDEX.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    records += 1
                    try:
                        record = json.loads(line)
                    except Exception:
                        continue
                    metrics = record.get('cvss_metrics') or {}
                    present = False
                    for version in ('3.1', '4.0'):
                        metric = metrics.get(version) if isinstance(metrics, dict) else None
                        if isinstance(metric, dict) and metric.get('cvss_score') is not None:
                            by_version[version] += 1
                            present = True
                    if present:
                        cvss_records += 1
        except Exception as exc:
            records = 0
            cvss_records = 0
            by_version = {'3.1': 0, '4.0': 0}
            status_error = f'{type(exc).__name__}: {exc}'
    stale_cvss = INDEX.exists() and records > 0 and cvss_records == 0
    nvd = nvd_client.status()
    local_available = INDEX.exists() and records > 0
    return {
        'source': OFFICIAL_CVE_SOURCE,
        'source_mode': 'local_index' if local_available else ('targeted_nvd_api' if nvd.get('enabled') else 'unavailable'),
        'available': local_available or bool(nvd.get('enabled')),
        'local_index_available': local_available,
        'nvd_enrichment': nvd,
        'attribution': nvd.get('attribution', ''),
        'matcher_status': 'error' if status_error else ('available' if (local_available or nvd.get('enabled')) else 'unavailable'),
        'status_error': status_error,
        'records_indexed': records,
        'records_with_cvss_metadata': cvss_records,
        'records_with_cvss_metadata_by_version': by_version,
        'cvss_metadata_stale': stale_cvss,
        'cvss_metadata_warning': 'CVE catalogue is available, but no CVSS 3.1/4.0 metadata is present. Rebuild the CVE catalogue.' if stale_cvss else '',
        'index_file': str(INDEX),
        'repo_dir': str(REPO_DIR),
        'minimum_fingerprint_confidence': MIN_FINGERPRINT_CONFIDENCE,
    }


def _norm(s: str) -> str:
    return re.sub(r'\s+', ' ', (s or '').replace('_', ' ').replace('-', ' ')).strip().lower()


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r'[^a-zA-Z0-9._+-]+', (s or '').lower()) if t}


def _first_version(s: str) -> str:
    if not s:
        return ''
    m = re.search(r'\d+(?:\.\d+){1,4}(?:[a-z]+\d*)?', s.lower())
    return m.group(0) if m else ''


def _version_tuple(s: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r'\d+', (s or ''))]
    return tuple(nums[:4])


def _cmp_tuple(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    ln = max(len(a), len(b))
    aa = a + (0,) * (ln - len(a))
    bb = b + (0,) * (ln - len(b))
    return (aa > bb) - (aa < bb)


def _version_le(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return bool(a and b) and _cmp_tuple(a, b) <= 0


def _version_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return bool(a and b) and _cmp_tuple(a, b) < 0


def _version_ge(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return bool(a and b) and _cmp_tuple(a, b) >= 0


def _same_major(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return bool(a and b) and a[0] == b[0]


def _same_major_minor(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    if not a or not b:
        return False
    if len(a) >= 2 and len(b) >= 2:
        return a[0] == b[0] and a[1] == b[1]
    return a[0] == b[0]


def _major_minor(s: str) -> str:
    nums = re.findall(r'\d+', s or '')
    return '.'.join(nums[:2]) if len(nums) >= 2 else (nums[0] if nums else '')


_WINDOWS_EDITION_VERSIONS: list[tuple[str, str]] = [
    ('windows server 2022', '10.0'),
    ('windows server 2019', '10.0'),
    ('windows server 2016', '10.0'),
    ('windows server 2012', '6.2'),
    ('windows server 2008', '6.0'),
    ('windows server 2003', '5.2'),
    ('windows 11', '10.0'),
    ('windows 10', '10.0'),
    ('windows 8.1', '6.3'),
    ('windows 8', '6.2'),
    ('windows 7', '6.1'),
    ('windows xp', '5.1'),
    ('windows vista', '6.0'),
    ('windows 2000', '5.0'),
]


def _derive_os_version(product: str, service: str, cpe: str) -> str:
    """Infer a numeric OS version when a scanner banner omits one."""
    text = _norm(' '.join([product or '', service or '', cpe or '']))
    for edition, version in _WINDOWS_EDITION_VERSIONS:
        if edition in text:
            return version
    # CPE fallback for windows_xp, windows_7, etc.
    for raw_cpe in re.split(r'[\s,]+', cpe or ''):
        parts = _cpe_parts(raw_cpe)
        if not parts:
            continue
        _part, vendor, cpe_product, cpe_version = parts
        if vendor != 'microsoft' or 'windows' not in cpe_product:
            continue
        if cpe_version not in {'', '*', '-'}:
            return cpe_version
        cpe_product_norm = cpe_product.replace('_', ' ')
        for edition, version in _WINDOWS_EDITION_VERSIONS:
            if edition in cpe_product_norm:
                return version
    return ''


def _application_cpe_values(cpe: str) -> list[str]:
    """Return only application CPEs (part ``a``) from a mixed CPE string.

    Nmap can attach operating-system CPEs to a service element.  Those describe
    the host environment, not the application listening on that port, and must
    never be allowed to become the service product identity.
    """
    out: list[str] = []
    for raw in re.split(r'[\s,]+', cpe or ''):
        value = raw.strip()
        low = value.lower()
        if low.startswith('cpe:/a:') or low.startswith('cpe:2.3:a:'):
            out.append(value)
    return out


def _concrete_application_cpe_version(cpe: str) -> str:
    versions: set[str] = set()
    for raw in _application_cpe_values(cpe):
        parts = _cpe_parts(raw)
        if not parts:
            continue
        version = str(parts[3] or '').strip()
        if version not in {'', '*', '-'}:
            versions.add(version)
    return next(iter(versions)) if len(versions) == 1 else ''


def _identity(product: str, service: str, cpe: str) -> tuple[str | None, dict[str, Any]]:
    app_cpes = _application_cpe_values(cpe)
    text = _norm(' '.join([product or '', service or '', ' '.join(app_cpes)]))
    for key, spec in PRODUCTS.items():
        for pat in spec['detect']:
            if re.search(pat, text, flags=re.I):
                return key, spec

    # Dynamic identities are derived only from an observed product name or an
    # application CPE.  A port name alone and OS/hardware CPEs are insufficient.
    names: set[str] = set()
    product_name = _norm(product)
    meaningful = {token for token in _tokens(product_name) if token not in GENERIC_TOKENS and not token.isdigit()}
    if product_name and meaningful:
        names.add(product_name)
    for raw_cpe in app_cpes:
        parts = _cpe_parts(raw_cpe)
        if not parts:
            continue
        _part, vendor, cpe_product, _version = parts
        cpe_name = _norm(cpe_product)
        if cpe_name and {token for token in _tokens(cpe_name) if token not in GENERIC_TOKENS and not token.isdigit()}:
            names.add(cpe_name)
            if vendor not in {'', '*', '-'}:
                names.add(_norm(f'{vendor} {cpe_product}'))
    if not names:
        return None, {}
    identity = sorted(names, key=lambda value: (-len(value), value))[0]
    return identity, {
        'detect': [],
        'affected_products': names,
        'desc_phrases': [],
        'blocked': set(),
        'dynamic_exact_identity': True,
    }


def _affected_entries(rec: dict[str, Any]) -> list[dict[str, Any]]:
    entries = rec.get('affected_entries')
    if isinstance(entries, list):
        return entries
    # Compatibility for older locally-built index rows.  New indexes always
    # preserve the full affected-entry structure including defaultStatus and
    # changes.
    products = rec.get('affected_products') or []
    versions = rec.get('affected_versions') or []
    vendors = rec.get('affected_vendors') or []
    if products or versions or vendors:
        return [{
            'vendor': ' '.join(map(str, vendors)),
            'product': ' '.join(map(str, products)),
            'defaultStatus': 'unknown',
            'versions': [{'version': str(v), 'status': 'affected'} for v in versions],
            'cpes': rec.get('cpes') or [],
        }]
    return []


def _record_text(rec: dict[str, Any]) -> str:
    vals = [rec.get('description', '')]
    vals.extend(rec.get('affected_products') or [])
    vals.extend(rec.get('affected_vendors') or [])
    vals.extend(rec.get('affected_versions') or [])
    for ent in _affected_entries(rec):
        vals.append(str(ent.get('vendor', '')))
        vals.append(str(ent.get('product', '')))
    return _norm(' '.join(map(str, vals)))


def _product_name_matches(name: str, allowed: set[str]) -> bool:
    n = _norm(name)
    if not n or n in {'n/a', 'na', 'unknown', '*'}:
        return False
    return any(n == _norm(a) for a in allowed if _norm(a))


def _product_ok_for_record(rec: dict[str, Any], spec: dict[str, Any]) -> tuple[bool, list[str], str]:
    """Match only structured CVE affected-product fields.

    Description prose is useful to a human but is not an applicability field;
    it must never manufacture a product match.
    """
    allowed = {_norm(x) for x in spec.get('affected_products', set()) if _norm(x)}
    matched: list[str] = []
    for ent in _affected_entries(rec):
        vendor = _norm(str(ent.get('vendor', '')))
        product = _norm(str(ent.get('product', '')))
        for name in (product, f'{vendor} {product}'.strip()):
            if _product_name_matches(name, allowed):
                matched.append(name)
    if matched:
        return True, sorted(set(matched)), 'structured_affected_product'
    return False, [], 'no_structured_affected_product_match'


def _entry_matches_product(ent: dict[str, Any], prod_hits: list[str]) -> bool:
    if not prod_hits:
        return False
    ent_prod = _norm(str(ent.get('product', '')))
    ent_vendor = _norm(str(ent.get('vendor', '')))
    ent_names = {ent_prod, f'{ent_vendor} {ent_prod}'.strip()}
    return any(_norm(hit) in ent_names for hit in prod_hits if _norm(hit))


def _is_observed_version_range(value: str) -> bool:
    text = str(value or '').strip()
    # Nmap commonly emits values such as "8.3.0 - 8.3.7".  A range is not a
    # concrete target version, so it cannot support target-specific CVE
    # applicability without further fingerprinting.
    return bool(re.search(r'\d+(?:\.\d+){1,4}[A-Za-z0-9._]*\s+(?:-|to|through|thru)\s+\d+(?:\.\d+){1,4}', text, re.I))


def _version_cmp_supported(version_type: str) -> bool:
    # Only use ordering when the CVE record declares comparison semantics that
    # this scanner can implement faithfully.  The CVE schema explicitly says
    # "custom" is unspecified, so custom ranges are not numerically guessed.
    return _norm(version_type) in {'semver', 'python'}


def _normalise_semver(value: str) -> str:
    value = str(value or '').strip()
    if value.startswith(('v', 'V')):
        value = value[1:]
    # CVE records conventionally use 0 as an earliest-version marker.
    if re.fullmatch(r'\d+', value):
        return f'{value}.0.0'
    if re.fullmatch(r'\d+\.\d+', value):
        return f'{value}.0'
    return value


def _compare_declared_versions(left: str, right: str, version_type: str) -> int | None:
    vt = _norm(version_type)
    try:
        if vt == 'semver':
            import semver  # type: ignore
            a = semver.Version.parse(_normalise_semver(left))
            b = semver.Version.parse(_normalise_semver(right))
            return (a > b) - (a < b)
        if vt == 'python':
            from packaging.version import Version  # type: ignore
            a = Version(left)
            b = Version(right)
            return (a > b) - (a < b)
    except Exception:
        return None
    return None


def _point_in_rule(obs_raw: str, rule: dict[str, Any]) -> tuple[bool, str]:
    """Apply the CVE Record Format affected-version algorithm.

    Exact version statements are safe for every version type.  Ordered ranges
    are evaluated only for explicitly supported version schemes.  Ambiguous
    ``custom`` ranges are held rather than silently imposing numeric ordering.
    """
    base = str(rule.get('version', '') or '').strip()
    lt = str(rule.get('lessThan', '') or '').strip()
    lte = str(rule.get('lessThanOrEqual', '') or '').strip()
    version_type = str(rule.get('versionType', '') or '').strip()

    if not lt and not lte:
        if base.lower() in {'*', 'all', 'any'}:
            # The CVE Record Format exact-version algorithm is equality.  It does
            # not define an unbounded wildcard interpretation for the `version`
            # field.  A CNA can express an all-version condition with
            # defaultStatus=affected; do not invent wildcard semantics here.
            return False, 'ambiguous_wildcard_single_version'
        return (_first_version(base) == obs_raw and bool(obs_raw), 'structured_exact_version')

    # Equality at an explicitly named endpoint can be decided without inventing
    # an ordering for an unknown/custom version scheme.
    if base not in {'', '*'} and _first_version(base) == obs_raw:
        return True, 'structured_range_lower_endpoint'
    if lte and _first_version(lte) == obs_raw:
        return True, 'structured_range_inclusive_upper_endpoint'

    if not _version_cmp_supported(version_type):
        return False, f'unsupported_or_custom_version_range:{version_type or "unspecified"}'
    if '*' in base or '*' in lt or '*' in lte:
        return False, 'wildcard_range_requires_version_scheme_specific_expansion'

    upper_raw = lte or lt
    upper_cmp = _compare_declared_versions(obs_raw, _first_version(upper_raw), version_type)
    if upper_cmp is None:
        return False, 'affected_upper_bound_unparseable'

    if base in {'', '0'}:
        lower_ok = True
    else:
        lower_cmp = _compare_declared_versions(obs_raw, _first_version(base), version_type)
        if lower_cmp is None:
            return False, 'affected_lower_bound_unparseable'
        lower_ok = lower_cmp >= 0

    upper_ok = upper_cmp <= 0 if lte else upper_cmp < 0
    return lower_ok and upper_ok, f'structured_affected_range:{_norm(version_type)}'


def _status_after_changes(rule: dict[str, Any], obs_raw: str, initial: str) -> str:
    changes = [c for c in (rule.get('changes') or []) if isinstance(c, dict)]
    version_type = str(rule.get('versionType', '') or '').strip()
    if not changes:
        return initial
    # Changes are range ordering statements and therefore require the same
    # declared, supported comparison semantics as the parent range.
    if not _version_cmp_supported(version_type):
        return initial
    applicable: list[tuple[str, str]] = []
    for change in changes:
        at = _first_version(str(change.get('at', '') or ''))
        status = str(change.get('status', '') or '').lower()
        cmp_result = _compare_declared_versions(obs_raw, at, version_type) if at else None
        if cmp_result is not None and cmp_result >= 0 and status:
            applicable.append((at, status))
    if not applicable:
        return initial
    # Pick the greatest change point <= the observed version without relying on
    # lexical ordering.
    best_at, best_status = applicable[0]
    for at, status in applicable[1:]:
        cmp_result = _compare_declared_versions(at, best_at, version_type)
        if cmp_result is not None and cmp_result > 0:
            best_at, best_status = at, status
    return best_status


def _entry_version_match(entry: dict[str, Any], observed_version: str) -> tuple[bool, str, str]:
    if _is_observed_version_range(observed_version):
        return False, '', 'observed_version_is_range'
    obs_raw = _first_version(observed_version)
    if not obs_raw:
        return False, '', 'observed_version_missing'

    for rule in entry.get('versions') or []:
        if not isinstance(rule, dict):
            continue
        contains, basis = _point_in_rule(obs_raw, rule)
        if not contains:
            continue
        status = str(rule.get('status', '') or 'unknown').lower()
        status = _status_after_changes(rule, obs_raw, status)
        if status == 'affected':
            return True, obs_raw, f'{basis}:status=affected'
        # Explicit unaffected or unknown status is authoritative and must not be
        # promoted to affected.
        return False, '', f'{basis}:status={status or "unknown"}'

    default_status = str(entry.get('defaultStatus', '') or 'unknown').lower()
    if default_status == 'affected':
        return True, obs_raw, 'structured_default_status_affected'
    return False, '', f'default_status={default_status or "unknown"}'

def _text_version_match(rec: dict[str, Any], observed_version: str) -> tuple[bool, str, str]:
    obs_raw = _first_version(observed_version)
    obs_tuple = _version_tuple(obs_raw)
    if not obs_raw or not obs_tuple:
        return False, '', 'observed_version_missing'
    text = _record_text(rec)
    if re.search(rf'(?<![0-9A-Za-z.]){re.escape(obs_raw)}(?![0-9A-Za-z.])', text):
        return True, obs_raw, 'exact_observed_version_in_record_text'

    range_patterns = [
        r'(?P<lo>\d+(?:\.\d+){1,4}(?:rc\d+)?)\s*(?:through|thru|to|-)\s*(?P<hi>\d+(?:\.\d+){1,4}(?:rc\d+)?)',
        r'(?P<lo>\d+(?:\.\d+){1,4}(?:rc\d+)?)\s*(?:up to and including|up to|until)\s*(?P<hi>\d+(?:\.\d+){1,4}(?:rc\d+)?)',
        r'(?P<lo>\d+(?:\.\d+){1,4}(?:rc\d+)?)\s*(?:through|thru|to|-)\s*(?:before|prior to)\s*(?P<hi>\d+(?:\.\d+){1,4}(?:rc\d+)?)',
    ]
    for pat in range_patterns:
        for m in re.finditer(pat, text, flags=re.I):
            lo_raw = m.group('lo')
            hi_raw = m.group('hi')
            lo = _version_tuple(lo_raw)
            hi = _version_tuple(hi_raw)
            if lo and hi and _version_ge(obs_tuple, lo) and _version_le(obs_tuple, hi) and _same_major(obs_tuple, lo):
                return True, obs_raw, f'explicit_same_product_text_range:{lo_raw}..{hi_raw}'

    # "before X" only when the observed major.minor branch is explicitly named in the same text.
    obs_mm = _major_minor(obs_raw)
    if obs_mm:
        before_patterns = [
            rf'\b{re.escape(obs_mm)}(?:\.x)?\b[^.\n]{{0,80}}(?:before|prior to)\s*(?P<hi>\d+(?:\.\d+){{1,4}}(?:rc\d+)?)',
            rf'(?:before|prior to)\s*(?P<hi>\d+(?:\.\d+){{1,4}}(?:rc\d+)?)[^.\n]{{0,80}}\b{re.escape(obs_mm)}(?:\.x)?\b',
        ]
        for pat in before_patterns:
            for m in re.finditer(pat, text, flags=re.I):
                hi = _version_tuple(m.group('hi'))
                if hi and _version_lt(obs_tuple, hi):
                    return True, obs_raw, f'named_branch_before:{m.group("hi")}'
    return False, '', 'no exact text version/range match'


def _cpe_parts(value: str) -> tuple[str, str, str, str] | None:
    raw = str(value or '').strip().lower()
    if raw.startswith('cpe:2.3:'):
        parts = raw.split(':')
        if len(parts) >= 6:
            return parts[2], parts[3], parts[4], parts[5]
    if raw.startswith('cpe:/'):
        parts = raw.split(':')
        if len(parts) >= 5:
            return parts[1].lstrip('/'), parts[2], parts[3], parts[4]
    return None


def _cpe_match(rec: dict[str, Any], observed_cpe: str) -> tuple[bool, str]:
    observed: list[tuple[str, tuple[str, str, str, str] | None]] = []
    for c in _application_cpe_values(observed_cpe):
        raw = c.strip().lower()
        parts = _cpe_parts(raw)
        if parts and parts[0] == 'a':
            observed.append((raw, parts))
    if not observed:
        return False, ''

    rec_cpes: list[tuple[str, tuple[str, str, str, str] | None]] = []
    for ent in _affected_entries(rec):
        for c in ent.get('cpes') or []:
            raw = str(c).strip().lower()
            parts = _cpe_parts(raw)
            if parts and parts[0] == 'a':
                rec_cpes.append((raw, parts))
    for observed_raw, observed_parts in observed:
        if not observed_parts:
            continue
        for record_raw, record_parts in rec_cpes:
            if not record_parts or observed_parts[:3] != record_parts[:3]:
                continue
            observed_version = observed_parts[3]
            record_version = record_parts[3]
            # Exact application CPE evidence is an identity/version match, but
            # still only establishes CVE applicability (Candidate), not target-
            # specific vulnerability confirmation.
            if observed_version not in {'', '*', '-'} and observed_version == record_version:
                return True, f'{observed_raw} == {record_raw}'
    return False, ''


def _entries_for_exact_application_cpe(rec: dict[str, Any], observed_cpe: str) -> list[dict[str, Any]]:
    """Return affected entries containing the same concrete application CPE."""
    observed_parts = []
    for raw in _application_cpe_values(observed_cpe):
        parts = _cpe_parts(raw)
        if parts and parts[0] == 'a' and parts[3] not in {'', '*', '-'}:
            observed_parts.append(parts)
    if not observed_parts:
        return []
    matched: list[dict[str, Any]] = []
    for ent in _affected_entries(rec):
        for raw in ent.get('cpes') or []:
            parts = _cpe_parts(str(raw))
            if not parts or parts[0] != 'a':
                continue
            if any(obs[:3] == parts[:3] and obs[3] == parts[3] for obs in observed_parts):
                matched.append(ent)
                break
    return matched


def _metric_for_version(record: dict[str, Any], version: str) -> dict[str, Any]:
    metrics = record.get('cvss_metrics') or {}
    if not isinstance(metrics, dict):
        return {}
    metric = metrics.get(str(version))
    return dict(metric) if isinstance(metric, dict) else {}


def _preferred_metric(record: dict[str, Any]) -> dict[str, Any]:
    # Backward-compatible single-metric view for older consumers. The canonical
    # record always preserves both versions independently in ``cvss_metrics``.
    return _metric_for_version(record, '3.1') or _metric_for_version(record, '4.0')


def _sort_key(row: dict[str, Any]) -> tuple[int, float, str]:
    metrics = row.get('cvss_metrics') or {}
    scores = []
    if isinstance(metrics, dict):
        for version in ('3.1', '4.0'):
            metric = metrics.get(version) or {}
            try:
                scores.append(float(metric.get('cvss_score')))
            except (TypeError, ValueError):
                pass
    return (0 if scores else 1, -max(scores) if scores else 0.0, str(row.get('cve_id') or ''))


@lru_cache(maxsize=4096)
def _search_cached(product: str, version: str, service: str, cpe: str = '') -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not INDEX.exists():
        return tuple(), ({'reason': 'cve_index_unavailable', 'matcher_status': 'unavailable', 'index_file': str(INDEX)},)

    # Nmap can attach OS CPEs to a service node. Only application CPEs may
    # participate in application/service CVE identity matching.
    app_cpe_text = ' '.join(_application_cpe_values(cpe))
    ident, spec = _identity(product, service, app_cpe_text)
    if not ident:
        return tuple(), ({'reason': 'unsupported_product_identity', 'matcher_status': 'held'},)

    cpe_version = _concrete_application_cpe_version(app_cpe_text)
    effective_version = cpe_version or version
    if _is_observed_version_range(effective_version):
        return tuple(), ({
            'reason': 'observed_version_is_range',
            'matcher_status': 'held',
            'observed_version': effective_version,
        },)
    obs_version = _first_version(effective_version)
    if not obs_version:
        return tuple(), ({'reason': 'observed_version_missing', 'matcher_status': 'held'},)

    matches: list[dict[str, Any]] = []
    malformed_records = 0
    try:
        with INDEX.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    malformed_records += 1
                    continue
                if rec.get('source') != OFFICIAL_CVE_SOURCE:
                    continue
                if str(rec.get('record_state') or 'PUBLISHED').upper() != 'PUBLISHED':
                    continue

                product_ok, product_hits, product_basis = _product_ok_for_record(rec, spec)
                cpe_ok, cpe_hit = _cpe_match(rec, app_cpe_text)
                if not (cpe_ok or product_ok):
                    continue

                candidate_entries = _entries_for_exact_application_cpe(rec, app_cpe_text) if cpe_ok else []
                if not candidate_entries:
                    candidate_entries = [
                        ent for ent in _affected_entries(rec)
                        if _entry_matches_product(ent, product_hits)
                    ]

                version_ok = False
                matched_version = obs_version
                basis = ''
                matched_entry: dict[str, Any] | None = None
                rejection_reasons: list[str] = []
                for ent in candidate_entries:
                    ok, token, why = _entry_version_match(ent, effective_version)
                    if ok:
                        version_ok = True
                        matched_version = token or obs_version
                        basis = f'exact_application_cpe:{cpe_hit};{why}' if cpe_ok else why
                        matched_entry = ent
                        break
                    if why:
                        rejection_reasons.append(why)

                # Do not fall back to description prose when structured affected
                # product/version data exists. Description text is explanatory,
                # not an applicability constraint.
                if not version_ok:
                    continue

                metrics = copy.deepcopy(rec.get('cvss_metrics') or {})
                preferred = _preferred_metric(rec)
                row = {
                    'cve_id': rec.get('cve_id'),
                    'description': rec.get('description'),
                    'references': rec.get('references') or [],
                    'source': rec.get('source'),
                    'cvss_metrics': metrics,
                    'cvss_score': preferred.get('cvss_score'),
                    'cvss_severity': preferred.get('cvss_severity'),
                    'cvss_vector': preferred.get('cvss_vector'),
                    'cvss_source': preferred.get('cvss_source'),
                    'cvss_version': preferred.get('cvss_version'),
                    'matched_product_tokens': product_hits or [ident],
                    'matched_version_tokens': [matched_version],
                    'match_basis': basis,
                    'product_match_basis': 'exact_application_cpe' if cpe_ok else product_basis,
                    'cve_publisher': rec.get('cve_publisher') or 'CVE Program CNA',
                    'cve_publisher_id': rec.get('cve_publisher_id') or '',
                    'affected_vendors': rec.get('affected_vendors') or [],
                    'affected_products': rec.get('affected_products') or [],
                    'affected_versions': rec.get('affected_versions') or [],
                    'affected_entries': rec.get('affected_entries') or [],
                    'affected_cpes': rec.get('cpes') or [],
                    'matched_affected_entry': copy.deepcopy(matched_entry) if matched_entry else {},
                }
                matches.append(row)
    except Exception as exc:
        return tuple(), ({
            'reason': 'cve_matcher_error',
            'matcher_status': 'error',
            'error_type': type(exc).__name__,
            'error': str(exc),
        },)

    dedup: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(matches, key=_sort_key):
        cve_id = str(row.get('cve_id') or '')
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            dedup.append(row)
    diagnostics: list[dict[str, Any]] = []
    if malformed_records:
        diagnostics.append({
            'reason': 'index_records_skipped',
            'matcher_status': 'degraded',
            'record_count': malformed_records,
        })
    return tuple(dedup), tuple(diagnostics)


def search(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
) -> tuple[dict[str, Any], ...]:
    confirmed, _ = search_with_held(
        product,
        version,
        service,
        cpe,
        confidence_score=confidence_score,
        recommended_for_cve=recommended_for_cve,
    )
    return tuple(confirmed)


def search_with_held(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Correlate observed identity against canonical CVE affected data.

    Fingerprint confidence is retained as diagnostic metadata only. It cannot
    manufacture or suppress an applicability result. Keyword-only NVD search is
    not used as a CVE candidate generator because it does not prove affected
    product/version applicability.
    """
    advisory: list[dict[str, Any]] = []
    if confidence_score is not None or recommended_for_cve is not None:
        try:
            score = float(confidence_score or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        if score < 0.70 or not bool(recommended_for_cve):
            advisory.append({
                'reason': 'fingerprint_confidence_advisory',
                'matcher_status': 'advisory',
                'confidence_score': round(score, 2),
                'recommended_for_cve': bool(recommended_for_cve),
                'effect': 'CVE applicability lookup was not suppressed',
            })

    if not INDEX.exists():
        return tuple(), tuple(advisory + [{
            'reason': 'canonical_cve_index_unavailable',
            'matcher_status': 'unavailable',
            'message': 'Canonical CVE applicability matching requires the synchronized CVE List index.',
        }])

    matched, diagnostics = _search_cached(product, version, service, cpe)
    return (
        tuple(copy.deepcopy(list(matched))),
        tuple(copy.deepcopy(advisory + list(diagnostics))),
    )

def _validated_metric(version: str, data: dict[str, Any], source: str, role: str) -> dict[str, Any]:
    score = data.get('baseScore')
    vector = data.get('vectorString') or ''
    severity = data.get('baseSeverity') or data.get('severity') or ''
    if score is None or not vector:
        return {}
    try:
        metric = validate_published_metric(version, score, severity, vector)
        metric['cvss_verified'] = True
        metric['cvss_verification'] = 'Vector recomputed; published score matches'
    except ScoringPolicyError as exc:
        # Preserve the publisher's data for auditability, but never claim that
        # an inconsistent vector/score pair was verified.
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            return {}
        metric = {
            'cvss_score': score_value,
            'cvss_severity': str(severity or '').upper(),
            'cvss_vector': str(vector),
            'cvss_version': version,
            'cvss_metric_integrity': 'published_source_inconsistent',
            'cvss_verified': False,
            'cvss_verification': f'Published metric could not be independently verified: {exc}',
        }
    metric['cvss_source'] = source
    metric['cvss_provider_role'] = role
    return metric


def _extract_metrics_from_node(node: Any, role: str = 'CNA') -> dict[str, dict[str, Any]]:
    if not isinstance(node, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    source = str((node.get('providerMetadata') or {}).get('orgId') or '')
    metrics = node.get('metrics') or []
    if not isinstance(metrics, list):
        return output
    key_map = {'cvssV3_1': '3.1', 'cvssV4_0': '4.0'}
    for candidate in metrics:
        if not isinstance(candidate, dict):
            continue
        metric_source = str(candidate.get('source') or source or '')
        for key, version in key_map.items():
            if version in output:
                continue
            data = candidate.get(key)
            if not isinstance(data, dict):
                continue
            metric = _validated_metric(version, data, metric_source, role)
            if metric:
                output[version] = metric
    return output


def _extract_metrics(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    containers = data.get('containers', {}) if isinstance(data, dict) else {}
    cna = containers.get('cna') or {}
    metrics = _extract_metrics_from_node(cna, 'CNA')
    # CNA is authoritative when it publishes a particular CVSS version. ADP
    # metrics may fill a version that the CNA did not publish, but never
    # overwrite a CNA metric for the same version.
    for adp in containers.get('adp') or []:
        for version, metric in _extract_metrics_from_node(adp, 'ADP').items():
            metrics.setdefault(version, metric)
    return metrics


def _extract_metric(data: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible preferred metric accessor (3.1, then 4.0)."""
    metrics = _extract_metrics(data)
    return dict(metrics.get('3.1') or metrics.get('4.0') or {})


def build_index() -> dict[str, Any]:
    BASE.mkdir(parents=True, exist_ok=True)
    if not REPO_DIR.exists():
        repo = OFFICIAL_CVE_REPO
        subprocess.run(['git', 'clone', '--depth', '1', repo, str(REPO_DIR)], check=True)
    else:
        subprocess.run(['git', '-C', str(REPO_DIR), 'pull', '--ff-only'], check=False)

    count = 0
    cvss_count = 0
    cvss_by_version = {'3.1': 0, '4.0': 0}
    with INDEX.open('w', encoding='utf-8') as out:
        for path in REPO_DIR.rglob('CVE-*.json'):
            try:
                data = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            metadata = data.get('cveMetadata', {}) or {}
            cve_id = metadata.get('cveId') or path.stem
            cna = data.get('containers', {}).get('cna', {})
            cna_provider = cna.get('providerMetadata') or {}
            cve_publisher = (
                cna_provider.get('shortName')
                or metadata.get('assignerShortName')
                or cna_provider.get('orgId')
                or metadata.get('assignerOrgId')
                or 'CVE Program CNA'
            )
            cve_publisher_id = (
                cna_provider.get('orgId')
                or metadata.get('assignerOrgId')
                or ''
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
            for a in cna.get('affected') or []:
                vendor = str(a.get('vendor', '') or '')
                product = str(a.get('product', '') or '')
                if vendor:
                    vendors.append(vendor)
                if product:
                    products.append(product)
                default_status = str(a.get('defaultStatus', '') or 'unknown').lower()
                entry_versions: list[dict[str, Any]] = []
                for v in a.get('versions') or []:
                    if not isinstance(v, dict):
                        continue
                    changes: list[dict[str, str]] = []
                    for change in v.get('changes') or []:
                        if isinstance(change, dict):
                            changes.append({
                                'at': str(change.get('at', '') or ''),
                                'status': str(change.get('status', '') or 'unknown').lower(),
                            })
                    entry = {
                        'version': str(v.get('version', '') or ''),
                        'status': str(v.get('status', '') or 'unknown').lower(),
                        'lessThan': str(v.get('lessThan', '') or ''),
                        'lessThanOrEqual': str(v.get('lessThanOrEqual', '') or ''),
                        'versionType': str(v.get('versionType', '') or ''),
                        'changes': changes,
                    }
                    entry_versions.append(entry)
                    for fld in ('version', 'lessThan', 'lessThanOrEqual'):
                        if entry.get(fld):
                            versions.append(str(entry[fld]))
                entry_cpes = []
                for c in a.get('cpes') or []:
                    if isinstance(c, str):
                        cpes.append(c)
                        entry_cpes.append(c)
                affected_entries.append({
                    'vendor': vendor,
                    'product': product,
                    'defaultStatus': default_status,
                    'versions': entry_versions,
                    'cpes': entry_cpes,
                    'platforms': [str(x) for x in (a.get('platforms') or [])],
                    'modules': [str(x) for x in (a.get('modules') or [])],
                    'packageName': str(a.get('packageName', '') or ''),
                    'collectionURL': str(a.get('collectionURL', '') or ''),
                })

            refs = []
            for r in cna.get('references') or []:
                url = r.get('url')
                if url:
                    refs.append(url)
            metrics = _extract_metrics(data)
            if metrics:
                cvss_count += 1
            for metric_version in ('3.1', '4.0'):
                if metric_version in metrics:
                    cvss_by_version[metric_version] += 1

            row = {
                'cve_id': cve_id,
                'description': desc,
                'affected_vendors': sorted(set(vendors)),
                'affected_products': sorted(set(products)),
                'affected_versions': sorted(set(versions)),
                'affected_entries': affected_entries,
                'cpes': sorted(set(cpes)),
                'references': refs[:10],
                'source': OFFICIAL_CVE_SOURCE,
                'cve_publisher': str(cve_publisher),
                'cve_publisher_id': str(cve_publisher_id),
                'record_state': str(metadata.get('state') or 'PUBLISHED'),
            }
            row['cvss_metrics'] = metrics
            preferred = metrics.get('3.1') or metrics.get('4.0') or {}
            row.update(preferred)
            out.write(json.dumps(row, ensure_ascii=False) + '\n')
            count += 1
    _search_cached.cache_clear()
    return {'records_indexed': count, 'records_with_cvss_metadata': cvss_count, 'records_with_cvss_metadata_by_version': cvss_by_version, 'index_file': str(INDEX)}
