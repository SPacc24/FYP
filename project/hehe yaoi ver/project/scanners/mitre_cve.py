
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

BASE = Path('storage/mitre_cve')
REPO_DIR = BASE / 'cvelistV5'
INDEX = BASE / 'official_mitre_cve_index.jsonl'
OFFICIAL_CVE_REPO = 'https://github.com/CVEProject/cvelistV5.git'
OFFICIAL_CVE_SOURCE = 'Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)'


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
    if INDEX.exists():
        try:
            with INDEX.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    records += 1
                    if 'cvss_score' in line:
                        cvss_records += 1
        except Exception:
            records = 0
            cvss_records = 0
    stale_cvss = INDEX.exists() and records > 0 and cvss_records == 0
    return {
        'source': OFFICIAL_CVE_SOURCE,
        'available': INDEX.exists() and records > 0,
        'records_indexed': records,
        'records_with_cvss_metadata': cvss_records,
        'cvss_metadata_stale': stale_cvss,
        'cvss_metadata_warning': 'CVE index is available, but CVSS metadata is missing. Run: python scripts/rebuild_mitre_cve_index.py' if stale_cvss else '',
        'rebuild_command': 'python scripts/rebuild_mitre_cve_index.py',
        'index_file': str(INDEX),
        'repo_dir': str(REPO_DIR),
        'matching_policy': 'v32_from_v31_mitre_only_candidates: official CVE List via CVEProject/cvelistV5 only; candidate records are further classified by the report as strict CVE matches or relevant version/exposure information based on exact version/CPE and context evidence',
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


def _identity(product: str, service: str, cpe: str) -> tuple[str | None, dict[str, Any]]:
    text = _norm(' '.join([product or '', service or '', cpe or '']))
    for key, spec in PRODUCTS.items():
        for pat in spec['detect']:
            if re.search(pat, text, flags=re.I):
                return key, spec
    return None, {}


def _affected_entries(rec: dict[str, Any]) -> list[dict[str, Any]]:
    entries = rec.get('affected_entries')
    if isinstance(entries, list):
        return entries
    products = rec.get('affected_products') or []
    versions = rec.get('affected_versions') or []
    vendors = rec.get('affected_vendors') or []
    if products or versions or vendors:
        return [{
            'vendor': ' '.join(map(str, vendors)),
            'product': ' '.join(map(str, products)),
            'versions': [{'version': str(v), 'status': 'affected'} for v in versions],
            'cpes': rec.get('cpes') or []
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
    for a in allowed:
        a = _norm(a)
        if n == a:
            return True
        # Allow full product phrase containment, but not generic one-word containment.
        if ' ' in a and re.search(rf'\b{re.escape(a)}\b', n):
            return True
    return False


def _product_ok_for_record(rec: dict[str, Any], spec: dict[str, Any]) -> tuple[bool, list[str], str]:
    text = _record_text(rec)
    toks = _tokens(text)
    blocked = {b for b in spec.get('blocked', set()) if b in text or b in toks}
    if blocked:
        return False, [], f'different product family token present: {sorted(blocked)}'

    allowed = {_norm(x) for x in spec.get('affected_products', set())}
    matched = []
    entries = _affected_entries(rec)
    for ent in entries:
        vendor = _norm(str(ent.get('vendor', '')))
        product = _norm(str(ent.get('product', '')))
        names = [product, f'{vendor} {product}'.strip()]
        for name in names:
            if _product_name_matches(name, allowed):
                matched.append(name)
    if matched:
        return True, sorted(set(matched)), 'affected_product_field'

    # Only fall back to description phrases when the record lacks usable structured affected product names.
    has_real_product = any(_norm(str(ent.get('product', ''))) not in {'', 'n/a', 'na', 'unknown', '*'} for ent in entries)
    if not has_real_product:
        for pat in spec.get('desc_phrases', []):
            if re.search(pat, text, flags=re.I):
                label = re.sub(r'\\b|\\s\+|\\s\*', ' ', pat).strip('^$ ')
                return True, [label or 'description_phrase'], 'description_full_product_phrase_no_structured_product'
    return False, [], 'no exact affected product identity'


def _entry_matches_product(ent: dict[str, Any], prod_hits: list[str]) -> bool:
    if not prod_hits:
        return True
    ent_prod = _norm(str(ent.get('product', '')))
    ent_vendor = _norm(str(ent.get('vendor', '')))
    ent_names = {ent_prod, f'{ent_vendor} {ent_prod}'.strip()}
    for hit in prod_hits:
        h = _norm(hit)
        if h in ent_names:
            return True
        if any(h and name and (h in name or name in h) for name in ent_names):
            return True
    return False


def _entry_version_match(entry: dict[str, Any], observed_version: str) -> tuple[bool, str, str]:
    obs_raw = _first_version(observed_version)
    obs_tuple = _version_tuple(obs_raw)
    if not obs_tuple:
        return False, '', 'observed_version_missing'
    obs_mm = _major_minor(obs_raw)
    versions = entry.get('versions') or []
    for v in versions:
        if not isinstance(v, dict):
            continue
        status = str(v.get('status', '')).lower()
        if status and status not in {'affected', 'unknown'}:
            continue
        base = str(v.get('version', '') or '')
        lt = str(v.get('lessThan', '') or '')
        lte = str(v.get('lessThanOrEqual', '') or '')
        entry_text = _norm(' '.join(str(x) for x in [base, lt, lte, v.get('versionType', '')]))

        for field in [base, lt, lte]:
            if field and _first_version(field) and _first_version(field) == obs_raw:
                return True, obs_raw, 'exact_structured_version'

        lower = _version_tuple(base)
        upper = _version_tuple(lte or lt)
        inclusive = bool(lte)
        if lower and upper:
            upper_ok = _version_le(obs_tuple, upper) if inclusive else _version_lt(obs_tuple, upper)
            if _version_ge(obs_tuple, lower) and upper_ok and _same_major(obs_tuple, lower):
                return True, obs_raw, f'structured_same_product_range:{base}..{lte or lt}'

        # Single upper-bound ranges are allowed only when the observed branch is explicitly named.
        if upper and not lower and obs_mm and obs_mm in entry_text:
            upper_ok = _version_le(obs_tuple, upper) if inclusive else _version_lt(obs_tuple, upper)
            if upper_ok:
                return True, obs_raw, f'structured_named_branch_upper_bound:{lte or lt}'
    return False, '', 'no exact structured version/range match'


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


def _cpe_match(rec: dict[str, Any], observed_cpe: str) -> tuple[bool, str]:
    if not observed_cpe:
        return False, ''
    observed = {c.strip().lower() for c in re.split(r'[\s,]+', observed_cpe) if c.strip()}
    rec_cpes = set()
    for ent in _affected_entries(rec):
        for c in ent.get('cpes') or []:
            rec_cpes.add(str(c).strip().lower())
    inter = observed & rec_cpes
    if inter:
        return True, sorted(inter)[0]
    return False, ''


def _sort_key(row: dict[str, Any]) -> tuple[int, str]:
    # Not a report ranking; just stable grouping by availability of source metadata.
    score = row.get('cvss_score')
    return (0 if score is not None else 1, str(row.get('cve_id') or ''))


@lru_cache(maxsize=4096)
def _search_cached(product: str, version: str, service: str, cpe: str = '') -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not INDEX.exists():
        return tuple(), tuple()
    ident, spec = _identity(product, service, cpe)
    if not ident:
        return tuple(), tuple()
    obs_version = _first_version(version)
    if not obs_version:
        return tuple(), tuple()

    confirmed: list[dict[str, Any]] = []
    try:
        with INDEX.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get('source') != OFFICIAL_CVE_SOURCE:
                    continue
                product_ok, product_hits, product_basis = _product_ok_for_record(rec, spec)
                cpe_ok, cpe_hit = _cpe_match(rec, cpe)
                if not (cpe_ok or product_ok):
                    continue

                version_ok = False
                matched_version = obs_version
                basis = ''
                if cpe_ok:
                    version_ok = True
                    basis = f'exact_cpe_match:{cpe_hit}'
                else:
                    for ent in _affected_entries(rec):
                        if not _entry_matches_product(ent, product_hits):
                            continue
                        ok, token, why = _entry_version_match(ent, version)
                        if ok:
                            version_ok = True
                            matched_version = token or obs_version
                            basis = why
                            break
                    if not version_ok:
                        ok, token, why = _text_version_match(rec, version)
                        if ok:
                            version_ok = True
                            matched_version = token or obs_version
                            basis = why
                if not version_ok:
                    continue
                row = {
                    'cve_id': rec.get('cve_id'),
                    'description': rec.get('description'),
                    'references': rec.get('references') or [],
                    'source': rec.get('source'),
                    'cvss_score': rec.get('cvss_score'),
                    'cvss_severity': rec.get('cvss_severity'),
                    'cvss_vector': rec.get('cvss_vector'),
                    'cvss_source': rec.get('cvss_source'),
                    'cvss_version': rec.get('cvss_version'),
                    'matched_product_tokens': product_hits or [ident],
                    'matched_version_tokens': [matched_version],
                    'match_basis': basis,
                    'product_match_basis': product_basis,
                }
                confirmed.append(row)
    except Exception:
        return tuple(), tuple()

    # Deduplicate by CVE and cap per service for display sanity. The JSON source still contains the raw CVE ID and references.
    dedup: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(confirmed, key=_sort_key):
        cve_id = str(row.get('cve_id') or '')
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            dedup.append(row)
        if len(dedup) >= int(os.getenv('MAX_CONFIRMED_CVES_PER_SERVICE', '6')):
            break
    return tuple(dedup), tuple()


def search(product: str, version: str, service: str, cpe: str = '') -> tuple[dict[str, Any], ...]:
    confirmed, _ = search_with_held(product, version, service, cpe)
    return tuple(confirmed)


def search_with_held(product: str, version: str, service: str, cpe: str = '') -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    confirmed, held = _search_cached(product, version, service, cpe)
    return tuple(copy.deepcopy(list(confirmed))), tuple(copy.deepcopy(list(held)))


def _extract_metrics_from_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    candidates = []
    metrics = node.get('metrics')
    if isinstance(metrics, list):
        candidates.extend(metrics)
    for c in candidates:
        if not isinstance(c, dict):
            continue
        for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
            data = c.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get('baseScore')
            severity = data.get('baseSeverity') or data.get('severity')
            vector = data.get('vectorString')
            if score is not None:
                try:
                    score = float(score)
                except Exception:
                    pass
                return {
                    'cvss_score': score,
                    'cvss_severity': str(severity or '').upper() if severity else '',
                    'cvss_vector': vector or '',
                    'cvss_source': c.get('source') or node.get('providerMetadata', {}).get('orgId') or '',
                    'cvss_version': key.replace('cvssV', '').replace('_', '.'),
                }
    return {}


def _extract_metric(data: dict[str, Any]) -> dict[str, Any]:
    containers = data.get('containers', {}) if isinstance(data, dict) else {}
    cna = containers.get('cna') or {}
    metric = _extract_metrics_from_node(cna)
    if metric:
        return metric
    for adp in containers.get('adp') or []:
        metric = _extract_metrics_from_node(adp)
        if metric:
            return metric
    return {}


def build_index() -> dict[str, Any]:
    BASE.mkdir(parents=True, exist_ok=True)
    if not REPO_DIR.exists():
        repo = OFFICIAL_CVE_REPO
        subprocess.run(['git', 'clone', '--depth', '1', repo, str(REPO_DIR)], check=True)
    else:
        subprocess.run(['git', '-C', str(REPO_DIR), 'pull', '--ff-only'], check=False)

    count = 0
    cvss_count = 0
    with INDEX.open('w', encoding='utf-8') as out:
        for path in REPO_DIR.rglob('CVE-*.json'):
            try:
                data = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            cve_id = data.get('cveMetadata', {}).get('cveId') or path.stem
            cna = data.get('containers', {}).get('cna', {})
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
            for r in cna.get('references') or []:
                url = r.get('url')
                if url:
                    refs.append(url)
            metric = _extract_metric(data)
            if metric:
                cvss_count += 1

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
            }
            row.update(metric)
            out.write(json.dumps(row, ensure_ascii=False) + '\n')
            count += 1
    return {'records_indexed': count, 'records_with_cvss_metadata': cvss_count, 'index_file': str(INDEX)}
