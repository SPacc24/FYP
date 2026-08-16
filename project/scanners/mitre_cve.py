
from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import subprocess
import threading
from functools import lru_cache
from datetime import datetime, timezone
import time
from pathlib import Path
from typing import Any

<<<<<<< HEAD
from . import nvd_client
=======
from . import command_builders
from . import nvd_client
from . import version_compare
from .cpe_utils import concrete, identity_matches, normalise_product, parse_cpe
from .scoring_policy import (
    CvssVerifierUnavailableError,
    InvalidCvssVectorError,
    PublishedMetricInconsistencyError,
    ScoringPolicyError,
    validate_published_metric,
)
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE = PROJECT_ROOT / 'storage' / 'mitre_cve'
REPO_DIR = BASE / 'cvelistV5'
INDEX = BASE / 'official_mitre_cve_index.jsonl'
OFFICIAL_CVE_REPO = 'https://github.com/CVEProject/cvelistV5.git'
OFFICIAL_CVE_SOURCE = 'Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)'
_LOOKUP_BUILD_LOCK = threading.Lock()


# v32-from-v31 principle: official CVE candidates only; report layer decides strict vs relevant information.
# The matcher does NOT use broad record-text search as proof. A visible CVE row
# needs exact CPE evidence, exact product identity plus exact observed version,
# or a clearly bounded affected-version range for the same product family.

@lru_cache(maxsize=8)
def _index_counts(index_file: str, size: int, mtime_ns: int) -> tuple[int, int, int, int, str]:
    records = 0
    cvss_records = 0
    by_version = {'3.1': 0, '4.0': 0}
    status_error = ''
    path = Path(index_file)
    if path.exists():
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as f:
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
    return records, cvss_records, by_version['3.1'], by_version['4.0'], status_error


def _lookup_path(index_path: Path | None = None) -> Path:
    return (index_path or INDEX).with_suffix('.lookup.sqlite3')


def _index_signature(index_path: Path) -> tuple[int, int]:
    stat = index_path.stat()
    return stat.st_size, stat.st_mtime_ns


def _lookup_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        return {
            str(key): str(value)
            for key, value in connection.execute('SELECT key, value FROM metadata')
        }
    except sqlite3.Error:
        return {}


def _lookup_is_current(index_path: Path, lookup_path: Path) -> bool:
    if not index_path.exists() or not lookup_path.exists():
        return False
    size, mtime_ns = _index_signature(index_path)
    try:
        with sqlite3.connect(lookup_path) as connection:
            metadata = _lookup_metadata(connection)
    except sqlite3.Error:
        return False
    return (
        metadata.get('index_size') == str(size)
        and metadata.get('index_mtime_ns') == str(mtime_ns)
        and metadata.get('schema_version') == '2'
    )


def _component_terms(value: str) -> set[str]:
    """Return bounded identity terms from a structured affected-product name.

    These terms are used only to retrieve CVE Program records whose structured
    ``affected[].product`` field mentions an observed protocol/component family.
    Description prose and reference text are never indexed here.
    """
    normalised = normalise_product(str(value or ''))
    words = [word for word in re.findall(r'[a-z0-9]+', normalised) if len(word) >= 2 and not word.isdigit()]
    terms = set(words)
    if len(words) >= 2:
        acronym = ''.join(word[0] for word in words)
        if len(acronym) >= 2:
            terms.add(acronym)
    return terms


def _vendor_compatible(observed: str, published: str) -> bool:
    """Compare vendor identity without treating missing/partial names as proof.

    An absent observed vendor means the vendor gate cannot add evidence and the
    structured product/version checks must carry applicability. An absent
    published vendor is malformed/insufficient structured data and does not
    become a wildcard. Corporate suffixes are normalised; arbitrary token
    subsets are never considered equivalent.
    """
    observed_name = normalise_product(observed)
    published_name = normalise_product(published)
    if not published_name:
        return False
    if not observed_name:
        return True
    suffixes = {'corporation', 'corp', 'inc', 'incorporated', 'llc', 'ltd', 'limited', 'company', 'co'}
    observed_tokens = [x for x in observed_name.split() if x not in suffixes]
    published_tokens = [x for x in published_name.split() if x not in suffixes]
    return bool(observed_tokens and published_tokens and observed_tokens == published_tokens)


def _component_product_matches(product: str, component: str) -> bool:
    component_name = normalise_product(component)
    if not component_name:
        return False
    product_terms = _component_terms(product)
    component_terms = _component_terms(component_name) | {component_name}
    return bool(product_terms & component_terms)


def _numeric_equivalent(left: str, right: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        values = [int(item) for item in re.findall(r'\d+', str(value or ''))]
        while len(values) > 1 and values[-1] == 0:
            values.pop()
        return tuple(values)
    a, b = parts(left), parts(right)
    return bool(a and b and a == b)


def _narrative_version_value(value: str) -> bool:
    """Return whether a structured version value is actually narrative prose.

    Older CVE records sometimes place a sentence describing both a protocol
    component and affected host releases in the ``version`` field.  A numeric
    token adjacent to the component may still be useful evidence, but it must
    not be labelled as a clean structured point-version match.
    """
    text = str(value or '').strip()
    if not text:
        return False
    words = re.findall(r'[A-Za-z0-9]+', text)
    if len(words) > 4:
        return True
    return bool(re.search(r'\b(?:server|client|running|affected|systems?|versions?|in|on|and|or)\b', text, re.I))


def _structured_component_version_match(
    entry: dict[str, Any],
    component: str,
    observed_version: str,
) -> tuple[bool, str]:
    """Match a directly observed component against structured affected data.

    Human-ish version strings are accepted only when they encode one concrete
    point version. Prose ranges (for example ``1 through 3``), wildcard ranges,
    and ordered range fields are never collapsed into an exact point match.
    Structured ranges are evaluated only through ``_point_in_rule`` using the
    record-declared version semantics.
    """
    component_name = normalise_product(component)
    version = str(observed_version or '').strip()
    if not component_name or not version:
        return False, 'component_or_version_missing'

    prose_range = re.compile(r'\b\d+(?:\.\d+)*\s*(?:-|to|through|thru)\s*\d+(?:\.\d+)*\b', re.I)
    unresolved: list[str] = []
    for rule in entry.get('versions') or []:
        if not isinstance(rule, dict):
            continue
        status = str(rule.get('status') or 'unknown').lower()
        raw = str(rule.get('version') or '').strip()
        has_structured_range = bool(rule.get('lessThan') or rule.get('lessThanOrEqual') or rule.get('changes'))

        if has_structured_range:
            contains, basis = _point_in_rule(version, rule)
            if not contains:
                if basis.startswith('unsupported_or_custom_version_range:') or basis.startswith('wildcard_range_requires_') or basis.endswith('_unparseable'):
                    unresolved.append(basis)
                continue
            effective_status = _status_after_changes(rule, version, status)
            if effective_status == 'affected':
                return True, f'{basis}:status=affected'
            return False, f'{basis}:status={effective_status or "unknown"}'

        if prose_range.search(raw) or re.search(r'(?:^|[.\s])(?:x|\*)(?:$|[.\s])', raw, re.I):
            unresolved.append('component_version_text_not_point_value')
            continue

        raw_normalised = normalise_product(raw)
        product_matches = _component_product_matches(str(entry.get('product') or ''), component_name)
        raw_mentions_component = bool(_component_terms(raw_normalised) & (_component_terms(component_name) | {component_name}))

        # Prefer a version token that is syntactically attached to the observed
        # component name. Legacy CVE Program records often store values such as
        # "SMBv1 server in ... Windows 8.1 ..." in the structured version field.
        # Taking the first dotted number from the whole sentence would select the
        # unrelated platform version. This parser is generic: it accepts only a
        # single point version adjacent to the component and never interprets a
        # prose range or a CVE-specific/product-specific exception.
        component_pattern = re.escape(component_name).replace(r'\ ', r'[\s._/-]+')
        adjacent = re.search(
            rf'(?<![a-z0-9]){component_pattern}\s*(?:v(?:ersion)?\s*)?([0-9]+(?:\.[0-9]+)*)(?![0-9.])',
            raw.lower(),
            re.I,
        )
        point = adjacent.group(1) if adjacent else _first_version(raw)
        if (product_matches or raw_mentions_component) and point and _numeric_equivalent(point, version):
            if status == 'affected':
                return True, (
                    'prose_affected_component_version_scrape'
                    if _narrative_version_value(raw)
                    else 'structured_affected_component_exact_version'
                )
            basis = (
                'prose_component_version_scrape'
                if _narrative_version_value(raw)
                else 'structured_component_exact_version'
            )
            return False, f'{basis}:status={status or "unknown"}'

    if unresolved:
        return False, unresolved[0]
    if str(entry.get('defaultStatus') or 'unknown').lower() == 'affected':
        return True, 'structured_component_default_status_affected'
    return False, 'structured_component_version_not_affected'


def _record_identity_keys(record: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for entry in _affected_entries(record):
        vendor = normalise_product(str(entry.get('vendor') or ''))
        product = normalise_product(str(entry.get('product') or ''))
        if product:
            keys.add(f'product:{product}')
            if vendor:
                keys.add(f'product:{vendor} {product}')
            for term in _component_terms(product):
                keys.add(f'component:{term}')
        for raw_cpe in entry.get('cpes') or []:
            parsed = parse_cpe(str(raw_cpe))
            if not parsed:
                continue
            part = parsed.get('part', '*')
            cpe_vendor = parsed.get('vendor', '*')
            cpe_product = parsed.get('product', '*')
            if concrete(part) and concrete(cpe_vendor) and concrete(cpe_product):
                keys.add(f'cpe:{part}:{cpe_vendor}:{cpe_product}')
    return keys


def build_lookup_index(index_path: Path | None = None) -> dict[str, Any]:
    """Build a compact identity-to-JSONL-offset index for bounded CVE retrieval."""
    source = index_path or INDEX
    if not source.exists():
        return {'available': False, 'reason': 'cve_index_unavailable'}
    destination = _lookup_path(source)
    with _LOOKUP_BUILD_LOCK:
        if _lookup_is_current(source, destination):
            return {'available': True, 'lookup_file': str(destination), 'reused': True}
        temporary = destination.with_name(
            f'{destination.name}.{os.getpid()}.{threading.get_ident()}.tmp'
        )
        temporary.parent.mkdir(parents=True, exist_ok=True)
        if temporary.exists():
            temporary.unlink()
        records = 0
        identity_rows = 0
        cvss_records = 0
        cvss_by_version = {'3.1': 0, '4.0': 0}
        connection = sqlite3.connect(temporary)
        try:
            connection.execute('PRAGMA journal_mode=OFF')
            connection.execute('PRAGMA synchronous=OFF')
            connection.execute(
                'CREATE TABLE identities (identity_key TEXT NOT NULL, line_offset INTEGER NOT NULL, '
                'PRIMARY KEY (identity_key, line_offset)) WITHOUT ROWID'
            )
            connection.execute('CREATE INDEX identities_key_idx ON identities(identity_key)')
            connection.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            pending: list[tuple[str, int]] = []
            with source.open('rb') as stream:
                while True:
                    offset = stream.tell()
                    line = stream.readline()
                    if not line:
                        break
                    try:
                        record = json.loads(line.decode('utf-8', errors='ignore'))
                    except (UnicodeDecodeError, ValueError):
                        continue
                    records += 1
                    metrics = record.get('cvss_metrics') or {}
                    present = False
                    for version in ('3.1', '4.0'):
                        metric = metrics.get(version) if isinstance(metrics, dict) else None
                        if isinstance(metric, dict) and metric.get('cvss_score') is not None:
                            cvss_by_version[version] += 1
                            present = True
                    if present:
                        cvss_records += 1
                    for key in _record_identity_keys(record):
                        pending.append((key, offset))
                    if len(pending) >= 10000:
                        connection.executemany(
                            'INSERT OR IGNORE INTO identities(identity_key, line_offset) VALUES (?, ?)',
                            pending,
                        )
                        identity_rows += len(pending)
                        pending.clear()
            if pending:
                connection.executemany(
                    'INSERT OR IGNORE INTO identities(identity_key, line_offset) VALUES (?, ?)',
                    pending,
                )
                identity_rows += len(pending)
            size, mtime_ns = _index_signature(source)
            metadata = {
                'schema_version': '2',
                'index_size': str(size),
                'index_mtime_ns': str(mtime_ns),
                'records_indexed': str(records),
                'records_with_cvss_metadata': str(cvss_records),
                'cvss_31_records': str(cvss_by_version['3.1']),
                'cvss_40_records': str(cvss_by_version['4.0']),
            }
            connection.executemany(
                'INSERT INTO metadata(key, value) VALUES (?, ?)',
                list(metadata.items()),
            )
            connection.commit()
        finally:
            connection.close()
        os.replace(temporary, destination)
        return {
            'available': True,
            'lookup_file': str(destination),
            'records_indexed': records,
            'identity_rows': identity_rows,
            'reused': False,
        }


def status() -> dict[str, Any]:
    lookup_ready = False
    lookup_metadata: dict[str, str] = {}
    if INDEX.exists():
        try:
            build_lookup_index(INDEX)
            lookup_ready = _lookup_is_current(INDEX, _lookup_path())
            if lookup_ready:
                with sqlite3.connect(_lookup_path()) as connection:
                    lookup_metadata = _lookup_metadata(connection)
        except (OSError, sqlite3.Error, ValueError):
            lookup_ready = False

    if lookup_metadata:
        records = int(lookup_metadata.get('records_indexed', '0') or 0)
        cvss_records = int(lookup_metadata.get('records_with_cvss_metadata', '0') or 0)
        cvss_31 = int(lookup_metadata.get('cvss_31_records', '0') or 0)
        cvss_40 = int(lookup_metadata.get('cvss_40_records', '0') or 0)
        status_error = ''
    else:
        index_size = INDEX.stat().st_size if INDEX.exists() else 0
        index_mtime_ns = INDEX.stat().st_mtime_ns if INDEX.exists() else 0
        records, cvss_records, cvss_31, cvss_40, status_error = _index_counts(
            str(INDEX), index_size, index_mtime_ns
        )
    by_version = {'3.1': cvss_31, '4.0': cvss_40}
    stale_cvss = INDEX.exists() and records > 0 and cvss_records == 0
    nvd = nvd_client.status()
    local_available = INDEX.exists() and records > 0
<<<<<<< HEAD
    return {
        'source': OFFICIAL_CVE_SOURCE,
        'source_mode': 'local_index' if local_available else ('targeted_nvd_api' if nvd.get('enabled') else 'unavailable'),
        'available': local_available or bool(nvd.get('enabled')),
        'local_index_available': local_available,
        'nvd_enrichment': nvd,
        'attribution': nvd.get('attribution', ''),
        'matcher_status': 'error' if status_error else ('available' if (local_available or nvd.get('enabled')) else 'unavailable'),
=======
    now = time.time()
    index_mtime = INDEX.stat().st_mtime if INDEX.exists() else 0.0
    repo_head_at = ''
    if REPO_DIR.exists():
        try:
            proc = subprocess.run(
                command_builders.git_log_head('git', REPO_DIR),
                capture_output=True, text=True, timeout=3, check=False,
            )
            repo_head_at = (proc.stdout or '').strip()
        except Exception:
            repo_head_at = ''
    index_updated_at = datetime.fromtimestamp(index_mtime, timezone.utc).isoformat() if index_mtime else ''
    index_age_seconds = int(max(0, now - index_mtime)) if index_mtime else None
    return {
        'source': OFFICIAL_CVE_SOURCE,
        'source_mode': 'local_index' if local_available else 'unavailable',
        'available': local_available,
        'local_index_available': local_available,
        'nvd_enrichment': nvd,
        'attribution': nvd.get('attribution', ''),
        'matcher_status': 'error' if status_error else ('available' if local_available else 'unavailable'),
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c
        'status_error': status_error,
        'records_indexed': records,
        'records_with_cvss_metadata': cvss_records,
        'records_with_cvss_metadata_by_version': by_version,
        'index_updated_at': index_updated_at,
        'index_age_seconds': index_age_seconds,
        'repo_head_at': repo_head_at,
        'freshness_basis': 'local_index_mtime',
        'cvss_metadata_stale': stale_cvss,
        'cvss_metadata_warning': 'CVE catalogue is available, but no CVSS 3.1/4.0 metadata is present. Rebuild the CVE catalogue.' if stale_cvss else '',
        'index_file': str(INDEX),
        'repo_dir': str(REPO_DIR),
        'rebuild_command': 'python scripts/sync_mitre_cve_database.py',
        'lookup_index_available': lookup_ready,
        'lookup_index_file': str(_lookup_path()),
    }


def _norm(s: str) -> str:
    return re.sub(r'\s+', ' ', (s or '').replace('_', ' ').replace('-', ' ')).strip().lower()


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r'[^a-zA-Z0-9._+-]+', (s or '').lower()) if t}


_VERSION_TOKEN_RE = re.compile(
    r'(?:\d+:)?'
    r'\d+(?:\.\d+){0,4}'
    r'(?:[a-z]+\d*)?'
    r'(?:[-~+](?!\d+(?:\.\d+){2,})[a-z0-9][a-z0-9.]*)*'
)
_VERSION_CORE_RE = re.compile(r'\d+(?:\.\d+)*')


def _version_specificity(token: str) -> int:
    core = str(token or '').split(':')[-1]
    match = _VERSION_CORE_RE.match(core)
    return len(match.group(0).split('.')) if match else 0


def _first_version(s: str) -> str:
    """Extract the most specific unambiguous version asserted by evidence.

    Product names often contain years or model numbers. Prefer the first
    dotted/multi-component token. If only several distinct bare integers are
    present, return no version rather than guessing which one is the version.
    """
    if not s:
        return ''
    candidates = [m.group(0) for m in _VERSION_TOKEN_RE.finditer(str(s).lower()) if m.group(0)]
    if not candidates:
        return ''
    for candidate in candidates:
        if _version_specificity(candidate) >= 2:
            return candidate
    return candidates[0] if len(set(candidates)) == 1 else ''


def _cpe_values(cpe: str, scope: str = 'application_service') -> list[str]:
    """Return CPEs appropriate for an observed identity scope.

    Service/application matching consumes CPE part ``a`` only; host OS matching
    consumes part ``o`` only.  This preserves the separation that prevents host
    platform CVEs from contaminating arbitrary network services.
    """
    wanted_part = 'o' if str(scope or '').lower() == 'host_os' else 'a'
    out: list[str] = []
    for raw in re.split(r'[\s,]+', cpe or ''):
        value = raw.strip()
        parts = _cpe_parts(value)
        if parts and parts[0] == wanted_part and value not in out:
            out.append(value)
    return out


def _application_cpe_values(cpe: str) -> list[str]:
    return _cpe_values(cpe, 'application_service')


def _operating_system_cpe_values(cpe: str) -> list[str]:
    return _cpe_values(cpe, 'host_os')


def _cpe_basis_label(scope: str) -> str:
    if str(scope or '').lower() == 'host_os':
        return 'exact_os_cpe'
    if str(scope or '').lower() == 'platform_component':
        return 'exact_component_cpe'
    return 'exact_application_cpe'


def _concrete_cpe_version(cpe: str, scope: str = 'application_service') -> str:
    versions: set[str] = set()
    for raw in _cpe_values(cpe, scope):
        parts = _cpe_parts(raw)
        if not parts:
            continue
        version = str(parts[3] or '').strip()
        if version not in {'', '*', '-'}:
            versions.add(version)
    return next(iter(versions)) if len(versions) == 1 else ''


def _concrete_application_cpe_version(cpe: str) -> str:
    return _concrete_cpe_version(cpe, 'application_service')


def _identity(product: str, service: str, cpe: str, scope: str = 'application_service') -> tuple[str | None, dict[str, Any]]:
    """Build identity only from observed product/CPE evidence.

    No maintained product alias table, CVE keyword map or description text is
    allowed to manufacture a product family. Service names are retained for
    context but are not themselves treated as product identity.
    """
    scoped_cpes = _cpe_values(cpe, scope)
    names: set[str] = set()
    product_name = _norm(product)
    if product_name and product_name not in {'unknown', 'n/a', 'na', '*', '-'}:
        names.add(product_name)

    observed_vendors: set[str] = set()
    for raw_cpe in scoped_cpes:
        parts = _cpe_parts(raw_cpe)
        if not parts:
            continue
        _part, vendor, cpe_product, _version = parts
        cpe_name = _norm(cpe_product)
        vendor_name = _norm(vendor)
        if vendor_name not in {'', '*', '-'}:
            observed_vendors.add(vendor_name)
        if cpe_name not in {'', '*', '-'}:
            names.add(cpe_name)
            if vendor_name not in {'', '*', '-'}:
                names.add(_norm(f'{vendor_name} {cpe_name}'))

    if not names:
        return None, {}
    identity = sorted(names, key=lambda value: (-len(value), value))[0]
    return identity, {
        'affected_products': names,
        'dynamic_exact_identity': True,
        'identity_scope': scope,
        'observed_vendors': observed_vendors,
        'observed_service': _norm(service),
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


def _product_name_matches(name: str, allowed: set[str], scope: str = 'application_service') -> bool:
    n = _norm(name)
    if not n or n in {'n/a', 'na', 'unknown', '*'}:
        return False
    for raw_allowed in allowed:
        a = _norm(raw_allowed)
        if not a:
            continue
        if n == a:
            return True
        if scope == 'host_os':
            # Host product strings may include vendor, edition and release
            # suffixes.  Containment is allowed only when the shorter identity
            # includes evidence beyond a generic OS family/vendor label.  This
            # prevents "Microsoft Windows" from silently becoming Windows 10/11
            # or "Apple macOS" from silently becoming a named macOS release.
            shorter, longer = (n, a) if len(n) <= len(a) else (a, n)
            short_tokens = shorter.split()
            generic_host_tokens = {
                'microsoft', 'windows', 'apple', 'macos', 'mac', 'os', 'darwin',
                'linux', 'unix', 'bsd', 'ios', 'operating', 'system',
            }
            distinguishing = [token for token in short_tokens if token not in generic_host_tokens]
            if distinguishing and all(token in longer.split() for token in short_tokens):
                return True
    return False


def _product_ok_for_record(rec: dict[str, Any], spec: dict[str, Any], scope: str = 'application_service') -> tuple[bool, list[str], str]:
    """Match only structured CVE affected-product fields.

    Description prose is useful to a human but is not an applicability field;
    it must never manufacture a product match.
    """
    allowed = {_norm(x) for x in spec.get('affected_products', set()) if _norm(x)}
    observed_vendors = {_norm(x) for x in spec.get('observed_vendors', set()) if _norm(x)}
    matched: list[str] = []
    for ent in _affected_entries(rec):
        vendor = _norm(str(ent.get('vendor', '')))
        product = _norm(str(ent.get('product', '')))
        if scope == 'host_os' and observed_vendors and vendor and vendor not in observed_vendors:
            continue
        for name in (product, f'{vendor} {product}'.strip()):
            if _product_name_matches(name, allowed, scope):
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
    if _norm(version_type) in {'semver', 'python'}:
        return True
    return version_compare.supports_version_type(version_type)


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
    if version_compare.supports_version_type(vt):
        return version_compare.compare_versions(left, right, vt)
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

    unresolved_reasons: list[str] = []
    for rule in entry.get('versions') or []:
        if not isinstance(rule, dict):
            continue
        contains, basis = _point_in_rule(obs_raw, rule)
        if not contains:
            if (
                basis.startswith('unsupported_or_custom_version_range:')
                or basis.startswith('wildcard_range_requires_')
                or basis.endswith('_unparseable')
            ):
                unresolved_reasons.append(basis)
            continue
        status = str(rule.get('status', '') or 'unknown').lower()
        status = _status_after_changes(rule, obs_raw, status)
        if status == 'affected':
            return True, obs_raw, f'{basis}:status=affected'
        # Explicit unaffected or unknown status is authoritative and must not be
        # promoted to affected.
        return False, '', f'{basis}:status={status or "unknown"}'

    if unresolved_reasons:
        return False, '', unresolved_reasons[0]
    default_status = str(entry.get('defaultStatus', '') or 'unknown').lower()
    if default_status == 'affected':
        return True, obs_raw, 'structured_default_status_affected'
    return False, '', f'default_status={default_status or "unknown"}'

def _cpe_parts(value: str) -> tuple[str, str, str, str] | None:
    parsed = parse_cpe(str(value or ''))
    if not parsed:
        return None
    return (
        parsed.get('part', '*'),
        parsed.get('vendor', '*'),
        parsed.get('product', '*'),
        parsed.get('version', '*'),
    )


def _cpe_match(rec: dict[str, Any], observed_cpe: str, scope: str = 'application_service') -> tuple[bool, str]:
    wanted_part = 'o' if scope == 'host_os' else 'a'
    observed: list[tuple[str, dict[str, str]]] = []
    for c in _cpe_values(observed_cpe, scope):
        raw = c.strip().lower()
        parsed = parse_cpe(raw)
        if parsed and parsed.get('part') == wanted_part:
            observed.append((raw, parsed))
    if not observed:
        return False, ''

    rec_cpes: list[tuple[str, dict[str, str]]] = []
    for ent in _affected_entries(rec):
        for c in ent.get('cpes') or []:
            raw = str(c).strip().lower()
            parsed = parse_cpe(raw)
            if parsed and parsed.get('part') == wanted_part:
                rec_cpes.append((raw, parsed))
    for observed_raw, observed_parts in observed:
        for record_raw, record_parts in rec_cpes:
            if not identity_matches(record_parts, observed_parts, ignore_version=True):
                continue
            observed_version = observed_parts.get('version', '*')
            record_version = record_parts.get('version', '*')
            if concrete(record_version):
                if concrete(observed_version) and observed_version == record_version:
                    return True, f'{observed_raw} == {record_raw}'
                continue
            return True, f'{observed_raw} matches affected CPE identity {record_raw}'
    return False, ''


def _entries_for_exact_cpe(rec: dict[str, Any], observed_cpe: str, scope: str = 'application_service') -> list[dict[str, Any]]:
    wanted_part = 'o' if scope == 'host_os' else 'a'
    observed_parts: list[dict[str, str]] = []
    for raw in _cpe_values(observed_cpe, scope):
        parsed = parse_cpe(raw)
        if parsed and parsed.get('part') == wanted_part and concrete(parsed.get('version', '')):
            observed_parts.append(parsed)
    if not observed_parts:
        return []
    matched: list[dict[str, Any]] = []
    for ent in _affected_entries(rec):
        for raw in ent.get('cpes') or []:
            parsed = parse_cpe(str(raw))
            if (
                not parsed
                or parsed.get('part') != wanted_part
                or not concrete(parsed.get('version', ''))
            ):
                continue
            if any(
                identity_matches(parsed, observed, ignore_version=False)
                for observed in observed_parts
            ):
                matched.append(ent)
                break
    return matched


def _entries_for_cpe_identity(rec: dict[str, Any], observed_cpe: str, scope: str = 'application_service') -> list[dict[str, Any]]:
    wanted_part = 'o' if scope == 'host_os' else 'a'
    observed = [
        parsed
        for raw in _cpe_values(observed_cpe, scope)
        if (parsed := parse_cpe(raw)) and parsed.get('part') == wanted_part
    ]
    if not observed:
        return []
    matched: list[dict[str, Any]] = []
    for entry in _affected_entries(rec):
        for raw in entry.get('cpes') or []:
            criteria = parse_cpe(str(raw))
            if not criteria or criteria.get('part') != wanted_part:
                continue
            if any(identity_matches(criteria, item, ignore_version=True) for item in observed):
                matched.append(entry)
                break
    return matched


def _entries_for_exact_application_cpe(rec: dict[str, Any], observed_cpe: str) -> list[dict[str, Any]]:
    return _entries_for_exact_cpe(rec, observed_cpe, 'application_service')


def _entry_match_without_observed_version(entry: dict[str, Any]) -> tuple[bool, str]:
    """Decide versionless applicability only when structured data is unambiguous."""
    if str(entry.get('defaultStatus', '') or 'unknown').lower() != 'affected':
        return False, 'observed_version_missing'
    rules = [rule for rule in entry.get('versions') or [] if isinstance(rule, dict)]
    if any(str(rule.get('status', '') or 'unknown').lower() not in {'affected'} for rule in rules):
        return False, 'observed_version_missing_with_exceptions'
    return True, 'structured_default_status_affected_without_version_exception'

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


def _sort_key(row: dict[str, Any]) -> tuple[str]:
    """Canonical CVE ordering is severity-neutral and version-neutral.

    CVSS 3.1 and 4.0 are separate standards. Presentation may sort by the
    operator-selected standard later, but the matcher must never mix them.
    """
    return (str(row.get('cve_id') or ''),)


def _query_identity_keys(spec: dict[str, Any], scoped_cpe_text: str) -> set[str]:
    keys = {
        f'product:{normalise_product(str(value))}'
        for value in spec.get('affected_products', set())
        if normalise_product(str(value))
    }
    for raw in _cpe_values(scoped_cpe_text, spec.get('identity_scope', 'application_service')):
        parsed = parse_cpe(raw)
        if not parsed:
            continue
        part = parsed.get('part', '*')
        vendor = parsed.get('vendor', '*')
        product = parsed.get('product', '*')
        if concrete(part) and concrete(vendor) and concrete(product):
            keys.add(f'cpe:{part}:{vendor}:{product}')
    return keys


def _candidate_offsets(index_path: Path, keys: set[str]) -> list[int] | None:
    lookup_path = _lookup_path(index_path)
    if not _lookup_is_current(index_path, lookup_path):
        try:
            build_lookup_index(index_path)
        except (OSError, sqlite3.Error, ValueError):
            return None
    if not keys or not _lookup_is_current(index_path, lookup_path):
        return None
    ordered_keys = sorted(keys)
    offsets: set[int] = set()
    try:
        with sqlite3.connect(lookup_path) as connection:
            for start in range(0, len(ordered_keys), 500):
                group = ordered_keys[start:start + 500]
                placeholders = ','.join('?' for _ in group)
                for (offset,) in connection.execute(
                    f'SELECT line_offset FROM identities WHERE identity_key IN ({placeholders})',
                    group,
                ):
                    offsets.add(int(offset))
    except sqlite3.Error:
        return None
    return sorted(offsets)


def _candidate_record_lines(index_path: Path, keys: set[str]):
    offsets = _candidate_offsets(index_path, keys)
    if offsets is None:
        with index_path.open('r', encoding='utf-8', errors='ignore') as stream:
            yield from stream
        return
    with index_path.open('rb') as stream:
        for offset in offsets:
            stream.seek(offset)
            yield stream.readline().decode('utf-8', errors='ignore')


@lru_cache(maxsize=8192)
def _search_cached(product: str, version: str, service: str, cpe: str = '', scope: str = 'application_service') -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not INDEX.exists():
        return tuple(), ({'reason': 'cve_index_unavailable', 'matcher_status': 'unavailable', 'index_file': str(INDEX)},)

    scope_value = str(scope or '').lower()
    scope = scope_value if scope_value in {'host_os', 'platform_component', 'application_service'} else 'application_service'
    scoped_cpe_text = ' '.join(_cpe_values(cpe, scope))
    ident, spec = _identity(product, service, scoped_cpe_text, scope)
    if not ident:
        return tuple(), ({'reason': 'unsupported_product_identity', 'matcher_status': 'held', 'identity_scope': scope},)

    cpe_version = _concrete_cpe_version(scoped_cpe_text, scope)
    effective_version = cpe_version or version
    if _is_observed_version_range(effective_version):
        return tuple(), ({
            'reason': 'observed_version_is_range',
            'matcher_status': 'held',
            'observed_version': effective_version,
            'identity_scope': scope,
        },)
    obs_version = _first_version(effective_version)
    if not obs_version:
        return tuple(), ({
            'reason': 'observed_version_missing',
            'matcher_status': 'held',
            'identity_scope': scope,
            'evidence_requirement': (
                'A concrete observed product/platform version or versioned CPE '
                'is required for a version-specific Candidate CVE.'
            ),
        },)

    matches: list[dict[str, Any]] = []
    malformed_records = 0
    candidate_records_considered = 0
    product_or_cpe_candidates = 0
    version_rejected = 0
    version_missing_seen = False
    held_version_rules: list[dict[str, Any]] = []
    held_cpe_context: list[dict[str, Any]] = []
    record_errors: list[dict[str, Any]] = []
    try:
        identity_spec = dict(spec)
        identity_spec['identity_scope'] = scope
        query_keys = _query_identity_keys(identity_spec, scoped_cpe_text)
        for line in _candidate_record_lines(INDEX, query_keys):
            try:
                rec = json.loads(line)
            except Exception:
                malformed_records += 1
                continue
            try:
                if rec.get('source') != OFFICIAL_CVE_SOURCE:
                    continue
                if str(rec.get('record_state') or 'PUBLISHED').upper() != 'PUBLISHED':
                    continue
                candidate_records_considered += 1

                product_ok, product_hits, product_basis = _product_ok_for_record(rec, spec, scope)
                cpe_ok, cpe_hit = _cpe_match(rec, scoped_cpe_text, scope)
                if not (cpe_ok or product_ok):
                    continue
                product_or_cpe_candidates += 1

                cpe_identity_entries = _entries_for_cpe_identity(rec, scoped_cpe_text, scope)
                candidate_entries = list(cpe_identity_entries) if cpe_ok else []
                if not candidate_entries:
                    product_entries = [
                        ent for ent in _affected_entries(rec)
                        if _entry_matches_product(ent, product_hits)
                    ]
                    candidate_entries = [
                        ent for ent in product_entries
                        if (
                            not scoped_cpe_text
                            or not (ent.get('cpes') or [])
                            or ent in cpe_identity_entries
                        )
                    ]
                    if (
                        scoped_cpe_text
                        and product_entries
                        and not candidate_entries
                        and any(ent.get('cpes') for ent in product_entries)
                    ):
                        held_cpe_context.append({
                            'reason': 'affected_cpe_context_not_satisfied',
                            'matcher_status': 'evidence_gap',
                            'cve_id': rec.get('cve_id'),
                            'identity_scope': scope,
                        })

                version_ok = False
                matched_version = obs_version
                basis = ''
                matched_entry: dict[str, Any] | None = None
                exact_cpe_entries = _entries_for_exact_cpe(rec, scoped_cpe_text, scope)
                for ent in candidate_entries:
                    if ent in exact_cpe_entries and not (ent.get('versions') or []):
                        ok, token, why = True, obs_version, 'exact_affected_cpe_version'
                    elif obs_version:
                        ok, token, why = _entry_version_match(ent, effective_version)
                    else:
                        ok, why = _entry_match_without_observed_version(ent)
                        token = ''
                        if not ok:
                            version_missing_seen = True
                    if ok:
                        version_ok = True
                        matched_version = token or obs_version
                        prefix = _cpe_basis_label(scope)
                        basis = f'{prefix}:{cpe_hit};{why}' if cpe_ok else why
                        matched_entry = ent
                        break
                    if (
                        why.startswith('unsupported_or_custom_version_range:')
                        or why.startswith('wildcard_range_requires_')
                        or why.endswith('_unparseable')
                    ):
                        held_version_rules.append({
                            'reason': 'published_version_rule_not_comparable',
                            'matcher_status': 'evidence_gap',
                            'cve_id': rec.get('cve_id'),
                            'observed_version': effective_version,
                            'version_rule_reason': why,
                            'identity_scope': scope,
                        })
                if not version_ok:
                    version_rejected += 1
                    continue

                metrics = copy.deepcopy(rec.get('cvss_metrics') or {})
                preferred = _preferred_metric(rec)
                row = {
                        'cve_id': rec.get('cve_id'),
                        'description': rec.get('description'),
                        'references': rec.get('references') or [],
                        'source': rec.get('source'),
                        'identity_scope': scope,
                        'cvss_metrics': metrics,
                        'cvss_score': preferred.get('cvss_score'),
                        'cvss_severity': preferred.get('cvss_severity'),
                        'cvss_vector': preferred.get('cvss_vector'),
                        'cvss_source': preferred.get('cvss_source'),
                        'cvss_version': preferred.get('cvss_version'),
                        'matched_product_tokens': product_hits or [ident],
                        'matched_version_tokens': [matched_version] if matched_version else [],
                        'match_basis': basis,
                        'product_match_basis': _cpe_basis_label(scope) if cpe_ok else product_basis,
                        'cve_publisher': rec.get('cve_publisher') or 'CVE Program CNA',
                        'cve_publisher_id': rec.get('cve_publisher_id') or '',
                        'affected_vendors': rec.get('affected_vendors') or [],
                        'affected_products': rec.get('affected_products') or [],
                        'affected_versions': rec.get('affected_versions') or [],
                        'affected_entries': rec.get('affected_entries') or [],
                        'affected_cpes': rec.get('cpes') or [],
                        'matched_affected_entry': copy.deepcopy(matched_entry) if matched_entry else {},
                        'structured_requirements': {
                            'modules': list((matched_entry or {}).get('modules') or []),
                            'platforms': list((matched_entry or {}).get('platforms') or []),
                            'package_name': str((matched_entry or {}).get('packageName') or ''),
                        },
                }
                matches.append(row)
            except Exception as exc:
                record_errors.append({
                    'reason': 'cve_record_processing_error',
                    'matcher_status': 'error',
                    'cve_id': str(rec.get('cve_id') or ''),
                    'error_type': type(exc).__name__,
                    'error': str(exc),
                    'identity_scope': scope,
                })
                continue
    except Exception as exc:
        # Preserve already-established matches and make source-iteration failure
        # explicit instead of silently returning an empty CVE set.
        record_errors.append({
            'reason': 'cve_source_iteration_error',
            'matcher_status': 'error',
            'error_type': type(exc).__name__,
            'error': str(exc),
            'identity_scope': scope,
        })

    dedup: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(matches, key=_sort_key):
        cve_id = str(row.get('cve_id') or '')
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            dedup.append(row)
    diagnostics: list[dict[str, Any]] = list(record_errors)
    diagnostics.append({
        'reason': 'cve_program_candidate_search_summary',
        'matcher_status': 'available',
        'identity_scope': scope,
        'candidate_records_considered': candidate_records_considered,
        'product_or_cpe_candidates': product_or_cpe_candidates,
        'version_rejected': version_rejected,
        'cpe_context_rejected': len({str(item.get('cve_id') or '') for item in held_cpe_context if item.get('cve_id')}),
        'matched_count': len(dedup),
    })
    if not obs_version and not dedup and version_missing_seen:
        diagnostics.append({'reason': 'observed_version_missing', 'matcher_status': 'held', 'identity_scope': scope})
    if malformed_records:
        diagnostics.append({
            'reason': 'index_records_skipped',
            'matcher_status': 'degraded',
            'record_count': malformed_records,
            'identity_scope': scope,
        })
    seen_held: set[tuple[str, str]] = set()
    for item in held_version_rules:
        signature = (str(item.get('cve_id') or ''), str(item.get('version_rule_reason') or ''))
        if signature in seen_held:
            continue
        seen_held.add(signature)
        diagnostics.append(item)
        if len(seen_held) >= 100:
            break
    seen_cpe_gaps: set[str] = set()
    for item in held_cpe_context:
        cve_id = str(item.get('cve_id') or '')
        if not cve_id or cve_id in seen_cpe_gaps:
            continue
        seen_cpe_gaps.add(cve_id)
        diagnostics.append(item)
        if len(seen_cpe_gaps) >= 100:
            break
    return tuple(dedup), tuple(diagnostics)


def search_component_candidates(
    component: str,
    version: str,
    *,
    host_vendor: str = '',
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Retrieve canonical component CVEs from structured CVE Program fields.

    This is deliberately a *candidate* stage.  The caller must corroborate the
    host/platform context from authoritative configuration data before emitting
    a CVE reference.  No description search, alias registry, or NVD keyword CVE
    search is performed here.
    """
    component_name = normalise_product(component)
    observed_version = str(version or '').strip()
    if not component_name or not observed_version:
        return tuple(), ({'reason': 'component_identity_incomplete', 'matcher_status': 'held'},)
    if not INDEX.exists():
        return tuple(), ({'reason': 'cve_index_unavailable', 'matcher_status': 'unavailable', 'index_file': str(INDEX)},)

    keys = {f'component:{term}' for term in (_component_terms(component_name) | {component_name}) if term}
    matches: list[dict[str, Any]] = []
    malformed = 0
    record_errors: list[dict[str, Any]] = []
    try:
        for line in _candidate_record_lines(INDEX, keys):
            try:
                rec = json.loads(line)
            except Exception:
                malformed += 1
                continue
            try:
                if rec.get('source') != OFFICIAL_CVE_SOURCE:
                    continue
                if str(rec.get('record_state') or 'PUBLISHED').upper() != 'PUBLISHED':
                    continue
                matched_entry = None
                version_basis = ''
                for entry in _affected_entries(rec):
                    if not _vendor_compatible(host_vendor, str(entry.get('vendor') or '')):
                        continue
                    if not _component_product_matches(str(entry.get('product') or ''), component_name):
                        continue
                    applicable, why = _structured_component_version_match(entry, component_name, observed_version)
                    if applicable:
                        matched_entry = entry
                        version_basis = why
                        break
                if matched_entry is None:
                    continue

                metrics = copy.deepcopy(rec.get('cvss_metrics') or {})
                preferred = _preferred_metric(rec)
                matches.append({
                    'cve_id': rec.get('cve_id'),
                    'description': rec.get('description'),
                    'references': rec.get('references') or [],
                    'source': OFFICIAL_CVE_SOURCE,
                    'identity_scope': 'platform_component',
                    'cvss_metrics': metrics,
                    'cvss_score': preferred.get('cvss_score'),
                    'cvss_severity': preferred.get('cvss_severity'),
                    'cvss_vector': preferred.get('cvss_vector'),
                    'cvss_source': preferred.get('cvss_source'),
                    'cvss_version': preferred.get('cvss_version'),
                    'matched_product_tokens': [str(matched_entry.get('product') or component_name)],
                    'matched_version_tokens': [observed_version],
                    'match_basis': version_basis,
                    'product_match_basis': 'structured_affected_component_product',
                    'cve_publisher': rec.get('cve_publisher') or 'CVE Program CNA',
                    'cve_publisher_id': rec.get('cve_publisher_id') or '',
                    'affected_vendors': rec.get('affected_vendors') or [],
                    'affected_products': rec.get('affected_products') or [],
                    'affected_versions': rec.get('affected_versions') or [],
                    'affected_entries': rec.get('affected_entries') or [],
                    'affected_cpes': rec.get('cpes') or [],
                    'matched_affected_entry': copy.deepcopy(matched_entry),
                    'structured_requirements': {
                        'modules': list(matched_entry.get('modules') or []),
                        'platforms': list(matched_entry.get('platforms') or []),
                        'package_name': str(matched_entry.get('packageName') or ''),
                    },
                })
            except Exception as exc:
                record_errors.append({
                    'reason': 'component_record_processing_error',
                    'matcher_status': 'error',
                    'cve_id': str(rec.get('cve_id') or ''),
                    'error_type': type(exc).__name__,
                    'error': str(exc),
                    'identity_scope': 'platform_component',
                })
                continue
    except Exception as exc:
        record_errors.append({'reason': 'component_source_iteration_error', 'matcher_status': 'error', 'error_type': type(exc).__name__, 'error': str(exc), 'identity_scope': 'platform_component'})

    dedup: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(matches, key=_sort_key):
        cve_id = str(row.get('cve_id') or '')
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            dedup.append(row)
    diagnostics: list[dict[str, Any]] = list(record_errors)
    if malformed:
        diagnostics.append({'reason': 'index_records_skipped', 'matcher_status': 'degraded', 'record_count': malformed, 'identity_scope': 'platform_component'})
    if not dedup:
        diagnostics.append({'reason': 'no_structured_component_cve_candidate', 'matcher_status': 'held', 'component': component_name, 'version': observed_version})
    return tuple(dedup), tuple(diagnostics)


def search(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
    scope: str = 'application_service',
    context_cpe: str = '',
) -> tuple[dict[str, Any], ...]:
    baseline_references, _ = search_with_held(
        product,
        version,
        service,
        cpe,
        confidence_score=confidence_score,
        recommended_for_cve=recommended_for_cve,
        scope=scope,
        context_cpe=context_cpe,
    )
    return tuple(baseline_references)


def search_with_held(
    product: str,
    version: str,
    service: str,
    cpe: str = '',
    *,
    confidence_score: float | None = None,
    recommended_for_cve: bool | None = None,
    scope: str = 'application_service',
    context_cpe: str = '',
    include_search_summary: bool = False,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Generate Candidate CVEs from canonical CVE Program affected data.

    Candidate generation has no confidence tier or confidence gate. If a
    concrete software product/version identity is supplied, structured CVE
    Program affected data decides whether a Candidate CVE is generated.
    Evidence provenance remains attached to the identity itself. NVD is not a
    candidate source; callers may enrich exact Candidate CVE IDs after this
    function returns.
    """
    if not INDEX.exists():
        # Candidate generation depends on the local CVE Program index. NVD
        # enrichment cannot create a replacement candidate when this source is unavailable.
        return (
            tuple(),
            tuple(copy.deepcopy([{
                'reason': 'cve_index_unavailable',
                'matcher_status': 'unavailable',
                'index_file': str(INDEX),
            }])),
        )

    matched, diagnostics = _search_cached(product, version, service, cpe, scope)
    visible_diagnostics = list(diagnostics)
    if not include_search_summary:
        visible_diagnostics = [
            item for item in visible_diagnostics
            if str(item.get('reason') or '') != 'cve_program_candidate_search_summary'
        ]
    return (
        tuple(copy.deepcopy(list(matched))),
        tuple(copy.deepcopy(visible_diagnostics)),
    )


def lookup_by_ids(cve_ids: set[str] | list[str] | tuple[str, ...]) -> tuple[dict[str, Any], ...]:
    """Return canonical CVE records for externally evidenced CVE identifiers."""
    wanted = {str(cve_id or "").upper() for cve_id in cve_ids}
    wanted = {
        cve_id
        for cve_id in wanted
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)
    }
    if not wanted or not INDEX.exists():
        return tuple()

    rows: list[dict[str, Any]] = []
    id_pattern = re.compile(r'\"cve_id\"\s*:\s*\"(CVE-\d{4}-\d{4,})\"', re.I)
    with INDEX.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            id_match = id_pattern.search(line)
            if not id_match or id_match.group(1).upper() not in wanted:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            cve_id = str(record.get("cve_id") or "").upper()
            if (
                cve_id not in wanted
                or record.get("source") != OFFICIAL_CVE_SOURCE
                or str(record.get("record_state") or "PUBLISHED").upper() != "PUBLISHED"
            ):
                continue
            metrics = copy.deepcopy(record.get("cvss_metrics") or {})
            preferred = _preferred_metric(record)
            rows.append({
                "cve_id": cve_id,
                "description": record.get("description"),
                "references": record.get("references") or [],
                "source": OFFICIAL_CVE_SOURCE,
                "cvss_metrics": metrics,
                "cvss_score": preferred.get("cvss_score"),
                "cvss_severity": preferred.get("cvss_severity"),
                "cvss_vector": preferred.get("cvss_vector"),
                "cvss_source": preferred.get("cvss_source"),
                "cvss_version": preferred.get("cvss_version"),
                "cve_publisher": record.get("cve_publisher") or "CVE Program CNA",
                "cve_publisher_id": record.get("cve_publisher_id") or "",
                "affected_vendors": record.get("affected_vendors") or [],
                "affected_products": record.get("affected_products") or [],
                "affected_versions": record.get("affected_versions") or [],
                "affected_entries": record.get("affected_entries") or [],
                "affected_cpes": record.get("cpes") or [],
            })
    return tuple(rows)


def resolve_held_version_candidates_by_ids(
    product: str,
    version: str,
    service: str,
    cpe: str,
    allowed_cve_ids: Iterable[str],
    *,
    scope: str = 'host_os',
    resolution_basis: str = 'cve_program_custom_version_resolved_by_external_build_context',
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Resolve only CVE Program records previously held on version semantics.

    ``allowed_cve_ids`` is an external *applicability-context* allow-set (for
    example, Microsoft build-line evidence).  It cannot introduce a CVE ID
    that the CVE Program matcher did not already encounter for the observed
    product identity.  This preserves cvelistV5 as the sole Candidate CVE
    source while allowing a vendor-specific comparator to resolve a version
    scheme the generic matcher intentionally refuses to guess.
    """
    wanted = {
        str(value or '').strip().upper()
        for value in allowed_cve_ids or []
        if re.fullmatch(r'CVE-\d{4}-\d{4,}', str(value or '').strip().upper())
    }
    if not wanted:
        return tuple(), tuple()

    _existing, search_diagnostics = _search_cached(product, version, service, cpe, scope)
    held_ids = {
        str(item.get('cve_id') or '').upper()
        for item in search_diagnostics
        if str(item.get('reason') or '') == 'published_version_rule_not_comparable'
        and str(item.get('cve_id') or '').strip()
    }
    eligible_ids = wanted & held_ids
    if not eligible_ids:
        return tuple(), ({
            'reason': 'external_version_context_did_not_intersect_cve_program_holds',
            'matcher_status': 'held',
            'requested_cve_count': len(wanted),
            'cve_program_held_count': len(held_ids),
            'identity_scope': scope,
        },)

    scoped_cpe_text = ' '.join(_cpe_values(cpe, scope))
    ident, spec = _identity(product, service, scoped_cpe_text, scope)
    if not ident:
        return tuple(), ({
            'reason': 'unsupported_product_identity',
            'matcher_status': 'held',
            'identity_scope': scope,
        },)

    resolved: list[dict[str, Any]] = []
    for canonical in lookup_by_ids(eligible_ids):
        rec = dict(canonical)
        rec['cpes'] = list(canonical.get('affected_cpes') or [])
        product_ok, product_hits, product_basis = _product_ok_for_record(rec, spec, scope)
        cpe_ok, cpe_hit = _cpe_match(rec, scoped_cpe_text, scope)
        if not (product_ok or cpe_ok):
            continue
        cpe_identity_entries = _entries_for_cpe_identity(rec, scoped_cpe_text, scope)
        candidate_entries = list(cpe_identity_entries) if cpe_ok else []
        if not candidate_entries:
            product_entries = [
                entry for entry in _affected_entries(rec)
                if _entry_matches_product(entry, product_hits)
            ]
            candidate_entries = [
                entry for entry in product_entries
                if not scoped_cpe_text or not (entry.get('cpes') or []) or entry in cpe_identity_entries
            ]
        matched_entry: dict[str, Any] | None = None
        held_reason = ''
        for entry in candidate_entries:
            ok, _token, why = _entry_version_match(entry, version)
            if ok:
                # The generic matcher would already have emitted this row; do
                # not duplicate it through the external-resolution path.
                matched_entry = None
                held_reason = ''
                break
            if (
                why.startswith('unsupported_or_custom_version_range:')
                or why.startswith('wildcard_range_requires_')
                or why.endswith('_unparseable')
            ):
                matched_entry = entry
                held_reason = why
                break
        if matched_entry is None or not held_reason:
            continue
        row = dict(canonical)
        row.update({
            'identity_scope': scope,
            'matched_product_tokens': product_hits or [ident],
            'matched_version_tokens': [str(version or '').strip()],
            'match_basis': resolution_basis,
            'product_match_basis': _cpe_basis_label(scope) if cpe_ok else product_basis,
            'matched_affected_entry': copy.deepcopy(matched_entry),
            'externally_resolved_version_rule': held_reason,
            'structured_requirements': {
                'modules': list(matched_entry.get('modules') or []),
                'platforms': list(matched_entry.get('platforms') or []),
                'package_name': str(matched_entry.get('packageName') or ''),
            },
        })
        resolved.append(row)

    resolved.sort(key=_sort_key)
    return tuple(resolved), ({
        'reason': 'held_version_candidates_resolved_by_external_build_context',
        'matcher_status': 'available',
        'resolved_cve_count': len(resolved),
        'identity_scope': scope,
        'resolution_basis': resolution_basis,
    },)


def _validated_metric(version: str, data: dict[str, Any], source: str, role: str) -> dict[str, Any]:
    score = data.get('baseScore')
    vector = data.get('vectorString') or ''
    severity = data.get('baseSeverity') or data.get('severity') or ''
    if score is None or not vector:
        return {}
    try:
        metric = validate_published_metric(version, score, severity, vector)
        metric['cvss_verification'] = 'Vector recomputed; published score matches'
    except CvssVerifierUnavailableError as exc:
        try:
            score_value = float(score)
        except (TypeError, ValueError):
<<<<<<< HEAD
            score = 0.0
        recommended = bool(recommended_for_cve)
        if score < MIN_FINGERPRINT_CONFIDENCE or not recommended:
            threshold_diag = {
                'reason': 'fingerprint_confidence_below_cve_threshold',
                'confidence_score': round(score, 2),
                'minimum_confidence': MIN_FINGERPRINT_CONFIDENCE,
                'recommended_for_cve': recommended,
            }
            # Never promote an uncorroborated fingerprint to a confirmed CVE.
            # However, a concrete product+version observed directly by Nmap
            # (normally confidence 0.60) is still useful as analyst-review
            # candidate information. Search the same official source and tag
            # every returned record so the report layer keeps it non-confirmed.
            has_identity = bool(str(product or '').strip() and str(version or '').strip())
            candidate_eligible = has_identity and score >= 0.60
            if candidate_eligible:
                if INDEX.exists():
                    candidates, source_diag = _search_cached(product, version, service, cpe)
                elif nvd_client.enabled():
                    candidates, source_diag = nvd_client.search(product, version, service, cpe)
                else:
                    candidates, source_diag = tuple(), tuple()
                candidate_rows = tuple({
                    **dict(row),
                    'low_confidence_candidate': True,
                    'nvd_candidate': bool(dict(row).get('nvd_candidate', False)),
                } for row in candidates)
                return candidate_rows, (threshold_diag, *tuple(source_diag))
            return tuple(), (threshold_diag,)
    if INDEX.exists():
        confirmed, held = _search_cached(product, version, service, cpe)
    else:
        confirmed, held = nvd_client.search(product, version, service, cpe)
    return tuple(copy.deepcopy(list(confirmed))), tuple(copy.deepcopy(list(held)))
=======
            return {}
        metric = {
            'cvss_score': score_value,
            'cvss_severity': str(severity or '').upper(),
            'cvss_vector': str(vector),
            'cvss_version': version,
            'cvss_metric_integrity': 'verifier_unavailable',
            'cvss_verified': False,
            'cvss_verification_status': 'verifier_unavailable',
            'cvss_verification_method': (
                'python_cvss4_library' if version == '4.0' else 'internal_cvss31_formula'
            ),
            'cvss_verification': f'Published metric retained; independent verifier unavailable: {exc}',
        }
    except InvalidCvssVectorError as exc:
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            return {}
        metric = {
            'cvss_score': score_value,
            'cvss_severity': str(severity or '').upper(),
            'cvss_vector': str(vector),
            'cvss_version': version,
            'cvss_metric_integrity': 'invalid_vector',
            'cvss_verified': False,
            'cvss_verification_status': 'invalid_vector',
            'cvss_verification_method': (
                'python_cvss4_library' if version == '4.0' else 'internal_cvss31_formula'
            ),
            'cvss_verification': f'Published metric retained; vector could not be independently calculated: {exc}',
        }
    except (PublishedMetricInconsistencyError, ScoringPolicyError) as exc:
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
            'cvss_verification_status': 'source_inconsistent',
            'cvss_verification_method': (
                'python_cvss4_library' if version == '4.0' else 'internal_cvss31_formula'
            ),
            'cvss_verification': f'Published metric could not be independently verified: {exc}',
        }
    metric['cvss_source'] = source
    metric['cvss_provider_role'] = role
    return metric
>>>>>>> 2521ca7f0d3b647d15fa553b1f1ef53400160f3c


def _extract_metrics_from_node(node: Any, role: str = 'CNA') -> dict[str, dict[str, Any]]:
    if not isinstance(node, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    provider_meta = node.get('providerMetadata') or {}
    source = str(provider_meta.get('orgId') or '')
    provider_name = str(provider_meta.get('shortName') or '')
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
                metric['cvss_provider_name'] = provider_name
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
        subprocess.run(command_builders.git_clone_shallow('git', repo, REPO_DIR), check=True)
    else:
        subprocess.run(command_builders.git_pull_ff_only('git', REPO_DIR), check=False)

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
    _index_counts.cache_clear()
    lookup = build_lookup_index(INDEX)
    return {
        'records_indexed': count,
        'records_with_cvss_metadata': cvss_count,
        'records_with_cvss_metadata_by_version': cvss_by_version,
        'index_file': str(INDEX),
        'lookup_index': lookup,
    }
