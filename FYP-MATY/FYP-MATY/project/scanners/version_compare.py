"""Conservative version ordering for CVE affected-range evaluation.

Only ecosystems whose ordering has been independently validated in this build
are enabled. Unsupported schemes return ``None`` so the matcher holds the CVE
range instead of guessing.
"""
from __future__ import annotations

from typing import Any

VERSION_TYPE_ALIASES = {
    'deb': 'deb',
    'debian': 'deb',
    'dpkg': 'deb',
    'apt': 'deb',
    'ubuntu': 'deb',
}
SUPPORTED_VERSION_TYPES = frozenset({'deb'})


def canonical_version_type(version_type: Any) -> str:
    return VERSION_TYPE_ALIASES.get(str(version_type or '').strip().lower(), '')


def supports_version_type(version_type: Any) -> bool:
    return canonical_version_type(version_type) in SUPPORTED_VERSION_TYPES


def _deb_order(char: str) -> int:
    if not char:
        return 0
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == '~':
        return -1
    return ord(char) + 256


def _deb_compare_part(left: str, right: str) -> int:
    a, b = str(left or ''), str(right or '')
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = a[i] if i < len(a) else ''
            cb = b[j] if j < len(b) else ''
            if ca.isdigit():
                ca = ''
            if cb.isdigit():
                cb = ''
            oa, ob = _deb_order(ca), _deb_order(cb)
            if oa != ob:
                return 1 if oa > ob else -1
            if ca:
                i += 1
            if cb:
                j += 1
            if not ca and not cb:
                break

        start_i = i
        while i < len(a) and a[i].isdigit():
            i += 1
        start_j = j
        while j < len(b) and b[j].isdigit():
            j += 1
        da = (a[start_i:i].lstrip('0') or '0') if i > start_i else '0'
        db = (b[start_j:j].lstrip('0') or '0') if j > start_j else '0'
        if len(da) != len(db):
            return 1 if len(da) > len(db) else -1
        if da != db:
            return 1 if da > db else -1
    return 0


def _split_deb_version(value: str) -> tuple[int, str, str] | None:
    text = str(value or '').strip()
    if not text:
        return None
    epoch = 0
    if ':' in text:
        head, _, text = text.partition(':')
        if not head.isdigit():
            return None
        epoch = int(head)
    if not text:
        return None
    if '-' in text:
        upstream, _, revision = text.rpartition('-')
    else:
        upstream, revision = text, ''
    if not upstream:
        return None
    return epoch, upstream, revision


def deb_vercmp(left: str, right: str) -> int | None:
    a = _split_deb_version(left)
    b = _split_deb_version(right)
    if a is None or b is None:
        return None
    ea, ua, ra = a
    eb, ub, rb = b
    if ea != eb:
        return 1 if ea > eb else -1
    result = _deb_compare_part(ua, ub)
    if result:
        return result
    # Missing package revision is not silently invented. A CVE range that is
    # more precise than the observed evidence remains held.
    if bool(ra) != bool(rb):
        return None
    if not ra:
        return 0
    return _deb_compare_part(ra, rb)


def compare_versions(left: str, right: str, version_type: Any) -> int | None:
    if canonical_version_type(version_type) == 'deb':
        return deb_vercmp(left, right)
    return None
