from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import requests

from .cpe_utils import concrete, normalise_product, parse_cpe


CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CACHE_FILE = Path("storage/nvd_cache/cpe_resolution.json")
_LOCK = threading.Lock()
_LAST_REQUEST = 0.0


def _delay() -> float:
    try:
        return max(0.0, float(os.getenv("NVD_REQUEST_DELAY_SECONDS", "6.5")))
    except ValueError:
        return 6.5


def _timeout() -> float:
    try:
        return max(3.0, float(os.getenv("NVD_REQUEST_TIMEOUT_SECONDS", "20")))
    except ValueError:
        return 20.0


def _load_cache() -> dict[str, Any]:
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    temporary.replace(CACHE_FILE)


def _request(params: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    global _LAST_REQUEST
    with _LOCK:
        wait = _delay() - (time.monotonic() - _LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        _LAST_REQUEST = time.monotonic()
    headers = {"User-Agent": "SP-FYP-AutoPenTest/1.0"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(CPE_API_URL, params=params, headers=headers, timeout=_timeout())
    except requests.RequestException as exc:
        return None, {
            "reason": "nvd_cpe_network_error",
            "matcher_status": "degraded",
            "error": str(exc),
        }
    if response.status_code in {403, 429}:
        return None, {
            "reason": "nvd_cpe_rate_limited",
            "matcher_status": "degraded",
            "http_status": response.status_code,
        }
    if not response.ok:
        return None, {
            "reason": "nvd_cpe_http_error",
            "matcher_status": "degraded",
            "http_status": response.status_code,
        }
    try:
        return response.json(), {}
    except ValueError:
        return None, {
            "reason": "nvd_cpe_invalid_json",
            "matcher_status": "degraded",
        }


def _product_forms(product: str) -> set[str]:
    normalised = normalise_product(product)
    forms = {normalised}
    if normalised.startswith("microsoft "):
        forms.add(normalised.removeprefix("microsoft ").strip())
    return {item for item in forms if item}




def _numeric_parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", str(value or "")))


def _trim_trailing_zeroes(parts: tuple[int, ...]) -> tuple[int, ...]:
    values = list(parts)
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values)


def _version_compatible(observed: str, candidate: str) -> bool:
    observed = str(observed or '').strip().lower()
    candidate = str(candidate or '').strip().lower()
    if not observed or candidate in {'', '*', '-'}:
        return True
    if observed == candidate:
        return True
    left = _numeric_parts(observed)
    right = _numeric_parts(candidate)
    if not left or not right:
        return False
    if _trim_trailing_zeroes(left) == _trim_trailing_zeroes(right):
        return True
    # A remotely observed Windows/product build may omit the servicing revision
    # that appears in the CPE Dictionary.  Prefix agreement is accepted only
    # when at least three numeric components were observed, so this cannot turn
    # a generic major version into an exact release.
    common = min(len(left), len(right))
    return common >= 3 and left[:common] == right[:common]


def _acronym(value: str) -> str:
    words = [word for word in normalise_product(value).split() if word and not word.isdigit()]
    return ''.join(word[0] for word in words if word) if len(words) >= 2 else ''


def _product_compatible(observed: str, candidate: str, *, strong_version: bool) -> bool:
    observed_forms = _product_forms(observed)
    candidate_forms = _product_forms(candidate)
    if observed_forms & candidate_forms:
        return True
    for observed_form in observed_forms:
        for candidate_form in candidate_forms:
            if observed_form == _acronym(candidate_form) or candidate_form == _acronym(observed_form):
                return True
            if not strong_version:
                continue
            observed_tokens = set(observed_form.split())
            candidate_tokens = set(candidate_form.split())
            shared = {token for token in observed_tokens & candidate_tokens if token}
            # Fuzzy family agreement is only allowed when a strong version/build
            # prefix already anchors the record.  Two shared tokens prevents a
            # generic vendor/family word from selecting a release by itself.
            if len(shared) >= 2:
                return True
    return False

def _generic_platform(cpe: dict[str, str]) -> bool:
    return all(
        cpe.get(field, "*") in {"*", "-"}
        for field in (
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        )
    )


def resolve(
    product: str,
    version: str,
    *,
    part: str = "o",
    vendor: str = "",
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...]]:
    """Resolve an observed product to official CPE names without inventing one."""
    product = " ".join(str(product or "").split())
    version = " ".join(str(version or "").split())
    if not product:
        return tuple(), ({"reason": "cpe_product_missing", "matcher_status": "evidence_gap"},)

    cache_key = hashlib.sha256(
        f"{part}|{vendor.lower()}|{product.lower()}|{version.lower()}".encode("utf-8")
    ).hexdigest()
    cache = _load_cache()
    cached = cache.get(cache_key)
    try:
        ttl = max(60, int(os.getenv("NVD_CACHE_TTL_SECONDS", str(7 * 24 * 60 * 60))))
    except ValueError:
        ttl = 7 * 24 * 60 * 60
    if isinstance(cached, dict) and time.time() - float(cached.get("cached_at") or 0) < ttl:
        return tuple(cached.get("cpes") or []), tuple(cached.get("diagnostics") or [])

    expected_products = _product_forms(product)
    exact: list[str] = []
    queries: list[str] = []
    request_diagnostics: list[dict[str, Any]] = []

    def consume_query(query: str) -> bool:
        query = " ".join(str(query or "").split())
        if not query or query in queries:
            return True
        queries.append(query)
        data, diagnostic = _request({"keywordSearch": query, "resultsPerPage": 200})
        request_diagnostics.append(dict(diagnostic or {}))
        if data is None:
            return False
        for wrapper in data.get("products") or []:
            cpe_record = wrapper.get("cpe") or {}
            if cpe_record.get("deprecated"):
                continue
            cpe_name = str(cpe_record.get("cpeName") or "")
            parsed = parse_cpe(cpe_name)
            if not parsed or parsed.get("part") != part:
                continue
            title_forms = {
                form
                for title in cpe_record.get("titles") or []
                for form in _product_forms(
                    str(title.get("title") or title.get("value") or "")
                    if isinstance(title, dict)
                    else str(title)
                )
            }
            cpe_vendor = normalise_product(parsed.get("vendor", ""))
            expected_vendor = normalise_product(vendor)
            if expected_vendor and cpe_vendor and expected_vendor not in {cpe_vendor, cpe_vendor.removesuffix(" corporation").strip()} and cpe_vendor not in {expected_vendor, expected_vendor.removesuffix(" corporation").strip()}:
                continue
            cpe_version = parsed.get("version", "*")
            if not _version_compatible(version, cpe_version):
                continue
            strong_version = bool(version and concrete(cpe_version) and _numeric_parts(version) and _numeric_parts(cpe_version))
            product_exact = normalise_product(parsed.get("product", "")) in expected_products
            title_exact = bool(expected_products & title_forms)
            compatible_name = _product_compatible(product, parsed.get("product", ""), strong_version=strong_version)
            if not product_exact and not title_exact and not compatible_name:
                continue
            if not _generic_platform(parsed) and not title_exact and not strong_version:
                continue
            if cpe_name not in exact:
                exact.append(cpe_name)
        return True

    primary_query = " ".join(item for item in (vendor, product, version) if item)
    primary_ok = consume_query(primary_query)
    # Product display strings can contain edition/build labels that are absent
    # from the official CPE title.  When a strong numeric build was directly
    # observed, make one bounded official-dictionary fallback query anchored on
    # vendor + build.  Existing product-family and version-prefix checks still
    # decide whether any returned CPE is acceptable; no build/release table is
    # maintained locally.
    if not exact and len(_numeric_parts(version)) >= 3:
        fallback_query = " ".join(item for item in (vendor, version) if item)
        consume_query(fallback_query)

    if not primary_ok and not exact:
        diagnostic = request_diagnostics[0] if request_diagnostics else {"reason": "cpe_lookup_failed", "matcher_status": "unavailable"}
        return tuple(), (diagnostic,)

    cpes = tuple(dict.fromkeys(exact))
    diagnostics = ({
        "reason": "official_cpe_resolution",
        "matcher_status": "available",
        "queries": queries,
        "result_count": len(cpes),
        "resolution_basis": "official_cpe_product_identity_and_compatible_version",
        "fallback_used": len(queries) > 1,
    },)
    cache[cache_key] = {
        "cached_at": time.time(),
        "cpes": list(cpes),
        "diagnostics": list(diagnostics),
    }
    _save_cache(cache)
    return cpes, diagnostics
