from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path("storage/nvd_cache")
CACHE_FILE = CACHE_DIR / "service_queries.json"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_DELAY_SECONDS = 6.5
DEFAULT_TIMEOUT_SECONDS = 20
ATTRIBUTION = "This product uses the NVD API but is not endorsed or certified by the NVD."

_lock = threading.Lock()
_last_request_at = 0.0


def enabled() -> bool:
    return os.getenv("NVD_ENRICHMENT_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _cache_ttl() -> int:
    try:
        return max(60, int(os.getenv("NVD_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _delay_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("NVD_REQUEST_DELAY_SECONDS", str(DEFAULT_DELAY_SECONDS))))
    except ValueError:
        return DEFAULT_DELAY_SECONDS


def _timeout_seconds() -> float:
    try:
        return max(3.0, float(os.getenv("NVD_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def _load_cache() -> dict[str, Any]:
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def _cache_key(product: str, version: str, service: str, cpe: str) -> str:
    raw = "|".join((product.strip().lower(), version.strip().lower(), service.strip().lower(), cpe.strip().lower()))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return ""


def _metric(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") or {}
    for group in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(group) or []
        if not rows:
            continue
        row = rows[0] or {}
        data = row.get("cvssData") or {}
        return {
            "cvss_score": data.get("baseScore"),
            "cvss_severity": str(row.get("baseSeverity") or data.get("baseSeverity") or "").upper(),
            "cvss_vector": data.get("vectorString") or "",
            "cvss_source": row.get("source") or "NVD",
            "cvss_version": data.get("version") or "",
        }
    return {}


def _references(cve: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in cve.get("references") or []:
        url = item.get("url") if isinstance(item, dict) else None
        if url and url not in refs:
            refs.append(url)
    return refs[:10]


def _config_nodes(cve: dict[str, Any]) -> list[dict[str, Any]]:
    configs = cve.get("configurations") or []
    if isinstance(configs, dict):
        configs = [configs]
    return configs if isinstance(configs, list) else []


def _cpe_matches(cve: dict[str, Any], observed_cpe: str) -> bool:
    observed = [x.strip().lower() for x in observed_cpe.split() if x.strip().startswith("cpe:")]
    if not observed:
        return False
    stack = list(_config_nodes(cve))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        stack.extend(node.get("nodes") or [])
        for match in node.get("cpeMatch") or []:
            criteria = str(match.get("criteria") or match.get("cpe23Uri") or "").lower()
            if not criteria:
                continue
            for item in observed:
                # Exact CPE or same vendor/product/version prefix.
                if criteria == item or criteria.startswith(item.rstrip("*")) or item.startswith(criteria.rstrip("*")):
                    return True
    return False


def _keyword(product: str, version: str, service: str) -> str:
    product = " ".join(product.split())
    version = " ".join(version.split())
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    if service and version:
        return f"{service} {version}"
    return service


def _wait_for_rate_limit() -> None:
    global _last_request_at
    with _lock:
        wait = _delay_seconds() - (time.monotonic() - _last_request_at)
        if wait > 0:
            time.sleep(wait)
        _last_request_at = time.monotonic()


def _request(params: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    headers = {"User-Agent": "SP-FYP-AutoPenTest/1.0"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    _wait_for_rate_limit()
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=_timeout_seconds())
    except requests.RequestException as exc:
        return None, {"reason": "nvd_network_error", "matcher_status": "degraded", "error": str(exc)}

    if response.status_code in {403, 429}:
        return None, {
            "reason": "nvd_rate_limited",
            "matcher_status": "degraded",
            "http_status": response.status_code,
            "message": "NVD enrichment temporarily unavailable because the public rate limit was reached.",
        }
    if response.status_code >= 500:
        return None, {"reason": "nvd_service_unavailable", "matcher_status": "degraded", "http_status": response.status_code}
    if not response.ok:
        return None, {"reason": "nvd_http_error", "matcher_status": "error", "http_status": response.status_code}
    try:
        return response.json(), {}
    except ValueError:
        return None, {"reason": "nvd_invalid_json", "matcher_status": "error"}


def search(product: str, version: str, service: str, cpe: str = "") -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not enabled():
        return tuple(), ({"reason": "nvd_enrichment_disabled", "matcher_status": "disabled"},)

    query = _keyword(product, version, service)
    if not query or not version:
        return tuple(), ({"reason": "observed_version_missing", "matcher_status": "held"},)

    key = _cache_key(product, version, service, cpe)
    cache = _load_cache()
    cached = cache.get(key) if isinstance(cache.get(key), dict) else None
    now = time.time()
    if cached and now - float(cached.get("cached_at") or 0) < _cache_ttl():
        return tuple(cached.get("results") or []), tuple(cached.get("diagnostics") or [])

    params: dict[str, Any] = {"keywordSearch": query, "resultsPerPage": 200}
    data, diagnostic = _request(params)
    if data is None:
        if cached:
            fallback_diag = list(cached.get("diagnostics") or []) + [{**diagnostic, "cache_fallback": True}]
            return tuple(cached.get("results") or []), tuple(fallback_diag)
        return tuple(), (diagnostic,)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for wrapper in data.get("vulnerabilities") or []:
        cve = wrapper.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        exact_cpe = _cpe_matches(cve, cpe)
        rows.append({
            "cve_id": cve_id,
            "description": _english_description(cve),
            "references": _references(cve),
            "source": "Official CVE List via CVEProject/cvelistV5 (MITRE/CVE Program)",
            "upstream_source": "NVD CVE API 2.0",
            "matched_product_tokens": [product or service],
            "matched_version_tokens": [version],
            "match_basis": "nvd_exact_cpe" if exact_cpe else "nvd_keyword_product_version_candidate",
            "product_match_basis": "exact_cpe" if exact_cpe else "keyword_product_version",
            "nvd_candidate": not exact_cpe,
            **_metric(cve),
        })

    diagnostics: list[dict[str, Any]] = [{
        "reason": "nvd_targeted_enrichment",
        "matcher_status": "available",
        "query": query,
        "result_count": len(rows),
        "cache": "miss",
    }]
    cache[key] = {"cached_at": now, "query": query, "results": rows, "diagnostics": diagnostics}
    _save_cache(cache)
    return tuple(rows), tuple(diagnostics)


def status() -> dict[str, Any]:
    cache = _load_cache()
    return {
        "enabled": enabled(),
        "api_url": NVD_API_URL,
        "api_key_configured": bool(os.getenv("NVD_API_KEY", "").strip()),
        "cache_file": str(CACHE_FILE),
        "cached_queries": len(cache),
        "request_delay_seconds": _delay_seconds(),
        "cache_ttl_seconds": _cache_ttl(),
        "attribution": ATTRIBUTION,
    }
