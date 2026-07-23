from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import requests

from .scoring_policy import (
    ScoringPolicyError,
    normalise_cvss_version,
    validate_published_metric,
)
from . import nvd_repository


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "NIST National Vulnerability Database (NVD) CVE API 2.0"
CACHE_DIR = Path("storage/mitre_cve/nvd_metrics")
_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.I)
_METRIC_KEYS = {
    "3.1": "cvssMetricV31",
    "4.0": "cvssMetricV40",
}
_MAX_CVES_PER_REQUEST = 100


class NVDEnrichmentError(RuntimeError):
    """Raised when official NVD enrichment cannot be retrieved safely."""


def _cache_ttl_seconds() -> int:
    raw = os.getenv("NVD_CACHE_TTL_HOURS", "24").strip()
    try:
        hours = int(raw)
    except ValueError:
        hours = 24
    return max(1, min(hours, 24 * 365)) * 3600


def _cache_path(cve_id: str) -> Path:
    canonical = str(cve_id or "").strip().upper()
    if not _CVE_ID.fullmatch(canonical):
        raise ValueError("Invalid CVE identifier for NVD cache")
    return CACHE_DIR / f"{canonical}.json"


def _read_cache(cve_id: str) -> tuple[dict[str, Any], bool]:
    path = _cache_path(cve_id)
    if not path.exists():
        return {}, False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("cve_id") != str(cve_id).upper():
            return {}, False
        metrics = payload.get("metrics")
        if not isinstance(metrics, dict):
            return {}, False
        fetched_at = float(payload.get("fetched_at_epoch") or 0)
        fresh = fetched_at > 0 and (time.time() - fetched_at) <= _cache_ttl_seconds()
        return payload, fresh
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}, False


def _write_cache(cve_id: str, metrics: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cve_id)
    temporary = path.with_suffix(f".json.{os.getpid()}.tmp")
    payload = {
        "cache_schema_version": 1,
        "cve_id": str(cve_id).upper(),
        "source": NVD_SOURCE,
        "fetched_at_epoch": time.time(),
        "metrics": metrics,
    }
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _metric_rank(metric: dict[str, Any]) -> tuple[int, int, str]:
    metric_type = str(metric.get("type") or "").upper()
    source = str(metric.get("source") or "").lower()
    return (
        0 if metric_type == "PRIMARY" else 1,
        0 if "nvd" in source or "nist" in source else 1,
        source,
    )


def _extract_nvd_metrics(cve: dict[str, Any]) -> dict[str, dict[str, Any]]:
    metrics_node = cve.get("metrics") if isinstance(cve, dict) else {}
    if not isinstance(metrics_node, dict):
        return {}
    extracted: dict[str, dict[str, Any]] = {}
    for version, key in _METRIC_KEYS.items():
        candidates = [item for item in (metrics_node.get(key) or []) if isinstance(item, dict)]
        for candidate in sorted(candidates, key=_metric_rank):
            data = candidate.get("cvssData")
            if not isinstance(data, dict):
                continue
            if str(data.get("version") or "").strip() != version:
                continue
            score = data.get("baseScore")
            try:
                published = validate_published_metric(
                    version,
                    score,
                    data.get("baseSeverity") or candidate.get("baseSeverity"),
                    data.get("vectorString"),
                )
            except ScoringPolicyError:
                continue
            extracted[version] = {
                **published,
                "cvss_source": str(candidate.get("source") or "NVD"),
                "cvss_provider_role": f"NVD {str(candidate.get('type') or 'published').title()}",
                "cvss_enrichment_source": NVD_SOURCE,
                "cvss_record_url": f"https://nvd.nist.gov/vuln/detail/{str(cve.get('id') or '')}",
                "cvss_record_last_modified": str(cve.get("lastModified") or ""),
            }
            break
    return extracted


def _fetch_metrics(cve_ids: list[str]) -> dict[str, dict[str, dict[str, Any]]]:
    if not cve_ids:
        return {}
    if len(cve_ids) > _MAX_CVES_PER_REQUEST:
        raise ValueError("NVD CVE batch exceeds the documented 100-ID request limit")
    headers = {
        "Accept": "application/json",
        "User-Agent": "AutoPenTest-CVSS-Enrichment/1.0",
    }
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveIds": ",".join(cve_ids)},
            headers=headers,
            timeout=(3.05, float(os.getenv("NVD_API_TIMEOUT_SECONDS", "15"))),
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
        raise NVDEnrichmentError(f"{type(exc).__name__}: {exc}") from exc

    requested = set(cve_ids)
    found: dict[str, dict[str, dict[str, Any]]] = {}
    for wrapper in payload.get("vulnerabilities") or []:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "").upper()
        if cve_id in requested:
            found[cve_id] = _extract_nvd_metrics(cve)
    for cve_id in cve_ids:
        found.setdefault(cve_id, {})
    return found


def enrich_matches(
    matches: list[dict[str, Any]],
    selected_version: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fill only a missing selected-version metric from the official NVD API.

    CVE identity and applicability remain owned by the NVD CPE applicability
    matcher. This function never creates a CVE match, converts a score, or
    falls back to a different CVSS version.
    """
    version = normalise_cvss_version(selected_version)
    output = [dict(row) for row in matches]
    missing_ids = sorted({
        str(row.get("cve_id") or "").upper()
        for row in output
        if row.get("cvss_score") is None and _CVE_ID.fullmatch(str(row.get("cve_id") or ""))
    })
    if not missing_ids:
        return output, []

    cache: dict[str, dict[str, Any]] = {}
    stale_cache: dict[str, dict[str, Any]] = {}
    fetch_ids: list[str] = []
    for cve_id in missing_ids:
        repository_record = nvd_repository.get_record(cve_id)
        if repository_record:
            repository_metrics = _extract_nvd_metrics({'id': cve_id, **repository_record})
            if repository_metrics:
                cache[cve_id] = {
                    'cve_id': cve_id,
                    'source': NVD_SOURCE,
                    'metrics': repository_metrics,
                }
                continue
        payload, fresh = _read_cache(cve_id)
        if payload:
            (cache if fresh else stale_cache)[cve_id] = payload
        if not fresh:
            fetch_ids.append(cve_id)

    diagnostics: list[dict[str, Any]] = []
    deferred = fetch_ids[_MAX_CVES_PER_REQUEST:]
    fetch_ids = fetch_ids[:_MAX_CVES_PER_REQUEST]
    if deferred:
        diagnostics.append({
            "reason": "nvd_enrichment_batch_limit_reached",
            "matcher_status": "degraded",
            "record_count": len(deferred),
            "detail": "Additional uncached CVEs were left without enrichment to keep final report assembly bounded.",
        })

    if fetch_ids:
        try:
            fetched = _fetch_metrics(fetch_ids)
        except (NVDEnrichmentError, ValueError) as exc:
            diagnostics.append({
                "reason": "nvd_cvss_enrichment_unavailable",
                "matcher_status": "degraded",
                "error": str(exc),
                "record_count": len(fetch_ids),
            })
            for cve_id in fetch_ids:
                if cve_id in stale_cache:
                    cache[cve_id] = stale_cache[cve_id]
        else:
            cache_write_errors = 0
            for cve_id, metrics in fetched.items():
                cache[cve_id] = {
                    "cve_id": cve_id,
                    "source": NVD_SOURCE,
                    "metrics": metrics,
                }
                try:
                    _write_cache(cve_id, metrics)
                except OSError:
                    cache_write_errors += 1
            if cache_write_errors:
                diagnostics.append({
                    "reason": "nvd_cvss_cache_write_failed",
                    "matcher_status": "degraded",
                    "record_count": cache_write_errors,
                    "detail": "Metrics were used for this report but could not be written to the local cache.",
                })

    enriched_count = 0
    unavailable_count = 0
    for row in output:
        if row.get("cvss_score") is not None:
            continue
        cve_id = str(row.get("cve_id") or "").upper()
        metric = ((cache.get(cve_id) or {}).get("metrics") or {}).get(version)
        if not isinstance(metric, dict) or metric.get("cvss_score") is None:
            unavailable_count += 1
            continue
        row.update(metric)
        row["cvss_status"] = "published"
        row["cvss_available_versions"] = sorted(set(
            list(row.get("cvss_available_versions") or [])
            + list(((cache.get(cve_id) or {}).get("metrics") or {}).keys())
        ))
        row["cvss_enriched"] = True
        enriched_count += 1

    if enriched_count:
        diagnostics.append({
            "reason": "nvd_cvss_enrichment_applied",
            "matcher_status": "available",
            "record_count": enriched_count,
            "source": NVD_SOURCE,
            "cvss_version": version,
        })
    if unavailable_count:
        diagnostics.append({
            "reason": "selected_cvss_not_published_by_cve_list_or_nvd",
            "matcher_status": "available",
            "record_count": unavailable_count,
            "cvss_version": version,
        })
    return output, diagnostics
