from __future__ import annotations

"""CISA Known Exploited Vulnerabilities enrichment for already-matched CVEs.

This module never discovers or suppresses CVE applicability.  It only annotates
canonical scanner CVE references after the CVE Program matcher has emitted them.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Iterable

import requests

KEV_URL = os.getenv(
    "CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / "storage" / "cisa_kev"
CACHE_FILE = CACHE_DIR / "known_exploited_vulnerabilities.json"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
DEFAULT_TIMEOUT_SECONDS = 20
SOURCE = "CISA Known Exploited Vulnerabilities Catalog"


def enabled() -> bool:
    return os.getenv("CISA_KEV_ENRICHMENT_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _ttl_seconds() -> int:
    try:
        return max(300, int(os.getenv("CISA_KEV_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _timeout_seconds() -> float:
    try:
        return max(3.0, float(os.getenv("CISA_KEV_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))))
    except ValueError:
        return float(DEFAULT_TIMEOUT_SECONDS)


def _load_cache() -> dict[str, Any] | None:
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _cache_fresh() -> bool:
    try:
        return CACHE_FILE.exists() and time.time() - CACHE_FILE.stat().st_mtime < _ttl_seconds()
    except OSError:
        return False


def _save_cache(data: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(CACHE_FILE)


def _validate_catalog(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None
    # Keep CISA's document intact. Validation here only ensures the lookup key is
    # structurally available; it does not alter or infer any vulnerability fact.
    if any(not isinstance(row, dict) for row in vulnerabilities):
        return None
    return data


def load_catalog(*, force: bool = False) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    cached = _load_cache()
    if not enabled():
        return None, {
            "source": SOURCE,
            "status": "disabled",
            "cache": "present_but_unused" if cached else "none",
        }
    if not force and cached is not None and _cache_fresh():
        return cached, {
            "source": SOURCE,
            "status": "available",
            "cache": "hit",
            "catalog_version": str(cached.get("catalogVersion") or ""),
            "date_released": str(cached.get("dateReleased") or ""),
            "count": len(cached.get("vulnerabilities") or []),
        }

    try:
        response = requests.get(
            KEV_URL,
            headers={"Accept": "application/json", "User-Agent": "SP-FYP-AutoPenTest/KEV-Enrichment"},
            timeout=_timeout_seconds(),
        )
        response.raise_for_status()
        data = _validate_catalog(response.json())
        if data is None:
            raise ValueError("CISA KEV response did not match the expected catalog structure")
        _save_cache(data)
        return data, {
            "source": SOURCE,
            "status": "available",
            "cache": "miss",
            "catalog_version": str(data.get("catalogVersion") or ""),
            "date_released": str(data.get("dateReleased") or ""),
            "count": len(data.get("vulnerabilities") or []),
        }
    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
        if cached is not None:
            return cached, {
                "source": SOURCE,
                "status": "degraded",
                "cache": "stale_fallback",
                "error_type": type(exc).__name__,
                "count": len(cached.get("vulnerabilities") or []),
            }
        return None, {
            "source": SOURCE,
            "status": "unavailable",
            "cache": "none",
            "error_type": type(exc).__name__,
        }


def enrich_cve_rows(rows: Iterable[dict[str, Any]], *, force: bool = False) -> dict[str, Any]:
    """Annotate canonical CVE rows with CISA KEV facts, without changing matches."""
    catalog, diagnostic = load_catalog(force=force)
    if catalog is None:
        for row in rows:
            row["kev_status"] = "unavailable" if diagnostic.get("status") != "disabled" else "disabled"
            row["kev_listed"] = None
            row["kev_source"] = SOURCE
        return diagnostic

    by_cve = {
        str(item.get("cveID") or "").strip().upper(): item
        for item in catalog.get("vulnerabilities") or []
        if str(item.get("cveID") or "").strip()
    }
    for row in rows:
        cve_id = str(row.get("cve_id") or "").strip().upper()
        item = by_cve.get(cve_id)
        row["kev_source"] = SOURCE
        if not item:
            row["kev_status"] = "not_listed"
            row["kev_listed"] = False
            continue
        row["kev_status"] = "listed"
        row["kev_listed"] = True
        row["kev"] = {
            "cve_id": cve_id,
            "vendor_project": str(item.get("vendorProject") or ""),
            "product": str(item.get("product") or ""),
            "vulnerability_name": str(item.get("vulnerabilityName") or ""),
            "date_added": str(item.get("dateAdded") or ""),
            "due_date": str(item.get("dueDate") or ""),
            "known_ransomware_campaign_use": str(item.get("knownRansomwareCampaignUse") or ""),
            "required_action": str(item.get("requiredAction") or ""),
            "notes": str(item.get("notes") or ""),
            "source": SOURCE,
        }
    return diagnostic


def status() -> dict[str, Any]:
    cached = _load_cache()
    return {
        "source": SOURCE,
        "enabled": enabled(),
        "available": cached is not None,
        "cache_file": str(CACHE_FILE),
        "cache_fresh": _cache_fresh() if cached is not None else False,
        "catalog_version": str((cached or {}).get("catalogVersion") or ""),
        "date_released": str((cached or {}).get("dateReleased") or ""),
        "records": len((cached or {}).get("vulnerabilities") or []),
        "network_lookup": "enabled" if enabled() else "disabled",
    }
