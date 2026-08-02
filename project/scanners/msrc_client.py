from __future__ import annotations

"""Targeted Microsoft Security Update Guide / CVRF remediation client.

CVEProject remains the scanner's CVE applicability authority.  This module is
only consulted for Microsoft product remediation metadata after a canonical CVE
reference already exists.
"""

import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import requests

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
MSRC_ATTRIBUTION = "Microsoft Security Response Center Security Update Guide / CVRF API"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / "storage" / "msrc"
MONTH_DIR = CACHE_DIR / "months"
CVE_CACHE_FILE = CACHE_DIR / "cve_remediations.json"
CACHE_SCHEMA_VERSION = "msrc-remediation-v1"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_DELAY_SECONDS = 0.75

_lock = threading.Lock()
_last_request_at = 0.0


def enabled() -> bool:
    return os.getenv("MSRC_ENRICHMENT_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _ttl_seconds() -> int:
    try:
        return max(300, int(os.getenv("MSRC_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _timeout_seconds() -> float:
    try:
        return max(3.0, float(os.getenv("MSRC_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def _delay_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("MSRC_REQUEST_DELAY_SECONDS", str(DEFAULT_DELAY_SECONDS))))
    except ValueError:
        return DEFAULT_DELAY_SECONDS


def _wait() -> None:
    global _last_request_at
    with _lock:
        pause = _delay_seconds() - (time.monotonic() - _last_request_at)
        if pause > 0:
            time.sleep(pause)
        _last_request_at = time.monotonic()


def _headers(accept: str = "application/json") -> dict[str, str]:
    headers = {"Accept": accept, "User-Agent": "SP-FYP-AutoPenTest/WindowsPatchEvidence"}
    api_key = os.getenv("MSRC_API_KEY", "").strip()
    if api_key:
        headers["Api-Key"] = api_key
    return headers


def _request(url: str, accept: str = "application/json") -> tuple[bytes | None, dict[str, Any]]:
    _wait()
    try:
        response = requests.get(url, headers=_headers(accept), timeout=_timeout_seconds())
    except requests.RequestException as exc:
        return None, {"reason": "msrc_network_error", "status": "degraded", "error_type": type(exc).__name__}
    if response.status_code in {403, 429}:
        return None, {"reason": "msrc_rate_limited_or_forbidden", "status": "degraded", "http_status": response.status_code}
    if response.status_code >= 500:
        return None, {"reason": "msrc_service_unavailable", "status": "degraded", "http_status": response.status_code}
    if not response.ok:
        return None, {"reason": "msrc_http_error", "status": "error", "http_status": response.status_code}
    return response.content, {"content_type": response.headers.get("content-type", ""), "http_status": response.status_code}


def _load_cve_cache() -> dict[str, Any]:
    try:
        data = json.loads(CVE_CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cve_cache(data: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CVE_CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CVE_CACHE_FILE)


def _normalise_kb(value: Any) -> str:
    match = re.search(r"(?:KB)?\s*(\d{5,9})", str(value or ""), re.I)
    return f"KB{match.group(1)}" if match else ""


def _all_kbs(*values: Any) -> list[str]:
    found: set[str] = set()
    for value in values:
        text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or "")
        for digits in re.findall(r"(?:KB)?\s*(\d{5,9})", text, flags=re.I):
            found.add(f"KB{digits}")
    return sorted(found)


def _text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("Value", "value", "Description", "description", "Text", "text"):
            if key in value:
                return _text(value.get(key))
        return ""
    if isinstance(value, list):
        return " ".join(filter(None, (_text(v) for v in value)))
    return str(value or "").strip()


def _json_product_map(document: dict[str, Any]) -> dict[str, str]:
    product_map: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            product_id = str(node.get("ProductID") or node.get("productID") or node.get("productId") or "").strip()
            product_name = _text(node.get("Value") or node.get("FullProductName") or node.get("Name"))
            if product_id and product_name:
                product_map[product_id] = product_name
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document.get("ProductTree") or document.get("productTree") or {})
    return product_map


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_product_map(root: ET.Element) -> dict[str, str]:
    product_map: dict[str, str] = {}
    for element in root.iter():
        if _xml_local(element.tag) != "FullProductName":
            continue
        product_id = str(element.attrib.get("ProductID") or element.attrib.get("ProductId") or "").strip()
        name = " ".join("".join(element.itertext()).split())
        if product_id and name:
            product_map[product_id] = name
    return product_map


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _json_vulnerabilities(document: dict[str, Any]) -> list[dict[str, Any]]:
    value = document.get("Vulnerability") or document.get("Vulnerabilities") or []
    if isinstance(value, dict):
        value = value.get("Vulnerability") or value.get("vulnerability") or value
    return [row for row in _as_list(value) if isinstance(row, dict)]


def _json_remediations(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    value = vulnerability.get("Remediations") or vulnerability.get("remediations") or []
    if isinstance(value, dict):
        value = value.get("Remediation") or value.get("remediation") or []
    return [row for row in _as_list(value) if isinstance(row, dict)]


def _extract_json_remediations(document: dict[str, Any], cve_id: str, release_id: str) -> list[dict[str, Any]]:
    products = _json_product_map(document)
    out: list[dict[str, Any]] = []
    for vulnerability in _json_vulnerabilities(document):
        current = str(vulnerability.get("CVE") or vulnerability.get("cve") or "").strip().upper()
        if current != cve_id:
            continue
        title = _text(vulnerability.get("Title") or vulnerability.get("title"))
        for remediation in _json_remediations(vulnerability):
            product_ids = [str(v) for v in _as_list(remediation.get("ProductID") or remediation.get("productID") or remediation.get("productId")) if str(v).strip()]
            description = _text(remediation.get("Description") or remediation.get("description"))
            url = _text(remediation.get("URL") or remediation.get("url"))
            supers = _text(remediation.get("Supercedence") or remediation.get("supercedence") or remediation.get("Supersedence") or remediation.get("supersedence"))
            fixed_build = _text(remediation.get("FixedBuild") or remediation.get("fixedBuild") or remediation.get("fixed_build"))
            subtype = _text(remediation.get("SubType") or remediation.get("subType") or remediation.get("sub_type"))
            kbs = _all_kbs(description, url)
            if not product_ids:
                product_ids = [""]
            for product_id in product_ids:
                out.append({
                    "cve_id": cve_id,
                    "title": title,
                    "product_id": product_id,
                    "product": products.get(product_id, ""),
                    "kb": kbs[0] if kbs else "",
                    "kb_candidates": kbs,
                    "fixed_build": fixed_build,
                    "supercedence": supers,
                    "superceded_kbs": _all_kbs(supers),
                    "description": description,
                    "url": url,
                    "subtype": subtype,
                    "release_id": release_id,
                    "source": MSRC_ATTRIBUTION,
                })
    return out


def _child_text(element: ET.Element, name: str) -> str:
    for child in list(element):
        if _xml_local(child.tag) == name:
            return " ".join("".join(child.itertext()).split())
    return ""


def _extract_xml_remediations(content: bytes, cve_id: str, release_id: str) -> list[dict[str, Any]]:
    root = ET.fromstring(content)
    products = _xml_product_map(root)
    out: list[dict[str, Any]] = []
    for vulnerability in root.iter():
        if _xml_local(vulnerability.tag) != "Vulnerability":
            continue
        current = ""
        for child in list(vulnerability):
            if _xml_local(child.tag) == "CVE":
                current = " ".join("".join(child.itertext()).split()).upper()
                break
        if current != cve_id:
            continue
        title = _child_text(vulnerability, "Title")
        for remediation in vulnerability.iter():
            if _xml_local(remediation.tag) != "Remediation":
                continue
            description = _child_text(remediation, "Description")
            url = _child_text(remediation, "URL")
            supers = _child_text(remediation, "Supercedence") or _child_text(remediation, "Supersedence")
            fixed_build = _child_text(remediation, "FixedBuild")
            subtype = _child_text(remediation, "SubType")
            product_ids = [" ".join("".join(child.itertext()).split()) for child in remediation.iter() if _xml_local(child.tag) == "ProductID"]
            product_ids = [value for value in product_ids if value] or [""]
            kbs = _all_kbs(description, url)
            for product_id in product_ids:
                out.append({
                    "cve_id": cve_id,
                    "title": title,
                    "product_id": product_id,
                    "product": products.get(product_id, ""),
                    "kb": kbs[0] if kbs else "",
                    "kb_candidates": kbs,
                    "fixed_build": fixed_build,
                    "supercedence": supers,
                    "superceded_kbs": _all_kbs(supers),
                    "description": description,
                    "url": url,
                    "subtype": subtype,
                    "release_id": release_id,
                    "source": MSRC_ATTRIBUTION,
                })
    return out


def parse_cvrf_document(content: bytes, cve_id: str, release_id: str = "") -> list[dict[str, Any]]:
    cve_id = str(cve_id or "").strip().upper()
    stripped = content.lstrip()
    if stripped.startswith((b"{", b"[")):
        data = json.loads(content.decode("utf-8"))
        if isinstance(data, list):
            # The CVRF document itself is normally an object; tolerate a single
            # object wrapper if an intermediary serialises it as a list.
            data = data[0] if data and isinstance(data[0], dict) else {}
        return _extract_json_remediations(data if isinstance(data, dict) else {}, cve_id, release_id)
    return _extract_xml_remediations(content, cve_id, release_id)


def _release_ids_from_updates(payload: bytes) -> list[str]:
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception:
        return []
    rows = data.get("value") if isinstance(data, dict) else data
    ids: set[str] = set()
    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue
        for key in ("ID", "Id", "id", "Alias", "alias"):
            value = str(row.get(key) or "").strip()
            if re.fullmatch(r"20\d{2}-[A-Za-z]{3}", value):
                ids.add(value)
    return sorted(ids)


def _load_cached_month(release_id: str) -> bytes | None:
    for suffix in (".json", ".xml"):
        path = MONTH_DIR / f"{release_id}{suffix}"
        try:
            if path.exists() and time.time() - path.stat().st_mtime < _ttl_seconds():
                return path.read_bytes()
        except OSError:
            pass
    return None


def fetch_cvrf_month(release_id: str, *, force: bool = False) -> tuple[bytes | None, dict[str, Any]]:
    release_id = str(release_id or "").strip()
    if not re.fullmatch(r"20\d{2}-[A-Za-z]{3}", release_id):
        return None, {"reason": "invalid_msrc_release_id", "status": "held", "release_id": release_id}
    if not force:
        cached = _load_cached_month(release_id)
        if cached is not None:
            return cached, {"reason": "msrc_month_cache", "status": "available", "cache": "hit", "release_id": release_id}
    if not enabled():
        return None, {"reason": "msrc_enrichment_disabled", "status": "disabled", "release_id": release_id}

    url = f"{MSRC_BASE_URL}/cvrf/{quote(release_id)}"
    content, diagnostic = _request(url, "application/json, application/xml;q=0.9")
    if content is None:
        return None, {**diagnostic, "release_id": release_id}
    MONTH_DIR.mkdir(parents=True, exist_ok=True)
    suffix = ".json" if content.lstrip().startswith((b"{", b"[")) else ".xml"
    path = MONTH_DIR / f"{release_id}{suffix}"
    path.write_bytes(content)
    return content, {"reason": "msrc_month_fetch", "status": "available", "cache": "miss", "release_id": release_id, "file": str(path)}


def _release_ids_for_cve(cve_id: str) -> tuple[list[str], dict[str, Any]]:
    if not enabled():
        return [], {"reason": "msrc_enrichment_disabled", "status": "disabled", "cve_id": cve_id}
    # Microsoft documents the Updates OData lookup as the discovery step for a
    # CVE before retrieving one or more monthly CVRF documents.
    url = f"{MSRC_BASE_URL}/Updates('{quote(cve_id)}')"
    payload, diagnostic = _request(url, "application/json")
    if payload is None:
        return [], {**diagnostic, "cve_id": cve_id}
    release_ids = _release_ids_from_updates(payload)
    return release_ids, {"reason": "msrc_update_lookup", "status": "available", "cve_id": cve_id, "release_ids": release_ids}


def lookup_cve_remediations(cve_id: str, *, force: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return Microsoft remediation metadata for an already-matched CVE ID."""
    cve_id = str(cve_id or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        return [], {"reason": "invalid_cve_id", "status": "held", "cve_id": cve_id}

    cache = _load_cve_cache()
    cached = cache.get(cve_id) if isinstance(cache.get(cve_id), dict) else None
    now = time.time()
    if not force and cached and now - float(cached.get("cached_at") or 0) < _ttl_seconds():
        return list(cached.get("remediations") or []), {
            "reason": "msrc_cve_remediation_lookup",
            "status": "available",
            "cve_id": cve_id,
            "cache": "hit",
            "release_ids": list(cached.get("release_ids") or []),
        }

    release_ids, lookup_diag = _release_ids_for_cve(cve_id)
    # The Updates lookup is the discovery source, but Microsoft has historically
    # had cases where a CVE's newest monthly revision was not listed there.
    # Include already-cached monthly documents as a local completeness fallback;
    # this never invents a CVE or downloads unrelated data during the lookup.
    cached_release_ids = {path.stem for path in (list(MONTH_DIR.glob("*.json")) + list(MONTH_DIR.glob("*.xml"))) if re.fullmatch(r"20\d{2}-[A-Za-z]{3}", path.stem)} if MONTH_DIR.exists() else set()
    release_ids = sorted(set(release_ids) | cached_release_ids)
    if not release_ids:
        if cached:
            return list(cached.get("remediations") or []), {**lookup_diag, "cache_fallback": True}
        return [], lookup_diag

    remediations: list[dict[str, Any]] = []
    month_diagnostics: list[dict[str, Any]] = []
    for release_id in release_ids:
        content, month_diag = fetch_cvrf_month(release_id, force=force)
        month_diagnostics.append(month_diag)
        if content is None:
            continue
        try:
            remediations.extend(parse_cvrf_document(content, cve_id, release_id))
        except (ValueError, ET.ParseError, json.JSONDecodeError) as exc:
            month_diagnostics.append({"reason": "msrc_parse_error", "status": "degraded", "release_id": release_id, "error_type": type(exc).__name__})

    # Stable de-duplication without inventing a priority or score.
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in remediations:
        key = (str(row.get("product_id") or ""), str(row.get("product") or ""), str(row.get("kb") or ""), str(row.get("fixed_build") or ""), str(row.get("url") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    cache[cve_id] = {
        "schema": CACHE_SCHEMA_VERSION,
        "cached_at": now,
        "cached_at_utc": datetime.now(timezone.utc).isoformat(),
        "release_ids": release_ids,
        "remediations": deduped,
    }
    _save_cve_cache(cache)
    return deduped, {
        "reason": "msrc_cve_remediation_lookup",
        "status": "available" if deduped else "no_remediation_metadata",
        "cve_id": cve_id,
        "cache": "miss",
        "release_ids": release_ids,
        "remediation_count": len(deduped),
        "month_diagnostics": month_diagnostics,
    }


def sync_recent_months(month_ids: Iterable[str], *, force: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for month_id in month_ids:
        _content, diagnostic = fetch_cvrf_month(str(month_id), force=force)
        results.append(diagnostic)
    return {"source": MSRC_ATTRIBUTION, "months": results, "available": any(row.get("status") == "available" for row in results)}


def status() -> dict[str, Any]:
    month_files = list(MONTH_DIR.glob("*.json")) + list(MONTH_DIR.glob("*.xml")) if MONTH_DIR.exists() else []
    cache = _load_cve_cache()
    return {
        "source": MSRC_ATTRIBUTION,
        "api_base": MSRC_BASE_URL,
        "enabled": enabled(),
        "available": bool(month_files or cache),
        "cached_month_documents": len(month_files),
        "cached_cve_remediation_queries": len([k for k in cache if str(k).startswith("CVE-")]),
        "cache_directory": str(CACHE_DIR),
        "network_lookup": "enabled" if enabled() else "disabled",
    }
