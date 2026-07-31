from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import requests

from .cpe_utils import compare_versions, normalise_product


BASE = Path(__file__).resolve().parents[1] / "storage" / "msrc_windows"
INDEX = BASE / "official_msrc_windows_index.jsonl"
UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
DOCUMENT_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{document_id}"
SOURCE = "Microsoft Security Response Center CVRF"


def _windows_build_line(value: str) -> str:
    """Return the shared Windows build-family component in observed/MSRC data.

    NTLM may expose a major/minor/build tuple while MSRC fixed-build values add
    a revision. This compares the shared upstream value without embedding a
    build-to-release table.
    """
    parts = re.findall(r"\d+", str(value or ""))
    if len(parts) >= 3:
        return parts[2]
    if len(parts) in {1, 2}:
        return parts[0]
    return ""


def _compare_windows_build(observed: str, fixed: str) -> int | None:
    observed_parts = re.findall(r"\d+", str(observed or ""))
    fixed_parts = re.findall(r"\d+", str(fixed or ""))
    observed_line = _windows_build_line(observed)
    fixed_line = _windows_build_line(fixed)
    if observed_line and observed_line == fixed_line and len(fixed_parts) >= 3:
        observed_tail = observed_parts[2:] if len(observed_parts) >= 3 else observed_parts
        fixed_tail = fixed_parts[2:]
        return compare_versions(".".join(observed_tail), ".".join(fixed_tail))
    return compare_versions(observed, fixed)


def resolve_products_for_build(
    build: str,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Resolve Microsoft product candidates sharing an official build line.

    This intentionally returns candidates: NTLM build evidence alone does not
    establish edition, architecture, servicing revision, or installed KBs.
    Product names and build relationships come only from the local MSRC index.
    """
    observed_line = _windows_build_line(build)
    if not observed_line:
        return tuple(), ({
            "reason": "windows_build_line_unavailable",
            "matcher_status": "held",
            "observed_build": str(build or ""),
        },)
    if not INDEX.exists():
        return tuple(), ({
            "reason": "msrc_index_unavailable",
            "matcher_status": "unavailable",
            "observed_build": str(build or ""),
            "rebuild_command": "python scripts/rebuild_msrc_windows_index.py",
        },)

    candidates: dict[str, dict[str, Any]] = {}
    with INDEX.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            fixed_builds = [
                str(value) for value in row.get("fixed_builds") or []
                if _windows_build_line(str(value)) == observed_line
            ]
            product = str(row.get("product") or "").strip()
            product_key = str(row.get("product_normalised") or normalise_product(product))
            if not product or not product_key or not fixed_builds:
                continue
            candidate = candidates.setdefault(product_key, {
                "product": product,
                "product_normalised": product_key,
                "product_ids": set(),
                "document_ids": set(),
                "fixed_build_examples": set(),
                "source": SOURCE,
                "resolution_basis": "msrc_shared_windows_build_line",
                "observed_build": str(build or ""),
                "observed_build_line": observed_line,
            })
            if row.get("product_id"):
                candidate["product_ids"].add(str(row["product_id"]))
            if row.get("document_id"):
                candidate["document_ids"].add(str(row["document_id"]))
            candidate["fixed_build_examples"].update(fixed_builds)

    resolved: list[dict[str, Any]] = []
    for candidate in candidates.values():
        resolved.append({
            **candidate,
            "product_ids": sorted(candidate["product_ids"]),
            "document_ids": sorted(candidate["document_ids"]),
            "fixed_build_examples": sorted(candidate["fixed_build_examples"])[:20],
        })
    resolved.sort(key=lambda row: normalise_product(row.get("product")))
    return tuple(resolved), ({
        "reason": "msrc_windows_build_product_resolution",
        "matcher_status": "available",
        "observed_build": str(build or ""),
        "observed_build_line": observed_line,
        "candidate_product_count": len(resolved),
    },)


def _timeout() -> float:
    try:
        return max(5.0, float(os.getenv("MSRC_REQUEST_TIMEOUT_SECONDS", "45")))
    except ValueError:
        return 45.0


def _request_json(url: str) -> dict[str, Any]:
    response = requests.get(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SP-FYP-AutoPenTest/1.0",
        },
        timeout=_timeout(),
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"MSRC returned a non-object response for {url}")
    return data


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _scalar_text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("Value", "value", "Text", "text", "Description", "description", "CVE", "cve"):
            if key in value:
                text = _scalar_text(value.get(key))
                if text:
                    return text
        return ""
    if isinstance(value, list):
        return " ".join(filter(None, (_scalar_text(item) for item in value)))
    return str(value or "").strip()


def _string_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_string_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_string_values(child))
    else:
        text = str(value or "").strip()
        if text:
            values.append(text)
    return values


def _product_map(document: dict[str, Any]) -> dict[str, str]:
    products: dict[str, str] = {}
    tree = document.get("ProductTree") or document.get("productTree") or {}
    for node in _walk(tree):
        product_id = _scalar_text(node.get("ProductID") or node.get("productID") or node.get("productId"))
        name = _scalar_text(
            node.get("Value")
            or node.get("value")
            or node.get("FullProductName")
            or node.get("fullProductName")
            or node.get("Name")
            or node.get("name")
        )
        if product_id and name:
            products[product_id] = name
    return products


def _affected_product_ids(vulnerability: dict[str, Any]) -> set[str]:
    affected: set[str] = set()
    statuses = vulnerability.get("ProductStatuses") or vulnerability.get("productStatuses") or []
    for status in _walk(statuses):
        # CVRF JSON has appeared in both {KnownAffected:[ids]} and
        # {Type:"Known Affected", ProductID:[ids]} representations.
        for key, values in status.items():
            normalised_key = re.sub(r"[^a-z]", "", str(key).lower())
            if normalised_key in {"knownaffected", "affected"}:
                affected.update(_string_values(values))
        status_type = _scalar_text(status.get("Type") or status.get("type")).lower().replace("_", " ")
        if "affected" not in status_type or "not affected" in status_type:
            continue
        values = (
            status.get("ProductID")
            or status.get("productID")
            or status.get("productId")
            or status.get("Products")
            or status.get("products")
            or []
        )
        affected.update(_string_values(values))
    return {value for value in affected if value}


def _remediations(vulnerability: dict[str, Any], product_id: str) -> dict[str, Any]:
    kb_ids: set[str] = set()
    supersedes: set[str] = set()
    fixed_builds: set[str] = set()
    urls: set[str] = set()
    rows = vulnerability.get("Remediations") or vulnerability.get("remediations") or []
    for remediation in _walk(rows):
        if not any(
            key in remediation
            for key in (
                "ProductID", "productID", "Products", "products",
                "FixedBuild", "fixedBuild", "URL", "url",
            )
        ):
            continue
        product_ids = _string_values(
            remediation.get("ProductID")
            or remediation.get("productID")
            or remediation.get("productId")
            or remediation.get("Products")
            or remediation.get("products")
            or []
        )
        if product_ids and product_id not in set(product_ids):
            continue
        description = _scalar_text(remediation.get("Description") or remediation.get("description"))
        fixed = _scalar_text(remediation.get("FixedBuild") or remediation.get("fixedBuild"))
        url = _scalar_text(remediation.get("URL") or remediation.get("url"))
        supersedence_values = _string_values(
            remediation.get("Supercedence")
            or remediation.get("supercedence")
            or remediation.get("Supersedence")
            or remediation.get("supersedence")
            or []
        )
        text = " ".join([description, url, fixed, *supersedence_values])
        kb_ids.update(match.upper() for match in re.findall(r"\bKB\d{5,8}\b", text, re.I))
        if fixed:
            fixed_builds.add(fixed)
        for value in supersedence_values:
            supersedes.update(match.upper() for match in re.findall(r"\bKB\d{5,8}\b", value, re.I))
        if url:
            urls.add(url)
    return {
        "kb_ids": sorted(kb_ids),
        "supersedes": sorted(supersedes),
        "fixed_builds": sorted(fixed_builds),
        "references": sorted(urls),
    }


def _document_rows(document: dict[str, Any], document_id: str) -> list[dict[str, Any]]:
    products = _product_map(document)
    vulnerabilities: list[dict[str, Any]] = []
    direct = document.get("Vulnerability") or document.get("vulnerability") or []
    if isinstance(direct, dict):
        direct = [direct]
    vulnerabilities.extend(item for item in direct if isinstance(item, dict))
    if not vulnerabilities:
        # Tolerate an API wrapper around the CVRF document without assuming a
        # wrapper name. A dictionary is a vulnerability only when it contains a
        # concrete CVE identifier and product-status data.
        for node in _walk(document):
            cve_text = _scalar_text(node.get("CVE") or node.get("cve")).upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_text) and ("ProductStatuses" in node or "productStatuses" in node):
                vulnerabilities.append(node)
    rows: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = _scalar_text(vulnerability.get("CVE") or vulnerability.get("cve")).upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue
        for product_id in sorted(_affected_product_ids(vulnerability)):
            product_name = products.get(product_id, "")
            if not product_name:
                continue
            remediation = _remediations(vulnerability, product_id)
            rows.append({
                "cve_id": cve_id,
                "product_id": product_id,
                "product": product_name,
                "product_normalised": normalise_product(product_name),
                "document_id": document_id,
                "source": SOURCE,
                **remediation,
            })
    return rows


def _xml_local(tag: str) -> str:
    return str(tag or "").rsplit("}", 1)[-1]


def _xml_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def _xml_product_map(root: ET.Element) -> dict[str, str]:
    products: dict[str, str] = {}
    for element in root.iter():
        if _xml_local(element.tag) != "FullProductName":
            continue
        product_id = str(element.attrib.get("ProductID") or element.attrib.get("ProductId") or "").strip()
        name = _xml_text(element)
        if product_id and name:
            products[product_id] = name
    return products


def _xml_affected_product_ids(vulnerability: ET.Element) -> set[str]:
    affected: set[str] = set()
    for element in vulnerability.iter():
        local = re.sub(r"[^a-z]", "", _xml_local(element.tag).lower())
        if local == "status":
            status_type = str(element.attrib.get("Type") or element.attrib.get("type") or "").lower()
            if "affected" not in status_type or "not affected" in status_type:
                continue
            for child in element.iter():
                if _xml_local(child.tag) == "ProductID":
                    value = _xml_text(child)
                    if value:
                        affected.add(value)
        elif local in {"knownaffected", "affected"}:
            for child in element.iter():
                if _xml_local(child.tag) == "ProductID":
                    value = _xml_text(child)
                    if value:
                        affected.add(value)
    return affected


def _xml_child_text(element: ET.Element, name: str) -> str:
    for child in list(element):
        if _xml_local(child.tag) == name:
            return _xml_text(child)
    return ""


def _xml_remediations(vulnerability: ET.Element, product_id: str) -> dict[str, Any]:
    kb_ids: set[str] = set()
    supersedes: set[str] = set()
    fixed_builds: set[str] = set()
    urls: set[str] = set()
    for remediation in vulnerability.iter():
        if _xml_local(remediation.tag) != "Remediation":
            continue
        product_ids = {
            _xml_text(child)
            for child in remediation.iter()
            if _xml_local(child.tag) == "ProductID" and _xml_text(child)
        }
        if product_ids and product_id not in product_ids:
            continue
        description = _xml_child_text(remediation, "Description")
        url = _xml_child_text(remediation, "URL")
        fixed = _xml_child_text(remediation, "FixedBuild")
        supersedence = _xml_child_text(remediation, "Supercedence") or _xml_child_text(remediation, "Supersedence")
        text = " ".join((description, url, fixed, supersedence))
        kb_ids.update(match.upper() for match in re.findall(r"\bKB\d{5,8}\b", text, re.I))
        supersedes.update(match.upper() for match in re.findall(r"\bKB\d{5,8}\b", supersedence, re.I))
        if fixed:
            fixed_builds.add(fixed)
        if url:
            urls.add(url)
    return {
        "kb_ids": sorted(kb_ids),
        "supersedes": sorted(supersedes),
        "fixed_builds": sorted(fixed_builds),
        "references": sorted(urls),
    }


def _document_rows_xml(content: bytes, document_id: str) -> list[dict[str, Any]]:
    root = ET.fromstring(content)
    products = _xml_product_map(root)
    rows: list[dict[str, Any]] = []
    for vulnerability in root.iter():
        if _xml_local(vulnerability.tag) != "Vulnerability":
            continue
        cve_id = ""
        for child in list(vulnerability):
            if _xml_local(child.tag) == "CVE":
                cve_id = _xml_text(child).upper()
                break
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue
        for product_id in sorted(_xml_affected_product_ids(vulnerability)):
            product_name = products.get(product_id, "")
            if not product_name:
                continue
            rows.append({
                "cve_id": cve_id,
                "product_id": product_id,
                "product": product_name,
                "product_normalised": normalise_product(product_name),
                "document_id": document_id,
                "source": SOURCE,
                **_xml_remediations(vulnerability, product_id),
            })
    return rows


def _request_document(url: str) -> bytes:
    response = requests.get(
        url,
        headers={
            "Accept": "application/xml, application/json;q=0.9",
            "User-Agent": "SP-FYP-AutoPenTest/1.0",
        },
        timeout=_timeout(),
    )
    response.raise_for_status()
    return response.content


def _document_rows_from_content(content: bytes, document_id: str) -> list[dict[str, Any]]:
    stripped = content.lstrip()
    if stripped.startswith((b"{", b"[")):
        data = json.loads(content.decode("utf-8"))
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else {}
        return _document_rows(data if isinstance(data, dict) else {}, document_id)
    return _document_rows_xml(content, document_id)


def _update_documents(updates: dict[str, Any], start_year: int) -> list[str]:
    values = updates.get("value") or updates.get("Value") or updates.get("Updates") or []
    document_ids: list[str] = []
    for update in values:
        if not isinstance(update, dict):
            continue
        document_id = str(
            update.get("ID")
            or update.get("Id")
            or update.get("id")
            or update.get("Alias")
            or update.get("alias")
            or ""
        ).strip()
        if not document_id:
            continue
        year_match = re.search(r"\b(20\d{2})\b", " ".join(map(str, update.values())))
        if year_match and int(year_match.group(1)) < start_year:
            continue
        document_ids.append(document_id)
    return list(dict.fromkeys(document_ids))


def build_index(start_year: int | None = None) -> dict[str, Any]:
    if start_year is None:
        start_year = max(2000, date.today().year - 10)
    updates = _request_json(UPDATES_URL)
    document_ids = _update_documents(updates, int(start_year))
    BASE.mkdir(parents=True, exist_ok=True)
    temporary = INDEX.with_suffix(".tmp")
    count = 0
    documents_processed = 0
    try:
        with temporary.open("w", encoding="utf-8") as output:
            for document_id in document_ids:
                content = _request_document(DOCUMENT_URL.format(document_id=document_id))
                documents_processed += 1
                for row in _document_rows_from_content(content, document_id):
                    output.write(json.dumps(row, ensure_ascii=False) + "\n")
                    count += 1
        if documents_processed and count == 0:
            raise RuntimeError(
                "MSRC documents were retrieved but no affected-product records were parsed; "
                "the existing advisory index was preserved rather than replacing it with an empty index."
            )
        temporary.replace(INDEX)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return {
        "source": SOURCE,
        "start_year": int(start_year),
        "documents_processed": documents_processed,
        "records_indexed": count,
        "index_file": str(INDEX),
        "atomic_rebuild": True,
    }


def status() -> dict[str, Any]:
    records = 0
    if INDEX.exists():
        with INDEX.open("r", encoding="utf-8", errors="ignore") as stream:
            records = sum(1 for line in stream if line.strip())
    return {
        "source": SOURCE,
        "available": records > 0,
        "records_indexed": records,
        "index_file": str(INDEX),
        "rebuild_command": "python scripts/rebuild_msrc_windows_index.py",
    }


def search(
    product: str,
    build: str,
    installed_kbs: Iterable[str] = (),
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    if not INDEX.exists():
        return tuple(), ({
            "reason": "msrc_index_unavailable",
            "matcher_status": "unavailable",
            "rebuild_command": "python scripts/rebuild_msrc_windows_index.py",
        },)
    product_key = normalise_product(product)
    installed = {str(value).upper() for value in installed_kbs}
    matches: list[dict[str, Any]] = []
    with INDEX.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("product_normalised") != product_key:
                continue
            remediation_kbs = {str(value).upper() for value in row.get("kb_ids") or []}
            if installed and remediation_kbs & installed:
                continue
            fixed_builds = [str(value) for value in row.get("fixed_builds") or []]
            applicable_builds = [
                fixed
                for fixed in fixed_builds
                if _compare_windows_build(build, fixed) == -1
            ]
            if not applicable_builds:
                continue
            matches.append({
                **row,
                "match_basis": "msrc_observed_build_below_fixed_build",
                "observed_build": build,
                "installed_kb_inventory_observed": bool(installed),
            })
    deduplicated = {
        (str(row.get("cve_id")), str(row.get("product_id"))): row
        for row in matches
    }
    return tuple(deduplicated.values()), ({
        "reason": "msrc_windows_advisory_match",
        "matcher_status": "available",
        "result_count": len(deduplicated),
    },)
