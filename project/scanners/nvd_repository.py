from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "NIST National Vulnerability Database (NVD) CVE API 2.0"
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."
REPOSITORY = Path("storage/mitre_cve/nvd_repository.sqlite3")
SCHEMA_VERSION = 2
DEFAULT_RESULTS_PER_PAGE = 2000


class NVDRepositoryError(RuntimeError):
    pass


def _connect() -> sqlite3.Connection:
    REPOSITORY.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(REPOSITORY, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            source_identifier TEXT NOT NULL DEFAULT '',
            vuln_status TEXT NOT NULL DEFAULT '',
            published TEXT NOT NULL DEFAULT '',
            last_modified TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            configurations_json TEXT NOT NULL DEFAULT '[]',
            affected_json TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS cpe_criteria (
            cve_id TEXT NOT NULL,
            configuration_index INTEGER NOT NULL,
            vulnerable INTEGER NOT NULL,
            criteria TEXT NOT NULL,
            match_criteria_id TEXT NOT NULL DEFAULT '',
            part TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            product TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            version_start_including TEXT NOT NULL DEFAULT '',
            version_start_excluding TEXT NOT NULL DEFAULT '',
            version_end_including TEXT NOT NULL DEFAULT '',
            version_end_excluding TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (cve_id, configuration_index, criteria, match_criteria_id),
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS cpe_vendor_product
            ON cpe_criteria(part, vendor, product, vulnerable);
        CREATE TABLE IF NOT EXISTS cpe_queries (
            query_hash TEXT PRIMARY KEY,
            cpe_name TEXT NOT NULL,
            queried_at_epoch REAL NOT NULL,
            cve_ids_json TEXT NOT NULL,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()
    return connection


def _meta(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return str(row[0]) if row else default


def _set_meta(connection: sqlite3.Connection, key: str, value: Any) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
        (key, str(value)),
    )


def _english(items: Iterable[dict[str, Any]]) -> str:
    rows = [item for item in items if isinstance(item, dict)]
    for item in rows:
        if str(item.get("lang") or "").lower().startswith("en"):
            return str(item.get("value") or "")
    return str(rows[0].get("value") or "") if rows else ""


def _split_escaped(value: str, delimiter: str = ":") -> list[str]:
    """Split a CPE binding without treating escaped delimiters as separators."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == delimiter:
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _cpe_parts(value: str) -> tuple[str, ...] | None:
    """Return the eleven CPE 2.3 attributes from formatted or URI binding."""
    raw = str(value or "").strip()
    if raw.lower().startswith("cpe:2.3:"):
        parts = _split_escaped(raw)
        if len(parts) != 13 or [item.lower() for item in parts[:2]] != ["cpe", "2.3"]:
            return None
        return tuple(parts[2:13])
    if raw.lower().startswith("cpe:/"):
        # Nmap commonly emits the CPE 2.2 URI binding. Convert its seven
        # components into the equivalent CPE 2.3 formatted-string attributes.
        legacy = [unquote(item) for item in _split_escaped(raw[5:])]
        if not 1 <= len(legacy) <= 7:
            return None
        legacy += ["*"] * (7 - len(legacy))
        part, vendor, product, version, update, edition, language = legacy
        sw_edition = target_sw = target_hw = other = "*"
        if edition.startswith("~"):
            packed = edition[1:].split("~")
            packed += [""] * (5 - len(packed))
            edition, sw_edition, target_sw, target_hw, other = packed[:5]
        return tuple(
            item if item else "*"
            for item in (
                part, vendor, product, version, update, edition, language,
                sw_edition, target_sw, target_hw, other,
            )
        )
    return None


def normalise_cpe23(value: str) -> str:
    parts = _cpe_parts(value)
    if not parts:
        return ""
    if parts[0].lower() not in {"a", "h", "o"}:
        return ""
    return "cpe:2.3:" + ":".join(part if part else "*" for part in parts)


def concrete_cpe23(value: str) -> str:
    """Return a query-eligible CPE Name or an empty string.

    The NVD CVE API requires concrete part, vendor, product and version
    attributes for ``cpeName`` matching. This deliberately does not infer any
    missing attribute from a banner, service name or port.
    """
    canonical = normalise_cpe23(value)
    parts = _cpe_parts(canonical)
    if not parts or any(parts[index] in {"", "*", "-"} for index in (0, 1, 2, 3)):
        return ""
    return canonical


def cpe_attributes(value: str) -> tuple[str, ...] | None:
    """Expose parsed CPE 2.3 attributes without permitting identity inference."""
    canonical = normalise_cpe23(value)
    return _cpe_parts(canonical) if canonical else None


def _criteria_rows(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def walk(node: Any, configuration_index: int) -> None:
        if not isinstance(node, dict):
            return
        for item in node.get("cpeMatch") or node.get("cpe_match") or []:
            if not isinstance(item, dict):
                continue
            criteria = str(item.get("criteria") or item.get("cpe23Uri") or "")
            parts = _cpe_parts(criteria) or ("",) * 11
            rows.append({
                "configuration_index": configuration_index,
                "vulnerable": 1 if item.get("vulnerable") else 0,
                "criteria": criteria,
                "match_criteria_id": str(item.get("matchCriteriaId") or ""),
                "part": parts[0],
                "vendor": parts[1],
                "product": parts[2],
                "version": parts[3],
                "version_start_including": str(item.get("versionStartIncluding") or ""),
                "version_start_excluding": str(item.get("versionStartExcluding") or ""),
                "version_end_including": str(item.get("versionEndIncluding") or ""),
                "version_end_excluding": str(item.get("versionEndExcluding") or ""),
            })
        for child in (node.get("nodes") or []) + (node.get("children") or []):
            walk(child, configuration_index)

    for index, configuration in enumerate(configurations or []):
        walk(configuration, index)
    return rows


def _record_from_cve(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(cve.get("id") or "").upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError("NVD record has no valid CVE identifier")
    references = [
        str(row.get("url"))
        for row in cve.get("references") or []
        if isinstance(row, dict) and row.get("url")
    ]
    return {
        "cve_id": cve_id,
        "source_identifier": str(cve.get("sourceIdentifier") or ""),
        "vuln_status": str(cve.get("vulnStatus") or ""),
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "description": _english(cve.get("descriptions") or []),
        "metrics": cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {},
        "configurations": cve.get("configurations") if isinstance(cve.get("configurations"), list) else [],
        "affected": cve.get("affected") if isinstance(cve.get("affected"), list) else [],
        "references": list(dict.fromkeys(references))[:50],
    }


def _upsert_records(connection: sqlite3.Connection, cves: Iterable[dict[str, Any]]) -> int:
    count = 0
    for cve in cves:
        try:
            record = _record_from_cve(cve)
        except (TypeError, ValueError):
            continue
        connection.execute(
            """
            INSERT INTO cves(
                cve_id, source_identifier, vuln_status, published, last_modified,
                description, metrics_json, configurations_json, affected_json, references_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                source_identifier=excluded.source_identifier,
                vuln_status=excluded.vuln_status,
                published=excluded.published,
                last_modified=excluded.last_modified,
                description=excluded.description,
                metrics_json=excluded.metrics_json,
                configurations_json=excluded.configurations_json,
                affected_json=excluded.affected_json,
                references_json=excluded.references_json
            """,
            (
                record["cve_id"], record["source_identifier"], record["vuln_status"],
                record["published"], record["last_modified"], record["description"],
                json.dumps(record["metrics"], separators=(",", ":")),
                json.dumps(record["configurations"], separators=(",", ":")),
                json.dumps(record["affected"], separators=(",", ":")),
                json.dumps(record["references"], separators=(",", ":")),
            ),
        )
        connection.execute("DELETE FROM cpe_criteria WHERE cve_id = ?", (record["cve_id"],))
        for criterion in _criteria_rows(record["configurations"]):
            connection.execute(
                """
                INSERT OR REPLACE INTO cpe_criteria(
                    cve_id, configuration_index, vulnerable, criteria, match_criteria_id,
                    part, vendor, product, version, version_start_including,
                    version_start_excluding, version_end_including, version_end_excluding
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (record["cve_id"],) + tuple(criterion[key] for key in (
                    "configuration_index", "vulnerable", "criteria", "match_criteria_id",
                    "part", "vendor", "product", "version", "version_start_including",
                    "version_start_excluding", "version_end_including", "version_end_excluding",
                )),
            )
        count += 1
    return count


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "AutoPenTest-NVD-Repository/1.0"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _request(params: list[tuple[str, str]] | dict[str, Any]) -> dict[str, Any]:
    response = None
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=_headers(),
                timeout=(3.05, float(os.getenv("NVD_API_TIMEOUT_SECONDS", "45"))),
            )
            if response.status_code == 429 or 500 <= response.status_code < 600:
                if attempt < 3:
                    retry_after = response.headers.get("Retry-After", "").strip()
                    try:
                        wait_seconds = float(retry_after) if retry_after else min(60.0, 2.0 ** (attempt + 1))
                    except ValueError:
                        wait_seconds = min(60.0, 2.0 ** (attempt + 1))
                    time.sleep(max(_delay(), wait_seconds))
                    continue
            response.raise_for_status()
            payload = response.json()
            break
        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(min(60.0, 2.0 ** (attempt + 1)))
                continue
            raise NVDRepositoryError(f"{type(exc).__name__}: {exc}") from exc
    else:
        raise NVDRepositoryError(f"NVD request failed: {last_error}")
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise NVDRepositoryError("NVD API returned an unexpected response schema")
    return payload


def _delay() -> float:
    configured = os.getenv("NVD_API_DELAY_SECONDS", "").strip()
    if configured:
        try:
            return max(0.6, float(configured))
        except ValueError:
            pass
    return 0.7 if os.getenv("NVD_API_KEY", "").strip() else 6.1


def _ingest_payload(connection: sqlite3.Connection, payload: dict[str, Any]) -> int:
    cves = []
    for wrapper in payload.get("vulnerabilities") or []:
        if isinstance(wrapper, dict) and isinstance(wrapper.get("cve"), dict):
            cves.append(wrapper["cve"])
    count = _upsert_records(connection, cves)
    connection.commit()
    return count


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def sync(*, full: bool = False, max_pages: int | None = None) -> dict[str, Any]:
    """Populate or incrementally update the complete local NVD repository.

    The initial population follows NVD offset pagination. Updates use bounded
    last-modified windows, never a hand-maintained CVE subset.
    """
    connection = _connect()
    started = datetime.now(timezone.utc)
    pages = 0
    received = 0
    try:
        has_complete = _meta(connection, "full_sync_complete") == "true"
        last_success = _parse_iso(_meta(connection, "last_successful_update"))
        initial = full or not has_complete or last_success is None
        windows: list[tuple[datetime | None, datetime | None]] = []
        if initial:
            windows.append((None, None))
        else:
            cursor = last_success - timedelta(minutes=5)
            end = started
            while cursor < end:
                window_end = min(cursor + timedelta(days=119), end)
                windows.append((cursor, window_end))
                cursor = window_end

        for window_number, (window_start, window_end) in enumerate(windows):
            resume_index = int(_meta(connection, "sync_progress_start_index", "0") or 0)
            start_index = resume_index if initial and not full and window_number == 0 else 0
            while True:
                params: dict[str, Any] = {
                    "resultsPerPage": DEFAULT_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                if window_start and window_end:
                    params["lastModStartDate"] = _iso(window_start)
                    params["lastModEndDate"] = _iso(window_end)
                payload = _request(params)
                received += _ingest_payload(connection, payload)
                pages += 1
                total = int(payload.get("totalResults") or 0)
                page_size = int(payload.get("resultsPerPage") or len(payload.get("vulnerabilities") or []))
                start_index += page_size
                _set_meta(connection, "sync_progress_start_index", start_index)
                _set_meta(connection, "source_total_results", total)
                connection.commit()
                if start_index >= total or page_size <= 0:
                    break
                if max_pages is not None and pages >= max_pages:
                    raise NVDRepositoryError("NVD sync stopped at the requested page limit before completion")
                time.sleep(_delay())

        _set_meta(connection, "last_successful_update", _iso(started))
        _set_meta(connection, "last_update_error", "")
        _set_meta(connection, "sync_progress_start_index", "0")
        if initial:
            _set_meta(connection, "full_sync_complete", "true")
        connection.commit()
        return status(connection)
    except Exception as exc:
        _set_meta(connection, "last_update_error", f"{type(exc).__name__}: {exc}")
        connection.commit()
        raise
    finally:
        connection.close()


def _decode_record(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "cve_id": row["cve_id"],
        "source_identifier": row["source_identifier"],
        "vuln_status": row["vuln_status"],
        "published": row["published"],
        "last_modified": row["last_modified"],
        "description": row["description"],
        "metrics": json.loads(row["metrics_json"] or "{}"),
        "configurations": json.loads(row["configurations_json"] or "[]"),
        "affected": json.loads(row["affected_json"] or "[]"),
        "references": json.loads(row["references_json"] or "[]"),
    }


def get_record(cve_id: str) -> dict[str, Any]:
    if not REPOSITORY.exists():
        return {}
    connection = _connect()
    try:
        return _decode_record(connection.execute("SELECT * FROM cves WHERE cve_id = ?", (str(cve_id).upper(),)).fetchone())
    finally:
        connection.close()


def _query_ttl() -> float:
    try:
        hours = int(os.getenv("NVD_APPLICABILITY_CACHE_TTL_HOURS", "24"))
    except ValueError:
        hours = 24
    return max(1, min(hours, 24 * 365)) * 3600.0


def query_vulnerable_cpe(cpe_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Ask NVD to perform its own CPE applicability match and cache the result."""
    canonical = concrete_cpe23(cpe_name)
    parts = _cpe_parts(canonical)
    if not canonical or not parts:
        return [], {"status": "not_evaluated", "reason": "concrete_cpe_required"}
    query_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    connection = _connect()
    try:
        cached = connection.execute("SELECT * FROM cpe_queries WHERE query_hash = ?", (query_hash,)).fetchone()
        if cached and (time.time() - float(cached["queried_at_epoch"])) <= _query_ttl():
            ids = json.loads(cached["cve_ids_json"] or "[]")
            records = [
                _decode_record(connection.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone())
                for cve_id in ids
            ]
            return [row for row in records if row], {
                "status": "available", "reason": "nvd_cpe_query_cache", "record_count": len(ids), "cpe": canonical,
                "authoritative_query_verified": True,
            }

        vulnerabilities: list[dict[str, Any]] = []
        start_index = 0
        while True:
            payload = _request([
                ("cpeName", canonical),
                ("isVulnerable", ""),
                ("noRejected", ""),
                ("resultsPerPage", str(DEFAULT_RESULTS_PER_PAGE)),
                ("startIndex", str(start_index)),
            ])
            vulnerabilities.extend(payload.get("vulnerabilities") or [])
            page_size = int(payload.get("resultsPerPage") or len(payload.get("vulnerabilities") or []))
            total = int(payload.get("totalResults") or 0)
            start_index += page_size
            if page_size <= 0 or start_index >= total:
                break
            time.sleep(_delay())
        payload = {"vulnerabilities": vulnerabilities}
        _ingest_payload(connection, payload)
        ids = [
            str(wrapper.get("cve", {}).get("id") or "").upper()
            for wrapper in payload.get("vulnerabilities") or []
            if isinstance(wrapper, dict) and wrapper.get("cve", {}).get("id")
        ]
        connection.execute(
            "INSERT OR REPLACE INTO cpe_queries(query_hash, cpe_name, queried_at_epoch, cve_ids_json, source) VALUES(?, ?, ?, ?, ?)",
            (query_hash, canonical, time.time(), json.dumps(ids), NVD_SOURCE),
        )
        connection.commit()
        records = [
            _decode_record(connection.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone())
            for cve_id in ids
        ]
        return [row for row in records if row], {
            "status": "available", "reason": "nvd_cpe_query_applied", "record_count": len(ids), "cpe": canonical,
            "authoritative_query_verified": True,
        }
    except NVDRepositoryError as exc:
        local_ids = [row[0] for row in connection.execute(
            """
            SELECT DISTINCT cve_id FROM cpe_criteria
            WHERE vulnerable = 1 AND part = ? AND vendor = ? AND product = ? AND version = ?
            """,
            parts[:4],
        ).fetchall()]
        local_records = [
            _decode_record(connection.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone())
            for cve_id in local_ids
        ]
        return [row for row in local_records if row], {
            "status": "degraded",
            "reason": "nvd_cpe_query_unavailable_local_exact_data_used" if local_records else "nvd_cpe_query_unavailable",
            "error": str(exc),
            "cpe": canonical,
            "record_count": len(local_records),
            "authoritative_query_verified": False,
        }
    finally:
        connection.close()


def _criterion_truth(
    item: dict[str, Any],
    observed_cpes: set[str],
    primary_cpe: str,
    primary_query_verified: bool,
) -> tuple[str, str]:
    criteria = normalise_cpe23(str(item.get("criteria") or item.get("cpe23Uri") or ""))
    if not criteria:
        return "unknown", "malformed CPE criterion"
    criterion_parts = _cpe_parts(criteria)
    primary_parts = _cpe_parts(primary_cpe)
    if not criterion_parts:
        return "unknown", criteria

    def attributes_match(observed_parts: tuple[str, ...], *, include_version: bool) -> bool:
        for index, expected in enumerate(criterion_parts):
            if index == 3 and not include_version:
                continue
            actual = observed_parts[index]
            if expected == "*":
                continue
            if expected == "-":
                if actual != "-":
                    return False
                continue
            if expected != actual:
                return False
        return True

    if criteria == primary_cpe:
        return "true", criteria

    # A successful NVD cpeName+isVulnerable query establishes that the primary
    # CPE matched at least one vulnerable CPE Match Criterion. Apply that result
    # only to a structurally compatible criterion. A different concrete version
    # or another CPE attribute must never be promoted merely because the first
    # three fields happen to be equal.
    if primary_query_verified and item.get("vulnerable") and primary_parts:
        same_family = primary_parts[:3] == criterion_parts[:3]
        range_present = any(item.get(key) for key in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        ))
        if same_family and attributes_match(primary_parts, include_version=not range_present):
            return "true", criteria

    for observed in observed_cpes:
        observed_parts = _cpe_parts(observed)
        if not observed_parts or observed_parts[:3] != criterion_parts[:3]:
            continue
        if not attributes_match(observed_parts, include_version=False):
            return "false", criteria
        criterion_version = criterion_parts[3]
        observed_version = observed_parts[3]
        if criterion_version not in {"", "*", "-"}:
            return ("true", criteria) if observed_version == criterion_version else ("false", criteria)
        # Range comparison is deliberately not recreated locally. NVD already
        # evaluated the primary CPE query; other ranged dependencies require
        # explicit analyst evidence rather than a private version algorithm.
        if any(item.get(key) for key in (
            "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"
        )):
            return "unknown", criteria
        return "true", criteria
    return "unknown", criteria


def _combine(operator: str, values: list[str]) -> str:
    if not values:
        return "unknown"
    if operator == "AND":
        if "false" in values:
            return "false"
        return "unknown" if "unknown" in values else "true"
    if "true" in values:
        return "true"
    return "unknown" if "unknown" in values else "false"


def evaluate_configurations(
    configurations: list[dict[str, Any]],
    primary_cpe: str,
    observed_environment_cpes: Iterable[str],
    *,
    primary_query_verified: bool = True,
) -> dict[str, Any]:
    observed = {normalise_cpe23(value) for value in observed_environment_cpes if normalise_cpe23(value)}
    observed.add(primary_cpe)
    unknown_requirements: set[str] = set()
    contradictions: set[str] = set()

    def evaluate_node(node: Any) -> str:
        if not isinstance(node, dict):
            return "unknown"
        values: list[str] = []
        for item in node.get("cpeMatch") or node.get("cpe_match") or []:
            truth, label = _criterion_truth(item, observed, primary_cpe, primary_query_verified)
            values.append(truth)
            if truth == "unknown" and label != primary_cpe:
                unknown_requirements.add(label)
            elif truth == "false":
                contradictions.add(label)
        for child in (node.get("nodes") or []) + (node.get("children") or []):
            values.append(evaluate_node(child))
        truth = _combine(str(node.get("operator") or "OR").upper(), values)
        if node.get("negate"):
            truth = {"true": "false", "false": "true"}.get(truth, "unknown")
        return truth

    roots: list[str] = []
    for configuration in configurations or []:
        nodes = configuration.get("nodes") if isinstance(configuration, dict) else None
        if isinstance(nodes, list):
            truth = _combine(
                str(configuration.get("operator") or "OR").upper(),
                [evaluate_node(node) for node in nodes],
            )
            if configuration.get("negate"):
                truth = {"true": "false", "false": "true"}.get(truth, "unknown")
            roots.append(truth)
        else:
            roots.append(evaluate_node(configuration))
    truth = _combine("OR", roots)
    decision = "potentially_affected" if truth == "true" else ("rejected" if truth == "false" else "needs_context")
    return {
        "decision": decision,
        "configuration_truth": truth,
        "required_conditions": sorted(unknown_requirements),
        "contradictions": sorted(contradictions),
        "basis": "nvd_cpe_2_3_name_match_and_configuration_applicability",
    }


def status(connection: sqlite3.Connection | None = None) -> dict[str, Any]:
    owns_connection = connection is None
    if not REPOSITORY.exists() and connection is None:
        return {
            "source": NVD_SOURCE,
            "available": False,
            "complete": False,
            "records": 0,
            "cpe_criteria": 0,
            "schema_version": SCHEMA_VERSION,
            "repository": str(REPOSITORY),
            "last_successful_update": "",
            "last_update_error": "",
            "notice": NVD_NOTICE,
        }
    connection = connection or _connect()
    try:
        records = int(connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0])
        criteria = int(connection.execute("SELECT COUNT(*) FROM cpe_criteria").fetchone()[0])
        return {
            "source": NVD_SOURCE,
            "available": records > 0,
            "complete": _meta(connection, "full_sync_complete") == "true",
            "records": records,
            "source_total_results": int(_meta(connection, "source_total_results", "0") or 0),
            "cpe_criteria": criteria,
            "schema_version": int(_meta(connection, "schema_version", str(SCHEMA_VERSION))),
            "repository": str(REPOSITORY),
            "last_successful_update": _meta(connection, "last_successful_update"),
            "last_update_error": _meta(connection, "last_update_error"),
            "notice": NVD_NOTICE,
        }
    finally:
        if owns_connection:
            connection.close()
