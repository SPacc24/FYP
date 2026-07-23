"""Standards-backed matching for the official CVE List V5 index.

The matcher emits only Candidate findings.  Confirmation requires separate
target-specific validation evidence and is intentionally outside correlation.
Records that do not satisfy every published machine-readable applicability
condition are not findings and are not assigned another CVE status.

No CVE identifier, product alias, version range, platform exception, target,
or validation result is embedded in this module.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

SQLITE_INDEX = Path("storage/mitre_cve/official_cve_list_v5.sqlite3")

_CPE_COMPONENTS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


def normalise_name(value: str) -> str:
    """Canonicalise case and separators without inventing aliases."""
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold()).strip()


def _split_escaped(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == separator:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def _cpe_value(value: str) -> str:
    decoded = unquote(str(value or "")).replace("\\:", ":").replace("\\\\", "\\")
    return decoded.casefold()


def parse_cpe(value: str) -> dict[str, str] | None:
    """Parse CPE 2.3 formatted-string and legacy URI bindings.

    The returned components are used only for exact CPE identity matching.  A
    malformed or unsupported binding is not repaired or guessed.
    """
    text = str(value or "").strip()
    if text.startswith("cpe:2.3:"):
        raw = _split_escaped(text[len("cpe:2.3:"):], ":")
        if len(raw) != len(_CPE_COMPONENTS):
            return None
        return {name: _cpe_value(component) for name, component in zip(_CPE_COMPONENTS, raw)}
    if text.startswith("cpe:/"):
        raw = _split_escaped(text[len("cpe:/"):], ":")
        if not 3 <= len(raw) <= 7:
            return None
        raw.extend(["*"] * (7 - len(raw)))
        values = raw + ["*", "*", "*", "*"]
        return {name: _cpe_value(component) for name, component in zip(_CPE_COMPONENTS, values)}
    return None


def _cpe_name_matches(published: dict[str, str], observed: dict[str, str]) -> bool:
    for component in _CPE_COMPONENTS:
        expected = published.get(component, "*")
        actual = observed.get(component, "*")
        if expected in {"", "*"}:
            continue
        if expected == "-":
            if actual != "-":
                return False
            continue
        if actual in {"", "*", "-"} or expected != actual:
            return False
    return True


def _observed_identity_keys(product: str, cpes: Iterable[str]) -> set[str]:
    keys = {normalise_name(product)} if normalise_name(product) else set()
    for value in cpes:
        parsed = parse_cpe(value)
        if not parsed:
            continue
        cpe_product = normalise_name(parsed.get("product", ""))
        vendor_product = normalise_name(
            " ".join(part for part in (parsed.get("vendor", ""), parsed.get("product", "")) if part)
        )
        if cpe_product:
            keys.add(cpe_product)
        if vendor_product:
            keys.add(vendor_product)
    return keys


def affected_identity_keys(entry: dict[str, Any]) -> set[str]:
    """Build exact lookup keys solely from published affected data."""
    product = normalise_name(str(entry.get("product") or ""))
    vendor_product = normalise_name(
        " ".join(str(entry.get(field) or "") for field in ("vendor", "product"))
    )
    keys = {key for key in (product, vendor_product) if key and key not in {"n a", "unknown", "unspecified"}}
    for value in entry.get("cpes") or []:
        parsed = parse_cpe(str(value))
        if not parsed:
            continue
        cpe_product = normalise_name(parsed.get("product", ""))
        cpe_vendor_product = normalise_name(
            " ".join(part for part in (parsed.get("vendor", ""), parsed.get("product", "")) if part)
        )
        if cpe_product:
            keys.add(cpe_product)
        if cpe_vendor_product:
            keys.add(cpe_vendor_product)
    return keys


def _semver(value: str) -> tuple[tuple[int, int, int], tuple[tuple[int, Any], ...] | None] | None:
    match = re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        str(value or "").strip(),
    )
    if not match:
        return None
    core = tuple(int(part) for part in match.group(1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return core, None
    components: list[tuple[int, Any]] = []
    for token in prerelease.split("."):
        if token.isdigit():
            # SemVer 2.0.0 forbids leading zeroes in numeric prerelease
            # identifiers.  Reject the whole value instead of silently
            # accepting a non-standard extension.
            if len(token) > 1 and token.startswith("0"):
                return None
            components.append((0, int(token)))
        else:
            components.append((1, token))
    return core, tuple(components)


def _compare_semver(left: str, right: str) -> int | None:
    a, b = _semver(left), _semver(right)
    if a is None or b is None:
        return None
    if a[0] != b[0]:
        return (a[0] > b[0]) - (a[0] < b[0])
    if a[1] is None and b[1] is None:
        return 0
    if a[1] is None:
        return 1
    if b[1] is None:
        return -1
    return (a[1] > b[1]) - (a[1] < b[1])


def _compare(left: str, right: str, version_type: str) -> int | None:
    """Use only comparison semantics named by the CVE record."""
    if str(left or "") == str(right or ""):
        return 0
    if str(version_type or "").casefold() == "semver":
        return _compare_semver(left, right)
    return None


def _compare_range_bound(
    observed: str,
    bound: str,
    version_type: str,
    *,
    upper: bool,
) -> int | None:
    """Compare a range bound using only CVE List and versionType semantics.

    CVE List V5 defines ``0`` as the conventional earliest version and permits
    an upper limit ending in ``*`` to represent the end of a branch.  This
    implementation applies those schema conventions only to SemVer values;
    it does not invent ordering for ``custom`` or other version types.
    """
    kind = str(version_type or "").casefold()
    if kind != "semver":
        return _compare(observed, bound, version_type)
    parsed_observed = _semver(observed)
    if parsed_observed is None:
        return None
    if not upper and bound == "0":
        return 1
    if upper and bound == "*":
        return -1
    if upper and bound.endswith(".*"):
        prefix_text = bound[:-2]
        prefix_parts = prefix_text.split(".") if prefix_text else []
        if not prefix_parts or len(prefix_parts) > 2 or any(
            not re.fullmatch(r"0|[1-9]\d*", part) for part in prefix_parts
        ):
            return None
        prefix = tuple(int(part) for part in prefix_parts)
        observed_prefix = parsed_observed[0][:len(prefix)]
        if observed_prefix <= prefix:
            return -1
        return 1
    return _compare(observed, bound, version_type)


def evaluate_versions(
    observed: str,
    rules: list[dict[str, Any]],
    default_status: str = "",
) -> dict[str, Any]:
    """Apply the CVE List V5 published version-selection algorithm.

    ``published_status`` is copied from the CVE record.  It is not a scanner
    finding status.  Only ``affected`` is eligible to produce a Candidate.
    """
    observed_value = str(observed or "").strip()
    if not observed_value:
        return {"affected": False, "published_status": "unknown", "rule": {}}
    for rule in rules:
        start = str(rule.get("version") or "")
        end_lt = str(rule.get("lessThan") or "")
        end_lte = str(rule.get("lessThanOrEqual") or "")
        version_type = str(rule.get("versionType") or "")
        matched = False
        if not end_lt and not end_lte:
            matched = observed_value == start
        else:
            lower = _compare_range_bound(
                observed_value,
                start,
                version_type,
                upper=False,
            )
            upper = _compare_range_bound(
                observed_value,
                end_lt or end_lte,
                version_type,
                upper=True,
            )
            matched = (
                lower is not None
                and upper is not None
                and lower >= 0
                and (upper < 0 if end_lt else upper <= 0)
            )
        if not matched:
            continue
        published_status = str(rule.get("status") or "unknown").casefold()
        latest_change: dict[str, Any] | None = None
        for change in rule.get("changes") or []:
            at = str(change.get("at") or "")
            comparison = _compare_range_bound(
                observed_value,
                at,
                version_type,
                upper=False,
            )
            if comparison is None or comparison < 0:
                continue
            if latest_change is None:
                latest_change = change
                continue
            latest_at = str(latest_change.get("at") or "")
            if at == latest_at:
                continue
            if version_type.casefold() == "semver" and latest_at == "0":
                latest_change = change
                continue
            if version_type.casefold() == "semver" and at == "0":
                continue
            ordering = _compare(at, latest_at, version_type)
            if ordering is not None and ordering > 0:
                latest_change = change
        if latest_change is not None:
            published_status = str(latest_change.get("status") or "unknown").casefold()
        return {
            "affected": published_status == "affected",
            "published_status": published_status,
            "rule": rule,
        }
    published_status = str(default_status or "unknown").casefold()
    return {
        "affected": published_status == "affected",
        "published_status": published_status,
        "rule": {},
    }


def _normalised_values(values: Iterable[Any]) -> set[str]:
    return {
        re.sub(r"\s+", " ", str(value or "").casefold()).strip()
        for value in values
        if str(value or "").strip()
    }


def _environment_values(cpes: Iterable[str], explicit: Iterable[str]) -> set[str]:
    values = _normalised_values(explicit)
    for value in cpes:
        parsed = parse_cpe(value)
        if not parsed or parsed.get("part") not in {"o", "h"}:
            continue
        for component in ("product", "target_sw", "target_hw"):
            normalised = normalise_name(parsed.get(component, ""))
            if normalised and normalised not in {"n a", "unknown"}:
                values.add(normalised)
        combined = normalise_name(
            " ".join(part for part in (parsed.get("vendor", ""), parsed.get("product", "")) if part)
        )
        if combined:
            values.add(combined)
    return values


def _all_published_values_match(published: Iterable[Any], observed: Iterable[Any]) -> bool:
    required = _normalised_values(published)
    if not required:
        return True
    available = _normalised_values(observed)
    return bool(required & available)


def _entry_matches_context(
    entry: dict[str, Any],
    *,
    product: str,
    service_cpes: tuple[str, ...],
    environment_cpes: tuple[str, ...],
    observed_platforms: tuple[str, ...],
    observed_modules: tuple[str, ...],
    observed_package_names: tuple[str, ...],
    observed_program_files: tuple[str, ...],
    observed_program_routines: tuple[str, ...],
) -> bool:
    observed_keys = _observed_identity_keys(product, service_cpes)
    if not (affected_identity_keys(entry) & observed_keys):
        return False

    published_cpes = [parse_cpe(str(value)) for value in entry.get("cpes") or []]
    published_cpes = [value for value in published_cpes if value]
    if published_cpes:
        observed_cpes = [parse_cpe(str(value)) for value in service_cpes + environment_cpes]
        observed_cpes = [value for value in observed_cpes if value]
        if not any(
            _cpe_name_matches(published, observed)
            for published in published_cpes
            for observed in observed_cpes
        ):
            return False

    platforms = entry.get("platforms") or []
    if platforms:
        available_platforms = _environment_values(environment_cpes, observed_platforms)
        if not (_normalised_values(platforms) & available_platforms):
            return False
    if not _all_published_values_match(entry.get("modules") or [], observed_modules):
        return False
    package_name = str(entry.get("packageName") or "").strip()
    if package_name and not _all_published_values_match((package_name,), observed_package_names):
        return False
    if not _all_published_values_match(entry.get("programFiles") or [], observed_program_files):
        return False
    routines = []
    for item in entry.get("programRoutines") or []:
        routines.append(item.get("name") if isinstance(item, dict) else item)
    if not _all_published_values_match(routines, observed_program_routines):
        return False
    return True


def _candidate_record(
    record: dict[str, Any],
    selected_cvss: str,
    entry: dict[str, Any],
    version_result: dict[str, Any],
) -> dict[str, Any]:
    metric = (record.get("cvss_metrics") or {}).get(selected_cvss) or {}
    cve_id = record.get("cve_id")
    return {
        **record,
        "classification": "Candidate",
        "status": "Candidate",
        "cvss_score": metric.get("cvss_score"),
        "cvss_severity": metric.get("cvss_severity") or "",
        "cvss_vector": metric.get("cvss_vector") or "",
        "cvss_source": metric.get("cvss_source") or "",
        "cvss_provider_role": metric.get("cvss_provider_role") or "",
        "cvss_record_url": metric.get("cvss_record_url") or f"https://www.cve.org/CVERecord?id={cve_id}",
        "cvss_record_last_modified": metric.get("cvss_record_last_modified") or "",
        "cvss_version": selected_cvss,
        "cvss_status": "published" if metric.get("cvss_score") is not None else "not_provided_for_selected_version",
        "cvss_available_versions": sorted((record.get("cvss_metrics") or {}).keys()),
        "match_basis": "CVE List V5 structured affected entry",
        "classification_reason": "Observed identity, version, and published applicability constraints matched.",
        "applicability_source": record.get("source"),
        "applicability_record_url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "published_applicability": {
            "container_role": entry.get("container_role") or "",
            "provider_org_id": entry.get("provider_org_id") or "",
            "vendor": entry.get("vendor") or "",
            "product": entry.get("product") or "",
            "platforms": entry.get("platforms") or [],
            "modules": entry.get("modules") or [],
            "packageName": entry.get("packageName") or "",
            "version_rule": version_result.get("rule") or {},
        },
    }


def search(
    product: str,
    version: str,
    *,
    selected_cvss: str,
    service_cpes: tuple[str, ...] = (),
    environment_cpes: tuple[str, ...] = (),
    observed_platforms: tuple[str, ...] = (),
    observed_modules: tuple[str, ...] = (),
    observed_package_names: tuple[str, ...] = (),
    observed_program_files: tuple[str, ...] = (),
    observed_program_routines: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return Candidate findings plus non-CVE operational diagnostics."""
    diagnostics: list[dict[str, Any]] = []
    identity_keys = _observed_identity_keys(product, service_cpes)
    if not identity_keys or not str(version or "").strip():
        return [], [{"event": "input_not_eligible", "detail": "Observed product identity and version are required for CVE correlation."}]
    if not SQLITE_INDEX.exists():
        return [], [{"event": "index_not_ready", "detail": "Build the local CVE List V5 index before scanning."}]

    records: list[dict[str, Any]] = []
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(SQLITE_INDEX)
        placeholders = ",".join("?" for _ in identity_keys)
        records = [
            json.loads(row[0])
            for row in connection.execute(
                f"SELECT DISTINCT record_json FROM affected_identities WHERE identity_key IN ({placeholders})",
                tuple(sorted(identity_keys)),
            )
        ]
    except (sqlite3.DatabaseError, json.JSONDecodeError) as exc:
        diagnostics.append({"event": "index_incompatible", "detail": f"Rebuild the CVE List V5 index: {type(exc).__name__}."})
        records = []
    finally:
        if connection is not None:
            connection.close()

    candidates: list[dict[str, Any]] = []
    for record in records:
        if record.get("state") != "PUBLISHED":
            continue
        applicable: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for entry in record.get("affected_entries") or []:
            if not _entry_matches_context(
                entry,
                product=product,
                service_cpes=service_cpes,
                environment_cpes=environment_cpes,
                observed_platforms=observed_platforms,
                observed_modules=observed_modules,
                observed_package_names=observed_package_names,
                observed_program_files=observed_program_files,
                observed_program_routines=observed_program_routines,
            ):
                continue
            version_result = evaluate_versions(
                version,
                entry.get("versions") or [],
                str(entry.get("defaultStatus") or ""),
            )
            if version_result.get("affected"):
                applicable.append((entry, version_result))
        if not applicable:
            continue
        entry, version_result = applicable[0]
        candidates.append(_candidate_record(record, selected_cvss, entry, version_result))

    unique = {row.get("cve_id"): row for row in candidates if row.get("cve_id")}
    return list(unique.values()), diagnostics
