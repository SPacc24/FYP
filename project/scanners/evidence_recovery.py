from __future__ import annotations

"""Deterministic evidence-recovery planning for recon-owned scanners.

The recovery planner never contains target, CVE, product-version, or lab facts.
It reasons only from:
  * operator-normalised recovery limits,
  * observed endpoint state/identity fields, and
  * collector capability metadata supplied by ``collector_plan``.

No missing value is inferred.  A recovery action can only replace an unresolved
fact when the follow-up tool actually returns evidence for that fact.
"""

from typing import Any, Iterable, Mapping
import math
import re


_RANGE_RE = re.compile(
    r"\b\d+(?:\.(?:\d+|[xX*])){0,5}[A-Za-z0-9._+-]*\s+"
    r"(?:-|to|through|thru)\s+"
    r"\d+(?:\.(?:\d+|[xX*])){0,5}[A-Za-z0-9._+-]*\b",
    re.I,
)


def clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(default)
    return max(low, min(high, number))


def version_is_unresolved(value: Any) -> bool:
    """Return True only when no concrete single-version fact is available."""
    text = str(value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered in {"unknown", "unidentified", "not established", "n/a", "none", "-", "—"}:
        return True
    if _RANGE_RE.search(text):
        return True
    # Wildcard/range markers are not concrete point versions.
    if re.search(r"(?:^|[.\s])(?:x|\*)(?:$|[.\s])", lowered):
        return True
    return False


def missing_evidence_types(row: Mapping[str, Any]) -> set[str]:
    """Describe missing facts without assigning a probability or confidence."""
    missing: set[str] = set()
    state = str(row.get("state") or "unknown").strip().lower()
    if state in {"open|filtered", "unknown", "no-response", "no response"}:
        missing.add("endpoint_state")
    if not str(row.get("product") or "").strip():
        missing.add("service_product")
    if version_is_unresolved(row.get("version")):
        missing.add("service_version")
    attrs = row.get("service_attributes") if isinstance(row.get("service_attributes"), Mapping) else {}
    if not list(row.get("os_cpe") or []) and not str(attrs.get("ostype") or "").strip():
        missing.add("host_os")
    return missing


def recovery_intensity_ladder(initial: Any, recovery_target: Any, attempts: Any) -> list[int]:
    """Build a transparent, bounded Nmap version-intensity sequence.

    ``initial`` is the intensity already used by ordinary service fingerprinting.
    ``recovery_target`` is the operator/policy recovery intensity.  When the
    recovery target is higher, attempts move monotonically toward it.  When it
    is equal/lower, the requested recovery intensity is repeated; no secret
    escalation is introduced.
    """
    start = clamp_int(initial, 0, 9, 0)
    target = clamp_int(recovery_target, 0, 9, start)
    count = clamp_int(attempts, 1, 4, 1)
    if target <= start:
        return [target for _ in range(count)]

    values: list[int] = []
    delta = target - start
    for index in range(1, count + 1):
        # Ceiling guarantees that each pass moves toward the operator-selected
        # ceiling instead of silently staying at the initial level.
        value = start + math.ceil((delta * index) / count)
        values.append(min(target, value))
    return values


def recovery_candidates(
    rows: Iterable[Mapping[str, Any]],
    *,
    protocol: str,
    include_uncertain_udp: bool = False,
) -> list[dict[str, Any]]:
    """Return endpoint rows that still need identity/state evidence.

    TCP recovery is restricted to confirmed-open endpoints. UDP recovery may
    additionally include ``open|filtered`` endpoints because that state is an
    explicit uncertainty produced by UDP discovery, not an assumption of
    openness.
    """
    proto = str(protocol or "").strip().lower()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for source in rows or []:
        row = dict(source)
        observed_proto = str(row.get("protocol") or "").strip().lower()
        if observed_proto != proto:
            continue
        state = str(row.get("state") or "unknown").strip().lower()
        allowed = state == "open" or (proto == "udp" and include_uncertain_udp and state == "open|filtered")
        if not allowed:
            continue
        missing = missing_evidence_types(row)
        if state == "open" and not ({"service_product", "service_version"} & missing):
            continue
        try:
            port = int(row.get("port") or row.get("portid") or 0)
        except (TypeError, ValueError):
            continue
        host = str(row.get("host") or "").strip()
        if not host or not (1 <= port <= 65535):
            continue
        key = (host, port, proto)
        if key in seen:
            continue
        seen.add(key)
        row["port"] = port
        row["protocol"] = proto
        row["recovery_missing_evidence"] = sorted(missing)
        out.append(row)
    return out



def recovery_port_batches(ports: Iterable[Any], *, max_ports: Any, batch_size: Any) -> list[list[int]]:
    """Return deterministic bounded recovery batches from authorised ports only."""
    limit = clamp_int(max_ports, 1, 256, 64)
    size = clamp_int(batch_size, 1, 2048, 5)
    selected: list[int] = []
    for raw in ports or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in selected:
            selected.append(port)
    selected = sorted(selected)[:limit]
    return [selected[start:start + size] for start in range(0, len(selected), size)]

def collector_needed(plan_entry: Mapping[str, Any], service: Mapping[str, Any]) -> bool:
    """Determine whether an AUTO collector can add evidence for this endpoint.

    This does not decide whether the collector is *applicable* to the protocol;
    the ordinary service-family/protocol gate still does that first.  ``always``
    mode remains an explicit operator override.
    """
    mode = str(plan_entry.get("mode") or "auto").lower()
    if mode == "always":
        return True
    produces = {str(value).strip() for value in plan_entry.get("produces") or [] if str(value).strip()}
    if not produces:
        return True

    missing = missing_evidence_types(service)
    # These evidence classes are not represented by ordinary service product /
    # version fields and therefore remain useful even when identity is complete.
    always_useful = {
        "protocol_component",
        "protocol_security",
        "security_configuration",
        "protocol_capabilities",
        "host_identity",
        "host_build",
        "hostname",
        "domain_identity",
        "advertised_endpoints",
        "tls_configuration",
        "authentication_configuration",
    }
    if produces & always_useful:
        return True
    return bool(produces & missing)


def recovery_snapshot(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarise unresolved evidence as counts only; no score is invented."""
    counts = {
        "endpoint_state": 0,
        "service_product": 0,
        "service_version": 0,
        "host_os": 0,
    }
    endpoints = 0
    for row in rows or []:
        endpoints += 1
        for key in missing_evidence_types(row):
            if key in counts:
                counts[key] += 1
    return {"endpoints_considered": endpoints, "missing": counts}


def merge_endpoint_observations(
    base_rows: Iterable[Mapping[str, Any]],
    update_rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge endpoint-state observations for recovery planning only.

    Later observations replace state/reason and fill concrete identity fields.
    This helper does not promote any row into the final service inventory; the
    caller still requires a confirmed ``open`` state for that.
    """
    ordered: list[dict[str, Any]] = []
    index: dict[tuple[str, int, str], dict[str, Any]] = {}

    def key_for(row: Mapping[str, Any]) -> tuple[str, int, str] | None:
        try:
            port = int(row.get("port") or row.get("portid") or 0)
        except (TypeError, ValueError):
            return None
        host = str(row.get("host") or "").strip()
        proto = str(row.get("protocol") or "").strip().lower()
        if not host or not proto or not (1 <= port <= 65535):
            return None
        return host, port, proto

    for source in list(base_rows or []) + list(update_rows or []):
        row = dict(source)
        key = key_for(row)
        if key is None:
            continue
        current = index.get(key)
        if current is None:
            current = row
            current["port"] = key[1]
            current["protocol"] = key[2]
            index[key] = current
            ordered.append(current)
            continue
        state = str(row.get("state") or "").strip()
        if state and state.lower() != "unknown":
            current["state"] = state
        for field in ("reason", "service", "product", "version", "extra", "extrainfo", "raw_evidence_file"):
            value = row.get(field)
            if value not in (None, "", [], {}):
                current[field] = value
        for field in ("cpe", "os_cpe", "hardware_cpe", "evidence_sources"):
            values = [str(x) for x in row.get(field) or [] if str(x).strip()]
            if values:
                current[field] = list(dict.fromkeys(list(current.get(field) or []) + values))
        if isinstance(row.get("service_attributes"), Mapping):
            attrs = dict(current.get("service_attributes") or {})
            attrs.update({k: v for k, v in row.get("service_attributes", {}).items() if v not in (None, "")})
            current["service_attributes"] = attrs
    return ordered
