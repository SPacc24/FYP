from __future__ import annotations

"""Validation and planning for the single adaptive scanner.

This module owns operator-controlled port coverage and workload settings.  It
does not identify services from port numbers; those decisions remain in the
fingerprinting pipeline and must be supported by collected evidence.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping


class ScanConfigurationError(ValueError):
    """Raised when an operator-supplied scan setting is invalid."""


_PORT_TOKEN = re.compile(r"^\d+(?:-\d+)?$")
_ALLOWED_TCP_COVERAGE = {"complete", "common", "custom"}
_ALLOWED_UDP_COVERAGE = {"disabled", "common", "complete", "custom"}


def _policy_path() -> Path:
    candidates = [
        Path("project/policies/port_coverage.json"),
        Path("policies/port_coverage.json"),
        Path(__file__).resolve().parents[1] / "policies" / "port_coverage.json",
    ]
    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        raise ScanConfigurationError("Port coverage configuration is missing")
    return path


def load_port_coverage_policy() -> tuple[dict[str, Any], str]:
    path = _policy_path()
    try:
        raw = path.read_bytes()
        policy = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ScanConfigurationError(f"Port coverage configuration is invalid: {exc}") from exc
    return policy, hashlib.sha256(raw).hexdigest()


def parse_port_expression(value: str | Iterable[int] | None) -> list[int]:
    """Parse comma/space separated ports and inclusive ranges."""

    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        ports: set[int] = set()
        for item in value:
            ports.update(parse_port_expression(str(item)))
        return sorted(ports)

    text = str(value).strip()
    if not text:
        return []

    ports: set[int] = set()
    for token in re.split(r"[\s,;]+", text):
        if not token:
            continue
        if not _PORT_TOKEN.fullmatch(token):
            raise ScanConfigurationError(f"Invalid port entry: {token}")
        if "-" in token:
            left, right = (int(part) for part in token.split("-", 1))
            if right < left:
                left, right = right, left
            if left < 1 or right > 65535:
                raise ScanConfigurationError(f"Port range must be within 1-65535: {token}")
            ports.update(range(left, right + 1))
        else:
            port = int(token)
            if port < 1 or port > 65535:
                raise ScanConfigurationError(f"Port must be within 1-65535: {token}")
            ports.add(port)
    return sorted(ports)


def _field(source: Mapping[str, Any] | Any, name: str, default: Any = "") -> Any:
    getter = getattr(source, "get", None)
    if callable(getter):
        return getter(name, default)
    return default


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int, default: int) -> int:
    raw = default if value in (None, "") else value
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise ScanConfigurationError(f"{name} must be a whole number") from exc
    if parsed < minimum or parsed > maximum:
        raise ScanConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def default_scan_configuration() -> dict[str, Any]:
    policy, policy_hash = load_port_coverage_policy()
    defaults = policy.get("defaults") or {}
    return {
        "scan_type": "adaptive_comprehensive",
        "tcp_coverage": str(defaults.get("tcp_coverage") or "complete"),
        "tcp_custom": "",
        "tcp_additional": "",
        "tcp_excluded": "",
        "udp_coverage": str(defaults.get("udp_coverage") or "disabled"),
        "udp_custom": "",
        "udp_additional": "",
        "udp_excluded": "",
        "advanced": {
            "ports_per_microbatch": int(defaults.get("ports_per_microbatch") or 256),
            "concurrent_targets": int(defaults.get("concurrent_targets") or 4),
            "probe_timeout_seconds": int(defaults.get("probe_timeout_seconds") or 3),
            "retry_limit": int(defaults.get("retry_limit") or 1),
        },
        "port_policy_sha256": policy_hash,
        "port_policy_version": str(policy.get("schema_version") or "unknown"),
    }


def normalise_scan_configuration(source: Mapping[str, Any] | Any | None) -> dict[str, Any]:
    """Return validated, compact settings without storing a 65,535-item list."""

    source = source or {}
    if isinstance(source, Mapping) and isinstance(source.get("port_selection"), Mapping):
        nested = source["port_selection"]
        advanced = source.get("advanced") if isinstance(source.get("advanced"), Mapping) else {}
        flattened = {
            **nested,
            "ports_per_microbatch": advanced.get("ports_per_microbatch"),
            "concurrent_targets": advanced.get("concurrent_targets"),
            "probe_timeout_seconds": advanced.get("probe_timeout_seconds"),
            "retry_limit": advanced.get("retry_limit"),
        }
        source = flattened

    policy, policy_hash = load_port_coverage_policy()
    defaults = policy.get("defaults") or {}

    tcp_coverage = str(_field(source, "tcp_coverage", defaults.get("tcp_coverage", "complete"))).strip().lower()
    udp_coverage = str(_field(source, "udp_coverage", defaults.get("udp_coverage", "disabled"))).strip().lower()
    if tcp_coverage not in _ALLOWED_TCP_COVERAGE:
        raise ScanConfigurationError("TCP coverage must be complete, common, or custom")
    if udp_coverage not in _ALLOWED_UDP_COVERAGE:
        raise ScanConfigurationError("UDP coverage must be disabled, common, complete, or custom")

    selection = {
        "tcp_coverage": tcp_coverage,
        "tcp_custom": str(_field(source, "tcp_custom", "") or "").strip(),
        "tcp_additional": str(_field(source, "tcp_additional", "") or "").strip(),
        "tcp_excluded": str(_field(source, "tcp_excluded", "") or "").strip(),
        "udp_coverage": udp_coverage,
        "udp_custom": str(_field(source, "udp_custom", "") or "").strip(),
        "udp_additional": str(_field(source, "udp_additional", "") or "").strip(),
        "udp_excluded": str(_field(source, "udp_excluded", "") or "").strip(),
    }

    advanced = {
        "ports_per_microbatch": _bounded_int(
            _field(source, "ports_per_microbatch", defaults.get("ports_per_microbatch")),
            name="Ports per microbatch", minimum=1, maximum=4096,
            default=int(defaults.get("ports_per_microbatch") or 256),
        ),
        "concurrent_targets": _bounded_int(
            _field(source, "concurrent_targets", defaults.get("concurrent_targets")),
            name="Concurrent targets", minimum=1, maximum=32,
            default=int(defaults.get("concurrent_targets") or 4),
        ),
        "probe_timeout_seconds": _bounded_int(
            _field(source, "probe_timeout_seconds", defaults.get("probe_timeout_seconds")),
            name="Probe timeout", minimum=1, maximum=30,
            default=int(defaults.get("probe_timeout_seconds") or 3),
        ),
        "retry_limit": _bounded_int(
            _field(source, "retry_limit", defaults.get("retry_limit")),
            name="Retry limit", minimum=0, maximum=5,
            default=int(defaults.get("retry_limit") or 1),
        ),
    }

    compact = {
        "scan_type": "adaptive_comprehensive",
        "port_selection": selection,
        "advanced": advanced,
        "port_policy_sha256": policy_hash,
        "port_policy_version": str(policy.get("schema_version") or "unknown"),
    }
    tcp_ports = resolve_tcp_ports(compact)
    udp_ports = resolve_udp_ports(compact)
    compact["plan_summary"] = {
        "tcp_port_count": len(tcp_ports),
        "udp_port_count": len(udp_ports),
        "tcp_complete": len(tcp_ports) == 65535,
        "udp_complete": len(udp_ports) == 65535,
        "microbatch_count_per_tcp_target": (len(tcp_ports) + advanced["ports_per_microbatch"] - 1) // advanced["ports_per_microbatch"],
    }
    return compact


def _resolve(protocol: str, options: Mapping[str, Any]) -> list[int]:
    policy, _ = load_port_coverage_policy()
    selection = options.get("port_selection") if isinstance(options.get("port_selection"), Mapping) else options
    coverage = str(selection.get(f"{protocol}_coverage") or ("complete" if protocol == "tcp" else "disabled"))
    if coverage == "disabled":
        return []
    if coverage == "complete":
        base = set(range(1, 65536))
    elif coverage == "common":
        common = ((policy.get("coverage_sets") or {}).get(protocol) or {}).get("common") or []
        base = set(parse_port_expression(common))
    elif coverage == "custom":
        base = set(parse_port_expression(selection.get(f"{protocol}_custom")))
    else:
        raise ScanConfigurationError(f"Unsupported {protocol.upper()} coverage: {coverage}")

    base.update(parse_port_expression(selection.get(f"{protocol}_additional")))
    base.difference_update(parse_port_expression(selection.get(f"{protocol}_excluded")))
    if not base:
        raise ScanConfigurationError(f"{protocol.upper()} port selection is empty")
    return sorted(base)


def resolve_tcp_ports(options: Mapping[str, Any]) -> list[int]:
    return _resolve("tcp", options)


def resolve_udp_ports(options: Mapping[str, Any]) -> list[int]:
    return _resolve("udp", options)


def iter_port_batches(ports: Iterable[int], batch_size: int) -> Iterable[list[int]]:
    ordered = sorted(set(int(port) for port in ports))
    for offset in range(0, len(ordered), int(batch_size)):
        yield ordered[offset:offset + int(batch_size)]


def compact_port_ranges(ports: Iterable[int]) -> list[str]:
    ordered = sorted(set(int(port) for port in ports))
    if not ordered:
        return []
    ranges: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ranges
