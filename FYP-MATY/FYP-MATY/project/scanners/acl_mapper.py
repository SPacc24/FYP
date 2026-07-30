from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True)
class ACLPattern:
    pattern_type: Literal[
        "stateless_udp_block",
        "stateful_tcp_inspection",
        "ids_active",
        "rate_limit_active",
        "port_specific_acl",
    ]
    confidence: float
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _acl_policy() -> dict[str, Any]:
    candidates = (
        Path(__file__).resolve().parents[1] / "policies" / "recon_policy.json",
        Path("project/policies/recon_policy.json"),
        Path("policies/recon_policy.json"),
    )
    for path in candidates:
        if not path.exists():
            continue
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        acl = policy.get("acl_detection")
        if isinstance(acl, dict):
            return acl
    # Standalone callers may not have the project policy in their current
    # directory. These conservative values match the shipped policy schema.
    return {"filtered_ratio_threshold": 0.6, "min_sampled_ports": 10}


def _normalise_state(value: Any) -> str:
    state = str(value or "unknown").strip().lower().replace(" ", "")
    return state or "unknown"


def _port_number(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _counts(results: dict[str, Any]) -> tuple[Counter[tuple[str, str]], list[dict[str, Any]]]:
    counts: Counter[tuple[str, str]] = Counter()
    rows: list[dict[str, Any]] = []
    for item in results.get("ports") or []:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        state = _normalise_state(item.get("state"))
        counts[(protocol, state)] += 1
        rows.append(item)
    for item in results.get("extraports") or []:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        state = _normalise_state(item.get("state"))
        try:
            count = max(0, int(item.get("count") or 0))
        except (TypeError, ValueError):
            count = 0
        counts[(protocol, state)] += count
    return counts, rows


def _sum_states(
    counts: Counter[tuple[str, str]],
    protocol: str,
    states: set[str],
) -> int:
    return sum(count for (proto, state), count in counts.items() if proto == protocol and state in states)


def _rate_pattern(results: dict[str, Any]) -> ACLPattern | None:
    observations = results.get("rate_observations") or []
    usable: list[dict[str, float]] = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        try:
            rate = float(item.get("rate") or item.get("packets_per_second") or 0)
            probes = float(item.get("probes") or item.get("sample_size") or 0)
            resets = float(item.get("resets") or 0)
            timeouts = float(item.get("timeouts") or item.get("drops") or 0)
        except (TypeError, ValueError):
            continue
        if rate > 0 and probes > 0:
            usable.append(
                {
                    "rate": rate,
                    "probes": probes,
                    "resets": resets,
                    "timeouts": timeouts,
                    "adverse_ratio": min(1.0, (resets + timeouts) / probes),
                    "reset_ratio": min(1.0, resets / probes),
                }
            )
    if len(usable) < 2:
        return None
    ordered = sorted(usable, key=lambda item: item["rate"])
    low, high = ordered[0], ordered[-1]
    if high["rate"] < low["rate"] * 1.5:
        return None
    adverse_delta = high["adverse_ratio"] - low["adverse_ratio"]
    reset_delta = high["reset_ratio"] - low["reset_ratio"]
    if adverse_delta < 0.25:
        return None
    if bool(results.get("reset_increase_with_rate")) and reset_delta >= 0.2:
        return ACLPattern(
            pattern_type="ids_active",
            confidence=0.85,
            description=(
                "Reset responses increased with the recorded probe rate "
                f"({low['rate']:g} to {high['rate']:g} probes/s)."
            ),
            recommendation="Stop rate escalation and retain the lowest policy-approved probe rate.",
        )
    return ACLPattern(
        pattern_type="rate_limit_active",
        confidence=0.85,
        description=(
            "Timeout/reset ratio increased by "
            f"{adverse_delta:.0%} as the recorded probe rate rose from "
            f"{low['rate']:g} to {high['rate']:g} probes/s."
        ),
        recommendation="Use the lowest policy-approved rate and avoid retry bursts.",
    )


def detect_firewall_acl(
    nmap_results: dict[str, Any],
    target: str,
) -> ACLPattern | None:
    """Classify corroborated filtering behaviour from Nmap port-state evidence.

    Static port states cannot prove IDS activity. ``ids_active`` and
    ``rate_limit_active`` therefore require explicit multi-rate observations in
    ``rate_observations`` instead of being inferred from a single scan.

    >>> result = {
    ...     "ports": [{"protocol": "tcp", "port": 22, "state": "open"}],
    ...     "extraports": [{"protocol": "udp", "state": "filtered", "count": 12}],
    ... }
    >>> detect_firewall_acl(result, "example-target").pattern_type
    'stateless_udp_block'
    """
    if not isinstance(nmap_results, dict):
        raise TypeError("nmap_results must be a dictionary")
    if not str(target or "").strip():
        raise ValueError("target cannot be empty")

    rate_pattern = _rate_pattern(nmap_results)
    if rate_pattern is not None:
        return rate_pattern

    policy = _acl_policy()
    try:
        threshold = min(1.0, max(0.0, float(policy.get("filtered_ratio_threshold", 0.6))))
        minimum = max(1, int(policy.get("min_sampled_ports", 10)))
    except (TypeError, ValueError):
        threshold, minimum = 0.6, 10

    counts, rows = _counts(nmap_results)
    filter_states = {"filtered", "open|filtered"}
    tcp_open = _sum_states(counts, "tcp", {"open"})
    tcp_closed = _sum_states(counts, "tcp", {"closed"})
    tcp_filtered = _sum_states(counts, "tcp", filter_states)
    udp_open = _sum_states(counts, "udp", {"open"})
    udp_closed = _sum_states(counts, "udp", {"closed"})
    udp_filtered = _sum_states(counts, "udp", filter_states)
    tcp_sample = tcp_open + tcp_closed + tcp_filtered
    udp_sample = udp_open + udp_closed + udp_filtered

    if (
        tcp_open > 0
        and udp_sample >= minimum
        and udp_open == 0
        and udp_closed == 0
        and udp_filtered == udp_sample
    ):
        return ACLPattern(
            pattern_type="stateless_udp_block",
            confidence=0.9,
            description=(
                f"All {udp_sample} sampled UDP ports were filtered while "
                f"{tcp_open} TCP service(s) were open on {target}."
            ),
            recommendation=(
                "Skip additional UDP probes unless the operator explicitly enables a "
                "service-specific follow-up; continue only against observed TCP services."
            ),
        )

    common_ports = {22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389}
    common_closed = [
        _port_number(item.get("port"))
        for item in rows
        if str(item.get("protocol") or "tcp").lower() == "tcp"
        and _normalise_state(item.get("state")) == "closed"
        and _port_number(item.get("port")) in common_ports
    ]
    if (
        tcp_sample >= minimum
        and tcp_filtered / max(1, tcp_sample) >= threshold
        and common_closed
    ):
        return ACLPattern(
            pattern_type="stateful_tcp_inspection",
            confidence=0.8,
            description=(
                f"{tcp_filtered}/{tcp_sample} sampled TCP ports were filtered while "
                f"common port(s) {', '.join(map(str, sorted(set(common_closed))))} returned closed."
            ),
            recommendation=(
                "Restrict follow-up checks to observed open services and retain the "
                "policy-defined low retry and scan-delay settings."
            ),
        )

    filtered_rows = [
        item
        for item in rows
        if _normalise_state(item.get("state")) in filter_states
    ]
    accessible_count = tcp_open + tcp_closed + udp_open + udp_closed
    if filtered_rows and accessible_count > 0:
        filtered_ports = sorted(
            {
                _port_number(item.get("port"))
                for item in filtered_rows
                if _port_number(item.get("port")) > 0
            }
        )
        sample_total = max(1, len(rows))
        ratio = len(filtered_rows) / sample_total
        confidence = round(min(0.85, 0.6 + ratio * 0.25), 2)
        return ACLPattern(
            pattern_type="port_specific_acl",
            confidence=confidence,
            description=(
                "Filtering was limited to specific reported ports: "
                + ", ".join(map(str, filtered_ports[:20]))
                + ("." if len(filtered_ports) <= 20 else "; additional ports omitted from this summary.")
            ),
            recommendation=(
                "Do not retry the filtered ports automatically; continue only with "
                "policy-enabled checks against observed open services."
            ),
        )
    return None


__all__ = ["ACLPattern", "detect_firewall_acl"]
