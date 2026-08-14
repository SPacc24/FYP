from __future__ import annotations

"""Stable scanner-owned result contracts for handover and audit consumers.

The helpers in this module are deliberately independent from Flask/templates
and downstream vulnerability decisions. They describe only execution, evidence and
runtime readiness observed by the scanner.
"""

import errno
import os
import shutil
import socket
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


LIFECYCLE_LABELS: dict[str, str] = {
    "executed_evidence": "Completed",
    "executed_no_evidence": "No Evidence Observed",
    "executed_timeout": "Timed Out - Incomplete",
    "executed_failed": "Failed - Incomplete",
    "not_applicable": "Not Applicable",
    "disabled_operator": "Disabled by Operator",
    "disabled_policy": "Disabled by Policy",
    "tool_unavailable": "Tool Unavailable",
    "insufficient_privilege": "Unavailable - Insufficient Privilege",
    "scope_blocked": "Scope Blocked",
    "deferred": "Deferred",
    "assumed_live": "Not Executed - Assumed Live",
    "skipped_policy": "Skipped by Policy",
}




def raw_packet_socket_readiness() -> tuple[bool | None, str]:
    """Check whether this process can open a raw packet socket without sending traffic.

    ARP discovery requires raw-packet privileges on Linux.  This readiness probe
    opens and immediately closes a socket; it does not transmit or capture any
    target traffic. ``None`` means the platform could not be assessed reliably.
    """
    af_packet = getattr(socket, "AF_PACKET", None)
    if af_packet is None:
        return None, "Raw packet-socket capability could not be assessed on this platform."
    probe = None
    try:
        probe = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(0x0003))
        return True, "Raw packet-socket capability is available to the scanner process."
    except PermissionError:
        return False, "Raw packet-socket access is not permitted; CAP_NET_RAW or equivalent privilege is required for ARP discovery."
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.EPERM, errno.EACCES}:
            return False, "Raw packet-socket access is not permitted; CAP_NET_RAW or equivalent privilege is required for ARP discovery."
        return None, f"Raw packet-socket capability probe was inconclusive ({type(exc).__name__})."
    finally:
        if probe is not None:
            try:
                probe.close()
            except OSError:
                pass


def command_completion_reason(result: Mapping[str, Any] | None) -> str:
    """Return a stable command completion reason without inspecting tool text."""
    result = result or {}
    explicit = str(result.get("completion_reason") or "").strip().lower()
    if explicit:
        return explicit
    error = str(result.get("error") or "").strip().lower()
    if error == "timeout" or bool(result.get("timed_out")):
        return "timeout"
    if result.get("success"):
        return "completed"
    if error == "binary not found":
        return "binary_not_found"
    return "command_error"


def execution_lifecycle(result: Mapping[str, Any] | None, produced: bool) -> str:
    """Classify execution separately from whether usable evidence was produced."""
    result = result or {}
    reason = command_completion_reason(result)
    if reason == "timeout":
        return "executed_timeout"
    if not result.get("success"):
        return "executed_failed"
    return "executed_evidence" if produced else "executed_no_evidence"


def compact_port_ranges(ports: Iterable[int]) -> list[dict[str, int]]:
    """Represent exact port sets compactly as inclusive ranges."""
    values = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if not values:
        return []
    ranges: list[dict[str, int]] = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append({"start": start, "end": previous})
        start = previous = value
    ranges.append({"start": start, "end": previous})
    return ranges


def analyse_nmap_port_batch(
    *,
    host: str,
    protocol: str,
    requested_ports: Iterable[int],
    result: Mapping[str, Any],
    parsed: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Record exactly which ports have parseable execution evidence.

    A successful exit code alone is not treated as proof that every requested
    endpoint was tested. Explicit port rows are exact. An Nmap ``extraports``
    state can cover the remaining selected ports only when its retained count
    accounts for the complete remainder.
    """
    requested = sorted({int(port) for port in requested_ports if 1 <= int(port) <= 65535})
    requested_set = set(requested)
    parsed = parsed or {}
    states: dict[int, str] = {}
    for row in parsed.get("ports") or []:
        if str(row.get("protocol") or protocol).lower() != protocol.lower():
            continue
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port in requested_set:
            state = str(row.get("state") or "unknown").strip().lower()
            states[port] = state if state in {"open", "closed", "filtered"} else "unknown"

    remaining = requested_set - set(states)
    extraports = [
        row for row in parsed.get("extraports") or []
        if str(row.get("protocol") or protocol).lower() == protocol.lower()
    ]
    if remaining and len(extraports) == 1:
        extraport = extraports[0]
        try:
            count = int(extraport.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        state = str(extraport.get("state") or "unknown").strip().lower()
        if count >= len(remaining):
            normalised_state = state if state in {"open", "closed", "filtered"} else "unknown"
            for port in remaining:
                states[port] = normalised_state

    scanned = sorted(states)
    unproven = sorted(requested_set - set(scanned))
    completion_reason = command_completion_reason(result)
    return {
        "host": str(host),
        "protocol": str(protocol).lower(),
        "requested_ports": requested,
        "scanned_ports": scanned,
        "unproven_ports": unproven,
        "port_states": {str(port): state for port, state in sorted(states.items())},
        "completion_reason": completion_reason,
        "lifecycle_state": execution_lifecycle(result, bool(scanned)),
        "attempts": int(result.get("attempts") or 1),
    }


def _selected_port_set(selection: Mapping[str, Any]) -> set[int]:
    if str(selection.get("mode") or "").lower() == "full":
        return set(range(1, 65536))
    return {
        int(port)
        for port in selection.get("ports") or []
        if str(port).isdigit() and 1 <= int(port) <= 65535
    }


def build_endpoint_coverage(
    *,
    live_hosts: Iterable[str],
    scan_options: Mapping[str, Any],
    batches: Iterable[Mapping[str, Any]],
    default_untested_reasons: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build exact, disjoint configured/scanned/untested endpoint coverage."""
    hosts = [str(host) for host in live_hosts]
    selections = (scan_options.get("port_selection") or {}) if scan_options else {}
    defaults = dict(default_untested_reasons or {})
    batch_rows = list(batches or [])
    output: dict[str, Any] = {}

    for protocol in ("tcp", "udp"):
        configured = _selected_port_set(selections.get(protocol) or {})
        protocol_hosts: dict[str, Any] = {}
        totals = {
            "configured": 0,
            "scanned": 0,
            "untested": 0,
            "failed": 0,
            "open": 0,
            "closed": 0,
            "filtered": 0,
            "unknown": 0,
        }
        protocol_invariants: list[bool] = []

        for host in hosts:
            relevant = [
                row for row in batch_rows
                if str(row.get("host") or "") == host
                and str(row.get("protocol") or "").lower() == protocol
            ]
            states: dict[int, str] = {}
            failure_causes: dict[str, set[int]] = {}
            for row in relevant:
                for key, state in (row.get("port_states") or {}).items():
                    try:
                        port = int(key)
                    except (TypeError, ValueError):
                        continue
                    if port in configured:
                        states[port] = str(state or "unknown").lower()
                cause = str(row.get("completion_reason") or "command_error")
                if cause != "completed":
                    failed = {
                        int(port) for port in row.get("unproven_ports") or []
                        if int(port) in configured
                    }
                    if failed:
                        failure_causes.setdefault(cause, set()).update(failed)

            scanned = set(states)
            untested = configured - scanned
            state_sets = {
                state: {port for port, value in states.items() if value == state}
                for state in ("open", "closed", "filtered")
            }
            known_states = set().union(*state_sets.values()) if state_sets else set()
            state_sets["unknown"] = scanned - known_states
            failed = set().union(*failure_causes.values()) if failure_causes else set()
            failed &= untested
            untested_without_specific_cause = untested - failed
            default_reason = defaults.get(protocol, "not_executed")
            if untested_without_specific_cause:
                failure_causes.setdefault(default_reason, set()).update(untested_without_specific_cause)

            partition_ok = (
                configured == scanned | untested
                and not (scanned & untested)
                and scanned == set().union(*state_sets.values())
            )
            protocol_invariants.append(partition_ok)
            host_row = {
                "configured_port_count": len(configured),
                "configured_port_ranges": compact_port_ranges(configured),
                "scanned_port_count": len(scanned),
                "scanned_port_ranges": compact_port_ranges(scanned),
                "ports_scanned": sorted(scanned),
                "untested_port_count": len(untested),
                "untested_port_ranges": compact_port_ranges(untested),
                "failed_port_count": len(failed),
                "failed_port_ranges": compact_port_ranges(failed),
                "untested_by_cause": {
                    cause: {
                        "count": len(ports),
                        "port_ranges": compact_port_ranges(ports),
                    }
                    for cause, ports in sorted(failure_causes.items())
                    if ports
                },
                "states": {
                    state: {
                        "count": len(ports),
                        "port_ranges": compact_port_ranges(ports),
                    }
                    for state, ports in state_sets.items()
                },
                "open_ports_observed": sorted(state_sets["open"]),
                "open_port_count": len(state_sets["open"]),
                "invariant": {
                    "configured_equals_scanned_plus_untested": partition_ok,
                    "scanned_state_partition_complete": scanned == set().union(*state_sets.values()),
                },
            }
            protocol_hosts[host] = host_row
            for key in totals:
                if key in {"open", "closed", "filtered", "unknown"}:
                    totals[key] += len(state_sets[key])
                else:
                    totals[key] += int(host_row.get(f"{key}_port_count") or 0)

        output[protocol] = {
            "mode": str((selections.get(protocol) or {}).get("mode") or ""),
            "hosts": protocol_hosts,
            "totals": totals,
            "invariant": {
                "all_hosts_reconcile": all(protocol_invariants),
                "configured_equals_scanned_plus_untested": (
                    totals["configured"] == totals["scanned"] + totals["untested"]
                ),
            },
        }
    return output


def build_selected_plan_readiness(
    *,
    scan_options: Mapping[str, Any],
    cve_source_status: Mapping[str, Any],
    cvss_verifiers: Mapping[str, Mapping[str, Any]] | None = None,
    storage_paths: Iterable[str | Path] = (),
    binary_resolver: Callable[[str], str | None] = shutil.which,
    nse_preflight: Callable[[Iterable[str]], Mapping[str, Any]] | None = None,
    raw_socket_probe: Callable[[], tuple[bool | None, str]] | None = None,
) -> dict[str, Any]:
    """Report readiness only for the selected plan and required data sources."""
    rows: list[dict[str, Any]] = []
    service_identity = scan_options.get("service_identity") or {}
    core_nmap_selected = any(
        bool(service_identity.get(key))
        for key in (
            "tcp_discovery_enabled",
            "udp_discovery_enabled",
            "service_fingerprinting_enabled",
        )
    ) or "nmap_os_identity" in set(scan_options.get("enabled_tools") or [])
    if core_nmap_selected:
        path = binary_resolver("nmap")
        rows.append({
            "component": "nmap",
            "kind": "core_binary",
            "required": True,
            "status": "ready" if path else "unavailable",
            "detail": path or "Required Nmap binary was not found in PATH.",
        })

    # Host-discovery controls sit outside collector_plan, so account for their
    # binaries explicitly rather than letting preflight overstate readiness.
    host_discovery = (scan_options.get("host_discovery") or {}).get("effective") or {}
    discovery_requirements = (
        ("icmp_echo", ("ping",)),
        ("reverse_dns", ("dig",)),
        ("arp_discovery", ("arp-scan",)),
        ("nmap_host_discovery", ("nmap",)),
        ("route_trace", ("traceroute", "tracepath")),
    )
    for control, candidates in discovery_requirements:
        if not host_discovery.get(control):
            continue
        resolved_name = ""
        resolved_path = ""
        for candidate in candidates:
            candidate_path = binary_resolver(candidate)
            if candidate_path:
                resolved_name, resolved_path = candidate, candidate_path
                break
        status = "ready" if resolved_path else "unavailable"
        detail = resolved_path or ("Missing optional binary: " + " or ".join(candidates))
        if control == "arp_discovery" and resolved_path:
            privilege_ready, privilege_detail = (raw_socket_probe or raw_packet_socket_readiness)()
            if privilege_ready is False:
                status, detail = "insufficient_privilege", privilege_detail
            elif privilege_ready is None:
                status, detail = "unknown", privilege_detail
            elif privilege_detail:
                detail = f"{resolved_path} · {privilege_detail}"
        rows.append({
            "component": f"host_discovery:{control}",
            "kind": "host_discovery_binary",
            "required": False,
            "status": status,
            "detail": detail,
            "resolved_binary": resolved_name,
        })

    for collector_id, entry in (scan_options.get("collector_plan") or {}).items():
        if not entry.get("requested"):
            continue
        if entry.get("policy_state") == "blocked":
            rows.append({
                "component": collector_id,
                "kind": "collector",
                "required": False,
                "status": "blocked_policy",
                "detail": str(entry.get("policy_reason") or "Disabled by effective policy."),
            })
            continue
        binary = str(entry.get("binary") or "").strip()
        binary_path = binary_resolver(binary) if binary else ""
        scripts = list(entry.get("nse_scripts") or [])
        credential_required = bool(entry.get("credential_required"))
        nse_state = dict(nse_preflight(scripts)) if scripts and nse_preflight else {
            "known": True,
            "available": True,
            "missing": [],
        }
        if credential_required:
            status = "deferred_credentials"
            detail = (
                "Collector requires explicitly authorised credentials, but the current "
                "IP/CIDR-only scanner input contract does not accept them; no default or guessed credential will be used."
            )
        elif binary and not binary_path:
            status, detail = "unavailable", f"Missing optional binary: {binary}"
        elif not nse_state.get("available", True):
            status = "unavailable"
            detail = "Missing Nmap NSE script(s): " + ", ".join(nse_state.get("missing") or [])
        elif scripts and not nse_state.get("known", True):
            status, detail = "unknown", "Nmap script directory could not be resolved during preflight."
        else:
            status, detail = "ready", binary_path or "No external binary required."
        rows.append({
            "component": collector_id,
            "kind": "collector",
            "required": False,
            "status": status,
            "detail": detail,
        })

    rows.append({
        "component": "cve_program_index",
        "kind": "data_source",
        "required": False,
        "status": "ready" if cve_source_status.get("available") else "unavailable",
        "detail": (
            f"{int(cve_source_status.get('records_indexed') or 0)} indexed record(s)."
            if cve_source_status.get("available")
            else str(cve_source_status.get("error") or "Official CVE index is unavailable.")
        ),
    })
    # CVSS is post-match vulnerability scoring metadata, not a scan-execution
    # dependency. Verifier availability must never block discovery, evidence
    # recovery, identity construction, or CVE applicability matching.
    for path_value in storage_paths:
        path = Path(path_value)
        ready = path.exists() and path.is_dir() and os.access(path, os.W_OK)
        rows.append({
            "component": path.name or str(path),
            "kind": "storage",
            "required": True,
            "status": "ready" if ready else "unavailable",
            "detail": str(path),
        })

    blockers = [row for row in rows if row["required"] and row["status"] == "unavailable"]
    degradations = [
        row for row in rows
        if not row["required"] and row["status"] in {"unavailable", "unknown", "blocked_policy", "deferred_credentials", "insufficient_privilege"}
    ]
    return {
        "status": "blocked" if blockers else ("degraded" if degradations else "ready"),
        "launch_blocked": bool(blockers),
        "blocking_components": [row["component"] for row in blockers],
        "degraded_components": [row["component"] for row in degradations],
        "rows": rows,
    }


def derive_result_state(
    *,
    readiness: Mapping[str, Any],
    services: Iterable[Mapping[str, Any]],
    baseline_cves: Iterable[Mapping[str, Any]],
    held_diagnostics: Iterable[Mapping[str, Any]],
    cve_source_available: bool,
) -> str:
    """Return a neutral backend state for report consumers."""
    if readiness.get("launch_blocked"):
        return "core_tool_unavailable"
    if not cve_source_available:
        return "cve_index_unavailable"
    service_rows = list(services or [])
    cve_rows = list(baseline_cves or [])
    held_rows = list(held_diagnostics or [])
    if not service_rows:
        return "completed_no_services"
    if cve_rows:
        return "completed_with_baseline_matches"
    if held_rows:
        return "all_matches_held"
    return "no_baseline_matches"
