"""Evidence-driven, operator-controlled network-layer discovery.

This module owns the scanner-side work that occurs before the existing
vulnerability-assessment pipeline.  It deliberately does not implement AI,
exploitation, Caldera, mapping, or pivoting.  A route created by another
component may be observed and followed, but this module never creates access,
adds routes, changes interface addresses, or guesses a hidden subnet.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from config import Config
from storage import scan_store

from . import command_builders


DISCOVERY_TASKS = [
    "Phase 1 — Entry Address Validation",
    "Phase 1 — Entry Reachability Evidence",
    "Phase 1 — Local Observation Snapshot",
    "Phase 2 — Initial Local Layer Enumeration",
]


def _phase2_host_discovery_timeout_seconds() -> int:
    """Bound Phase 2 host-discovery commands without environment-specific values."""

    try:
        configured = int(os.getenv("PHASE2_HOST_DISCOVERY_TIMEOUT_SECONDS", "120"))
    except ValueError:
        configured = 120
    return max(15, min(configured, 600))

_NON_FORWARDING_ROUTE_TYPES = {
    "blackhole",
    "broadcast",
    "local",
    "multicast",
    "prohibit",
    "throw",
    "unreachable",
}


class DiscoveryWorkflowError(RuntimeError):
    """Raised when discovery cannot safely continue from retained evidence."""


def validate_external_target(value: str) -> str:
    """Return one canonical IP address and reject ranges, CIDRs and hostnames."""

    raw = str(value or "").strip()
    if not raw:
        raise DiscoveryWorkflowError("An entry IP address is required.")
    if any(token in raw for token in ("/", ",", " ", "-")):
        raise DiscoveryWorkflowError(
            "Phase 1 accepts one entry IP address only, not a CIDR or range."
        )
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise DiscoveryWorkflowError("The entry target is not a valid IP address.") from exc


def _run_command(
    scan_id: str,
    command: list[str],
    purpose: str,
    *,
    timeout: int = 30,
    output_file: Path | None = None,
    interface: str = "",
    source_address: str = "",
    segment_id: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Run one bounded command and retain exact execution provenance."""

    rendered = shlex.join([str(part) for part in command])
    started_at = scan_store.now()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        success = completed.returncode == 0
        output = stdout if stdout.strip() else stderr
        if output_file is not None and not output_file.exists():
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output, encoding="utf-8")
        ended_at = scan_store.now()
        scan_store.log_command(
            scan_id,
            command=rendered,
            purpose=purpose,
            output=output,
            output_summary=(output.strip().splitlines() or ["No console output"])[0][:300],
            status="Completed" if success else "Failed",
            exit_code=completed.returncode,
            output_file=str(output_file or ""),
            output_truncated=False,
            started_at=started_at,
            ended_at=ended_at,
            interface=interface,
            source_address=source_address,
            segment_id=segment_id,
            target=target,
        )
        return {
            "success": success,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": rendered,
            "output_file": str(output_file or ""),
            "started_at": started_at,
            "ended_at": ended_at,
        }
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(
            part for part in (str(exc.stdout or ""), str(exc.stderr or "")) if part
        )
        ended_at = scan_store.now()
        scan_store.log_command(
            scan_id,
            command=rendered,
            purpose=purpose,
            output=output,
            output_summary=f"Timed out after {timeout} seconds",
            status="Timed Out",
            exit_code=-1,
            output_file=str(output_file or ""),
            output_truncated=False,
            started_at=started_at,
            ended_at=ended_at,
            interface=interface,
            source_address=source_address,
            segment_id=segment_id,
            target=target,
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "command": rendered,
            "output_file": str(output_file or ""),
            "timed_out": True,
            "started_at": started_at,
            "ended_at": ended_at,
        }
    except OSError as exc:
        ended_at = scan_store.now()
        scan_store.log_command(
            scan_id,
            command=rendered,
            purpose=purpose,
            output=str(exc),
            output_summary=str(exc),
            status="Failed",
            exit_code=-1,
            output_file=str(output_file or ""),
            output_truncated=False,
            started_at=started_at,
            ended_at=ended_at,
            interface=interface,
            source_address=source_address,
            segment_id=segment_id,
            target=target,
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": rendered,
            "output_file": str(output_file or ""),
            "started_at": started_at,
            "ended_at": ended_at,
        }


def _json_command(
    scan_id: str,
    command: list[str],
    purpose: str,
    *,
    required: bool = True,
    **provenance: Any,
) -> list[dict[str, Any]]:
    result = _run_command(scan_id, command, purpose, timeout=20, **provenance)
    if not result.get("success"):
        if required:
            raise DiscoveryWorkflowError(
                f"Could not inspect the scanner network configuration: {purpose}."
            )
        return []
    try:
        payload = json.loads(result.get("stdout") or "[]")
    except json.JSONDecodeError as exc:
        if required:
            raise DiscoveryWorkflowError(
                f"The scanner returned invalid network data for: {purpose}."
            ) from exc
        return []
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        if required:
            raise DiscoveryWorkflowError(f"Unexpected network data for: {purpose}.")
        return []
    return [item for item in payload if isinstance(item, dict)]


def _host_is_up_from_nmap_xml(path: Path) -> bool:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return False
    return any(
        (host.find("status") is not None)
        and (host.find("status").attrib.get("state") == "up")
        for host in root.findall("host")
    )


def check_external_reachability(scan_id: str, external_ip: str) -> dict[str, Any]:
    """Collect bounded entry-host evidence without requiring a response to continue."""

    evidence: list[dict[str, Any]] = []
    reachable = False

    ping = shutil.which("ping")
    if ping:
        result = _run_command(
            scan_id,
            command_builders.ping_echo(ping, external_ip, 1, 2),
            "Phase 1 ICMP entry reachability evidence",
            timeout=8,
            target=external_ip,
        )
        observed = bool(result.get("success"))
        reachable = reachable or observed
        evidence.append(
            {
                "method": "icmp_echo",
                "response_observed": observed,
                "command": result.get("command"),
                "returncode": result.get("returncode"),
            }
        )

    nmap = shutil.which("nmap")
    if nmap:
        output_path = scan_store.scan_path(f"{scan_id}_phase1_entry.xml")
        output_path.unlink(missing_ok=True)
        result = _run_command(
            scan_id,
            command_builders.nmap_external_reachability(nmap, external_ip, output_path),
            "Phase 1 Nmap entry host-discovery evidence",
            timeout=30,
            output_file=output_path,
            target=external_ip,
        )
        observed = _host_is_up_from_nmap_xml(output_path)
        reachable = reachable or observed
        evidence.append(
            {
                "method": "nmap_host_discovery",
                "response_observed": observed,
                "command": result.get("command"),
                "returncode": result.get("returncode"),
                "evidence_file": str(output_path),
            }
        )

    # Path tracing is retained as observation only.  Intermediate addresses do
    # not become subnet candidates and are never classified as routers or
    # filtering devices solely because they appear in a trace.
    tracepath = shutil.which("tracepath")
    traceroute = shutil.which("traceroute")
    trace_tool = tracepath or traceroute
    if trace_tool:
        try:
            max_hops = max(
                1,
                min(int(os.getenv("DISCOVERY_TRACE_MAX_HOPS", "16")), 64),
            )
        except ValueError:
            max_hops = 16
        if tracepath:
            trace_argv = command_builders.tracepath_observation(
                tracepath, external_ip, max_hops
            )
            method = "tracepath"
        else:
            trace_argv = command_builders.traceroute_observation(
                traceroute, external_ip, max_hops
            )
            method = "traceroute"
        result = _run_command(
            scan_id,
            trace_argv,
            "Phase 1 bounded path observation",
            timeout=max(10, min(max_hops * 2, 90)),
            target=external_ip,
        )
        output = str(result.get("stdout") or result.get("stderr") or "")
        evidence.append(
            {
                "method": method,
                "response_observed": bool(output.strip()),
                "completed": bool(result.get("success")),
                "command": result.get("command"),
                "returncode": result.get("returncode"),
                "raw_output": output,
                "interpretation": "path_observation_only",
            }
        )

    state = "responsive" if reachable else "reachability_not_established"
    return {
        "target": external_ip,
        "reachable": reachable,
        "reachability_state": state,
        "evidence": evidence,
        "statement": (
            "At least one permitted entry probe received a response."
            if reachable
            else "No response was observed from the permitted entry probes."
        ),
    }


def _route_network(route: dict[str, Any], version: int) -> ipaddress._BaseNetwork | None:
    dst = str(route.get("dst") or "").strip()
    if not dst or dst == "default":
        dst = "0.0.0.0/0" if version == 4 else "::/0"
    try:
        network = ipaddress.ip_network(dst, strict=False)
    except ValueError:
        return None
    return network if network.version == version else None


def _observable_route_network(network: ipaddress._BaseNetwork) -> bool:
    """Return whether a route destination can be retained as unicast evidence."""

    if network.is_unspecified or network.is_loopback or network.is_link_local:
        return False
    return not network.is_multicast


def _usable_internal_network(network: ipaddress._BaseNetwork) -> bool:
    """Compatibility name for a bounded, enumeratable unicast network.

    No private/public assumption is made.  The decision uses only address
    semantics and the configured expansion limit.
    """

    if not _observable_route_network(network):
        return False
    maximum = max(1, int(getattr(Config, "MAX_EXPANDED_TARGETS", 256)))
    return int(network.num_addresses) <= maximum


def _interface_index(address_rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in address_rows or []:
        name = str(row.get("ifname") or "").strip()
        if not name:
            continue
        addresses: list[dict[str, Any]] = []
        for item in row.get("addr_info") or []:
            if not isinstance(item, dict):
                continue
            local = str(item.get("local") or "").strip()
            try:
                address = ipaddress.ip_address(local)
            except ValueError:
                continue
            addresses.append(
                {
                    "address": str(address),
                    "prefixlen": int(item.get("prefixlen") or address.max_prefixlen),
                    "family": str(item.get("family") or ""),
                    "scope": str(item.get("scope") or ""),
                }
            )
        result[name] = {
            "ifname": name,
            "operstate": str(row.get("operstate") or ""),
            "flags": [str(flag) for flag in row.get("flags") or []],
            "link_type": str(row.get("link_type") or ""),
            "address": str(row.get("address") or ""),
            "addresses": addresses,
        }
    return result


def _source_for_interface(
    interface_index: dict[str, dict[str, Any]], interface: str, version: int
) -> str:
    for item in (interface_index.get(interface) or {}).get("addresses") or []:
        try:
            address = ipaddress.ip_address(str(item.get("address") or ""))
        except ValueError:
            continue
        if address.version == version and not address.is_loopback and not address.is_link_local:
            return str(address)
    return ""


def _interface_networks(
    address_rows: Iterable[dict[str, Any]], interface: str, version: int
) -> list[ipaddress._BaseNetwork]:
    networks: set[ipaddress._BaseNetwork] = set()
    for row in address_rows or []:
        if str(row.get("ifname") or "") != interface:
            continue
        for item in row.get("addr_info") or []:
            if not isinstance(item, dict):
                continue
            local = str(item.get("local") or "").strip()
            prefix = item.get("prefixlen")
            try:
                network = ipaddress.ip_network(f"{local}/{int(prefix)}", strict=False)
            except (TypeError, ValueError):
                continue
            if network.version == version and _usable_internal_network(network):
                networks.add(network)
    return sorted(networks, key=lambda value: (-value.prefixlen, str(value)))


def _route_signature(route: dict[str, Any], version: int | None = None) -> str:
    if version is None:
        dst = str(route.get("dst") or "")
        version = 6 if ":" in dst else 4
    network = _route_network(route, version)
    return "|".join(
        [
            str(network or ""),
            str(route.get("dev") or ""),
            str(route.get("gateway") or ""),
            str(route.get("table") or "main"),
            str(route.get("protocol") or ""),
            str(route.get("scope") or ""),
            str(route.get("type") or "unicast"),
        ]
    )


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(material.encode('utf-8')).hexdigest()[:14]}"


def _segment_identifier(
    network: str,
    interface: str,
    source_address: str,
    next_hop: str,
    route_table: str,
    scope_kind: str,
) -> str:
    return _stable_id(
        "segment",
        network,
        interface,
        source_address,
        next_hop,
        route_table,
        scope_kind,
    )


def _path_identifier(from_segment_id: str, route: dict[str, Any], network: str) -> str:
    return _stable_id("path", from_segment_id, network, _route_signature(route))


def collect_network_snapshot(scan_id: str, purpose_prefix: str) -> dict[str, Any]:
    """Compatibility snapshot that deliberately excludes the kernel routing table.

    The live Phase 2 workflow discovers continuation networks from selected
    infrastructure devices. This compatibility helper keeps only local address/neighbour
    observations for older callers and cannot create continuation routes.
    """

    ip_tool = shutil.which("ip")
    if not ip_tool:
        return {
            "captured_at": scan_store.now(),
            "interfaces": [],
            "interface_index": {},
            "routes": [],
            "neighbours": [],
            "route_signatures": [],
        }
    addresses = _json_command(
        scan_id,
        [ip_tool, "-j", "addr", "show"],
        f"{purpose_prefix} local interface snapshot",
        required=False,
    )
    neighbours = _json_command(
        scan_id,
        [ip_tool, "-j", "neigh", "show"],
        f"{purpose_prefix} local neighbour snapshot",
        required=False,
    )
    return {
        "captured_at": scan_store.now(),
        "interfaces": addresses,
        "interface_index": _interface_index(addresses),
        "routes": [],
        "neighbours": neighbours,
        "route_signatures": [],
    }


def _route_get(scan_id: str, destination: str, purpose: str) -> dict[str, Any]:
    """Deprecated compatibility hook; live Phase 2 kernel route lookup is disabled."""

    raise DiscoveryWorkflowError(
        "Kernel route lookup is disabled. Phase 2 continuation networks must come from infrastructure topology evidence."
    )


def _longest_route_for_address(
    routes: Iterable[dict[str, Any]], address: ipaddress._BaseAddress
) -> tuple[dict[str, Any] | None, ipaddress._BaseNetwork | None]:
    candidates: list[tuple[int, dict[str, Any], ipaddress._BaseNetwork]] = []
    for route in routes or []:
        route_type = str(route.get("type") or "unicast").lower()
        if route_type in _NON_FORWARDING_ROUTE_TYPES:
            continue
        network = _route_network(route, address.version)
        if network is None or address not in network:
            continue
        candidates.append((network.prefixlen, route, network))
    candidates.sort(key=lambda item: item[0], reverse=True)
    if not candidates:
        return None, None
    return candidates[0][1], candidates[0][2]


def _candidate_network_records(
    external_ip: ipaddress._BaseAddress,
    interface: str,
    route_rows: Iterable[dict[str, Any]],
    address_rows: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Compatibility helper returning observed, bounded non-default routes.

    It does not infer VPNs from interface names, require private address space,
    or automatically approve any candidate for scanning.
    """

    routes = list(route_rows or [])
    matched_route, _ = _longest_route_for_address(routes, external_ip)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for route in routes:
        route_type = str(route.get("type") or "unicast").lower()
        if route_type in _NON_FORWARDING_ROUTE_TYPES:
            continue
        network = _route_network(route, external_ip.version)
        if network is None or network.prefixlen == 0 or not _usable_internal_network(network):
            continue
        subnet = str(network)
        if subnet in seen:
            continue
        seen.add(subnet)
        gateway = str(route.get("gateway") or "").strip()
        route_interface = str(route.get("dev") or interface or "").strip()
        relationship = "observed_specific_route"
        if gateway == str(external_ip):
            relationship = "specific_route_via_external_target"
        elif external_ip in network:
            relationship = "route_contains_entry_target"
        records.append(
            {
                "subnet": subnet,
                "interface": route_interface,
                "gateway": gateway,
                "access_mode": "directly_connected" if not gateway else "routed",
                "relationship": relationship,
                "evidence_source": "kernel_route_table",
                "route": dict(route),
                "verification_state": "observed",
            }
        )
    records.sort(
        key=lambda item: (
            -ipaddress.ip_network(item["subnet"], strict=False).prefixlen,
            item["subnet"],
        )
    )
    return records, matched_route


def _candidate_networks(
    external_ip: ipaddress._BaseAddress,
    interface: str,
    route_rows: Iterable[dict[str, Any]],
    address_rows: Iterable[dict[str, Any]],
) -> tuple[list[ipaddress._BaseNetwork], dict[str, Any] | None]:
    records, matched = _candidate_network_records(
        external_ip, interface, route_rows, address_rows
    )
    return [ipaddress.ip_network(item["subnet"], strict=False) for item in records], matched


def discover_network_context(scan_id: str, external_ip: str) -> dict[str, Any]:
    """Collect the entry route and current network-state snapshot.

    The entry layer is intentionally host-scoped.  Wider networks are retained
    only as observed continuation paths and require an operator decision.
    """

    snapshot = collect_network_snapshot(scan_id, "Phase 1")
    selected_route = _route_get(
        scan_id, external_ip, "Phase 1 route selection for entry address"
    )
    address = ipaddress.ip_address(external_ip)
    matched_route, matched_network = _longest_route_for_address(
        snapshot.get("routes") or [], address
    )
    interface = str(selected_route.get("dev") or "").strip()
    if not interface:
        raise DiscoveryWorkflowError(
            "No scanner interface is currently routed to the supplied entry address."
        )
    interface_index = snapshot.get("interface_index") or {}
    source_ip = str(selected_route.get("prefsrc") or selected_route.get("src") or "").strip()
    source_ip = source_ip or _source_for_interface(interface_index, interface, address.version)
    gateway = str(selected_route.get("gateway") or "").strip()
    route_table = str(selected_route.get("table") or (matched_route or {}).get("table") or "main")
    route_kind = "default" if matched_network is None or matched_network.prefixlen == 0 else "specific"
    return {
        "entry_target": external_ip,
        "interface": interface,
        "scanner_ip": source_ip,
        "gateway": gateway,
        "route_table": route_table,
        "route_type": route_kind,
        "route": selected_route,
        "matched_route": matched_route or {},
        "matched_network": str(matched_network or ""),
        "snapshot": snapshot,
        "access_mode": "directly_connected" if matched_route and not matched_route.get("gateway") and matched_route.get("scope") == "link" else "routed",
    }


def _selected_context(context: dict[str, Any], selected_subnet: str) -> dict[str, Any]:
    """Compatibility adapter for callers that still submit a route destination."""

    candidates = [
        item
        for item in context.get("subnet_candidates") or []
        if isinstance(item, dict) and str(item.get("subnet") or "") == selected_subnet
    ]
    if not candidates:
        raise DiscoveryWorkflowError(
            "The selected network was not present in retained route evidence."
        )
    match = candidates[0]
    selected = dict(context)
    selected.update(
        {
            "internal_subnet": str(match.get("subnet") or ""),
            "interface": str(match.get("interface") or context.get("interface") or ""),
            "scanner_ip": str(match.get("scanner_ip") or context.get("scanner_ip") or ""),
            "gateway": str(match.get("gateway") or ""),
            "access_mode": str(match.get("access_mode") or "routed"),
            "selected_subnet_evidence": dict(match),
        }
    )
    return selected


def _parse_host_inventory(
    path: Path,
    *,
    scanner_ip: str = "",
    gateway: str = "",
    segment_id: str = "",
) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise DiscoveryWorkflowError("Nmap host-discovery XML could not be parsed.") from exc

    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue
        primary_ip = ""
        mac = ""
        vendor = ""
        for address in host.findall("address"):
            value = str(address.attrib.get("addr") or "")
            kind = str(address.attrib.get("addrtype") or "")
            if kind in {"ipv4", "ipv6"} and not primary_ip:
                primary_ip = value
            elif kind == "mac":
                mac = value
                vendor = str(address.attrib.get("vendor") or "")
        if not primary_ip or primary_ip in seen:
            continue
        seen.add(primary_ip)
        hostname_observations = [
            {
                "value": str(node.attrib.get("name") or ""),
                "source": "nmap_host_discovery",
                "record_type": str(node.attrib.get("type") or ""),
            }
            for node in host.findall("hostnames/hostname")
            if node.attrib.get("name")
        ]
        hostname = str((hostname_observations[0] if hostname_observations else {}).get("value") or "")
        status_reason = str(status.attrib.get("reason") or "")
        is_scanner = bool(scanner_ip and primary_ip == scanner_ip)
        role = "scanner" if is_scanner else ("gateway" if gateway and primary_ip == gateway else "host")
        hosts.append(
            {
                "host_id": _stable_id("host", segment_id, primary_ip),
                "segment_id": segment_id,
                "ip": primary_ip,
                "address": primary_ip,
                "status": "up",
                "reachability_state": "responsive",
                "reachability_evidence": [
                    {
                        "source": "nmap_host_discovery",
                        "state": "up",
                        "reason": status_reason,
                    }
                ],
                "hostname": hostname,
                "hostname_observations": hostname_observations,
                "hostname_conflict": len(
                    {
                        str(item.get("value") or "").strip().lower()
                        for item in hostname_observations
                        if str(item.get("value") or "").strip()
                    }
                ) > 1,
                "mac": mac,
                "mac_vendor": vendor,
                "role": role,
                "is_scanner": is_scanner,
                "selectable": not is_scanner,
                "record_type": "scanner_source" if is_scanner else "discovered_host",
                "origin": "local_interface_configuration" if is_scanner else "network_enumeration",
                "origins": ["local_interface_configuration"] if is_scanner else ["network_enumeration"],
                "independently_discovered": not is_scanner,
                "discovered_by": ["nmap_host_discovery"],
                "verification_methods": ["nmap_host_discovery"],
                "evidence_file": str(path),
            }
        )
    return _sort_hosts(hosts)


def _sort_hosts(hosts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(item: dict[str, Any]) -> tuple[int, int, str]:
        try:
            address = ipaddress.ip_address(str(item.get("ip") or item.get("address") or ""))
            return (address.version, int(address), "")
        except ValueError:
            return (99, 0, str(item.get("ip") or item.get("address") or ""))

    return sorted([dict(item) for item in hosts], key=key)


def _merge_host_observation(
    inventory: dict[str, dict[str, Any]], observation: dict[str, Any]
) -> None:
    address = str(observation.get("ip") or observation.get("address") or "").strip()
    if not address:
        return
    existing = inventory.get(address)
    if existing is None:
        inventory[address] = dict(observation)
        return
    for key in ("hostname", "mac", "mac_vendor"):
        if not existing.get(key) and observation.get(key):
            existing[key] = observation[key]
    existing["hostname_observations"] = list(
        {
            (
                str(item.get("value") or ""),
                str(item.get("source") or ""),
            ): dict(item)
            for item in [
                *[value for value in existing.get("hostname_observations") or [] if isinstance(value, dict)],
                *[value for value in observation.get("hostname_observations") or [] if isinstance(value, dict)],
            ]
            if str(item.get("value") or "").strip()
        }.values()
    )
    existing["hostname_conflict"] = len(
        {
            str(item.get("value") or "").strip().lower()
            for item in existing.get("hostname_observations") or []
            if str(item.get("value") or "").strip()
        }
    ) > 1
    existing["reachability_evidence"] = list(
        {
            json.dumps(item, sort_keys=True, default=str): dict(item)
            for item in [
                *[value for value in existing.get("reachability_evidence") or [] if isinstance(value, dict)],
                *[value for value in observation.get("reachability_evidence") or [] if isinstance(value, dict)],
            ]
        }.values()
    )
    existing["is_scanner"] = bool(existing.get("is_scanner") or observation.get("is_scanner"))
    if existing["is_scanner"]:
        existing["role"] = "scanner"
        existing["selectable"] = False
        existing["reachability_state"] = "scanner_source"
    elif observation.get("role") == "gateway":
        existing["role"] = "gateway"
    existing["selectable"] = bool(existing.get("selectable", True) and observation.get("selectable", True))
    existing["discovered_by"] = list(
        dict.fromkeys(
            [
                *[str(value) for value in existing.get("discovered_by") or []],
                *[str(value) for value in observation.get("discovered_by") or []],
            ]
        )
    )
    existing["origins"] = list(
        dict.fromkeys(
            [
                *[str(value) for value in existing.get("origins") or ([existing.get("origin")] if existing.get("origin") else [])],
                *[str(value) for value in observation.get("origins") or ([observation.get("origin")] if observation.get("origin") else [])],
            ]
        )
    )
    existing["verification_methods"] = list(
        dict.fromkeys(
            [
                *[str(value) for value in existing.get("verification_methods") or []],
                *[str(value) for value in observation.get("verification_methods") or []],
            ]
        )
    )
    existing["independently_discovered"] = bool(
        existing.get("independently_discovered") or observation.get("independently_discovered")
    )
    if "operator_supplied" in existing.get("origins", []):
        existing["origin"] = "operator_supplied"
        existing["record_type"] = "entry_target"
    elif existing.get("is_scanner"):
        existing["origin"] = "local_interface_configuration"
        existing["record_type"] = "scanner_source"
    elif existing.get("independently_discovered"):
        existing["origin"] = "network_enumeration"
        existing["record_type"] = "discovered_host"
    if existing.get("reachability_state") != "responsive" and observation.get("reachability_state"):
        existing["reachability_state"] = observation["reachability_state"]


def _neighbour_observations(
    neighbours: Iterable[dict[str, Any]], segment: dict[str, Any]
) -> list[dict[str, Any]]:
    network = ipaddress.ip_network(str(segment["network"]), strict=False)
    interface = str(segment.get("interface") or "")
    scanner_ip = str(segment.get("source_address") or "")
    gateway = str(segment.get("next_hop") or "")
    rows: list[dict[str, Any]] = []
    for item in neighbours or []:
        if interface and str(item.get("dev") or "") != interface:
            continue
        address_text = str(item.get("dst") or "").strip()
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        if address not in network:
            continue
        is_scanner = bool(scanner_ip and address_text == scanner_ip)
        rows.append(
            {
                "host_id": _stable_id("host", segment.get("segment_id"), address_text),
                "segment_id": segment.get("segment_id"),
                "ip": address_text,
                "address": address_text,
                "status": "observed",
                "reachability_state": "observed_through_neighbour_evidence",
                "reachability_evidence": [
                    {
                        "source": "kernel_neighbour_table",
                        "state": item.get("state"),
                    }
                ],
                "hostname": "",
                "hostname_observations": [],
                "mac": str(item.get("lladdr") or ""),
                "mac_vendor": "",
                "role": "scanner" if is_scanner else ("gateway" if gateway and address_text == gateway else "host"),
                "is_scanner": is_scanner,
                "selectable": not is_scanner,
                "record_type": "scanner_source" if is_scanner else "discovered_host",
                "origin": "local_interface_configuration" if is_scanner else "network_enumeration",
                "origins": ["local_interface_configuration"] if is_scanner else ["network_enumeration"],
                "independently_discovered": not is_scanner,
                "discovered_by": ["kernel_neighbour_table"],
                "verification_methods": ["kernel_neighbour_table"],
                "neighbour_state": [str(value) for value in item.get("state") or []]
                if isinstance(item.get("state"), list)
                else str(item.get("state") or ""),
            }
        )
    return rows


def _parse_arp_scan(text: str, segment: dict[str, Any]) -> list[dict[str, Any]]:
    network = ipaddress.ip_network(str(segment["network"]), strict=False)
    scanner_ip = str(segment.get("source_address") or "")
    gateway = str(segment.get("next_hop") or "")
    rows: list[dict[str, Any]] = []
    for line in str(text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        address_text = parts[0].strip()
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        if address not in network:
            continue
        mac = parts[1].strip()
        vendor = parts[2].strip() if len(parts) > 2 else ""
        is_scanner = bool(scanner_ip and address_text == scanner_ip)
        rows.append(
            {
                "host_id": _stable_id("host", segment.get("segment_id"), address_text),
                "segment_id": segment.get("segment_id"),
                "ip": address_text,
                "address": address_text,
                "status": "observed",
                "reachability_state": "observed_through_arp_evidence",
                "reachability_evidence": [
                    {"source": "arp_scan", "state": "response_observed"}
                ],
                "hostname": "",
                "hostname_observations": [],
                "mac": mac,
                "mac_vendor": vendor,
                "role": "scanner" if is_scanner else ("gateway" if gateway and address_text == gateway else "host"),
                "is_scanner": is_scanner,
                "selectable": not is_scanner,
                "record_type": "scanner_source" if is_scanner else "discovered_host",
                "origin": "local_interface_configuration" if is_scanner else "network_enumeration",
                "origins": ["local_interface_configuration"] if is_scanner else ["network_enumeration"],
                "independently_discovered": not is_scanner,
                "discovered_by": ["arp_scan"],
                "verification_methods": ["arp_scan"],
            }
        )
    return rows


def _scanner_observation(segment: dict[str, Any]) -> dict[str, Any] | None:
    source = str(segment.get("source_address") or "").strip()
    if not source:
        return None
    try:
        address = ipaddress.ip_address(source)
        network = ipaddress.ip_network(str(segment.get("network") or ""), strict=False)
    except ValueError:
        return None
    if address not in network:
        return None
    return {
        "host_id": _stable_id("host", segment.get("segment_id"), source),
        "segment_id": segment.get("segment_id"),
        "ip": source,
        "address": source,
        "status": "observed",
        "reachability_state": "scanner_source",
        "reachability_evidence": [
            {"source": "local_interface_configuration", "state": "local_source"}
        ],
        "hostname": "",
        "hostname_observations": [],
        "mac": "",
        "mac_vendor": "",
        "role": "scanner",
        "is_scanner": True,
        "selectable": False,
        "record_type": "scanner_source",
        "origin": "local_interface_configuration",
        "origins": ["local_interface_configuration"],
        "independently_discovered": False,
        "discovered_by": ["local_interface_configuration"],
        "verification_methods": ["local_interface_configuration"],
    }



def _entry_target_observation(
    segment: dict[str, Any], entry_result: dict[str, Any]
) -> dict[str, Any]:
    """Create the operator-supplied entry record without relabelling it discovered."""

    address = str(segment.get("enumeration_target") or "").strip()
    evidence = [
        {
            "source": str(item.get("method") or "entry_probe"),
            "state": "response_observed" if item.get("response_observed") else "no_response_observed",
            "command": item.get("command"),
            "returncode": item.get("returncode"),
        }
        for item in entry_result.get("evidence") or []
        if isinstance(item, dict)
    ]
    verification_methods = list(
        dict.fromkeys(
            str(item.get("method") or "")
            for item in entry_result.get("evidence") or []
            if isinstance(item, dict) and str(item.get("method") or "")
        )
    )
    responsive = bool(entry_result.get("reachable"))
    return {
        "host_id": _stable_id("host", segment.get("segment_id"), address),
        "segment_id": segment.get("segment_id"),
        "ip": address,
        "address": address,
        "status": "up" if responsive else "observed",
        "reachability_state": "responsive" if responsive else "reachability_not_established",
        "reachability_evidence": evidence,
        "hostname": "",
        "hostname_observations": [],
        "hostname_conflict": False,
        "mac": "",
        "mac_vendor": "",
        "role": "entry_target",
        "is_scanner": False,
        "selectable": responsive,
        "record_type": "entry_target",
        "origin": "operator_supplied",
        "origins": ["operator_supplied"],
        "independently_discovered": False,
        "discovered_by": [],
        "verification_methods": verification_methods,
        "operator_supplied": True,
    }


def discover_host_scope(
    segment: dict[str, Any], entry_result: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return the supplied host record; Phase 1 probes verify rather than discover it."""

    host = _entry_target_observation(segment, entry_result)
    execution = {
        "entry_target_verification": {
            "requested": True,
            "executed": True,
            "success": bool(entry_result.get("reachable")),
            "evidence_produced": bool(entry_result.get("evidence")),
            "verification_methods": host.get("verification_methods") or [],
            "address_origin": "operator_supplied",
            "independently_discovered": False,
        },
        "network_enumeration": {
            "requested": False,
            "executed": False,
            "evidence_produced": False,
            "unavailable_reason": "current_scope_is_single_host",
        },
        "arp_discovery": {
            "requested": False,
            "applicable": False,
            "executed": False,
            "evidence_produced": False,
            "unavailable_reason": "current_scope_is_single_host",
        },
    }
    return [host], execution

def discover_internal_hosts(
    scan_id: str,
    subnet: str,
    *,
    interface: str,
    scanner_ip: str = "",
    gateway: str = "",
    segment_id: str = "",
    layer2_connected: bool = False,
    snapshot: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Enumerate one verified layer without service or CVE assessment."""

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise DiscoveryWorkflowError("The selected network scope is invalid.") from exc
    if not _usable_internal_network(network):
        raise DiscoveryWorkflowError(
            "The selected network exceeds the configured layer-enumeration limit or is not an enumeratable unicast network."
        )

    segment = {
        "segment_id": segment_id,
        "network": str(network),
        "interface": interface,
        "source_address": scanner_ip,
        "next_hop": gateway,
    }
    inventory: dict[str, dict[str, Any]] = {}
    execution: dict[str, Any] = {}
    host_discovery_timeout = _phase2_host_discovery_timeout_seconds()

    nmap = shutil.which("nmap")
    output_path = scan_store.scan_path(f"{scan_id}_{segment_id}_hosts.xml")
    if nmap:
        output_path.unlink(missing_ok=True)
        result = _run_command(
            scan_id,
            command_builders.nmap_internal_host_discovery(
                nmap, str(network), output_path, interface=interface
            ),
            "Phase 2 current-scope Nmap host discovery",
            timeout=host_discovery_timeout,
            output_file=output_path,
            interface=interface,
            source_address=scanner_ip,
            segment_id=segment_id,
            target=str(network),
        )
        parsed = _parse_host_inventory(
            output_path,
            scanner_ip=scanner_ip,
            gateway=gateway,
            segment_id=segment_id,
        ) if output_path.exists() else []
        for item in parsed:
            _merge_host_observation(inventory, item)
        execution["nmap_host_discovery"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(result.get("success")),
            "evidence_produced": bool(parsed),
            "evidence_file": str(output_path),
            "returncode": result.get("returncode"),
        }
        if not result.get("success") and not parsed:
            execution["nmap_host_discovery"]["unavailable_reason"] = "command_failed_without_retained_host_evidence"
    else:
        execution["nmap_host_discovery"] = {
            "requested": True,
            "tool_available": False,
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "unavailable_reason": "tool_unavailable",
        }

    # Complement the normal Nmap pass with an IP-layer discovery pass that
    # disables Nmap's automatic ARP discovery. This gives Phase 2 independent
    # ICMP/TCP evidence and avoids making one discovery mechanism authoritative.
    resilient_path = scan_store.scan_path(f"{scan_id}_{segment_id}_hosts_ip.xml")
    if nmap:
        resilient_path.unlink(missing_ok=True)
        resilient = _run_command(
            scan_id,
            command_builders.nmap_resilient_host_discovery(
                nmap, str(network), resilient_path, interface=interface
            ),
            "Phase 2 complementary ICMP/TCP host discovery",
            timeout=host_discovery_timeout,
            output_file=resilient_path,
            interface=interface,
            source_address=scanner_ip,
            segment_id=segment_id,
            target=str(network),
        )
        resilient_hosts = (
            _parse_host_inventory(
                resilient_path,
                scanner_ip=scanner_ip,
                gateway=gateway,
                segment_id=segment_id,
            )
            if resilient_path.exists()
            else []
        )
        for item in resilient_hosts:
            item["discovered_by"] = ["nmap_icmp_tcp_discovery"]
            item["verification_methods"] = ["nmap_icmp_tcp_discovery"]
            for evidence in item.get("reachability_evidence") or []:
                if isinstance(evidence, dict):
                    evidence["source"] = "nmap_icmp_tcp_discovery"
            _merge_host_observation(inventory, item)
        execution["nmap_icmp_tcp_discovery"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(resilient.get("success")),
            "evidence_produced": bool(resilient_hosts),
            "observation_count": len(resilient_hosts),
            "evidence_file": str(resilient_path),
            "returncode": resilient.get("returncode"),
        }
        if not resilient.get("success") and not resilient_hosts:
            execution["nmap_icmp_tcp_discovery"]["unavailable_reason"] = (
                "command_failed_without_retained_host_evidence"
            )
    else:
        execution["nmap_icmp_tcp_discovery"] = {
            "requested": True,
            "tool_available": False,
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "observation_count": 0,
            "unavailable_reason": "tool_unavailable",
        }

    current_snapshot = snapshot or collect_network_snapshot(
        scan_id, "Phase 2 current-scope"
    )
    neighbours = _neighbour_observations(
        current_snapshot.get("neighbours") or [], segment
    )
    for item in neighbours:
        _merge_host_observation(inventory, item)
    execution["neighbour_table"] = {
        "requested": True,
        "tool_available": True,
        "executed": True,
        "success": True,
        "evidence_produced": bool(neighbours),
        "observation_count": len(neighbours),
    }

    arp_applicable = bool(layer2_connected and network.version == 4)
    arp_bin = shutil.which("arp-scan")
    if arp_applicable and arp_bin:
        arp_output = scan_store.scan_path(f"{scan_id}_{segment_id}_arp.txt")
        arp_output.unlink(missing_ok=True)
        capability_state = "unknown"
        getcap = shutil.which("getcap")
        if getcap:
            capability = _run_command(
                scan_id,
                [getcap, arp_bin],
                "Phase 2 ARP discovery capability check",
                timeout=8,
                interface=interface,
                source_address=scanner_ip,
                segment_id=segment_id,
                target=str(network),
            )
            capability_text = str(capability.get("stdout") or "")
            capability_state = (
                "packet_capability_present"
                if "cap_net_raw" in capability_text
                else "packet_capability_not_reported"
            )
        result = _run_command(
            scan_id,
            command_builders.arp_scan(arp_bin, str(network), interface=interface),
            "Phase 2 current-scope ARP discovery",
            timeout=180,
            output_file=arp_output,
            interface=interface,
            source_address=scanner_ip,
            segment_id=segment_id,
            target=str(network),
        )
        text = arp_output.read_text(encoding="utf-8", errors="ignore") if arp_output.exists() else str(result.get("stdout") or "")
        arp_hosts = _parse_arp_scan(text, segment)
        for item in arp_hosts:
            _merge_host_observation(inventory, item)
        stderr = " ".join(str(result.get(key) or "") for key in ("stderr",)).lower()
        reason = ""
        if not result.get("success"):
            reason = (
                "insufficient_privilege"
                if any(token in stderr for token in ("permission denied", "operation not permitted", "must be root", "cap_net_raw"))
                else "command_failed"
            )
        execution["arp_discovery"] = {
            "requested": True,
            "applicable": True,
            "tool_available": True,
            "executed": True,
            "success": bool(result.get("success")),
            "evidence_produced": bool(arp_hosts),
            "evidence_file": str(arp_output),
            "unavailable_reason": reason,
            "capability_state": capability_state,
            "observation_count": len(arp_hosts),
        }
    else:
        execution["arp_discovery"] = {
            "requested": True,
            "applicable": arp_applicable,
            "tool_available": bool(arp_bin),
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "unavailable_reason": (
                "not_layer2_connected"
                if not layer2_connected
                else "address_family_not_supported"
                if network.version != 4
                else "tool_unavailable"
            ),
        }

    scanner = _scanner_observation(segment)
    if scanner:
        _merge_host_observation(inventory, scanner)

    return _sort_hosts(inventory.values()), execution


def _representative_address(network: ipaddress._BaseNetwork) -> str:
    if network.num_addresses <= 2:
        return str(network.network_address)
    return str(network.network_address + 1)


def _route_observation_record(
    route: dict[str, Any], snapshot: dict[str, Any], version: int
) -> dict[str, Any] | None:
    route_type = str(route.get("type") or "unicast").lower()
    if route_type in _NON_FORWARDING_ROUTE_TYPES:
        return None
    network = _route_network(route, version)
    if network is None or network.prefixlen == 0 or not _observable_route_network(network):
        return None
    interface = str(route.get("dev") or "").strip()
    gateway = str(route.get("gateway") or "").strip()
    return {
        "route_signature": _route_signature(route),
        "destination_network": str(network),
        "interface": interface,
        "source_address": _source_for_interface(
            snapshot.get("interface_index") or {}, interface, network.version
        ),
        "next_hop": gateway,
        "route_table": str(route.get("table") or "main"),
        "route_type": route_type,
        "route_scope": str(route.get("scope") or ""),
        "route_protocol": str(route.get("protocol") or ""),
        "address_count": int(network.num_addresses),
        "enumeration_eligible": _usable_internal_network(network),
        "route": dict(route),
        "captured_at": snapshot.get("captured_at"),
    }


def _path_relationship(
    workflow: dict[str, Any],
    current_segment: dict[str, Any],
    route_record: dict[str, Any],
) -> tuple[bool, str, list[dict[str, Any]]]:
    """Return whether route evidence is connected to mission progression."""

    signature = str(route_record.get("route_signature") or "")
    baseline = set(workflow.get("baseline_route_signatures") or [])
    current_network = ipaddress.ip_network(str(current_segment.get("network") or ""), strict=False)
    current_kind = str(current_segment.get("scope_kind") or "")
    entry_target = str(workflow.get("entry_target") or "")
    gateway_text = str(route_record.get("next_hop") or "")
    evidence: list[dict[str, Any]] = []

    if signature and signature not in baseline:
        evidence.append({"type": "route_delta", "relationship": "new_since_mission_baseline"})
        return True, "newly_observed_route", evidence

    try:
        gateway = ipaddress.ip_address(gateway_text) if gateway_text else None
    except ValueError:
        gateway = None

    try:
        destination_network = ipaddress.ip_network(str(route_record.get("destination_network") or ""), strict=False)
        entry_address = ipaddress.ip_address(entry_target) if entry_target else None
    except ValueError:
        destination_network = None
        entry_address = None

    if current_kind == "entry_host" and destination_network is not None and entry_address is not None and entry_address in destination_network:
        if str(route_record.get("interface") or "") == str(current_segment.get("interface") or ""):
            evidence.append({"type": "route_relationship", "relationship": "route_contains_entry_target"})
            return True, "route_contains_entry_target", evidence

    if gateway is not None:
        if current_kind == "entry_host" and gateway_text == entry_target:
            evidence.append({"type": "route_relationship", "relationship": "next_hop_is_entry_target"})
            return True, "specific_route_via_entry_target", evidence
        if current_kind != "entry_host" and gateway in current_network:
            evidence.append({"type": "route_relationship", "relationship": "next_hop_observed_in_current_scope"})
            return True, "next_hop_on_current_scope", evidence

    return False, "baseline_route_observation_only", [
        {"type": "route_baseline", "relationship": "pre_existing_route_not_connected_to_current_scope"}
    ]


def _path_records_from_snapshot(
    workflow: dict[str, Any],
    current_segment: dict[str, Any],
    snapshot: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build operator-authorised paths while retaining every route as evidence.

    Automatic route relationships are suggestions only.  A route becomes a
    continuation path only after the operator explicitly authorises the exact
    retained route signature (or an authorised scope source provides the exact
    destination network).  This preserves full operator choice without
    allowing the scanner to silently traverse unrelated local networks.
    """

    current_network = ipaddress.ip_network(str(current_segment["network"]), strict=False)
    visited = set(workflow.get("visited_segment_ids") or [])
    paths = {
        str(key): dict(value)
        for key, value in (workflow.get("paths") or {}).items()
        if isinstance(value, dict)
    }
    observations = {
        str(item.get("observation_id") or ""): dict(item)
        for item in workflow.get("route_observations") or []
        if isinstance(item, dict) and str(item.get("observation_id") or "")
    }
    current_path_ids: list[str] = []
    current_observation_ids: list[str] = []
    observed_path_ids: set[str] = set()
    authorised_signatures = set(workflow.get("authorized_route_signatures") or [])
    authorised_networks = set(workflow.get("authorized_route_networks") or [])
    authorised_records = {
        str(key): dict(value)
        for key, value in (workflow.get("authorized_route_records") or {}).items()
        if isinstance(value, dict)
    }

    for route in snapshot.get("routes") or []:
        record = _route_observation_record(route, snapshot, current_network.version)
        if not record:
            continue
        network = ipaddress.ip_network(str(record["destination_network"]), strict=False)
        interface = str(record.get("interface") or "")
        gateway = str(record.get("next_hop") or "")
        if (
            str(network) == str(current_network)
            and interface == str(current_segment.get("interface") or "")
            and gateway == str(current_segment.get("next_hop") or "")
        ):
            continue

        signature = str(record["route_signature"])
        related, relationship, relationship_evidence = _path_relationship(
            workflow, current_segment, record
        )
        observation_id = _stable_id(
            "routeobs", current_segment.get("segment_id"), signature
        )
        existing_observation = observations.get(observation_id) or {}
        authorised = signature in authorised_signatures or str(network) in authorised_networks
        authorisation = authorised_records.get(signature) or {}
        record.update(
            {
                "observation_id": observation_id,
                "from_segment_id": current_segment.get("segment_id"),
                "baseline": signature in set(workflow.get("baseline_route_signatures") or []),
                "mission_related": related,
                "relationship": relationship,
                "mission_relationship": (
                    "operator_authorized"
                    if authorised
                    else relationship
                    if related
                    else "observation_only"
                ),
                "operator_authorized": authorised,
                "authorization_state": (
                    "operator_authorized" if authorised else "not_authorized"
                ),
                "authorized_by": authorisation.get("authorized_by"),
                "authorized_at": authorisation.get("authorized_at"),
                "first_observed_at": existing_observation.get("first_observed_at")
                or existing_observation.get("captured_at")
                or snapshot.get("captured_at"),
                "last_observed_at": snapshot.get("captured_at"),
                "evidence": relationship_evidence,
            }
        )
        observations[observation_id] = record
        current_observation_ids.append(observation_id)

        if not authorised:
            continue

        destination_segment_id = _segment_identifier(
            str(network),
            interface,
            str(record.get("source_address") or ""),
            gateway,
            str(record.get("route_table") or "main"),
            "route_network",
        )
        path_id = _path_identifier(str(current_segment["segment_id"]), route, str(network))
        enumeration_eligible = bool(record.get("enumeration_eligible"))
        if destination_segment_id in visited:
            state = "previously_visited"
        elif not enumeration_eligible:
            state = "scope_exceeds_discovery_limit"
        else:
            previous_state = str((paths.get(path_id) or {}).get("verification_state") or "")
            state = (
                previous_state
                if previous_state in {"verification_failed", "route_unavailable"}
                else "authorized_pending_verification"
            )
        path_record = {
            "path_id": path_id,
            "from_segment_id": str(current_segment["segment_id"]),
            "destination_segment_id": destination_segment_id,
            "destination_network": str(network),
            "representative_destination": _representative_address(network),
            "interface": interface,
            "source_address": str(record.get("source_address") or ""),
            "next_hop": gateway,
            "route_table": str(record.get("route_table") or "main"),
            "route_type": str(record.get("route_type") or "unicast"),
            "route_scope": str(record.get("route_scope") or ""),
            "route_protocol": str(record.get("route_protocol") or ""),
            "route_signature": signature,
            "route_observation_id": observation_id,
            "relationship": "operator_authorized",
            "evidence_relationship": relationship,
            "mission_related": related,
            "authorization_state": "operator_authorized",
            "authorized_by": authorisation.get("authorized_by") or "operator",
            "authorized_at": authorisation.get("authorized_at"),
            "discovery_source": "kernel_route_table",
            "verification_state": state,
            "enumeration_eligible": enumeration_eligible,
            "address_count": int(record.get("address_count") or 0),
            "discovery_limit": max(1, int(getattr(Config, "MAX_EXPANDED_TARGETS", 256))),
            "operator_selected": bool((paths.get(path_id) or {}).get("operator_selected")),
            "first_observed_at": (paths.get(path_id) or {}).get("first_observed_at") or snapshot.get("captured_at"),
            "last_observed_at": snapshot.get("captured_at"),
            "route": dict(route),
            "evidence": [
                {
                    "type": "route_snapshot",
                    "captured_at": snapshot.get("captured_at"),
                    "route_signature": signature,
                },
                {
                    "type": "operator_authorization",
                    "authorized_by": authorisation.get("authorized_by") or "operator",
                    "authorized_at": authorisation.get("authorized_at"),
                    "route_observation_id": observation_id,
                },
                *relationship_evidence,
            ],
        }
        paths[path_id] = path_record
        current_path_ids.append(path_id)
        observed_path_ids.add(path_id)

    for path_id, path in paths.items():
        if path.get("from_segment_id") != current_segment.get("segment_id"):
            continue
        signature = str(path.get("route_signature") or _route_signature(path.get("route") or {}))
        destination_network = str(path.get("destination_network") or "")
        if signature not in authorised_signatures and destination_network not in authorised_networks:
            path["authorization_state"] = "not_authorized"
            if path.get("verification_state") not in {"verified_reachable", "previously_visited"}:
                path["verification_state"] = "authorization_required"
            continue
        if path_id not in observed_path_ids and path.get("verification_state") not in {"verified_reachable", "previously_visited"}:
            path["verification_state"] = "stale"

    workflow["route_observations"] = sorted(
        observations.values(), key=lambda item: (str(item.get("destination_network") or ""), str(item.get("interface") or ""))
    )
    current_segment["route_observation_ids"] = sorted(set(current_observation_ids))
    pending = [
        path_id
        for path_id in current_path_ids
        if (paths.get(path_id) or {}).get("verification_state")
        == "authorized_pending_verification"
    ]
    pending.sort(key=lambda value: str((paths.get(value) or {}).get("destination_network") or ""))
    return paths, pending

def _phase_results(workflow: dict[str, Any]) -> dict[str, Any]:
    segments = [
        workflow.get("segments", {}).get(segment_id)
        for segment_id in workflow.get("segment_order") or []
        if workflow.get("segments", {}).get(segment_id)
    ]
    current = workflow.get("segments", {}).get(workflow.get("current_segment_id")) or {}
    entry = dict(workflow.get("entry_result") or {})
    return {
        "external": {"status": "completed", **entry},
        "entry": {"status": "completed", **entry},
        "internal": {
            "status": "completed" if current else "not_started",
            "subnet": current.get("network"),
            "interface": current.get("interface"),
            "scanner_ip": current.get("source_address"),
            "gateway": current.get("next_hop"),
            "access_mode": current.get("access_mode"),
            "scope_kind": current.get("scope_kind"),
            "host_count": len(current.get("hosts") or []),
            "entry_target_count": len([host for host in current.get("hosts") or [] if host.get("record_type") == "entry_target"]),
            "independently_discovered_host_count": len([host for host in current.get("hosts") or [] if host.get("independently_discovered")]),
            "selectable_host_count": len(
                [host for host in current.get("hosts") or [] if host.get("selectable")]
            ),
            "hosts": current.get("hosts") or [],
        },
        "traversal": {
            "status": "awaiting_operator_decision",
            "visited_segment_count": len(segments),
            "current_segment_id": current.get("segment_id"),
            "pending_path_count": len(workflow.get("pending_path_ids") or []),
            "segments": segments,
        },
        "assessment": dict(
            (workflow.get("phase_results") or {}).get("assessment")
            or {"status": "not_started", "targets": []}
        ),
    }


def _set_current_aliases(workflow: dict[str, Any]) -> dict[str, Any]:
    current = (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
    workflow["current_segment"] = current
    workflow["internal_subnet"] = str(current.get("network") or "")
    workflow["access_mode"] = str(current.get("access_mode") or "")
    workflow["discovered_hosts"] = list(current.get("hosts") or [])
    workflow["network_context"] = {
        "segment_id": current.get("segment_id"),
        "interface": current.get("interface"),
        "scanner_ip": current.get("source_address"),
        "gateway": current.get("next_hop"),
        "internal_subnet": current.get("network"),
        "access_mode": current.get("access_mode"),
        "route_table": current.get("route_table"),
        "route_type": current.get("route_type"),
        "layer2_connected": current.get("layer2_connected"),
        "scope_kind": current.get("scope_kind"),
    }
    workflow["phase_results"] = _phase_results(workflow)
    return workflow


def _segment_from_entry(context: dict[str, Any], entry_result: dict[str, Any]) -> dict[str, Any]:
    address = ipaddress.ip_address(str(context["entry_target"]))
    network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)
    segment_id = _segment_identifier(
        str(network),
        str(context.get("interface") or ""),
        str(context.get("scanner_ip") or ""),
        str(context.get("gateway") or ""),
        str(context.get("route_table") or "main"),
        "entry_host",
    )
    return {
        "segment_id": segment_id,
        "layer_index": 0,
        "scope_kind": "entry_host",
        "network": str(network),
        "enumeration_target": str(address),
        "interface": str(context.get("interface") or ""),
        "source_address": str(context.get("scanner_ip") or ""),
        "next_hop": str(context.get("gateway") or ""),
        "route_table": str(context.get("route_table") or "main"),
        "route_type": str(context.get("route_type") or ""),
        "access_mode": str(context.get("access_mode") or "routed"),
        "layer2_connected": False,
        "verification_state": "verified_reachable" if entry_result.get("reachable") else "route_verified_reachability_not_established",
        "created_at": scan_store.now(),
        "last_enumerated_at": None,
        "hosts": [],
        "path_ids": [],
        "discovery_execution": {},
        "route": dict(context.get("route") or {}),
        "evidence": [
            {
                "type": "entry_route",
                "route": dict(context.get("route") or {}),
                "matched_route": dict(context.get("matched_route") or {}),
            },
            {"type": "entry_reachability", **entry_result},
        ],
    }


def _segment_from_verified_path(
    path: dict[str, Any],
    route_get: dict[str, Any],
    matched_route: dict[str, Any],
    snapshot: dict[str, Any],
    layer_index: int,
) -> dict[str, Any]:
    network = ipaddress.ip_network(str(path["destination_network"]), strict=False)
    interface = str(route_get.get("dev") or matched_route.get("dev") or path.get("interface") or "")
    source = str(route_get.get("prefsrc") or route_get.get("src") or "").strip()
    source = source or _source_for_interface(
        snapshot.get("interface_index") or {}, interface, network.version
    )
    gateway = str(route_get.get("gateway") or matched_route.get("gateway") or path.get("next_hop") or "")
    route_table = str(route_get.get("table") or matched_route.get("table") or path.get("route_table") or "main")
    layer2 = bool(str(matched_route.get("scope") or "") == "link" and not gateway)
    segment_id = _segment_identifier(
        str(network), interface, source, gateway, route_table, "route_network"
    )
    return {
        "segment_id": segment_id,
        "layer_index": layer_index,
        "scope_kind": "route_network",
        "network": str(network),
        "enumeration_target": str(network),
        "interface": interface,
        "source_address": source,
        "next_hop": gateway,
        "route_table": route_table,
        "route_type": str(matched_route.get("type") or "unicast"),
        "access_mode": "directly_connected" if layer2 else "routed",
        "layer2_connected": layer2,
        "verification_state": "verified_reachable",
        "created_at": scan_store.now(),
        "last_enumerated_at": None,
        "hosts": [],
        "path_ids": [],
        "discovery_execution": {},
        "route": dict(matched_route),
        "evidence": [
            {
                "type": "selected_path",
                "path_id": path.get("path_id"),
                "route_get": dict(route_get),
                "route": dict(matched_route),
                "verified_at": scan_store.now(),
            }
        ],
    }


def _enumerate_and_pause(
    scan_id: str,
    workflow: dict[str, Any],
    segment: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    task_name: str,
) -> None:
    scan_store.set_task(scan_id, task_name, scan_store.STATUS_RUNNING)
    if str(segment.get("scope_kind") or "") == "entry_host":
        hosts, execution = discover_host_scope(
            segment, dict(workflow.get("entry_result") or {})
        )
    else:
        hosts, execution = discover_internal_hosts(
            scan_id,
            str(segment["network"]),
            interface=str(segment.get("interface") or ""),
            scanner_ip=str(segment.get("source_address") or ""),
            gateway=str(segment.get("next_hop") or ""),
            segment_id=str(segment["segment_id"]),
            layer2_connected=bool(segment.get("layer2_connected")),
            snapshot=snapshot,
        )
    segment["hosts"] = hosts
    segment["discovery_execution"] = execution
    segment["last_enumerated_at"] = scan_store.now()
    responsive_observations = [
        host
        for host in hosts
        if not host.get("is_scanner")
        and str(host.get("reachability_state") or "")
        in {
            "responsive",
            "observed_through_neighbour_evidence",
            "observed_through_arp_evidence",
            "observed_through_passive_evidence",
        }
    ]
    segment["verification_state"] = (
        "responsive_hosts_observed"
        if responsive_observations
        else "route_verified_reachability_not_established"
    )
    scan_store.set_task(
        scan_id,
        task_name,
        scan_store.STATUS_SUCCESS if hosts else scan_store.STATUS_EMPTY,
        summary=(
            f"Verified operator-supplied entry target; {len([host for host in hosts if host.get('independently_discovered')])} additional host(s) independently discovered"
            if str(segment.get("scope_kind") or "") == "entry_host"
            else f"Retained {len(hosts)} host observation(s) for this network scope"
        ),
    )

    paths, pending = _path_records_from_snapshot(workflow, segment, snapshot)
    segment["path_ids"] = [
        path_id
        for path_id, path in paths.items()
        if path.get("from_segment_id") == segment.get("segment_id")
        and path.get("authorization_state") == "operator_authorized"
        and path.get("verification_state") != "stale"
    ]
    workflow["paths"] = paths
    workflow["pending_path_ids"] = pending
    workflow["last_route_signatures"] = snapshot.get("route_signatures") or []
    workflow["last_network_snapshot_at"] = snapshot.get("captured_at")
    workflow.setdefault("segments", {})[str(segment["segment_id"])] = segment
    workflow["current_segment_id"] = str(segment["segment_id"])
    if segment["segment_id"] not in workflow.setdefault("segment_order", []):
        workflow["segment_order"].append(segment["segment_id"])
    if segment["segment_id"] not in workflow.setdefault("visited_segment_ids", []):
        workflow["visited_segment_ids"].append(segment["segment_id"])
    _set_current_aliases(workflow)

    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        current_task="Waiting for operator decision",
        next_task="Assess this layer, follow one observed path, refresh, retry, or stop",
        error=None,
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [host.get("ip") for host in hosts],
            "internal_host_inventory": hosts,
        },
    )
    scan_store.audit_event(
        scan_id,
        "system",
        "reachable_scope_enumerated",
        {
            "segment_id": segment.get("segment_id"),
            "network": segment.get("network"),
            "host_observation_count": len(hosts),
            "selectable_host_count": len([host for host in hosts if host.get("selectable")]),
            "continuation_path_count": len(segment.get("path_ids") or []),
            "scope_kind": segment.get("scope_kind"),
            "independently_discovered_host_count": len([host for host in hosts if host.get("independently_discovered")]),
        },
    )
    scan_store.persist(scan_id)


def _record_discovery_failure(scan_id: str, exc: Exception) -> None:
    message = str(exc)
    current = scan_store.get(scan_id) or {}
    running = next(
        (
            task
            for task in current.get("tasks") or []
            if task.get("status") == scan_store.STATUS_RUNNING
        ),
        None,
    )
    if running:
        scan_store.set_task(
            scan_id,
            str(running.get("name") or ""),
            scan_store.STATUS_FAILED,
            summary=message,
        )
    scan_store.log(scan_id, f"Network discovery error: {message}", "ERROR")
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_FAILED,
        error=message,
        completed_at=scan_store.now(),
    )
    scan_store.persist(scan_id)


# Removed deprecated pre-v6 run_discovery_pipeline implementation; active topology-driven version is defined below.


def _find_route_for_path(
    path: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any] | None:
    destination = ipaddress.ip_network(str(path.get("destination_network") or ""), strict=False)
    matches: list[dict[str, Any]] = []
    for route in snapshot.get("routes") or []:
        network = _route_network(route, destination.version)
        if network != destination:
            continue
        if path.get("interface") and str(route.get("dev") or "") != str(path.get("interface") or ""):
            continue
        if path.get("next_hop") and str(route.get("gateway") or "") != str(path.get("next_hop") or ""):
            continue
        if path.get("route_table") and str(route.get("table") or "main") != str(path.get("route_table") or "main"):
            continue
        if str(route.get("type") or "unicast").lower() in _NON_FORWARDING_ROUTE_TYPES:
            continue
        matches.append(route)
    return matches[0] if matches else None


def continue_discovery_with_path(scan_id: str, path_id: str) -> None:
    """Verify one operator-selected path and enumerate its destination layer."""

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_PATH_VERIFICATION:
            raise DiscoveryWorkflowError("The mission is not waiting for path verification.")
        workflow = dict(current.get("workflow") or {})
        paths = {str(key): dict(value) for key, value in (workflow.get("paths") or {}).items()}
        path = paths.get(str(path_id))
        if not path:
            raise DiscoveryWorkflowError("The selected path is not present in retained route evidence.")
        if path.get("from_segment_id") != workflow.get("current_segment_id"):
            raise DiscoveryWorkflowError("The selected path does not start from the current layer.")
        signature = str(path.get("route_signature") or _route_signature(path.get("route") or {}))
        authorised_signatures = set(workflow.get("authorized_route_signatures") or [])
        authorised_networks = set(workflow.get("authorized_route_networks") or [])
        if (
            path.get("authorization_state") != "operator_authorized"
            or (
                signature not in authorised_signatures
                and str(path.get("destination_network") or "") not in authorised_networks
            )
        ):
            raise DiscoveryWorkflowError(
                "The selected route has not been explicitly authorised for this mission."
            )
        if path.get("verification_state") in {"stale", "previously_visited"}:
            raise DiscoveryWorkflowError("The selected path is stale or leads to a visited layer.")

        snapshot = collect_network_snapshot(scan_id, "Selected path verification")
        matched_route = _find_route_for_path(path, snapshot)
        if matched_route is None:
            path["verification_state"] = "route_unavailable"
            path["last_verification_at"] = scan_store.now()
            paths[str(path_id)] = path
            workflow["paths"] = paths
            _set_current_aliases(workflow)
            scan_store.update(
                scan_id,
                status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                workflow_stage="awaiting_layer_decision",
                workflow=workflow,
                current_task="Waiting for operator decision",
                next_task="Select another observed path, refresh, retry, assess, or stop",
                error="The selected route is no longer present in the current kernel route table.",
            )
            scan_store.persist(scan_id)
            return

        representative = str(path.get("representative_destination") or "")
        route_get = _route_get(
            scan_id,
            representative,
            "Selected continuation path route verification",
        )
        expected_interface = str(matched_route.get("dev") or path.get("interface") or "")
        actual_interface = str(route_get.get("dev") or "")
        if expected_interface and actual_interface != expected_interface:
            raise DiscoveryWorkflowError(
                "The kernel selected a different interface than the retained continuation path."
            )

        layer_index = len(workflow.get("segment_order") or [])
        segment = _segment_from_verified_path(
            path, route_get, matched_route, snapshot, layer_index
        )
        if segment["segment_id"] in set(workflow.get("visited_segment_ids") or []):
            path["verification_state"] = "previously_visited"
            paths[str(path_id)] = path
            workflow["paths"] = paths
            _set_current_aliases(workflow)
            scan_store.update(
                scan_id,
                status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                workflow_stage="awaiting_layer_decision",
                workflow=workflow,
                current_task="Waiting for operator decision",
                next_task="The selected path leads to a previously visited layer",
                error=None,
            )
            scan_store.persist(scan_id)
            return

        path["verification_state"] = "route_verified"
        path["operator_selected"] = True
        path["last_verification_at"] = scan_store.now()
        path["destination_segment_id"] = segment["segment_id"]
        paths[str(path_id)] = path
        workflow["paths"] = paths
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "follow_path",
                "path_id": path_id,
                "from_segment_id": path.get("from_segment_id"),
                "destination_network": path.get("destination_network"),
                "state_before": scan_store.STATUS_PATH_VERIFICATION,
                "state_after": scan_store.STATUS_LAYER_ENUMERATION,
                "timestamp": scan_store.now(),
            }
        )
        workflow.setdefault("segments", {})[segment["segment_id"]] = segment
        workflow["current_segment_id"] = segment["segment_id"]
        if segment["segment_id"] not in workflow.setdefault("segment_order", []):
            workflow["segment_order"].append(segment["segment_id"])
        if segment["segment_id"] not in workflow.setdefault("visited_segment_ids", []):
            workflow["visited_segment_ids"].append(segment["segment_id"])
        _set_current_aliases(workflow)

        task_name = f"Phase 2 — Layer {layer_index + 1} Enumeration"
        scan_store.append_tasks(scan_id, [task_name], phase="discovery")
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_LAYER_ENUMERATION,
            workflow_stage="layer_enumeration",
            workflow=workflow,
            error=None,
        )
        scan_store.audit_event(
            scan_id,
            "operator",
            "continuation_path_selected",
            {
                "path_id": path_id,
                "from_segment_id": path.get("from_segment_id"),
                "destination_network": path.get("destination_network"),
            },
        )
        _enumerate_and_pause(
            scan_id,
            workflow,
            segment,
            snapshot,
            task_name=task_name,
        )
    except Exception as exc:
        current = scan_store.load(scan_id) or {}
        workflow = dict(current.get("workflow") or {})
        path = dict((workflow.get("paths") or {}).get(str(path_id)) or {})
        if path:
            path["verification_state"] = "verification_failed"
            path["last_verification_at"] = scan_store.now()
            path["verification_error"] = str(exc)
            workflow.setdefault("paths", {})[str(path_id)] = path
            _set_current_aliases(workflow)
            scan_store.log(scan_id, f"Path verification failed: {exc}", "ERROR")
            scan_store.update(
                scan_id,
                status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                workflow_stage="awaiting_layer_decision",
                workflow=workflow,
                current_task="Waiting for operator decision",
                next_task="Select another path, refresh, retry, assess, or stop",
                error=str(exc),
            )
            scan_store.persist(scan_id)
            return
        _record_discovery_failure(scan_id, exc)


# Removed deprecated pre-v6 revisit_discovered_segment implementation; active topology-driven version is defined below.


def refresh_current_layer_paths(scan_id: str) -> None:
    """Refresh only route/path evidence for the current layer."""

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_LAYER_ENUMERATION:
            raise DiscoveryWorkflowError("The mission is not in a layer-refresh state.")
        workflow = dict(current.get("workflow") or {})
        segment = dict((workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {})
        if not segment:
            raise DiscoveryWorkflowError("The current layer record is unavailable.")
        snapshot = collect_network_snapshot(scan_id, "Current-layer path refresh")
        paths, pending = _path_records_from_snapshot(workflow, segment, snapshot)
        segment["path_ids"] = [
            path_id
            for path_id, path in paths.items()
            if path.get("from_segment_id") == segment.get("segment_id")
            and path.get("authorization_state") == "operator_authorized"
            and path.get("verification_state") != "stale"
        ]
        workflow["paths"] = paths
        workflow["pending_path_ids"] = pending
        workflow["last_route_signatures"] = snapshot.get("route_signatures") or []
        workflow["last_network_snapshot_at"] = snapshot.get("captured_at")
        workflow.setdefault("segments", {})[segment["segment_id"]] = segment
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "refresh_paths",
                "segment_id": segment.get("segment_id"),
                "state_before": scan_store.STATUS_LAYER_ENUMERATION,
                "state_after": scan_store.STATUS_AWAITING_LAYER_DECISION,
                "timestamp": scan_store.now(),
            }
        )
        _set_current_aliases(workflow)
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_AWAITING_LAYER_DECISION,
            workflow_stage="awaiting_layer_decision",
            workflow=workflow,
            current_task="Waiting for operator decision",
            next_task="Assess, follow one observed path, retry, refresh, or stop",
            error=None,
            results={
                "workflow": workflow,
                "phase_results": workflow.get("phase_results") or {},
                "hosts": [host.get("ip") for host in segment.get("hosts") or []],
                "internal_host_inventory": segment.get("hosts") or [],
            },
        )
        scan_store.audit_event(
            scan_id,
            "operator",
            "continuation_paths_refreshed",
            {
                "segment_id": segment.get("segment_id"),
                "path_count": len(segment.get("path_ids") or []),
            },
        )
        scan_store.persist(scan_id)
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)



def authorize_observed_route(scan_id: str, observation_id: str) -> None:
    """Let the operator explicitly associate one retained route with the mission.

    This does not add or modify a route. It only changes whether an already
    observed, bounded route may be offered as a continuation candidate.
    """

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_LAYER_ENUMERATION:
            raise DiscoveryWorkflowError("The mission is not in a route-authorization state.")
        workflow = dict(current.get("workflow") or {})
        segment = dict((workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {})
        if not segment:
            raise DiscoveryWorkflowError("The current reachable-scope record is unavailable.")
        selected_observation_id = str(observation_id or "").strip()
        observation = next(
            (
                dict(row)
                for row in workflow.get("route_observations") or []
                if isinstance(row, dict)
                and str(row.get("observation_id") or "") == selected_observation_id
                and selected_observation_id in set(segment.get("route_observation_ids") or [])
            ),
            None,
        )
        signature = str((observation or {}).get("route_signature") or "")
        if not observation:
            raise DiscoveryWorkflowError(
                "The selected route observation is not retained for the current scope."
            )
        if not observation.get("enumeration_eligible"):
            raise DiscoveryWorkflowError(
                "The selected route exceeds the configured bounded discovery limit."
            )
        if (
            signature in set(workflow.get("authorized_route_signatures") or [])
            or str(observation.get("destination_network") or "")
            in set(workflow.get("authorized_route_networks") or [])
        ):
            raise DiscoveryWorkflowError(
                "The selected route is already authorised for this mission."
            )

        snapshot = collect_network_snapshot(scan_id, "Operator-authorized route presence check")
        live_route = next(
            (
                route
                for route in snapshot.get("routes") or []
                if _route_signature(route) == signature
            ),
            None,
        )
        if live_route is None:
            raise DiscoveryWorkflowError(
                "The selected observed route is no longer present in the kernel route table."
            )

        authorized = list(workflow.get("authorized_route_signatures") or [])
        if signature not in authorized:
            authorized.append(signature)
        workflow["authorized_route_signatures"] = authorized
        authorized_at = scan_store.now()
        authorized_records = {
            str(key): dict(value)
            for key, value in (workflow.get("authorized_route_records") or {}).items()
            if isinstance(value, dict)
        }
        authorized_records[signature] = {
            "route_signature": signature,
            "route_observation_id": selected_observation_id,
            "segment_id": segment.get("segment_id"),
            "destination_network": observation.get("destination_network"),
            "interface": observation.get("interface"),
            "next_hop": observation.get("next_hop"),
            "route_table": observation.get("route_table"),
            "authorized_by": "operator",
            "authorized_at": authorized_at,
            "authorization_state": "operator_authorized",
            "verification_state": "authorized_pending_verification",
        }
        workflow["authorized_route_records"] = authorized_records
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "authorize_observed_route",
                "segment_id": segment.get("segment_id"),
                "route_observation_id": selected_observation_id,
                "route_signature": signature,
                "destination_network": observation.get("destination_network"),
                "state_before": scan_store.STATUS_LAYER_ENUMERATION,
                "state_after": scan_store.STATUS_AWAITING_LAYER_DECISION,
                "timestamp": authorized_at,
            }
        )
        paths, pending = _path_records_from_snapshot(workflow, segment, snapshot)
        segment["path_ids"] = [
            path_id
            for path_id, path in paths.items()
            if path.get("from_segment_id") == segment.get("segment_id")
            and path.get("authorization_state") == "operator_authorized"
            and path.get("verification_state") != "stale"
        ]
        workflow["paths"] = paths
        workflow["pending_path_ids"] = pending
        workflow["last_route_signatures"] = snapshot.get("route_signatures") or []
        workflow["last_network_snapshot_at"] = snapshot.get("captured_at")
        workflow.setdefault("segments", {})[segment["segment_id"]] = segment
        _set_current_aliases(workflow)
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_AWAITING_LAYER_DECISION,
            workflow_stage="awaiting_layer_decision",
            workflow=workflow,
            current_task="Waiting for operator decision",
            next_task="Verify and follow the authorized route, assess, refresh, retry, or stop",
            error=None,
            results={
                "workflow": workflow,
                "phase_results": workflow.get("phase_results") or {},
                "hosts": [host.get("ip") for host in segment.get("hosts") or []],
                "internal_host_inventory": segment.get("hosts") or [],
            },
        )
        scan_store.audit_event(
            scan_id,
            "operator",
            "observed_route_authorized_for_mission",
            {
                "segment_id": segment.get("segment_id"),
                "route_observation_id": selected_observation_id,
                "route_signature": signature,
                "destination_network": observation.get("destination_network"),
                "authorization_state": "operator_authorized",
                "verification_state": "authorized_pending_verification",
            },
        )
        scan_store.persist(scan_id)
    except Exception as exc:
        current = scan_store.load(scan_id) or {}
        workflow = dict(current.get("workflow") or {})
        scan_store.log(scan_id, f"Observed route authorization failed: {exc}", "ERROR")
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_AWAITING_LAYER_DECISION,
            workflow_stage="awaiting_layer_decision",
            workflow=workflow,
            current_task="Waiting for operator decision",
            next_task="Select another scope action",
            error=str(exc),
        )
        scan_store.persist(scan_id)


def revoke_authorized_route(scan_id: str, path_id: str) -> None:
    """Revoke one mission-only route authorisation without changing Kali.

    The retained route observation remains visible.  Only the mission's
    permission to verify and follow that route is removed.
    """

    current = scan_store.load(scan_id) or {}
    if str(current.get("status") or "") != scan_store.STATUS_AWAITING_LAYER_DECISION:
        raise DiscoveryWorkflowError(
            "The mission is not waiting for a route-authorisation decision."
        )
    workflow = dict(current.get("workflow") or {})
    segment = dict((workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {})
    path = dict((workflow.get("paths") or {}).get(str(path_id)) or {})
    if not segment or not path:
        raise DiscoveryWorkflowError("The selected authorised path is unavailable.")
    if path.get("from_segment_id") != segment.get("segment_id"):
        raise DiscoveryWorkflowError(
            "The selected authorised path does not belong to the current scope."
        )

    signature = str(path.get("route_signature") or _route_signature(path.get("route") or {}))
    destination_network = str(path.get("destination_network") or "")
    if (
        path.get("authorization_state") != "operator_authorized"
        or (
            signature not in set(workflow.get("authorized_route_signatures") or [])
            and destination_network
            not in set(workflow.get("authorized_route_networks") or [])
        )
    ):
        raise DiscoveryWorkflowError(
            "The selected path is not currently authorised for this mission."
        )
    signatures = [
        value
        for value in workflow.get("authorized_route_signatures") or []
        if str(value) != signature
    ]
    workflow["authorized_route_signatures"] = signatures
    workflow["authorized_route_networks"] = [
        value
        for value in workflow.get("authorized_route_networks") or []
        if str(value) != destination_network
    ]
    records = {
        str(key): dict(value)
        for key, value in (workflow.get("authorized_route_records") or {}).items()
        if isinstance(value, dict) and str(key) != signature
    }
    workflow["authorized_route_records"] = records

    path["authorization_state"] = "authorization_revoked"
    path["verification_state"] = "authorization_required"
    path["revoked_at"] = scan_store.now()
    workflow.setdefault("paths", {})[str(path_id)] = path
    segment["path_ids"] = [
        value for value in segment.get("path_ids") or [] if str(value) != str(path_id)
    ]
    workflow.setdefault("segments", {})[str(segment["segment_id"])] = segment
    workflow["pending_path_ids"] = [
        value for value in workflow.get("pending_path_ids") or [] if str(value) != str(path_id)
    ]
    workflow.setdefault("operator_decisions", []).append(
        {
            "decision": "revoke_authorized_route",
            "segment_id": segment.get("segment_id"),
            "path_id": path_id,
            "route_signature": signature,
            "destination_network": destination_network,
            "state_before": "operator_authorized",
            "state_after": "observation_only",
            "timestamp": scan_store.now(),
        }
    )
    _set_current_aliases(workflow)
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        current_task="Waiting for operator decision",
        next_task="Authorise another route, assess, refresh, retry, or stop",
        error=None,
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [host.get("ip") for host in segment.get("hosts") or []],
            "internal_host_inventory": segment.get("hosts") or [],
        },
    )
    scan_store.audit_event(
        scan_id,
        "operator",
        "route_authorization_revoked",
        {
            "segment_id": segment.get("segment_id"),
            "path_id": path_id,
            "route_signature": signature,
            "destination_network": destination_network,
        },
    )
    scan_store.persist(scan_id)

# Removed deprecated pre-v6 retry_current_layer implementation; active topology-driven version is defined below.


# Removed deprecated pre-v6 prepare_assessment_from_current_layer implementation; active topology-driven version is defined below.


def stop_discovery(scan_id: str) -> dict[str, Any]:
    """Compatibility alias for finishing Phase 2 and opening Phase 3.

    The operator-facing workflow uses "Stop Phase 2" to stop further topology
    traversal, not to terminate the assessment mission. All retained eligible
    assets therefore remain available for Phase 3 configuration.
    """
    return prepare_assessment_from_current_layer(scan_id)


def continue_discovery_with_subnet(scan_id: str, selected_subnet: str) -> None:
    """Compatibility wrapper resolving an observed path by destination network."""

    current = scan_store.load(scan_id) or {}
    workflow = dict(current.get("workflow") or {})
    matching = [
        path_id
        for path_id, path in (workflow.get("paths") or {}).items()
        if str((path or {}).get("destination_network") or "") == str(selected_subnet or "")
        and str((path or {}).get("from_segment_id") or "") == str(workflow.get("current_segment_id") or "")
    ]
    if len(matching) != 1:
        _record_discovery_failure(
            scan_id,
            DiscoveryWorkflowError(
                "The selected network does not resolve to exactly one current-scope path."
            ),
        )
        return
    continue_discovery_with_path(scan_id, matching[0])

# =============================================================================
# Phase 2 operator-controlled topology discovery (v11)
# =============================================================================
# Legacy route-record helpers above remain only for historical stored-mission
# compatibility. The active Phase 1/2 workflow below never reads Kali's kernel
# routing table for discovery; current scope comes from interface address/prefix
# observations and continuation networks come from selected-device evidence.


def collect_local_observation_snapshot(scan_id: str, purpose_prefix: str) -> dict[str, Any]:
    """Collect interface/neighbour observations without reading the route table."""

    ip_tool = shutil.which("ip")
    if not ip_tool:
        return {
            "captured_at": scan_store.now(),
            "interfaces": [],
            "interface_index": {},
            "routes": [],
            "neighbours": [],
            "route_signatures": [],
        }
    addresses = _json_command(
        scan_id,
        [ip_tool, "-j", "addr", "show"],
        f"{purpose_prefix} local interface snapshot",
        required=False,
    )
    neighbours = _json_command(
        scan_id,
        [ip_tool, "-j", "neigh", "show"],
        f"{purpose_prefix} local neighbour snapshot",
        required=False,
    )
    return {
        "captured_at": scan_store.now(),
        "interfaces": addresses,
        "interface_index": _interface_index(addresses),
        "routes": [],
        "neighbours": neighbours,
        "route_signatures": [],
    }


def _asset_ip(host: dict[str, Any]) -> str:
    return str(host.get("ip") or host.get("address") or "").strip()


def _local_connected_scope_for_entry(
    snapshot: dict[str, Any],
    entry_ip: str,
) -> dict[str, Any] | None:
    """Return the directly connected subnet containing the Phase 1 entry IP.

    This is intentionally derived only from the scanner interface address and
    prefix information collected with ``ip -j addr show``.  The kernel routing
    table is not consulted.  When several interfaces could contain the entry
    address, the most-specific usable network is selected deterministically.
    """

    try:
        entry = ipaddress.ip_address(str(entry_ip))
    except ValueError:
        return None

    candidates: list[dict[str, Any]] = []
    for row in snapshot.get("interfaces") or []:
        if not isinstance(row, dict):
            continue
        interface = str(row.get("ifname") or "").strip()
        if not interface or interface == "lo":
            continue
        for item in row.get("addr_info") or []:
            if not isinstance(item, dict):
                continue
            local_text = str(item.get("local") or "").strip()
            try:
                local = ipaddress.ip_address(local_text)
                prefixlen = int(item.get("prefixlen"))
                network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
            except (TypeError, ValueError):
                continue
            if local.version != entry.version or entry not in network:
                continue
            if local.is_loopback or local.is_link_local:
                continue
            if network.prefixlen >= network.max_prefixlen:
                # A /32 or /128 does not provide a subnet to enumerate.
                continue
            if not _usable_internal_network(network):
                continue
            scope_allowed, scope_state = _discovery_network_scope_state(str(network))
            candidates.append(
                {
                    "network": str(network),
                    "interface": interface,
                    "scanner_ip": str(local),
                    "prefixlen": int(network.prefixlen),
                    "scope_allowed": bool(scope_allowed),
                    "scope_state": str(scope_state),
                    "address_count": int(network.num_addresses),
                    "evidence_source": "scanner_interface_address",
                }
            )

    if not candidates:
        return None

    # Prefer an authorised candidate, then the most-specific prefix.  This
    # avoids accidentally selecting a broader overlapping interface network.
    candidates.sort(
        key=lambda row: (
            0 if row.get("scope_allowed") else 1,
            -int(row.get("prefixlen") or 0),
            str(row.get("interface") or ""),
            str(row.get("network") or ""),
        )
    )
    return candidates[0]


def _segment_from_local_connected_scope(
    local_scope: dict[str, Any],
    *,
    entry_ip: str,
    layer_index: int = 1,
) -> dict[str, Any]:
    """Build the first Phase 2 subnet segment from local interface evidence."""

    network = ipaddress.ip_network(str(local_scope["network"]), strict=False)
    interface = str(local_scope.get("interface") or "")
    source = str(local_scope.get("scanner_ip") or "")
    segment_id = _segment_identifier(
        str(network),
        interface,
        source,
        "",
        "local_interface",
        "local_connected_network",
    )
    return {
        "segment_id": segment_id,
        "layer_index": int(layer_index),
        "scope_kind": "local_connected_network",
        "network": str(network),
        "enumeration_target": str(network),
        "interface": interface,
        "source_address": source,
        "next_hop": "",
        "route_table": "",
        "route_type": "local_interface",
        "access_mode": "directly_connected",
        "access_transport": "direct",
        "layer2_connected": True,
        "verification_state": "local_interface_verified",
        "created_at": scan_store.now(),
        "last_enumerated_at": None,
        "hosts": [],
        "path_ids": [],
        "discovery_execution": {},
        "route": {},
        "entry_target": str(entry_ip),
        "scope_allowed": bool(local_scope.get("scope_allowed")),
        "scope_state": str(local_scope.get("scope_state") or ""),
        "evidence": [
            {
                "type": "local_connected_scope",
                "source": "scanner_interface_address",
                "interface": interface,
                "scanner_ip": source,
                "network": str(network),
                "entry_target": str(entry_ip),
                "kernel_route_discovery": False,
                "scope_state": str(local_scope.get("scope_state") or ""),
                "observed_at": scan_store.now(),
            }
        ],
    }


def _phase2_stop_summary(workflow: dict[str, Any]) -> dict[str, Any]:
    """Describe why operator-controlled Phase 2 ended in reportable terms."""

    segments = workflow.get("segments") or {}
    ordered = [
        segments.get(segment_id) or {}
        for segment_id in workflow.get("segment_order") or []
        if segments.get(segment_id)
    ]
    network_segments = [
        row for row in ordered
        if str(row.get("scope_kind") or "") != "entry_host"
    ]
    topology_paths = [
        row for row in (workflow.get("paths") or {}).values()
        if isinstance(row, dict) and row.get("path_kind") == "infrastructure_topology"
    ]
    selected_paths = [
        row for row in topology_paths
        if row.get("operator_selected") or row.get("authorization_state") == "operator_selected"
    ]
    available_paths = [
        row for row in topology_paths
        if row.get("enumeration_eligible")
        and row.get("verification_state") not in {"visited", "scope_exceeds_discovery_limit"}
    ]
    # v14 uses the operator-facing "Collect Network Evidence" decision name.
    # Retain the historical name only when reopening an older mission so report
    # summaries remain backwards compatible without reviving the old workflow.
    network_evidence_checks = [
        row for row in workflow.get("operator_decisions") or []
        if isinstance(row, dict)
        and row.get("decision") in {"collect_network_evidence", "query_infrastructure_topology"}
    ]

    continuation = dict(workflow.get("topology_continuation") or {})
    continuation_state = str(continuation.get("state") or "")
    selected_device_ips = [
        str(value).strip()
        for value in continuation.get("selected_device_ips") or []
        if str(value).strip()
    ]
    if not selected_device_ips and continuation.get("selected_device_ip"):
        selected_device_ips = [str(continuation.get("selected_device_ip")).strip()]
    selected_device_label = ", ".join(dict.fromkeys(selected_device_ips)) or "the selected device(s)"

    if continuation_state in {"discovery_failed", "no_continuation_observed"} and not selected_paths:
        code = "operator_finished_without_observed_continuation"
        message = (
            f"Phase 2 was finished after network evidence was collected from {selected_device_label}; "
            "no additional continuation network was established from the observable evidence. "
            "This does not prove that no deeper network exists."
        )
    elif not network_evidence_checks and not network_segments:
        code = "operator_finished_after_entry_verification_no_local_scope"
        message = (
            "Phase 2 was finished by the operator after entry-host verification; "
            "no authorised directly connected subnet or further network layer was available for enumeration."
        )
    elif not network_evidence_checks and len(network_segments) == 1:
        code = "operator_finished_after_local_discovery_no_topology_continuation"
        message = (
            "Phase 2 was finished by the operator after local subnet enumeration; "
            "no further network layer was discovered or authorised before Phase 2 ended."
        )
    elif available_paths and not selected_paths:
        code = "operator_finished_with_unselected_continuation"
        message = (
            f"Phase 2 was finished by the operator with {len(available_paths)} discovered "
            "continuation network(s) available, but none was authorised for traversal."
        )
    elif selected_paths:
        code = "operator_finished_after_layered_traversal"
        message = (
            f"Phase 2 was finished by the operator after {len(network_segments)} network "
            "layer(s) were enumerated; no further continuation was selected."
        )
    else:
        code = "operator_finished_no_eligible_continuation"
        message = (
            "Phase 2 was finished by the operator because no further eligible continuation "
            "network was available from the retained topology evidence."
        )

    return {
        "code": code,
        "message": message,
        "visited_network_layers": len(network_segments),
        # Compatibility field retained for older report consumers.
        "topology_queries": len(network_evidence_checks),
        "network_evidence_checks": len(network_evidence_checks),
        "available_continuations": len(available_paths),
        "selected_continuations": len(selected_paths),
        "current_segment_id": workflow.get("current_segment_id"),
        "recorded_at": scan_store.now(),
    }


def _infrastructure_candidate_hint(host: dict[str, Any]) -> tuple[str, str]:
    """Return a conservative operator hint; never auto-traverse from it."""
    if host.get("is_scanner"):
        return "not_applicable", "scanner/controller address"
    if host.get("infrastructure_topology_queried"):
        return "confirmed", "selected-device network evidence collection completed"

    role = str(host.get("role") or "").strip().lower()
    device_type = str(host.get("device_type") or "").strip().lower()
    hostname = str(host.get("hostname") or "").strip().lower()
    vendor = str(host.get("mac_vendor") or "").strip().lower()
    evidence = " ".join((role, device_type, hostname, vendor))
    strong_terms = (
        "gateway", "router", "firewall", "layer 3", "layer3", "l3",
        "cisco", "palo alto", "juniper", "fortinet", "fortigate",
        "linksys", "belkin",
    )
    if any(term in evidence for term in strong_terms):
        return "likely", "retained role/hostname/vendor metadata suggests network infrastructure"

    # A generic responsive host remains selectable, but Phase 2 should not
    # imply that every endpoint is equally likely to expose Layer-3 topology.
    # This is guidance only and never blocks operator selection.
    if role in {"host", "endpoint", "observed_host", ""} and not any(
        term in evidence for term in ("switch", "ap", "access point", "network")
    ):
        return "possible", "no retained evidence currently identifies this device as Layer-3 infrastructure"
    return "possible", "device type is not yet established; operator may still select it for an authorised topology check"


def _apply_infrastructure_hint(host: dict[str, Any]) -> dict[str, Any]:
    row = dict(host)
    state, reason = _infrastructure_candidate_hint(row)
    row["infrastructure_candidate_state"] = state
    row["infrastructure_candidate_reason"] = reason
    return row


def _merge_asset_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing or {})
    for key, value in incoming.items():
        if value not in (None, "", [], {}):
            if key not in merged or merged.get(key) in (None, "", [], {}):
                merged[key] = value
    for key in ("origins", "discovered_by", "verification_methods", "segment_ids", "discovery_layers"):
        values: list[Any] = []
        for source in (existing.get(key) if isinstance(existing, dict) else [], incoming.get(key)):
            for value in source or []:
                if value not in values:
                    values.append(value)
        if values:
            merged[key] = values
    evidence: list[dict[str, Any]] = []
    for row in [*(existing.get("reachability_evidence") or []), *(incoming.get("reachability_evidence") or [])]:
        if isinstance(row, dict) and row not in evidence:
            evidence.append(row)
    if evidence:
        merged["reachability_evidence"] = evidence
    hostname_observations: list[dict[str, Any]] = []
    for row in [*(existing.get("hostname_observations") or []), *(incoming.get("hostname_observations") or [])]:
        if isinstance(row, dict) and row not in hostname_observations:
            hostname_observations.append(row)
    if hostname_observations:
        merged["hostname_observations"] = hostname_observations
    merged["selectable"] = bool(existing.get("selectable") or incoming.get("selectable")) and not bool(
        existing.get("is_scanner") or incoming.get("is_scanner")
    )
    merged["is_scanner"] = bool(existing.get("is_scanner") or incoming.get("is_scanner"))
    if incoming.get("reachability_state") == "responsive" or existing.get("reachability_state") == "responsive":
        merged["reachability_state"] = "responsive"
    merged["last_observed_at"] = scan_store.now()
    return merged


def _accumulate_assets(
    workflow: dict[str, Any],
    hosts: Iterable[dict[str, Any]],
    *,
    segment: dict[str, Any],
) -> list[dict[str, Any]]:
    """Merge Phase 1 and every Phase 2 layer into one retained asset inventory."""

    index = {
        _asset_ip(row): dict(row)
        for row in workflow.get("asset_inventory") or []
        if isinstance(row, dict) and _asset_ip(row)
    }
    segment_id = str(segment.get("segment_id") or "")
    layer_index = int(segment.get("layer_index") or 0)
    phase = "Phase 1" if str(segment.get("scope_kind") or "") == "entry_host" else "Phase 2"
    for source in hosts or []:
        if not isinstance(source, dict):
            continue
        ip_text = _asset_ip(source)
        if not ip_text:
            continue
        incoming = dict(source)
        incoming.setdefault("segment_ids", [])
        if segment_id and segment_id not in incoming["segment_ids"]:
            incoming["segment_ids"].append(segment_id)
        incoming.setdefault("discovery_layers", [])
        layer_label = f"{phase} / Layer {layer_index}" if phase == "Phase 2" else "Phase 1"
        if layer_label not in incoming["discovery_layers"]:
            incoming["discovery_layers"].append(layer_label)
        incoming["discovery_phase"] = phase
        incoming["last_segment_id"] = segment_id
        incoming["last_network"] = str(segment.get("network") or "")
        incoming["authorized_scope"] = True
        index[ip_text] = _apply_infrastructure_hint(
            _merge_asset_record(index.get(ip_text, {}), incoming)
        )
    ordered = _sort_hosts(index.values())
    workflow["asset_inventory"] = ordered
    return ordered


def _selectable_inventory(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(host)
        for host in workflow.get("asset_inventory") or workflow.get("discovered_hosts") or []
        if isinstance(host, dict)
        and host.get("selectable")
        and not host.get("is_scanner")
        and _asset_ip(host)
    ]


def _phase_results(workflow: dict[str, Any]) -> dict[str, Any]:
    """Build phase summaries using the complete retained inventory."""

    segments = [
        workflow.get("segments", {}).get(segment_id)
        for segment_id in workflow.get("segment_order") or []
        if workflow.get("segments", {}).get(segment_id)
    ]
    current = workflow.get("segments", {}).get(workflow.get("current_segment_id")) or {}
    entry = dict(workflow.get("entry_result") or {})
    inventory = [dict(row) for row in workflow.get("asset_inventory") or [] if isinstance(row, dict)]
    topology_paths = [
        dict(row)
        for row in (workflow.get("paths") or {}).values()
        if isinstance(row, dict) and row.get("path_kind") == "infrastructure_topology"
    ]
    previous_assessment = dict(
        (workflow.get("phase_results") or {}).get("assessment")
        or {"status": "not_started", "targets": []}
    )
    return {
        "external": {"status": "completed", **entry},
        "entry": {"status": "completed", **entry},
        "internal": {
            "status": "completed" if current else "not_started",
            "subnet": current.get("network"),
            "access_mode": current.get("access_mode"),
            "scope_kind": current.get("scope_kind"),
            "current_host_count": len(current.get("hosts") or []),
            "inventory_host_count": len(inventory),
            "selectable_host_count": len([row for row in inventory if row.get("selectable") and not row.get("is_scanner")]),
            "hosts": inventory,
        },
        "traversal": {
            "status": "completed" if workflow.get("phase2_finished") else "awaiting_operator_decision",
            "visited_segment_count": len(segments),
            "current_segment_id": current.get("segment_id"),
            "available_path_count": len(
                [
                    row
                    for row in topology_paths
                    if row.get("from_segment_id") == current.get("segment_id")
                    and row.get("verification_state") not in {"visited", "scope_exceeds_discovery_limit"}
                ]
            ),
            "stop_reason": workflow.get("phase2_stop_reason", ""),
            "stop": dict(workflow.get("phase2_stop") or {}),
            "segments": segments,
        },
        "assessment": previous_assessment,
    }


def _set_current_aliases(workflow: dict[str, Any]) -> dict[str, Any]:
    """Maintain legacy aliases while retaining the complete mission inventory."""

    current = (workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {}
    workflow["current_segment"] = current
    workflow["internal_subnet"] = str(current.get("network") or "")
    workflow["access_mode"] = str(current.get("access_mode") or "")
    if not workflow.get("asset_inventory"):
        _accumulate_assets(workflow, current.get("hosts") or [], segment=current)
    workflow["discovered_hosts"] = list(workflow.get("asset_inventory") or [])
    workflow["network_context"] = {
        "segment_id": current.get("segment_id"),
        "interface": current.get("interface"),
        "scanner_ip": current.get("source_address"),
        "gateway": current.get("next_hop"),
        "internal_subnet": current.get("network"),
        "access_mode": current.get("access_mode"),
        "route_table": current.get("route_table"),
        "route_type": current.get("route_type"),
        "layer2_connected": current.get("layer2_connected"),
        "scope_kind": current.get("scope_kind"),
        "access_transport": current.get("access_transport"),
    }
    workflow["phase_results"] = _phase_results(workflow)
    return workflow


def _discovery_network_scope_state(network_text: str) -> tuple[bool, str]:
    """Apply the configured engagement policy to one discovered network."""

    from scanners.enterprise_readiness import load_engagement_policy

    try:
        network = ipaddress.ip_network(str(network_text), strict=False)
    except ValueError:
        return False, "invalid_network"
    try:
        policy = load_engagement_policy()
    except Exception as exc:
        return False, f"engagement_policy_unavailable: {exc}"
    controls = policy.get("scope_controls") or {}
    allowed = []
    denied = []
    for value in controls.get("allowed_networks") or []:
        try:
            allowed.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    for value in controls.get("denied_networks") or []:
        try:
            denied.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    if any(network.overlaps(blocked) for blocked in denied):
        return False, "overlaps_denied_network"
    if allowed:
        if any(network.subnet_of(permitted) for permitted in allowed if permitted.version == network.version):
            return True, "explicit_allowlist"
        return False, "outside_allowed_networks"
    first = network.network_address
    private_like = first.is_private or first.is_loopback or first.is_link_local
    if private_like and controls.get("allow_private_lab_targets_without_signed_roe"):
        return True, "private_lab_fallback"
    if not private_like and controls.get("allow_public_targets"):
        return True, "public_targets_allowed"
    return False, "network_not_authorized_by_engagement_policy"


def _topology_path_id(from_segment_id: str, device_ip: str, network: str) -> str:
    return _stable_id("topopath", from_segment_id, device_ip, network)


def _network_already_visited(workflow: dict[str, Any], network_text: str) -> bool:
    try:
        target = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return False
    for segment_id in workflow.get("visited_segment_ids") or []:
        segment = (workflow.get("segments") or {}).get(segment_id) or {}
        try:
            existing = ipaddress.ip_network(str(segment.get("network") or ""), strict=False)
        except ValueError:
            continue
        if existing == target:
            return True
    return False


def _update_asset_device_classification(
    workflow: dict[str, Any],
    segment: dict[str, Any],
    device_ip: str,
    platform: str,
    interfaces: Iterable[dict[str, Any]] | None = None,
    *,
    network_evidence_observed: bool = False,
) -> None:
    """Update a selected device without falsely promoting every host to infrastructure.

    A device is classified as network infrastructure only when the retained
    evidence actually supports that role (known platform or a continuation
    network/interface observation). Merely selecting a host for inspection is
    not sufficient.
    """
    role = "network_device"
    device_type = "Network device"
    role_established = bool(network_evidence_observed)
    if platform == "cisco_ios":
        role = "router_or_switch"
        device_type = "Cisco network device"
        role_established = True
    elif platform == "palo_alto":
        role = "firewall"
        device_type = "Palo Alto firewall"
        role_established = True

    interface_addresses = [
        {
            "interface": str(row.get("interface") or ""),
            "address": str(row.get("address") or ""),
            "network": str(row.get("network") or ""),
        }
        for row in interfaces or []
        if isinstance(row, dict) and str(row.get("address") or "")
    ]
    if interface_addresses:
        role_established = True

    for collection in (segment.get("hosts") or [], workflow.get("asset_inventory") or []):
        for host in collection:
            if _asset_ip(host) != device_ip:
                continue
            host["infrastructure_topology_queried"] = True
            host["network_evidence_checked"] = True
            host["network_evidence_observed"] = bool(network_evidence_observed or interface_addresses)
            if role_established:
                host["role"] = role
                host["device_type"] = device_type
            if interface_addresses:
                host["device_interfaces"] = interface_addresses
            host.update(_apply_infrastructure_hint(host))


def _retain_topology_interface_assets(
    workflow: dict[str, Any],
    *,
    device_ip: str,
    topology: dict[str, Any],
) -> None:
    """Retain interface IPs learned from the selected device's control plane.

    These are legitimate Phase 2 discoveries even before a subnet enumeration
    runs. They are selectable for Phase 3 when their network is inside the
    engagement policy; Phase 3 still performs its own reachability/service
    validation.
    """

    platform = str(topology.get("platform") or "generic")
    device_type = (
        "Cisco network device"
        if platform == "cisco_ios"
        else "Palo Alto firewall"
        if platform == "palo_alto"
        else "Network device"
    )
    role = "firewall" if platform == "palo_alto" else "router_or_switch" if platform == "cisco_ios" else "network_device"
    index = {
        _asset_ip(row): dict(row)
        for row in workflow.get("asset_inventory") or []
        if isinstance(row, dict) and _asset_ip(row)
    }
    for interface in topology.get("interfaces") or []:
        if not isinstance(interface, dict):
            continue
        address = str(interface.get("address") or "").strip()
        network_text = str(interface.get("network") or "").strip()
        try:
            address = str(ipaddress.ip_address(address))
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            continue
        scope_allowed, scope_state = _discovery_network_scope_state(str(network))
        incoming = {
            "host_id": _stable_id("topology-host", device_ip, address),
            "ip": address,
            "address": address,
            "status": "observed",
            "reachability_state": "topology_observed",
            "reachability_evidence": [
                {
                    "source": "infrastructure_control_plane_interface",
                    "state": "interface_address_observed",
                    "device_ip": device_ip,
                    "interface": str(interface.get("interface") or ""),
                    "network": str(network),
                    "topology_observation_id": str(topology.get("observation_id") or ""),
                }
            ],
            "hostname": "",
            "hostname_observations": [],
            "mac": "",
            "mac_vendor": "",
            "role": role,
            "device_type": device_type,
            "is_scanner": False,
            "selectable": bool(scope_allowed),
            "record_type": "topology_interface",
            "origin": "infrastructure_control_plane",
            "origins": ["infrastructure_control_plane"],
            "independently_discovered": True,
            "discovered_by": ["infrastructure_topology_query"],
            "verification_methods": ["device_control_plane_interface"],
            "discovery_phase": "Phase 2",
            "discovery_layers": ["Phase 2 / Topology"],
            "topology_observation_id": str(topology.get("observation_id") or ""),
            "topology_parent_device_ip": device_ip,
            "device_interface": str(interface.get("interface") or ""),
            "last_network": str(network),
            "authorized_scope": bool(scope_allowed),
            "scope_state": scope_state,
        }
        index[address] = _apply_infrastructure_hint(
            _merge_asset_record(index.get(address, {}), incoming)
        )
    workflow["asset_inventory"] = _sort_hosts(index.values())


def discover_next_networks_from_device(
    scan_id: str,
    device_ip: str,
    *,
    profile_ref: str = "",
    runtime_profile: dict[str, Any] | None = None,
    runtime_secret: str = "",
) -> dict[str, Any]:
    """Query one operator-selected device and retain its next network branches."""

    current = scan_store.load(scan_id) or {}
    if str(current.get("status") or "") not in {scan_store.STATUS_AWAITING_LAYER_DECISION, scan_store.STATUS_LAYER_ENUMERATION}:
        raise DiscoveryWorkflowError("The mission is not waiting for a Phase 2 topology query.")
    workflow = dict(current.get("workflow") or {})
    segment = dict((workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {})
    if not segment:
        raise DiscoveryWorkflowError("The current discovery layer is unavailable.")
    device_ip = validate_external_target(device_ip)
    current_host_ips = {
        _asset_ip(host)
        for host in segment.get("hosts") or []
        if isinstance(host, dict) and not host.get("is_scanner")
    }
    if device_ip not in current_host_ips:
        raise DiscoveryWorkflowError(
            "Select a device that was retained in the current discovery layer."
        )
    from scanners.enterprise_readiness import validate_scope
    validate_scope([device_ip], device_ip)

    legacy_profile_mode = bool(str(profile_ref or "").strip() or runtime_profile is not None)
    if legacy_profile_mode:
        # Backward-compatible programmatic path for older tests/integrations.
        # The Phase 2 operator UI no longer requests or exposes infrastructure
        # credentials/profiles.
        from scanners.infrastructure_discovery import collect_device_topology

        if runtime_profile is not None:
            topology = collect_device_topology(
                scan_id,
                device_ip,
                profile_ref=profile_ref,
                runtime_profile=runtime_profile,
                runtime_secret=runtime_secret,
            )
        else:
            topology = collect_device_topology(
                scan_id,
                device_ip,
                profile_ref=profile_ref,
            )
        evidence_mode = "configured_device_query"
    else:
        from scanners.topology_evidence import collect_device_topology_evidence

        snapshot = collect_local_observation_snapshot(
            scan_id, "Phase 2 selected-device network evidence"
        )
        observed = collect_device_topology_evidence(
            scan_id,
            device_ip=device_ip,
            current_segment=segment,
            snapshot=snapshot,
        )
        observation_id = _stable_id(
            "network-evidence",
            scan_id,
            segment.get("segment_id"),
            device_ip,
            observed.get("captured_at"),
        )
        topology = {
            "observation_id": observation_id,
            "device_ip": device_ip,
            "profile_ref": "",
            "platform": "generic",
            "transport": "observed_evidence",
            "access_source": "observed_network_evidence",
            "interfaces": [],
            "networks": [
                {
                    "destination_network": str(row.get("network") or ""),
                    "device_interface": str(row.get("interface") or ""),
                    "device_interface_ip": "",
                    "evidence_sources": list(row.get("evidence_sources") or []),
                    "enumeration_eligible": bool(row.get("enumeration_eligible")),
                    "confidence": str(row.get("confidence") or ""),
                    "evidence": list(row.get("evidence") or []),
                }
                for row in observed.get("candidate_networks") or []
                if isinstance(row, dict) and str(row.get("network") or "")
            ],
            "observed_network_evidence": observed,
        }
        evidence_mode = "observed_network_evidence"

    if legacy_profile_mode:
        supplemental: dict[str, Any] = {}
        if str(os.getenv("INFRA_TOPOLOGY_SUPPLEMENTAL_EVIDENCE", "0")).strip().lower() not in {"0", "false", "no", "off"}:
            try:
                from scanners.topology_evidence import collect_device_topology_evidence
                supplemental_snapshot = collect_local_observation_snapshot(
                    scan_id, "Phase 2 supplemental topology"
                )
                supplemental = collect_device_topology_evidence(
                    scan_id,
                    device_ip=device_ip,
                    current_segment=segment,
                    snapshot=supplemental_snapshot,
                )
            except Exception as exc:
                supplemental = {
                    "device_ip": device_ip,
                    "boundary_state": "supplemental_collection_unavailable",
                    "statement": str(exc),
                    "candidate_networks": [],
                    "collectors": {},
                }
        supplemental_by_network = {
            str(row.get("network") or ""): dict(row)
            for row in supplemental.get("candidate_networks") or []
            if isinstance(row, dict) and str(row.get("network") or "")
        }
        for network_row in topology.get("networks") or []:
            if not isinstance(network_row, dict):
                continue
            match = supplemental_by_network.get(str(network_row.get("destination_network") or ""))
            if not match:
                continue
            sources = list(network_row.get("evidence_sources") or [])
            supplemental_source = str(match.get("source") or "supplemental_observation")
            label = f"supplemental:{supplemental_source}"
            if label not in sources:
                sources.append(label)
            network_row["evidence_sources"] = sources
            network_row["supplemental_confidence"] = str(match.get("confidence") or "")
            network_row["supplemental_evidence"] = list(match.get("evidence") or [])
        topology["supplemental_topology_evidence"] = supplemental

    discovered_count = len(topology.get("networks") or [])
    existing_continuation = dict(workflow.get("topology_continuation") or {})
    selected_device_ips = [
        str(value)
        for value in existing_continuation.get("selected_device_ips") or []
        if str(value)
    ]
    if device_ip not in selected_device_ips:
        selected_device_ips.append(device_ip)
    device_results = {
        str(key): dict(value)
        for key, value in (existing_continuation.get("device_results") or {}).items()
        if isinstance(value, dict)
    }
    device_results[device_ip] = {
        "state": "network_evidence_observed" if discovered_count else "no_continuation_observed",
        "network_count": discovered_count,
        "platform": str(topology.get("platform") or "generic"),
        "access_source": evidence_mode,
        "message": (
            f"{discovered_count} continuation network(s) retained."
            if discovered_count
            else "No additional continuation network was established from observable evidence."
        ),
        "updated_at": scan_store.now(),
    }
    workflow["topology_continuation"] = {
        **existing_continuation,
        "selected_device_ip": device_ip,
        "selected_device_ips": selected_device_ips,
        "device_results": device_results,
        "state": "network_evidence_observed" if discovered_count else "no_continuation_observed",
        "profile_ref": str(topology.get("profile_ref") or profile_ref or ""),
        "platform": str(topology.get("platform") or "generic"),
        "transport": str(topology.get("transport") or ""),
        "access_source": evidence_mode,
        "message": (
            f"Network evidence identified {discovered_count} continuation network(s) from {device_ip}."
            if discovered_count
            else f"No additional network prefix was established from observable evidence for {device_ip}."
        ),
        "updated_at": scan_store.now(),
    }
    observation_id = str(topology.get("observation_id") or "")
    observations = {
        str(row.get("observation_id") or ""): dict(row)
        for row in workflow.get("topology_observations") or []
        if isinstance(row, dict) and str(row.get("observation_id") or "")
    }
    observations[observation_id] = topology
    workflow["topology_observations"] = list(observations.values())

    _update_asset_device_classification(
        workflow,
        segment,
        device_ip,
        str(topology.get("platform") or "generic"),
        topology.get("interfaces") or [],
        network_evidence_observed=bool(discovered_count),
    )
    _retain_topology_interface_assets(workflow, device_ip=device_ip, topology=topology)

    paths = {str(key): dict(value) for key, value in (workflow.get("paths") or {}).items()}
    # Preserve branches previously discovered from other devices on this same
    # layer. Re-querying one device updates its stable path IDs without hiding
    # the operator's other branch choices.
    current_path_ids: list[str] = [
        str(path_id)
        for path_id in segment.get("path_ids") or []
        if str(path_id) in paths
        and str((paths.get(str(path_id)) or {}).get("path_kind") or "") == "infrastructure_topology"
        and str((paths.get(str(path_id)) or {}).get("from_segment_id") or "") == str(segment.get("segment_id") or "")
    ]
    try:
        selected_address = ipaddress.ip_address(device_ip)
    except ValueError:
        selected_address = None
    for network_row in topology.get("networks") or []:
        destination_network = str(network_row.get("destination_network") or "").strip()
        if not destination_network:
            continue
        try:
            network = ipaddress.ip_network(destination_network, strict=False)
        except ValueError:
            continue
        # The interface on which the operator reached this device is the current
        # side, not a continuation branch. Do not offer that same network again.
        if selected_address is not None and selected_address in network:
            continue
        path_id = _topology_path_id(str(segment.get("segment_id") or ""), device_ip, str(network))
        visited = _network_already_visited(workflow, str(network))
        scope_allowed, scope_state = _discovery_network_scope_state(str(network))
        eligible = bool(network_row.get("enumeration_eligible")) and not visited and scope_allowed
        path = {
            "path_id": path_id,
            "path_kind": "infrastructure_topology",
            "from_segment_id": str(segment.get("segment_id") or ""),
            "source_device_ip": device_ip,
            "source_device_platform": str(topology.get("platform") or "generic"),
            "source_device_profile_ref": str(topology.get("profile_ref") or ""),
            "topology_observation_id": observation_id,
            "destination_network": str(network),
            "destination_interface_ip": str(network_row.get("device_interface_ip") or ""),
            "device_interface": str(network_row.get("device_interface") or ""),
            "evidence_sources": list(network_row.get("evidence_sources") or []),
            "address_count": int(network.num_addresses),
            "discovery_limit": int(Config.MAX_EXPANDED_TARGETS),
            "enumeration_eligible": eligible,
            "scope_allowed": scope_allowed,
            "scope_state": scope_state,
            "authorization_state": "operator_selection_required",
            "reachability_state": "unknown",
            "evidence_source_label": (
                "Observed network evidence from selected device"
                if evidence_mode == "observed_network_evidence"
                else "Configured device interface/routing query"
            ),
            "verification_state": (
                "visited"
                if visited
                else "outside_engagement_scope"
                if not scope_allowed
                else "discovered"
                if bool(network_row.get("enumeration_eligible"))
                else "scope_exceeds_discovery_limit"
            ),
            "access_transport": "unverified",
            "first_observed_at": scan_store.now(),
            "last_observed_at": scan_store.now(),
        }
        paths[path_id] = path
        current_path_ids.append(path_id)

    segment["path_ids"] = list(dict.fromkeys(current_path_ids))
    segment["last_topology_device_ip"] = device_ip
    segment["last_topology_observation_id"] = observation_id
    workflow.setdefault("segments", {})[str(segment["segment_id"])] = segment
    workflow["paths"] = paths
    workflow.setdefault("operator_decisions", []).append(
        {
            "decision": "collect_network_evidence",
            "segment_id": segment.get("segment_id"),
            "device_ip": device_ip,
            "profile_ref": str(topology.get("profile_ref") or ""),
            "access_source": str(topology.get("access_source") or evidence_mode),
            "path_count": len(current_path_ids),
            "timestamp": scan_store.now(),
        }
    )
    _set_current_aliases(workflow)
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        current_task="Waiting for operator decision",
        next_task="Select a discovered network to continue, inspect more devices, or finish Phase 2",
        error=None,
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [_asset_ip(host) for host in workflow.get("asset_inventory") or []],
            "internal_host_inventory": workflow.get("asset_inventory") or [],
        },
    )
    scan_store.audit_event(
        scan_id,
        "operator",
        "selected_device_network_evidence_collected",
        {
            "segment_id": segment.get("segment_id"),
            "device_ip": device_ip,
            "profile_ref": str(topology.get("profile_ref") or ""),
            "network_count": len(current_path_ids),
        },
    )
    scan_store.persist(scan_id)
    return workflow


def _verify_direct_topology_path(scan_id: str, path: dict[str, Any]) -> dict[str, Any]:
    """Verify a discovered branch without inspecting Kali's routing table."""

    representative = str(path.get("destination_interface_ip") or "").strip()
    if not representative:
        return {
            "reachable": False,
            "state": "reachability_not_established",
            "reason": "No device interface address was available for direct path verification.",
            "evidence": [],
        }
    try:
        address = ipaddress.ip_address(representative)
        network = ipaddress.ip_network(str(path.get("destination_network") or ""), strict=False)
    except ValueError:
        return {
            "reachable": False,
            "state": "reachability_not_established",
            "reason": "The retained interface or network address is invalid.",
            "evidence": [],
        }
    if address not in network:
        return {
            "reachable": False,
            "state": "reachability_not_established",
            "reason": "The retained interface address is outside the discovered network.",
            "evidence": [],
        }

    evidence: list[dict[str, Any]] = []
    nmap = shutil.which("nmap")
    if nmap:
        output_path = scan_store.scan_path(f"{scan_id}_{path.get('path_id')}_verify.xml")
        output_path.unlink(missing_ok=True)
        result = _run_command(
            scan_id,
            command_builders.nmap_external_reachability(nmap, representative, output_path),
            "Phase 2 selected network reachability verification",
            timeout=30,
            output_file=output_path,
            target=representative,
        )
        observed = _host_is_up_from_nmap_xml(output_path)
        evidence.append(
            {
                "method": "nmap_host_discovery",
                "target": representative,
                "response_observed": observed,
                "evidence_file": str(output_path),
                "returncode": result.get("returncode"),
            }
        )
        if observed:
            return {"reachable": True, "state": "verified_reachable", "reason": "", "evidence": evidence}

    ping = shutil.which("ping")
    if ping:
        result = _run_command(
            scan_id,
            command_builders.ping_echo(ping, representative, 1, 2),
            "Phase 2 selected network ICMP verification",
            timeout=8,
            target=representative,
        )
        observed = bool(result.get("success"))
        evidence.append(
            {
                "method": "icmp_echo",
                "target": representative,
                "response_observed": observed,
                "returncode": result.get("returncode"),
            }
        )
        if observed:
            return {"reachable": True, "state": "verified_reachable", "reason": "", "evidence": evidence}
    return {
        "reachable": False,
        "state": "reachability_not_established",
        "reason": "The discovered network exists in device topology evidence, but direct reachability was not established.",
        "evidence": evidence,
    }


def _segment_from_topology_path(path: dict[str, Any], layer_index: int, access_transport: str) -> dict[str, Any]:
    network = ipaddress.ip_network(str(path["destination_network"]), strict=False)
    segment_id = _segment_identifier(
        str(network),
        "",
        "",
        str(path.get("source_device_ip") or ""),
        "topology",
        "topology_network",
    )
    return {
        "segment_id": segment_id,
        "layer_index": layer_index,
        "scope_kind": "topology_network",
        "network": str(network),
        "enumeration_target": str(network),
        "interface": "",
        "source_address": "",
        "next_hop": str(path.get("source_device_ip") or ""),
        "route_table": "",
        "route_type": "infrastructure_topology",
        "access_mode": access_transport,
        "access_transport": access_transport,
        "layer2_connected": False,
        "verification_state": "verified_reachable",
        "created_at": scan_store.now(),
        "last_enumerated_at": None,
        "hosts": [],
        "path_ids": [],
        "discovery_execution": {},
        "route": {},
        "parent_path_id": path.get("path_id"),
        "source_device_ip": path.get("source_device_ip"),
        "source_device_interface": path.get("device_interface"),
        "source_device_interface_ip": path.get("destination_interface_ip"),
        "evidence": [
            {
                "type": "infrastructure_topology_path",
                "path_id": path.get("path_id"),
                "topology_observation_id": path.get("topology_observation_id"),
                "source_device_ip": path.get("source_device_ip"),
                "destination_network": path.get("destination_network"),
                "access_transport": access_transport,
                "verified_at": scan_store.now(),
            }
        ],
    }


def continue_discovery_with_topology_path(
    scan_id: str,
    path_id: str,
    *,
    access_transport: str = "direct",
) -> None:
    """Follow one operator-selected topology branch and enumerate the next layer."""

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_PATH_VERIFICATION:
            raise DiscoveryWorkflowError("The mission is not waiting for selected-network verification.")
        workflow = dict(current.get("workflow") or {})
        path = dict((workflow.get("paths") or {}).get(str(path_id)) or {})
        if not path or path.get("path_kind") != "infrastructure_topology":
            raise DiscoveryWorkflowError("The selected continuation network is unavailable.")
        if path.get("from_segment_id") != workflow.get("current_segment_id"):
            raise DiscoveryWorkflowError("The selected network does not start from the current layer.")
        if not path.get("enumeration_eligible"):
            raise DiscoveryWorkflowError("The selected network exceeds the configured bounded discovery limit or was already visited.")
        transport = str(access_transport or "direct").strip().lower()
        if transport not in {"direct"}:
            raise DiscoveryWorkflowError("Unsupported continuation access transport.")

        verification: dict[str, Any]
        if transport == "direct":
            verification = _verify_direct_topology_path(scan_id, path)
            if not verification.get("reachable"):
                path["verification_state"] = "direct_reachability_not_established"
                path["reachability_state"] = "unreachable"
                path["access_transport"] = "direct"
                path["last_verification_at"] = scan_store.now()
                path["verification_evidence"] = verification.get("evidence") or []
                workflow.setdefault("paths", {})[str(path_id)] = path
                _set_current_aliases(workflow)
                scan_store.update(
                    scan_id,
                    status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                    workflow_stage="awaiting_layer_decision",
                    workflow=workflow,
                    current_task="Waiting for operator decision",
                    next_task="Choose another branch or finish Phase 2",
                    error=str(verification.get("reason") or "Direct reachability was not established."),
                )
                scan_store.persist(scan_id)
                return

        layer_index = len(workflow.get("segment_order") or [])
        segment = _segment_from_topology_path(path, layer_index, transport)
        if segment["segment_id"] in set(workflow.get("visited_segment_ids") or []):
            path["verification_state"] = "visited"
            path["enumeration_eligible"] = False
            workflow.setdefault("paths", {})[str(path_id)] = path
            _set_current_aliases(workflow)
            scan_store.update(
                scan_id,
                status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                workflow_stage="awaiting_layer_decision",
                workflow=workflow,
                error=None,
            )
            scan_store.persist(scan_id)
            return

        path["verification_state"] = "verified_reachable"
        path["reachability_state"] = "reachable"
        path["authorization_state"] = "operator_selected"
        path["operator_selected"] = True
        path["access_transport"] = transport
        path["last_verification_at"] = scan_store.now()
        path["verification_evidence"] = verification.get("evidence") or []
        path["destination_segment_id"] = segment["segment_id"]
        workflow.setdefault("paths", {})[str(path_id)] = path
        workflow.setdefault("segments", {})[segment["segment_id"]] = segment
        workflow["current_segment_id"] = segment["segment_id"]
        workflow["topology_continuation"] = {
            "selected_device_ip": "",
            "state": "awaiting_device_selection",
            "profile_ref": "",
            "message": "The selected continuation network is now the current layer. Select a device in this layer to continue deeper.",
            "updated_at": scan_store.now(),
        }
        workflow.setdefault("segment_order", []).append(segment["segment_id"])
        workflow.setdefault("visited_segment_ids", []).append(segment["segment_id"])
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "continue_discovery",
                "path_id": path_id,
                "from_segment_id": path.get("from_segment_id"),
                "destination_network": path.get("destination_network"),
                "access_transport": transport,
                "timestamp": scan_store.now(),
            }
        )
        _set_current_aliases(workflow)
        task_name = f"Phase 2 — Layer {layer_index} Enumeration"
        scan_store.append_tasks(scan_id, [task_name], phase="discovery")
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_LAYER_ENUMERATION,
            workflow_stage="layer_enumeration",
            workflow=workflow,
            error=None,
        )
        scan_store.audit_event(
            scan_id,
            "operator",
            "network_layer_continuation_selected",
            {
                "path_id": path_id,
                "destination_network": path.get("destination_network"),
                "access_transport": transport,
            },
        )
        snapshot = collect_local_observation_snapshot(scan_id, "Phase 2")
        _enumerate_and_pause(scan_id, workflow, segment, snapshot, task_name=task_name)
    except Exception as exc:
        current = scan_store.load(scan_id) or {}
        workflow = dict(current.get("workflow") or {})
        path = dict((workflow.get("paths") or {}).get(str(path_id)) or {})
        if path:
            path["verification_state"] = "verification_failed"
            path["reachability_state"] = "unreachable"
            path["verification_error"] = str(exc)
            path["last_verification_at"] = scan_store.now()
            workflow.setdefault("paths", {})[str(path_id)] = path
            _set_current_aliases(workflow)
            scan_store.update(
                scan_id,
                status=scan_store.STATUS_AWAITING_LAYER_DECISION,
                workflow_stage="awaiting_layer_decision",
                workflow=workflow,
                current_task="Waiting for operator decision",
                next_task="Choose another branch or finish Phase 2",
                error=str(exc),
            )
            scan_store.persist(scan_id)
            return
        _record_discovery_failure(scan_id, exc)


def _enumerate_and_pause(
    scan_id: str,
    workflow: dict[str, Any],
    segment: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    task_name: str,
) -> None:
    """Enumerate one approved scope, accumulate assets, then return control."""

    scan_store.set_task(scan_id, task_name, scan_store.STATUS_RUNNING)
    if str(segment.get("scope_kind") or "") == "entry_host":
        hosts, execution = discover_host_scope(segment, dict(workflow.get("entry_result") or {}))
    else:
        hosts, execution = discover_internal_hosts(
            scan_id,
            str(segment["network"]),
            interface=str(segment.get("interface") or ""),
            scanner_ip=str(segment.get("source_address") or ""),
            gateway=str(segment.get("next_hop") or ""),
            segment_id=str(segment["segment_id"]),
            layer2_connected=bool(segment.get("layer2_connected")),
            snapshot=snapshot,
        )
    segment["hosts"] = hosts
    segment["discovery_execution"] = execution
    segment["last_enumerated_at"] = scan_store.now()
    responsive = [
        host
        for host in hosts
        if not host.get("is_scanner")
        and str(host.get("reachability_state") or "")
        in {"responsive", "observed_through_neighbour_evidence", "observed_through_arp_evidence"}
    ]
    segment["verification_state"] = "responsive_hosts_observed" if responsive else "reachability_not_established"
    scan_store.set_task(
        scan_id,
        task_name,
        scan_store.STATUS_SUCCESS if hosts else scan_store.STATUS_EMPTY,
        summary=(
            "Retained the operator-supplied Phase 1 entry target"
            if str(segment.get("scope_kind") or "") == "entry_host"
            else f"Retained {len(hosts)} host observation(s) from this approved network layer"
        ),
    )

    workflow.setdefault("segments", {})[str(segment["segment_id"])] = segment
    workflow["current_segment_id"] = str(segment["segment_id"])
    if segment["segment_id"] not in workflow.setdefault("segment_order", []):
        workflow["segment_order"].append(segment["segment_id"])
    if segment["segment_id"] not in workflow.setdefault("visited_segment_ids", []):
        workflow["visited_segment_ids"].append(segment["segment_id"])
    _accumulate_assets(workflow, hosts, segment=segment)
    _set_current_aliases(workflow)

    scan_store.update(
        scan_id,
        status=scan_store.STATUS_AWAITING_LAYER_DECISION,
        workflow_stage="awaiting_layer_decision",
        workflow=workflow,
        current_task="Waiting for operator decision",
        next_task="Select a device to discover the next network, continue a discovered branch, or finish Phase 2",
        error=None,
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [_asset_ip(host) for host in workflow.get("asset_inventory") or []],
            "internal_host_inventory": workflow.get("asset_inventory") or [],
        },
    )
    scan_store.audit_event(
        scan_id,
        "system",
        "discovery_layer_enumerated",
        {
            "segment_id": segment.get("segment_id"),
            "network": segment.get("network"),
            "host_observation_count": len(hosts),
            "retained_inventory_count": len(workflow.get("asset_inventory") or []),
            "scope_kind": segment.get("scope_kind"),
        },
    )
    scan_store.persist(scan_id)


def run_discovery_pipeline(scan_id: str, external_target: str) -> None:
    """Validate the entry IP, enumerate its connected local subnet, then pause.

    Phase 2 uses two deliberately separate discovery mechanisms:

    * local subnet discovery is derived from the scanner interface address and
      prefix that contains the operator-supplied entry IP; and
    * continuation discovery starts only after the operator selects a retained
      discovered device, then collects bounded observable network evidence for
      explicit network prefixes beyond the current subnet.

    No hidden RFC1918 subnet is guessed. A continuation branch is created only
    when an explicit network prefix is retained from observable evidence.
    """

    try:
        tasks = [
            "Phase 1 — Entry Address Validation",
            "Phase 1 — Entry Reachability Evidence",
            "Phase 1 — Local Observation Snapshot",
            "Phase 2 — Initial Local Layer Enumeration",
        ]
        scan_store.init_tasks(scan_id, tasks, phase="discovery")
        scan_store.update(scan_id, status=scan_store.STATUS_ENTRY_DISCOVERY, workflow_stage="entry_discovery")

        scan_store.set_task(scan_id, tasks[0], scan_store.STATUS_RUNNING)
        entry_ip = validate_external_target(external_target)
        from scanners.enterprise_readiness import validate_scope
        validate_scope([entry_ip], entry_ip)
        scan_store.set_task(scan_id, tasks[0], scan_store.STATUS_SUCCESS, summary=f"Validated authorised entry address {entry_ip}")

        scan_store.set_task(scan_id, tasks[1], scan_store.STATUS_RUNNING)
        entry_result = check_external_reachability(scan_id, entry_ip)
        scan_store.set_task(
            scan_id,
            tasks[1],
            scan_store.STATUS_SUCCESS if entry_result.get("reachable") else scan_store.STATUS_EMPTY,
            summary=str(entry_result.get("statement") or "Entry evidence retained"),
        )

        scan_store.set_task(scan_id, tasks[2], scan_store.STATUS_RUNNING)
        snapshot = collect_local_observation_snapshot(scan_id, "Phase 1")
        local_scope = _local_connected_scope_for_entry(snapshot, entry_ip)
        snapshot_summary = "Captured local interface/neighbour observations; kernel routes are not used for Phase 2 discovery"
        if local_scope and local_scope.get("scope_allowed"):
            snapshot_summary += (
                f"; entry address belongs to directly connected {local_scope.get('network')} "
                f"on {local_scope.get('interface')}"
            )
        elif local_scope:
            snapshot_summary += (
                f"; connected network {local_scope.get('network')} was observed but is outside the configured engagement scope"
            )
        scan_store.set_task(
            scan_id,
            tasks[2],
            scan_store.STATUS_SUCCESS,
            summary=snapshot_summary,
        )

        context = {
            "entry_target": entry_ip,
            "interface": str((local_scope or {}).get("interface") or ""),
            "scanner_ip": str((local_scope or {}).get("scanner_ip") or ""),
            "gateway": "",
            "route_table": "",
            "route_type": "local_interface" if local_scope else "",
            "route": {},
            "matched_route": {},
            "matched_network": str((local_scope or {}).get("network") or ""),
            "snapshot": snapshot,
            "access_mode": "directly_connected" if local_scope else "entry_target",
        }
        entry_segment = _segment_from_entry(context, entry_result)
        entry_segment["access_mode"] = "directly_connected" if local_scope else "entry_target"
        entry_segment["access_transport"] = "direct"
        entry_segment["layer2_connected"] = bool(local_scope)
        entry_segment["route_table"] = ""
        entry_segment["route_type"] = ""
        entry_segment["route"] = {}
        entry_segment["evidence"] = [
            {"type": "entry_reachability", **entry_result},
            {
                "type": "discovery_architecture",
                "local_network_source": "scanner_interface_address",
                "continuation_network_source": "selected_device_observable_evidence",
                "kernel_route_discovery": False,
            },
        ]
        entry_hosts, entry_execution = discover_host_scope(entry_segment, entry_result)
        entry_segment["hosts"] = entry_hosts
        entry_segment["discovery_execution"] = entry_execution
        entry_segment["last_enumerated_at"] = scan_store.now()

        workflow = {
            "mode": "operator_controlled_topology_discovery",
            "continuous": False,
            "discovery_source": "local_interface_then_selected_device_evidence",
            "local_network_discovery": True,
            "topology_continuation_discovery": True,
            "kernel_route_discovery": False,
            "entry_target": entry_ip,
            "external_target": entry_ip,
            "entry_result": entry_result,
            "entry_context": {
                "entry_target": entry_ip,
                "access_mode": "directly_connected" if local_scope else "entry_target",
                "interface": str((local_scope or {}).get("interface") or ""),
                "scanner_ip": str((local_scope or {}).get("scanner_ip") or ""),
                "matched_network": str((local_scope or {}).get("network") or ""),
                "evidence_source": str((local_scope or {}).get("evidence_source") or ""),
            },
            "local_connected_scope": dict(local_scope or {}),
            "discovery_stages": {
                "local_subnet": "interface_address_prefix",
                "topology_continuation": "operator_selected_device_observable_evidence",
            },
            "segments": {entry_segment["segment_id"]: entry_segment},
            "paths": {},
            "topology_observations": [],
            "segment_order": [entry_segment["segment_id"]],
            "visited_segment_ids": [entry_segment["segment_id"]],
            "pending_path_ids": [],
            "current_segment_id": entry_segment["segment_id"],
            "operator_decisions": [],
            "assessment_targets": [],
            "assessment_target": None,
            "asset_inventory": [],
            "phase_results": {"assessment": {"status": "not_started", "targets": []}},
            # Compatibility fields intentionally remain empty. They are not a
            # source for topology-driven discovery.
            "baseline_route_signatures": [],
            "baseline_route_snapshot": [],
            "last_route_signatures": [],
            "route_observations": [],
            "authorized_route_signatures": [],
            "authorized_route_networks": [],
            "authorized_route_records": {},
        }
        _accumulate_assets(workflow, entry_hosts, segment=entry_segment)

        # If the entry target is on one of Kali's directly connected,
        # authorised interface networks, enumerate that subnet first.
        # This requires no router/firewall credential profile because no hidden
        # topology is being requested yet.
        if local_scope and local_scope.get("scope_allowed"):
            local_segment = _segment_from_local_connected_scope(
                local_scope, entry_ip=entry_ip, layer_index=1
            )
            workflow.setdefault("segments", {})[local_segment["segment_id"]] = local_segment
            workflow["current_segment_id"] = local_segment["segment_id"]
            workflow.setdefault("segment_order", []).append(local_segment["segment_id"])
            workflow.setdefault("visited_segment_ids", []).append(local_segment["segment_id"])
            workflow.setdefault("discovery_events", []).append(
                {
                    "event": "local_connected_subnet_identified",
                    "network": local_segment.get("network"),
                    "interface": local_segment.get("interface"),
                    "scanner_ip": local_segment.get("source_address"),
                    "entry_target": entry_ip,
                    "source": "scanner_interface_address",
                    "timestamp": scan_store.now(),
                }
            )
            scan_store.update(
                scan_id,
                workflow=workflow,
                status=scan_store.STATUS_LAYER_ENUMERATION,
                workflow_stage="local_subnet_enumeration",
            )
            _enumerate_and_pause(scan_id, workflow, local_segment, snapshot, task_name=tasks[3])
            return

        # Safe fallback when the entry address is not inside an authorised
        # directly connected interface subnet. Retain the host-only scope and
        # wait for the operator instead of guessing a surrounding network.
        scan_store.update(
            scan_id,
            workflow=workflow,
            status=scan_store.STATUS_LAYER_ENUMERATION,
            workflow_stage="layer_enumeration",
        )
        _enumerate_and_pause(scan_id, workflow, entry_segment, snapshot, task_name=tasks[3])
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)


def retry_current_layer(scan_id: str) -> None:
    """Repeat enumeration for the current approved layer without route discovery."""

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_LAYER_ENUMERATION:
            raise DiscoveryWorkflowError("The mission is not in a layer-retry state.")
        workflow = dict(current.get("workflow") or {})
        segment = dict((workflow.get("segments") or {}).get(workflow.get("current_segment_id")) or {})
        if not segment:
            raise DiscoveryWorkflowError("The current layer record is unavailable.")
        workflow.setdefault("operator_decisions", []).append(
            {
                "decision": "retry_layer",
                "segment_id": segment.get("segment_id"),
                "timestamp": scan_store.now(),
            }
        )
        task_name = f"Phase 2 — Layer {int(segment.get('layer_index') or 0)} Retry"
        scan_store.append_tasks(scan_id, [task_name], phase="discovery")
        snapshot = collect_local_observation_snapshot(scan_id, "Phase 2 retry")
        _enumerate_and_pause(scan_id, workflow, segment, snapshot, task_name=task_name)
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)


def revisit_discovered_segment(scan_id: str, segment_id: str) -> None:
    """Return to a previously enumerated branch without consulting kernel routes."""

    try:
        current = scan_store.load(scan_id) or {}
        workflow = dict(current.get("workflow") or {})
        segment = dict((workflow.get("segments") or {}).get(str(segment_id)) or {})
        if not segment or str(segment_id) not in set(workflow.get("visited_segment_ids") or []):
            raise DiscoveryWorkflowError("The selected discovery layer is not part of this mission history.")
        workflow["current_segment_id"] = str(segment_id)
        workflow["topology_continuation"] = {
            "selected_device_ip": "",
            "state": "awaiting_device_selection",
            "profile_ref": "",
            "message": "Returned to this discovery layer. Select a device here to continue deeper.",
            "updated_at": scan_store.now(),
        }
        workflow.setdefault("operator_decisions", []).append(
            {"decision": "revisit_layer", "segment_id": segment_id, "timestamp": scan_store.now()}
        )
        _set_current_aliases(workflow)
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_AWAITING_LAYER_DECISION,
            workflow_stage="awaiting_layer_decision",
            workflow=workflow,
            current_task="Waiting for operator decision",
            next_task="Continue from this previously discovered layer or finish Phase 2",
            error=None,
            results={
                "workflow": workflow,
                "phase_results": workflow.get("phase_results") or {},
                "hosts": [_asset_ip(host) for host in workflow.get("asset_inventory") or []],
                "internal_host_inventory": workflow.get("asset_inventory") or [],
            },
        )
        scan_store.persist(scan_id)
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)


def prepare_assessment_from_current_layer(
    scan_id: str,
    *,
    allow_inconclusive_operator_targets: bool = False,
) -> dict[str, Any]:
    """Finish Phase 2 and expose every retained eligible asset to Phase 3."""

    current = scan_store.load(scan_id) or {}
    if str(current.get("status") or "") != scan_store.STATUS_AWAITING_LAYER_DECISION:
        raise DiscoveryWorkflowError("The mission is not waiting for the operator to finish Phase 2.")
    workflow = dict(current.get("workflow") or {})
    segments = {str(key): dict(value) for key, value in (workflow.get("segments") or {}).items()}
    if not workflow.get("asset_inventory"):
        workflow["asset_inventory"] = []
        for segment_id in workflow.get("segment_order") or []:
            segment = segments.get(str(segment_id)) or {}
            _accumulate_assets(workflow, segment.get("hosts") or [], segment=segment)

    promoted_targets: list[str] = []
    if allow_inconclusive_operator_targets:
        for segment in segments.values():
            for host in segment.get("hosts") or []:
                address = _asset_ip(host)
                if not address or host.get("is_scanner"):
                    continue
                if str(host.get("record_type") or "") != "entry_target" or str(host.get("origin") or "") != "operator_supplied":
                    continue
                if host.get("selectable"):
                    continue
                host["selectable"] = True
                host["assessment_override"] = "operator_authorized_inconclusive_reachability"
                host["assessment_discovery_bypass"] = True
                host["assessment_override_at"] = scan_store.now()
                promoted_targets.append(address)
            segments[str(segment.get("segment_id") or "")] = segment
        workflow["segments"] = segments
        # Rebuild accumulated inventory so the promoted entry target is reflected.
        workflow["asset_inventory"] = []
        for segment_id in workflow.get("segment_order") or []:
            segment = workflow.get("segments", {}).get(segment_id) or {}
            _accumulate_assets(workflow, segment.get("hosts") or [], segment=segment)

    selectable = _selectable_inventory(workflow)
    if not selectable:
        raise DiscoveryWorkflowError(
            "No selectable target has been retained. Continue discovery, retry the current layer, or explicitly allow the inconclusive Phase 1 entry target."
        )
    phase2_stop = _phase2_stop_summary(workflow)
    workflow["phase2_stop"] = phase2_stop
    workflow["phase2_stop_reason"] = str(phase2_stop.get("message") or "")
    workflow["phase2_finished"] = True
    workflow["phase2_finished_at"] = scan_store.now()
    workflow.setdefault("operator_decisions", []).append(
        {
            "decision": "finish_phase2",
            "segment_id": workflow.get("current_segment_id"),
            "retained_target_count": len(selectable),
            "promoted_targets": promoted_targets,
            "reason_code": phase2_stop.get("code"),
            "reason": phase2_stop.get("message"),
            "timestamp": scan_store.now(),
        }
    )
    assessment = dict((workflow.get("phase_results") or {}).get("assessment") or {})
    assessment.update(
        {
            "status": "awaiting_configuration",
            "targets": [],
            "segment_id": workflow.get("current_segment_id"),
            "inventory_scope": "all_discovered_assets",
            "eligible_target_count": len(selectable),
            "inconclusive_reachability_override": bool(promoted_targets),
            "override_targets": promoted_targets,
        }
    )
    workflow.setdefault("phase_results", {})["assessment"] = assessment
    _set_current_aliases(workflow)
    transitioned = scan_store.transition_status(
        scan_id,
        {scan_store.STATUS_AWAITING_LAYER_DECISION},
        scan_store.STATUS_AWAITING_CONFIGURATION,
        workflow_stage="awaiting_assessment_configuration",
        workflow=workflow,
        current_task="Waiting for Phase 3 configuration",
        next_task="Select one or more retained targets and configure the vulnerability assessment",
        error=None,
        results={
            "workflow": workflow,
            "phase_results": workflow.get("phase_results") or {},
            "hosts": [_asset_ip(host) for host in workflow.get("asset_inventory") or []],
            "internal_host_inventory": workflow.get("asset_inventory") or [],
        },
    )
    if not transitioned:
        raise DiscoveryWorkflowError("The Phase 2 finish decision was already submitted.")
    scan_store.audit_event(
        scan_id,
        "operator",
        "phase2_finished_for_assessment",
        {"eligible_target_count": len(selectable), "current_segment_id": workflow.get("current_segment_id")},
    )
    scan_store.persist(scan_id)
    return workflow
