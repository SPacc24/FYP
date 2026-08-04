"""External-to-internal discovery workflow used before the existing assessment.

This module owns only Phase 1 and Phase 2.  It does not perform service
fingerprinting, CVE correlation, exploitation, AI planning, Caldera execution,
or any other teammate-owned assessment work.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from config import Config
from storage import scan_store

from . import command_builders


DISCOVERY_TASKS = [
    "Phase 1 — External Target Validation",
    "Phase 1 — External Reachability",
    "Phase 1 — Network Route Inspection",
    "Phase 1 — Internal Subnet Identification",
    "Phase 2 — Internal Host Discovery",
    "Phase 2 — Host Inventory Assembly",
]

_TUNNEL_INTERFACE_RE = re.compile(r"^(tun|tap|wg|ppp|tailscale|zt|vpn)", re.I)


class DiscoveryWorkflowError(RuntimeError):
    """Raised when the discovery workflow cannot safely continue."""


def validate_external_target(value: str) -> str:
    """Return one canonical IP address and reject ranges/CIDRs/hostnames."""

    raw = str(value or "").strip()
    if not raw:
        raise DiscoveryWorkflowError("An external IP address is required.")
    if any(token in raw for token in ("/", ",", " ", "-")):
        raise DiscoveryWorkflowError(
            "Phase 1 accepts one external IP address only, not a CIDR or range."
        )
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise DiscoveryWorkflowError("The external target is not a valid IP address.") from exc


def _run_command(
    scan_id: str,
    command: list[str],
    purpose: str,
    *,
    timeout: int = 30,
    output_file: Path | None = None,
) -> dict[str, Any]:
    """Run a bounded command and retain its exact command/evidence."""

    rendered = " ".join(command)
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
        )
        return {
            "success": success,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": rendered,
            "output_file": str(output_file or ""),
        }
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(
            part for part in (str(exc.stdout or ""), str(exc.stderr or "")) if part
        )
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
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "command": rendered,
            "output_file": str(output_file or ""),
            "timed_out": True,
        }
    except OSError as exc:
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
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": rendered,
            "output_file": str(output_file or ""),
        }


def _json_command(scan_id: str, command: list[str], purpose: str) -> list[dict[str, Any]]:
    result = _run_command(scan_id, command, purpose, timeout=20)
    if not result.get("success"):
        raise DiscoveryWorkflowError(
            f"Could not inspect the scanner network configuration: {purpose}."
        )
    try:
        payload = json.loads(result.get("stdout") or "[]")
    except json.JSONDecodeError as exc:
        raise DiscoveryWorkflowError(
            f"The scanner returned invalid network configuration data for: {purpose}."
        ) from exc
    if not isinstance(payload, list):
        raise DiscoveryWorkflowError(
            f"Unexpected network configuration data for: {purpose}."
        )
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
    """Use low-impact host-discovery probes to establish external reachability."""

    evidence: list[dict[str, Any]] = []
    reachable = False

    ping = shutil.which("ping")
    if ping:
        ping_cmd = [ping, "-c", "1", "-W", "2", external_ip]
        ping_result = _run_command(
            scan_id,
            ping_cmd,
            "Phase 1 ICMP reachability evidence",
            timeout=8,
        )
        ping_up = bool(ping_result.get("success"))
        reachable = reachable or ping_up
        evidence.append({
            "method": "icmp_echo",
            "reachable": ping_up,
            "command": ping_result.get("command"),
            "returncode": ping_result.get("returncode"),
        })

    nmap = shutil.which("nmap")
    if nmap:
        output_path = scan_store.scan_path(f"{scan_id}_phase1_external.xml")
        nmap_result = _run_command(
            scan_id,
            command_builders.nmap_external_reachability(nmap, external_ip, output_path),
            "Phase 1 Nmap host-discovery evidence",
            timeout=30,
            output_file=output_path,
        )
        nmap_up = _host_is_up_from_nmap_xml(output_path)
        reachable = reachable or nmap_up
        evidence.append({
            "method": "nmap_host_discovery",
            "reachable": nmap_up,
            "command": nmap_result.get("command"),
            "returncode": nmap_result.get("returncode"),
            "evidence_file": str(output_path),
        })

    if not evidence:
        raise DiscoveryWorkflowError(
            "Neither ping nor Nmap is available to validate external reachability."
        )

    return {
        "target": external_ip,
        "reachable": reachable,
        "evidence": evidence,
        "statement": (
            "The external network entry point is reachable."
            if reachable
            else "No external reachability response was observed."
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


def _usable_internal_network(network: ipaddress._BaseNetwork) -> bool:
    """Return whether a route-derived network is safe for automatic inventory.

    The decision is based on address properties and the configured expansion
    limit. No environment-specific subnet, target, interface, or product value
    is embedded here.
    """

    if network.prefixlen == network.max_prefixlen:
        return False
    if network.is_loopback or network.is_link_local or network.is_multicast:
        return False
    if not network.is_private:
        return False
    usable_hosts = max(
        0,
        int(network.num_addresses) - (2 if network.version == 4 else 0),
    )
    return usable_hosts <= int(getattr(Config, "MAX_EXPANDED_TARGETS", 256))


def _interface_networks(
    address_rows: Iterable[dict[str, Any]],
    interface: str,
    version: int,
) -> list[ipaddress._BaseNetwork]:
    networks: set[ipaddress._BaseNetwork] = set()
    for interface_row in address_rows:
        if str(interface_row.get("ifname") or "") != interface:
            continue
        for address in interface_row.get("addr_info") or []:
            if not isinstance(address, dict):
                continue
            family = str(address.get("family") or "")
            if (version == 4 and family != "inet") or (
                version == 6 and family != "inet6"
            ):
                continue
            local = str(address.get("local") or "").strip()
            prefix = address.get("prefixlen")
            try:
                network = ipaddress.ip_network(f"{local}/{int(prefix)}", strict=False)
            except (ValueError, TypeError):
                continue
            if _usable_internal_network(network):
                networks.add(network)
    return sorted(networks, key=lambda item: (-item.prefixlen, str(item.network_address)))


def _candidate_network_records(
    external_ip: ipaddress._BaseAddress,
    interface: str,
    route_rows: Iterable[dict[str, Any]],
    address_rows: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Build evidence-backed internal-subnet candidates.

    A candidate must have a concrete relationship to the route used for this
    mission. A default Internet route alone never authorises scanning the
    interface's local network. This avoids hardcoded allow/deny CIDRs while
    preventing an unrelated management, NAT, or home subnet from being selected.
    """

    route_rows = list(route_rows or [])
    address_rows = list(address_rows or [])
    matching_routes: list[tuple[int, dict[str, Any], ipaddress._BaseNetwork]] = []
    for route in route_rows:
        network = _route_network(route, external_ip.version)
        if network is None or external_ip not in network:
            continue
        matching_routes.append((network.prefixlen, route, network))
    matching_routes.sort(key=lambda item: item[0], reverse=True)

    matched_route = matching_routes[0][1] if matching_routes else None
    matched_network = matching_routes[0][2] if matching_routes else None
    matched_is_specific = bool(matched_network and matched_network.prefixlen > 0)
    matched_gateway = str((matched_route or {}).get("gateway") or "").strip()
    tunnel_interfaces = {
        str(row.get("dev") or "").strip()
        for row in route_rows
        if _TUNNEL_INTERFACE_RE.search(str(row.get("dev") or "").strip())
    }
    tunnel_interfaces.update(
        str(row.get("ifname") or "").strip()
        for row in address_rows
        if _TUNNEL_INTERFACE_RE.search(str(row.get("ifname") or "").strip())
    )
    tunnel_interfaces.discard("")
    tunnel_interface = interface in tunnel_interfaces
    interface_networks = _interface_networks(address_rows, interface, external_ip.version)
    external_direct_networks = {
        network for network in interface_networks if external_ip in network
    }

    records_by_subnet: dict[str, dict[str, Any]] = {}
    relation_priority = {
        "external_target_on_connected_subnet": 0,
        "specific_route_via_external_target": 1,
        "tunnel_specific_route": 2,
        "shared_specific_route_gateway": 3,
        "tunnel_connected_subnet": 4,
    }

    def add_candidate(
        network: ipaddress._BaseNetwork,
        *,
        relation: str,
        source: str,
        route: dict[str, Any] | None = None,
        candidate_interface: str = "",
    ) -> None:
        if not _usable_internal_network(network):
            return
        route = dict(route or {})
        route_interface = str(candidate_interface or route.get("dev") or interface).strip()
        gateway = str(route.get("gateway") or "").strip()
        access_mode = (
            "directly_connected"
            if relation == "external_target_on_connected_subnet"
            else "tunnel"
            if relation.startswith("tunnel_") or route_interface in tunnel_interfaces
            else "routed"
        )
        record = {
            "subnet": str(network),
            "interface": route_interface,
            "gateway": gateway,
            "access_mode": access_mode,
            "relationship": relation,
            "evidence_source": source,
            "route": route,
        }
        existing = records_by_subnet.get(str(network))
        if existing is None or relation_priority.get(relation, 99) < relation_priority.get(
            str(existing.get("relationship") or ""), 99
        ):
            records_by_subnet[str(network)] = record

    # A target already inside an interface's connected network is a valid direct
    # test case. It is labelled accurately rather than presented as a routed hop.
    for network in external_direct_networks:
        add_candidate(
            network,
            relation="external_target_on_connected_subnet",
            source="interface_address_and_route_get",
            route=matched_route,
        )

    # An already-established tunnel may carry the internal routes even when
    # the external VPN/entry endpoint itself is reached through a separate
    # management interface. Every bounded private tunnel route is retained as
    # a candidate; multiple candidates require operator selection.
    for tunnel_dev in sorted(tunnel_interfaces):
        for network in _interface_networks(address_rows, tunnel_dev, external_ip.version):
            if not (tunnel_dev == interface and network in external_direct_networks):
                add_candidate(
                    network,
                    relation="tunnel_connected_subnet",
                    source="tunnel_interface_address",
                    candidate_interface=tunnel_dev,
                )
        for route in route_rows:
            if str(route.get("dev") or "").strip() != tunnel_dev:
                continue
            network = _route_network(route, external_ip.version)
            if network is None or network.prefixlen == 0 or not _usable_internal_network(network):
                continue
            add_candidate(
                network,
                relation="tunnel_specific_route",
                source="specific_route_on_available_tunnel",
                route=route,
                candidate_interface=tunnel_dev,
            )

    for route in route_rows:
        if str(route.get("dev") or "") != interface:
            continue
        network = _route_network(route, external_ip.version)
        if network is None or network.prefixlen == 0 or not _usable_internal_network(network):
            continue
        gateway = str(route.get("gateway") or "").strip()

        if external_ip in network:
            add_candidate(
                network,
                relation="external_target_on_connected_subnet",
                source="specific_route_contains_external_target",
                route=route,
            )
        elif gateway and gateway == str(external_ip):
            add_candidate(
                network,
                relation="specific_route_via_external_target",
                source="specific_route_gateway_matches_external_target",
                route=route,
            )
        elif tunnel_interface:
            add_candidate(
                network,
                relation="tunnel_specific_route",
                source="specific_route_on_selected_tunnel",
                route=route,
            )
        elif matched_is_specific and matched_gateway and gateway == matched_gateway:
            # A non-default route to the supplied target and a private route using
            # the same gateway form a concrete routing relationship. A default
            # route never satisfies this condition.
            add_candidate(
                network,
                relation="shared_specific_route_gateway",
                source="specific_route_shared_gateway",
                route=route,
            )

    ordered = sorted(
        records_by_subnet.values(),
        key=lambda item: (
            relation_priority.get(str(item.get("relationship") or ""), 99),
            -ipaddress.ip_network(str(item["subnet"]), strict=False).prefixlen,
            str(item["subnet"]),
        ),
    )
    return ordered, matched_route


def _candidate_networks(
    external_ip: ipaddress._BaseAddress,
    interface: str,
    route_rows: Iterable[dict[str, Any]],
    address_rows: Iterable[dict[str, Any]],
) -> tuple[list[ipaddress._BaseNetwork], dict[str, Any] | None]:
    """Compatibility wrapper returning only network objects for callers/tests."""

    records, matched_route = _candidate_network_records(
        external_ip,
        interface,
        route_rows,
        address_rows,
    )
    return [ipaddress.ip_network(item["subnet"], strict=False) for item in records], matched_route


def discover_network_context(scan_id: str, external_ip: str) -> dict[str, Any]:
    """Inspect routes and return every safe, evidence-backed subnet candidate."""

    ip_tool = shutil.which("ip")
    if not ip_tool:
        raise DiscoveryWorkflowError(
            "The Linux ip command is required to discover the routed internal subnet."
        )

    route_get = _json_command(
        scan_id,
        [ip_tool, "-j", "route", "get", external_ip],
        "Phase 1 route selection inspection",
    )
    addresses = _json_command(
        scan_id,
        [ip_tool, "-j", "addr", "show"],
        "Phase 1 interface address inspection",
    )
    routes = _json_command(
        scan_id,
        [ip_tool, "-j", "route", "show"],
        "Phase 1 connected route inspection",
    )

    selected_route = route_get[0] if route_get else {}
    interface = str(selected_route.get("dev") or "").strip()
    source_ip = str(selected_route.get("prefsrc") or selected_route.get("src") or "").strip()
    gateway = str(selected_route.get("gateway") or "").strip()
    if not interface:
        raise DiscoveryWorkflowError(
            "No scanner interface is routed to the supplied external IP address."
        )

    external_address = ipaddress.ip_address(external_ip)
    candidate_records, matched_route = _candidate_network_records(
        external_address,
        interface,
        routes,
        addresses,
    )
    if not candidate_records:
        raise DiscoveryWorkflowError(
            "The external address is reachable, but no internal assessment subnet "
            "with a specific route relationship was identified. Connect the "
            "authorised VPN, assessment adapter, or routed pivot before continuing."
        )

    selected_record = candidate_records[0] if len(candidate_records) == 1 else None
    selected_interface = str((selected_record or {}).get("interface") or interface)
    selected_gateway = str((selected_record or {}).get("gateway") or gateway)
    selected_source_ip = source_ip
    if selected_interface != interface:
        candidate_source_ip = ""
        for interface_row in addresses:
            if str(interface_row.get("ifname") or "") != selected_interface:
                continue
            for address in interface_row.get("addr_info") or []:
                family = str(address.get("family") or "")
                if (external_address.version == 4 and family == "inet") or (external_address.version == 6 and family == "inet6"):
                    candidate_source_ip = str(address.get("local") or "")
                    if candidate_source_ip:
                        break
            if candidate_source_ip:
                break
        selected_source_ip = candidate_source_ip or source_ip
    return {
        "interface": selected_interface,
        "scanner_ip": selected_source_ip,
        "gateway": selected_gateway,
        "external_route_interface": interface,
        "external_route_source_ip": source_ip,
        "internal_subnet": str((selected_record or {}).get("subnet") or ""),
        "access_mode": str((selected_record or {}).get("access_mode") or "selection_required"),
        "candidate_subnets": [str(item["subnet"]) for item in candidate_records],
        "subnet_candidates": candidate_records,
        "route": selected_route,
        "matched_route": matched_route or {},
        "selection_rule": "route_relationship_and_bounded_private_scope",
    }


def _selected_context(context: dict[str, Any], selected_subnet: str) -> dict[str, Any]:
    """Validate a subnet against persisted candidates and return selected context."""

    candidate_records = [
        item
        for item in context.get("subnet_candidates") or []
        if isinstance(item, dict) and item.get("subnet")
    ]
    match = next(
        (item for item in candidate_records if str(item.get("subnet")) == selected_subnet),
        None,
    )
    if match is None:
        raise DiscoveryWorkflowError(
            "The selected subnet was not one of the route-derived Phase 1 candidates."
        )
    selected = dict(context)
    selected["internal_subnet"] = str(match["subnet"])
    selected["access_mode"] = str(match.get("access_mode") or "routed")
    selected["interface"] = str(match.get("interface") or selected.get("interface") or "")
    selected["gateway"] = str(match.get("gateway") or selected.get("gateway") or "")
    selected["selected_subnet_evidence"] = dict(match)
    return selected


def _parse_host_inventory(
    path: Path,
    *,
    scanner_ip: str = "",
    gateway: str = "",
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
            addr = str(address.attrib.get("addr") or "")
            addr_type = str(address.attrib.get("addrtype") or "")
            if addr_type in {"ipv4", "ipv6"} and not primary_ip:
                primary_ip = addr
            elif addr_type == "mac":
                mac = addr
                vendor = str(address.attrib.get("vendor") or "")
        if not primary_ip or primary_ip in seen:
            continue
        seen.add(primary_ip)
        hostname_nodes = host.findall("hostnames/hostname")
        hostname = next(
            (
                str(node.attrib.get("name") or "")
                for node in hostname_nodes
                if node.attrib.get("name")
            ),
            "",
        )
        role = "gateway" if gateway and primary_ip == gateway else "host"
        is_scanner = bool(scanner_ip and primary_ip == scanner_ip)
        hosts.append({
            "ip": primary_ip,
            "address": primary_ip,
            "status": "up",
            "hostname": hostname,
            "mac": mac,
            "mac_vendor": vendor,
            "role": "scanner" if is_scanner else role,
            "is_scanner": is_scanner,
            "selectable": not is_scanner,
            "discovered_by": ["nmap_host_discovery"],
            "evidence_file": str(path),
        })

    def _address_key(item: dict[str, Any]) -> tuple[int, int]:
        address = ipaddress.ip_address(item["ip"])
        return (address.version, int(address))

    return sorted(hosts, key=_address_key)


def discover_internal_hosts(
    scan_id: str,
    subnet: str,
    *,
    interface: str,
    scanner_ip: str = "",
    gateway: str = "",
) -> list[dict[str, Any]]:
    """Perform Phase 2 inventory discovery only; no service/CVE assessment."""

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise DiscoveryWorkflowError("The discovered internal subnet is invalid.") from exc
    if not _usable_internal_network(network):
        raise DiscoveryWorkflowError(
            "The discovered internal subnet exceeds the configured automatic host-discovery limit."
        )

    nmap = shutil.which("nmap")
    if not nmap:
        raise DiscoveryWorkflowError(
            "Nmap is required for automatic internal host discovery."
        )

    output_path = scan_store.scan_path(f"{scan_id}_phase2_internal_hosts.xml")
    result = _run_command(
        scan_id,
        command_builders.nmap_internal_host_discovery(
            nmap,
            str(network),
            output_path,
            interface=interface,
        ),
        "Phase 2 internal subnet host discovery",
        timeout=600,
        output_file=output_path,
    )
    if not output_path.exists():
        raise DiscoveryWorkflowError(
            "Internal host discovery did not produce an evidence file."
        )
    hosts = _parse_host_inventory(
        output_path,
        scanner_ip=scanner_ip,
        gateway=gateway,
    )
    if not result.get("success") and not hosts:
        raise DiscoveryWorkflowError(
            "Internal host discovery failed before any host evidence was retained."
        )
    return hosts


def _phase_result(
    *,
    external: dict[str, Any],
    context: dict[str, Any],
    hosts: list[dict[str, Any]],
) -> dict[str, Any]:
    selectable = [host for host in hosts if host.get("selectable")]
    return {
        "external": {
            "status": "completed",
            **external,
        },
        "internal": {
            "status": "completed",
            "subnet": context.get("internal_subnet"),
            "interface": context.get("interface"),
            "scanner_ip": context.get("scanner_ip"),
            "gateway": context.get("gateway"),
            "access_mode": context.get("access_mode"),
            "host_count": len(hosts),
            "selectable_host_count": len(selectable),
            "hosts": hosts,
            "statement": f"{len(hosts)} live device(s) were observed in the selected subnet.",
        },
        "assessment": {
            "status": "awaiting_configuration",
            "targets": [],
        },
    }


def _persist_subnet_selection_pause(
    scan_id: str,
    *,
    external_ip: str,
    external_result: dict[str, Any],
    context: dict[str, Any],
) -> None:
    phase_results = {
        "external": {"status": "completed", **external_result},
        "internal": {
            "status": "awaiting_subnet_selection",
            "candidate_subnets": context.get("subnet_candidates") or [],
            "interface": context.get("interface"),
            "scanner_ip": context.get("scanner_ip"),
        },
        "assessment": {"status": "not_started", "targets": []},
    }
    workflow = {
        "mode": "external_internal_assessment",
        "continuous": True,
        "external_target": external_ip,
        "network_context": context,
        "internal_subnet": "",
        "discovered_hosts": [],
        "assessment_targets": [],
        "assessment_target": None,
        "phase_results": phase_results,
    }
    scan_store.set_task(
        scan_id,
        DISCOVERY_TASKS[3],
        scan_store.STATUS_QUEUED,
        summary="Multiple eligible routed subnets require operator selection",
    )
    scan_store.update(
        scan_id,
        target=external_ip,
        status=scan_store.STATUS_AWAITING_SUBNET_SELECTION,
        workflow_stage="awaiting_subnet_selection",
        workflow=workflow,
        current_task="Waiting for internal subnet selection",
        next_task="Phase 2 internal host discovery",
        results={
            "workflow": workflow,
            "phase_results": phase_results,
            "hosts": [],
            "internal_host_inventory": [],
        },
    )
    scan_store.audit_event(
        scan_id,
        "system",
        "multiple_internal_subnets_detected",
        {
            "external_target": external_ip,
            "candidate_subnets": context.get("candidate_subnets") or [],
        },
    )
    scan_store.persist(scan_id)


def _complete_internal_discovery(
    scan_id: str,
    *,
    external_ip: str,
    external_result: dict[str, Any],
    context: dict[str, Any],
) -> None:
    internal_subnet = str(context.get("internal_subnet") or "")
    if not internal_subnet:
        raise DiscoveryWorkflowError("No internal subnet was selected for Phase 2.")

    scan_store.set_task(
        scan_id,
        DISCOVERY_TASKS[3],
        scan_store.STATUS_SUCCESS,
        summary=f"Selected internal subnet {internal_subnet}",
    )
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_INTERNAL_DISCOVERY,
        workflow_stage="internal",
    )

    task = DISCOVERY_TASKS[4]
    scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
    hosts = discover_internal_hosts(
        scan_id,
        internal_subnet,
        interface=str(context.get("interface") or ""),
        scanner_ip=str(context.get("scanner_ip") or ""),
        gateway=str(context.get("gateway") or ""),
    )
    scan_store.set_task(
        scan_id,
        task,
        scan_store.STATUS_SUCCESS if hosts else scan_store.STATUS_EMPTY,
        summary=f"Observed {len(hosts)} live host(s)",
    )

    task = DISCOVERY_TASKS[5]
    scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
    selectable_hosts = [host for host in hosts if host.get("selectable")]
    if not selectable_hosts:
        raise DiscoveryWorkflowError(
            "No selectable internal host was discovered. The scanner's own address is never offered as an assessment target."
        )
    scan_store.set_task(
        scan_id,
        task,
        scan_store.STATUS_SUCCESS,
        summary=f"{len(selectable_hosts)} host(s) available for Phase 3",
    )

    phase_results = _phase_result(
        external=external_result,
        context=context,
        hosts=hosts,
    )
    workflow = {
        "mode": "external_internal_assessment",
        "continuous": True,
        "external_target": external_ip,
        "network_context": context,
        "internal_subnet": internal_subnet,
        "access_mode": context.get("access_mode"),
        "discovered_hosts": hosts,
        "assessment_targets": [],
        "assessment_target": None,
        "phase_results": phase_results,
    }
    scan_store.update(
        scan_id,
        target=external_ip,
        status=scan_store.STATUS_AWAITING_CONFIGURATION,
        workflow_stage="awaiting_assessment_configuration",
        workflow=workflow,
        current_task="Waiting for Phase 3 configuration",
        next_task="Select one or more discovered hosts and configure the assessment",
        results={
            "workflow": workflow,
            "phase_results": phase_results,
            "hosts": [host.get("ip") for host in hosts],
            "internal_host_inventory": hosts,
        },
    )
    scan_store.audit_event(
        scan_id,
        "system",
        "internal_discovery_completed",
        {
            "external_target": external_ip,
            "internal_subnet": internal_subnet,
            "access_mode": context.get("access_mode"),
            "host_count": len(hosts),
            "selectable_host_count": len(selectable_hosts),
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
    scan_store.log(scan_id, f"Discovery workflow error: {message}", "ERROR")
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_FAILED,
        error=message,
        completed_at=scan_store.now(),
    )
    scan_store.persist(scan_id)


def continue_discovery_with_subnet(scan_id: str, selected_subnet: str) -> None:
    """Resume Phase 2 after the operator chooses one persisted candidate subnet."""

    try:
        current = scan_store.load(scan_id) or {}
        if str(current.get("status") or "") != scan_store.STATUS_INTERNAL_DISCOVERY:
            raise DiscoveryWorkflowError(
                "The mission is not in the internal-discovery state."
            )
        workflow = dict(current.get("workflow") or {})
        external_ip = validate_external_target(str(workflow.get("external_target") or ""))
        context = _selected_context(
            dict(workflow.get("network_context") or {}),
            str(selected_subnet or "").strip(),
        )
        external_result = dict(
            (workflow.get("phase_results") or {}).get("external") or {}
        )
        external_result.pop("status", None)
        _complete_internal_discovery(
            scan_id,
            external_ip=external_ip,
            external_result=external_result,
            context=context,
        )
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)


def run_discovery_pipeline(scan_id: str, external_target: str) -> None:
    """Run Phase 1, select/pause for a subnet, then build Phase 2 inventory."""

    try:
        scan_store.init_tasks(scan_id, DISCOVERY_TASKS, phase="discovery")
        scan_store.update(
            scan_id,
            status=scan_store.STATUS_EXTERNAL_DISCOVERY,
            workflow_stage="external",
        )

        task = DISCOVERY_TASKS[0]
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        external_ip = validate_external_target(external_target)
        scan_store.set_task(
            scan_id,
            task,
            scan_store.STATUS_SUCCESS,
            summary=f"Validated single external IP {external_ip}",
        )

        task = DISCOVERY_TASKS[1]
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        external_result = check_external_reachability(scan_id, external_ip)
        if not external_result.get("reachable"):
            raise DiscoveryWorkflowError(
                "The external IP did not respond to the configured reachability checks."
            )
        scan_store.set_task(
            scan_id,
            task,
            scan_store.STATUS_SUCCESS,
            summary="External network entry point is reachable",
        )

        task = DISCOVERY_TASKS[2]
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        context = discover_network_context(scan_id, external_ip)
        scan_store.set_task(
            scan_id,
            task,
            scan_store.STATUS_SUCCESS,
            summary=(
                f"Route uses {context.get('interface')}; "
                f"{len(context.get('subnet_candidates') or [])} eligible subnet(s)"
            ),
        )

        if len(context.get("subnet_candidates") or []) > 1:
            _persist_subnet_selection_pause(
                scan_id,
                external_ip=external_ip,
                external_result=external_result,
                context=context,
            )
            return

        selected_subnet = str(context.get("internal_subnet") or "")
        context = _selected_context(context, selected_subnet)
        _complete_internal_discovery(
            scan_id,
            external_ip=external_ip,
            external_result=external_result,
            context=context,
        )
    except Exception as exc:
        _record_discovery_failure(scan_id, exc)
