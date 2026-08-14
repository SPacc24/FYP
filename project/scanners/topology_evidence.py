"""Bounded, evidence-first topology discovery for Phase 2.

This module deliberately avoids device login, credential guessing, route injection,
or hidden-subnet guessing.  It collects only information observable from the
scanner's current vantage point and returns explicit evidence records that the
operator can review before any traversal attempt.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from config import Config
from storage import scan_store

from . import command_builders


def _passive_filter(device_ip: str, device_mac: str = "") -> str:
    """Return a capture filter scoped to the selected device.

    OSPF/RIP evidence is attributed only when the packet source is the selected
    IPv4 device.  LLDP/CDP evidence is included only when the selected host's
    MAC address is already retained, preventing unrelated control-plane frames
    from being assigned to the wrong device.
    """

    clauses = [
        f"(src host {device_ip} and (ip proto 89 or udp src port 520))",
    ]
    mac = str(device_mac or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        clauses.append(
            f"(ether src {mac} and (ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc))"
        )
    return " or ".join(clauses)

_CIDR_RE = re.compile(
    r"(?<![0-9.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}/(?:3[0-2]|[12]?\d))(?![0-9.])"
)
_IPV4_RE = re.compile(
    r"(?<![0-9.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![0-9.])"
)
_MASK_RE = re.compile(
    r"(?i)(?:network\s+mask|netmask|mask)\s*[:=]\s*((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
)
_LABELLED_IPV4_RE = re.compile(
    r"(?i)(?:link\s+state\s+id|network(?:\s+address)?|ip\s+address|address|router\s+interface\s+address)\s*[:=]\s*((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
)


class TopologyEvidenceError(RuntimeError):
    pass


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(material.encode('utf-8')).hexdigest()[:14]}"


def _run(
    scan_id: str,
    command: list[str],
    purpose: str,
    *,
    timeout: int,
    output_file: Path | None = None,
    interface: str = "",
    target: str = "",
) -> dict[str, Any]:
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
        output = stdout if stdout.strip() else stderr
        if output_file is not None:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            if not output_file.exists():
                output_file.write_text(output, encoding="utf-8")
        ended_at = scan_store.now()
        scan_store.log_command(
            scan_id,
            command=rendered,
            purpose=purpose,
            output=output,
            output_summary=(output.strip().splitlines() or ["No console output"])[0][:300],
            status="Completed" if completed.returncode == 0 else "Failed",
            exit_code=completed.returncode,
            output_file=str(output_file or ""),
            output_truncated=False,
            started_at=started_at,
            ended_at=ended_at,
            interface=interface,
            source_address="",
            segment_id="",
            target=target,
        )
        return {
            "success": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": rendered,
            "output_file": str(output_file or ""),
            "started_at": started_at,
            "ended_at": ended_at,
        }
    except subprocess.TimeoutExpired as exc:
        ended_at = scan_store.now()
        stdout = str(exc.stdout or "")
        stderr = str(exc.stderr or "")
        scan_store.log_command(
            scan_id,
            command=rendered,
            purpose=purpose,
            output="\n".join(part for part in (stdout, stderr) if part),
            output_summary=f"Timed out after {timeout} seconds",
            status="Timed Out",
            exit_code=-1,
            output_file=str(output_file or ""),
            output_truncated=False,
            started_at=started_at,
            ended_at=ended_at,
            interface=interface,
            source_address="",
            segment_id="",
            target=target,
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "command": rendered,
            "output_file": str(output_file or ""),
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
            source_address="",
            segment_id="",
            target=target,
        )
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": rendered,
            "output_file": str(output_file or ""),
        }


def _bounded_network(value: str) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None
    if network.version != 4:
        return None
    if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
        return None
    return network


def _network_from_address_mask(address: str, mask: str) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(f"{address}/{mask}", strict=False)
    except ValueError:
        return None
    return _bounded_network(str(network))


def _extract_explicit_cidrs(text: str) -> set[ipaddress.IPv4Network]:
    result: set[ipaddress.IPv4Network] = set()
    for value in _CIDR_RE.findall(text or ""):
        network = _bounded_network(value)
        if network is not None:
            result.add(network)
    return result


def _extract_labelled_address_mask_pairs(text: str) -> set[ipaddress.IPv4Network]:
    """Extract only address/mask combinations that occur near labelled fields.

    This intentionally avoids turning arbitrary IP literals into subnets.  The
    parser accepts a labelled address and a labelled mask within a small block,
    which fits common RIP/OSPF/tshark verbose output while keeping inference
    conservative.
    """

    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    result: set[ipaddress.IPv4Network] = set()
    for index, line in enumerate(lines):
        address_match = _LABELLED_IPV4_RE.search(line)
        if not address_match:
            continue
        address = address_match.group(1)
        for candidate_line in lines[index : index + 8]:
            mask_match = _MASK_RE.search(candidate_line)
            if not mask_match:
                continue
            network = _network_from_address_mask(address, mask_match.group(1))
            if network is not None:
                result.add(network)
            break
    return result


def _extract_ipv4_addresses(text: str) -> set[str]:
    addresses: set[str] = set()
    for value in _IPV4_RE.findall(text or ""):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (
            address.version == 4
            and not address.is_unspecified
            and not address.is_loopback
            and not address.is_multicast
        ):
            addresses.add(str(address))
    return addresses


def _candidate_record(
    *,
    network: ipaddress.IPv4Network,
    device_ip: str,
    interface: str,
    source: str,
    confidence: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    limit = max(1, int(getattr(Config, "MAX_EXPANDED_TARGETS", 256)))
    candidate_id = _stable_id(
        "toponet", device_ip, str(network), interface, source
    )
    return {
        "candidate_id": candidate_id,
        "network": str(network),
        "source_device": str(device_ip),
        "gateway_candidate": str(device_ip),
        "interface": str(interface or ""),
        "source": source,
        "confidence": confidence,
        "evidence_sources": [source],
        "evidence": [dict(evidence)],
        "address_count": int(network.num_addresses),
        "enumeration_eligible": int(network.num_addresses) <= limit,
        "discovery_limit": limit,
        "discovered_at": scan_store.now(),
        "reachability_state": "not_yet_verified",
        "traversal_state": "candidate",
    }


def _merge_candidate(
    inventory: dict[str, dict[str, Any]], candidate: dict[str, Any]
) -> None:
    network = str(candidate.get("network") or "")
    if not network:
        return
    existing = inventory.get(network)
    if existing is None:
        inventory[network] = dict(candidate)
        return
    rank = {"low": 1, "medium": 2, "high": 3}
    if rank.get(str(candidate.get("confidence") or "low"), 1) > rank.get(
        str(existing.get("confidence") or "low"), 1
    ):
        existing["confidence"] = candidate.get("confidence")
    existing["evidence_sources"] = list(
        dict.fromkeys(
            [
                *[str(value) for value in existing.get("evidence_sources") or []],
                *[str(value) for value in candidate.get("evidence_sources") or []],
            ]
        )
    )
    existing["evidence"] = [
        *[dict(value) for value in existing.get("evidence") or [] if isinstance(value, dict)],
        *[dict(value) for value in candidate.get("evidence") or [] if isinstance(value, dict)],
    ]
    existing["enumeration_eligible"] = bool(
        existing.get("enumeration_eligible") and candidate.get("enumeration_eligible")
    )


def _parse_nmap_script_text(path: Path) -> tuple[str, set[str]]:
    if not path.exists():
        return "", set()
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return "", set()
    fragments: list[str] = []
    for script in root.findall(".//script"):
        output = str(script.attrib.get("output") or "")
        if output:
            fragments.append(output)
        for elem in script.findall(".//elem"):
            if elem.text:
                fragments.append(str(elem.text))
    text = "\n".join(fragments)
    return text, _extract_ipv4_addresses(text)


def collect_device_topology_evidence(
    scan_id: str,
    *,
    device_ip: str,
    current_segment: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Collect bounded topology evidence for one already-discovered device.

    No credentials are requested or guessed. No route is created and the Kali
    kernel routing table is not read for topology discovery. No routing protocol
    is injected into. Returned networks are derived only from explicit observable
    advertisements or selected-device metadata.
    """

    try:
        device = ipaddress.ip_address(str(device_ip))
        current_network = ipaddress.ip_network(
            str(current_segment.get("network") or ""), strict=False
        )
    except ValueError as exc:
        raise TopologyEvidenceError("The selected topology device is invalid.") from exc
    if device.version != 4:
        raise TopologyEvidenceError("Automatic topology evidence collection currently supports IPv4 devices.")
    if device not in current_network:
        raise TopologyEvidenceError("The selected device is not inside the current retained network scope.")

    interface = str(current_segment.get("interface") or "").strip()
    selected_host = next(
        (
            item
            for item in current_segment.get("hosts") or []
            if isinstance(item, dict)
            and str(item.get("ip") or item.get("address") or "") == str(device)
        ),
        {},
    )
    device_mac = str((selected_host or {}).get("mac") or "").strip()
    capture_filter = _passive_filter(str(device), device_mac)
    candidate_inventory: dict[str, dict[str, Any]] = {}
    device_addresses: set[str] = {str(device)}
    collectors: dict[str, dict[str, Any]] = {}

    # Phase 2 intentionally does not consult Kali's routing table. The snapshot
    # supplied by the active workflow contains interface and neighbour evidence
    # only; continuation networks must be established independently from the
    # selected device's observable evidence.

    # Passive observation of routing/control-plane advertisements.  This does
    # not transmit OSPF/RIP/CDP/LLDP frames or modify routing state.
    tshark = shutil.which("tshark")
    passive_seconds = max(
        3,
        min(int(os.getenv("DISCOVERY_TOPOLOGY_PASSIVE_SECONDS", "8")), 30),
    )
    if tshark and interface:
        passive_file = scan_store.scan_path(
            f"{scan_id}_topology_{str(device).replace(':', '_')}_passive.txt"
        )
        passive_file.unlink(missing_ok=True)
        command = command_builders.tshark_passive_topology_observation(
            tshark, interface, capture_filter, passive_seconds
        )
        result = _run(
            scan_id,
            command,
            "Phase 2 passive topology advertisement observation",
            timeout=passive_seconds + 8,
            output_file=passive_file,
            interface=interface,
            target=str(device),
        )
        text = (
            passive_file.read_text(encoding="utf-8", errors="ignore")
            if passive_file.exists()
            else str(result.get("stdout") or "")
        )
        networks = _extract_explicit_cidrs(text) | _extract_labelled_address_mask_pairs(text)
        network_count = 0
        for network in sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)):
            if network == current_network:
                continue
            candidate = _candidate_record(
                network=network,
                device_ip=str(device),
                interface=interface,
                source="passive_routing_advertisement",
                confidence="medium",
                evidence={
                    "type": "passive_control_plane_observation",
                    "network": str(network),
                    "capture_file": str(passive_file),
                    "filter": capture_filter,
                    "interpretation": "explicit network/prefix or labelled address+mask observed in passive protocol decode",
                },
            )
            _merge_candidate(candidate_inventory, candidate)
            network_count += 1
        device_addresses.update(_extract_ipv4_addresses(text))
        collectors["passive_topology_advertisements"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(result.get("success")) or bool(text.strip()),
            "evidence_produced": bool(network_count or text.strip()),
            "network_count": network_count,
            "evidence_file": str(passive_file),
            "duration_seconds": passive_seconds,
            "selected_device": str(device),
            "selected_device_mac": device_mac,
            "capture_filter": capture_filter,
        }
    else:
        collectors["passive_topology_advertisements"] = {
            "requested": True,
            "tool_available": bool(tshark),
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "unavailable_reason": "interface_unavailable" if not interface else "tool_unavailable",
        }

    # Direct SSDP/UPnP metadata request.  This is bounded information gathering
    # against the already-selected device and does not authenticate or change it.
    nmap = shutil.which("nmap")
    if nmap:
        upnp_file = scan_store.scan_path(
            f"{scan_id}_topology_{str(device).replace(':', '_')}_upnp.xml"
        )
        upnp_file.unlink(missing_ok=True)
        command = command_builders.nmap_upnp_topology_metadata(
            nmap, str(device), upnp_file
        )
        result = _run(
            scan_id,
            command,
            "Phase 2 selected-device UPnP topology metadata probe",
            timeout=25,
            output_file=upnp_file,
            interface=interface,
            target=str(device),
        )
        script_text, script_addresses = _parse_nmap_script_text(upnp_file)
        device_addresses.update(script_addresses)
        networks = _extract_explicit_cidrs(script_text) | _extract_labelled_address_mask_pairs(script_text)
        network_count = 0
        for network in sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)):
            if network == current_network:
                continue
            candidate = _candidate_record(
                network=network,
                device_ip=str(device),
                interface=interface,
                source="upnp_management_disclosure",
                confidence="medium",
                evidence={
                    "type": "upnp_metadata",
                    "network": str(network),
                    "evidence_file": str(upnp_file),
                    "interpretation": "explicit network/prefix or labelled address+mask disclosed by UPnP metadata",
                },
            )
            _merge_candidate(candidate_inventory, candidate)
            network_count += 1
        collectors["upnp_metadata"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(result.get("success")),
            "evidence_produced": bool(script_text.strip()),
            "network_count": network_count,
            "address_observation_count": len(script_addresses),
            "evidence_file": str(upnp_file),
        }
    else:
        collectors["upnp_metadata"] = {
            "requested": True,
            "tool_available": False,
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "unavailable_reason": "tool_unavailable",
        }

    # Unauthenticated management-plane disclosure check.  Only the root page is
    # fetched, with a hard byte range and short timeout.  Explicit CIDRs or
    # labelled address+mask fields may become medium-confidence candidates;
    # arbitrary IP literals remain address observations only.
    curl = shutil.which("curl")
    management_network_count = 0
    management_addresses: set[str] = set()
    management_evidence_files: list[str] = []
    if curl:
        for scheme in ("http", "https"):
            output_file = scan_store.scan_path(
                f"{scan_id}_topology_{str(device).replace(':', '_')}_{scheme}.txt"
            )
            output_file.unlink(missing_ok=True)
            command = command_builders.curl_topology_root_metadata(
                curl, scheme, str(device)
            )
            result = _run(
                scan_id,
                command,
                f"Phase 2 selected-device {scheme.upper()} management metadata observation",
                timeout=8,
                output_file=output_file,
                interface=interface,
                target=str(device),
            )
            text = (
                output_file.read_text(encoding="utf-8", errors="ignore")
                if output_file.exists()
                else str(result.get("stdout") or "")
            )
            if text.strip():
                management_evidence_files.append(str(output_file))
            management_addresses.update(_extract_ipv4_addresses(text))
            networks = _extract_explicit_cidrs(text) | _extract_labelled_address_mask_pairs(text)
            for network in sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)):
                if network == current_network:
                    continue
                candidate = _candidate_record(
                    network=network,
                    device_ip=str(device),
                    interface=interface,
                    source="management_plane_disclosure",
                    confidence="medium",
                    evidence={
                        "type": "unauthenticated_management_metadata",
                        "scheme": scheme,
                        "network": str(network),
                        "evidence_file": str(output_file),
                        "interpretation": "explicit network/prefix or labelled address+mask observed on bounded unauthenticated root page",
                    },
                )
                _merge_candidate(candidate_inventory, candidate)
                management_network_count += 1
        device_addresses.update(management_addresses)
        collectors["management_plane_disclosure"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(management_evidence_files),
            "evidence_produced": bool(management_evidence_files),
            "network_count": management_network_count,
            "address_observation_count": len(management_addresses),
            "evidence_files": management_evidence_files,
            "interpretation": "bounded_unauthenticated_root_page_only",
        }
    else:
        collectors["management_plane_disclosure"] = {
            "requested": True,
            "tool_available": False,
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "network_count": 0,
            "unavailable_reason": "tool_unavailable",
        }

    # Bounded traceroute to the selected device is retained as path evidence.
    # It is not converted into a subnet unless an explicit prefix/mask appears.
    trace_tool = shutil.which("tracepath") or shutil.which("traceroute")
    if trace_tool:
        is_tracepath = Path(trace_tool).name == "tracepath"
        command = (
            [trace_tool, "-n", "-m", "8", str(device)]
            if is_tracepath
            else [trace_tool, "-n", "-m", "8", "-w", "1", "-q", "1", str(device)]
        )
        result = _run(
            scan_id,
            command,
            "Phase 2 selected-device path observation",
            timeout=20,
            interface=interface,
            target=str(device),
        )
        text = str(result.get("stdout") or result.get("stderr") or "")
        device_addresses.update(_extract_ipv4_addresses(text))
        collectors["path_observation"] = {
            "requested": True,
            "tool_available": True,
            "executed": True,
            "success": bool(result.get("success")) or bool(text.strip()),
            "evidence_produced": bool(text.strip()),
            "interpretation": "path_hint_only_no_subnet_inference",
        }
    else:
        collectors["path_observation"] = {
            "requested": True,
            "tool_available": False,
            "executed": False,
            "success": False,
            "evidence_produced": False,
            "unavailable_reason": "tool_unavailable",
        }

    current_network_string = str(current_network)
    for network in list(candidate_inventory):
        if network == current_network_string:
            candidate_inventory.pop(network, None)

    candidates = sorted(
        candidate_inventory.values(),
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("confidence") or "low"), 3),
            str(item.get("network") or ""),
        ),
    )
    return {
        "device_ip": str(device),
        "current_network": current_network_string,
        "interface": interface,
        "captured_at": scan_store.now(),
        "collectors": collectors,
        "candidate_networks": candidates,
        "device_address_observations": sorted(device_addresses, key=lambda value: int(ipaddress.ip_address(value))),
        "boundary_state": "continuation_candidates_observed" if candidates else "no_additional_network_established",
        "statement": (
            f"Retained {len(candidates)} evidence-backed continuation network candidate(s)."
            if candidates
            else "No additional network prefix could be established from the currently observable evidence."
        ),
    }
