"""Read-only infrastructure topology discovery for operator-controlled Phase 2.

The scanner does not infer hidden networks from Kali's route table. Instead, an
operator selects a discovered infrastructure device and this module queries that
device with either a configured read-only credential profile or one-query
operator-supplied access. Secrets remain only in process/request memory or
environment variables and are never written into mission records or command logs.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from config import Config
from storage import scan_store


class InfrastructureDiscoveryError(RuntimeError):
    """Raised when read-only topology evidence cannot be collected safely."""


_PROFILE_ENV = "INFRA_TOPOLOGY_PROFILES_JSON"
_DEFAULT_PROFILE_ENV = "INFRA_TOPOLOGY_DEFAULT_PROFILE"
_ALLOWED_PLATFORMS = {"cisco_ios", "palo_alto", "generic"}
_ALLOWED_TRANSPORTS = {"ssh", "snmp_v2c"}
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_profiles() -> dict[str, dict[str, Any]]:
    raw = str(os.getenv(_PROFILE_ENV) or "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InfrastructureDiscoveryError(
            f"{_PROFILE_ENV} must contain valid JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise InfrastructureDiscoveryError(
            f"{_PROFILE_ENV} must be a JSON object keyed by profile name."
        )
    profiles: dict[str, dict[str, Any]] = {}
    for ref, value in payload.items():
        if not isinstance(value, dict):
            continue
        profile_ref = str(ref or "").strip()
        if not profile_ref:
            continue
        platform = str(value.get("platform") or "generic").strip().lower()
        transport = str(value.get("transport") or "ssh").strip().lower()
        if platform not in _ALLOWED_PLATFORMS:
            continue
        if transport not in _ALLOWED_TRANSPORTS:
            continue
        profile = dict(value)
        profile["profile_ref"] = profile_ref
        profile["platform"] = platform
        profile["transport"] = transport
        profiles[profile_ref] = profile
    return profiles


def public_profile_catalog() -> list[dict[str, Any]]:
    """Return secret-free profile metadata suitable for the operator UI."""
    profiles = _load_profiles()
    rows = []
    for ref, profile in sorted(profiles.items()):
        rows.append(
            {
                "profile_ref": ref,
                "platform": profile.get("platform"),
                "transport": profile.get("transport"),
                "label": str(profile.get("label") or ref),
                "is_default": ref == str(os.getenv(_DEFAULT_PROFILE_ENV) or "").strip(),
                # Match metadata is not secret material. Exposing it lets the
                # Phase 2 UI explain why a profile will (or will not) be used
                # for a selected device without ever exposing credentials.
                "match_hosts": [str(v) for v in profile.get("match_hosts") or []],
                "match_networks": [str(v) for v in profile.get("match_networks") or []],
                "priority": profile.get("priority") if str(profile.get("priority") or "").strip() else 100,
            }
        )
    return rows


def _profile_has_match_scope(profile: dict[str, Any]) -> bool:
    return bool(
        [v for v in profile.get("match_hosts") or [] if str(v).strip()]
        or [v for v in profile.get("match_networks") or [] if str(v).strip()]
    )


def _host_in_match_scope(host_ip: str, profile: dict[str, Any]) -> bool:
    matches = [str(value).strip() for value in profile.get("match_hosts") or [] if str(value).strip()]
    if host_ip in matches:
        return True
    try:
        address = ipaddress.ip_address(host_ip)
    except ValueError:
        return False
    for value in profile.get("match_networks") or []:
        try:
            if address in ipaddress.ip_network(str(value), strict=False):
                return True
        except ValueError:
            continue
    return False


def profile_selection_context(host_ip: str, requested_ref: str = "") -> dict[str, Any]:
    """Describe profile readiness for one selected device without raising.

    This is intentionally a control-plane/UI helper: it never resolves or
    returns secret values.  A device can always be selected in Phase 2; this
    context only determines whether a deeper read-only topology query can run
    immediately or whether the operator must choose/configure a profile first.
    """

    try:
        host_ip = str(ipaddress.ip_address(str(host_ip).strip()))
    except ValueError:
        return {
            "host_ip": str(host_ip or ""),
            "state": "invalid_device",
            "ready": False,
            "resolved_profile_ref": "",
            "resolved_profile_label": "",
            "matching_profile_refs": [],
            "message": "The selected device address is invalid.",
        }

    profiles = _load_profiles()
    if not profiles:
        return {
            "host_ip": host_ip,
            "state": "profile_required",
            "ready": False,
            "resolved_profile_ref": "",
            "resolved_profile_label": "",
            "matching_profile_refs": [],
            "message": (
                "The device was selected successfully, but no read-only infrastructure "
                "profile is configured for deeper topology discovery."
            ),
        }

    requested = str(requested_ref or "").strip()
    if requested:
        profile = profiles.get(requested)
        if not profile:
            return {
                "host_ip": host_ip,
                "state": "profile_selection_invalid",
                "ready": False,
                "resolved_profile_ref": "",
                "resolved_profile_label": "",
                "matching_profile_refs": [],
                "message": "The selected read-only infrastructure profile is not configured.",
            }
        return {
            "host_ip": host_ip,
            "state": "ready",
            "ready": True,
            "resolved_profile_ref": requested,
            "resolved_profile_label": str(profile.get("label") or requested),
            "matching_profile_refs": [requested] if _host_in_match_scope(host_ip, profile) else [],
            "selection_source": "operator_selected",
            "message": f"Ready to query {host_ip} using the selected read-only profile.",
        }

    scoped = [
        (ref, profile)
        for ref, profile in profiles.items()
        if _host_in_match_scope(host_ip, profile)
    ]
    if scoped:
        scoped.sort(key=lambda item: (int(item[1].get("priority") or 100), item[0]))
        ref, profile = scoped[0]
        return {
            "host_ip": host_ip,
            "state": "ready",
            "ready": True,
            "resolved_profile_ref": ref,
            "resolved_profile_label": str(profile.get("label") or ref),
            "matching_profile_refs": [item[0] for item in scoped],
            "selection_source": "device_match",
            "message": f"Matching read-only profile found for {host_ip}.",
        }

    default_ref = str(os.getenv(_DEFAULT_PROFILE_ENV) or "").strip()
    if default_ref and default_ref in profiles:
        profile = profiles[default_ref]
        if not _profile_has_match_scope(profile) or _host_in_match_scope(host_ip, profile):
            return {
                "host_ip": host_ip,
                "state": "ready",
                "ready": True,
                "resolved_profile_ref": default_ref,
                "resolved_profile_label": str(profile.get("label") or default_ref),
                "matching_profile_refs": [],
                "selection_source": "default",
                "message": f"The default read-only profile is available for {host_ip}.",
            }

    if len(profiles) == 1:
        ref = next(iter(profiles))
        profile = profiles[ref]
        if not _profile_has_match_scope(profile):
            return {
                "host_ip": host_ip,
                "state": "ready",
                "ready": True,
                "resolved_profile_ref": ref,
                "resolved_profile_label": str(profile.get("label") or ref),
                "matching_profile_refs": [],
                "selection_source": "single_unscoped_profile",
                "message": f"The configured read-only profile is available for {host_ip}.",
            }
        return {
            "host_ip": host_ip,
            "state": "profile_not_matched",
            "ready": False,
            "resolved_profile_ref": "",
            "resolved_profile_label": "",
            "matching_profile_refs": [],
            "selection_source": "device_match_required",
            "message": (
                "A read-only profile is configured, but its host/network match scope does not "
                "include this device. Select a different profile or explicitly override the profile choice."
            ),
        }

    return {
        "host_ip": host_ip,
        "state": "profile_selection_required",
        "ready": False,
        "resolved_profile_ref": "",
        "resolved_profile_label": "",
        "matching_profile_refs": [],
        "selection_source": "operator_selection_required",
        "message": (
            "Multiple read-only infrastructure profiles are configured, but none is "
            "matched to this device. Select the profile to use and continue again."
        ),
    }


def resolve_profile(host_ip: str, requested_ref: str = "") -> tuple[str, dict[str, Any]]:
    """Resolve one configured profile without persisting any secret material."""
    try:
        host_ip = str(ipaddress.ip_address(str(host_ip).strip()))
    except ValueError as exc:
        raise InfrastructureDiscoveryError("The selected infrastructure address is invalid.") from exc

    profiles = _load_profiles()
    if not profiles:
        raise InfrastructureDiscoveryError(
            "No read-only infrastructure profile is configured. Set "
            f"{_PROFILE_ENV} in project/.env and restart the application."
        )

    requested = str(requested_ref or "").strip()
    if requested:
        profile = profiles.get(requested)
        if not profile:
            raise InfrastructureDiscoveryError("The selected credential profile is not configured.")
        return requested, profile

    scoped = [(ref, profile) for ref, profile in profiles.items() if _host_in_match_scope(host_ip, profile)]
    if len(scoped) == 1:
        return scoped[0]
    if len(scoped) > 1:
        scoped.sort(key=lambda item: int(item[1].get("priority") or 100))
        return scoped[0]

    default_ref = str(os.getenv(_DEFAULT_PROFILE_ENV) or "").strip()
    if default_ref and default_ref in profiles:
        profile = profiles[default_ref]
        if not _profile_has_match_scope(profile) or _host_in_match_scope(host_ip, profile):
            return default_ref, profile
    if len(profiles) == 1:
        ref = next(iter(profiles))
        profile = profiles[ref]
        if not _profile_has_match_scope(profile):
            return ref, profile
        raise InfrastructureDiscoveryError(
            "The configured infrastructure profile is scoped to a different device. "
            "Select that profile explicitly only if this device is authorised to use it."
        )
    raise InfrastructureDiscoveryError(
        "Multiple infrastructure profiles are configured. Select the profile to use for this device."
    )


def _safe_command_log(
    scan_id: str,
    *,
    rendered: str,
    purpose: str,
    result: subprocess.CompletedProcess[str] | None,
    error: str = "",
    target: str = "",
) -> None:
    stdout = result.stdout if result else ""
    stderr = result.stderr if result else error
    returncode = result.returncode if result else -1
    output = stdout if str(stdout or "").strip() else str(stderr or "")
    scan_store.log_command(
        scan_id,
        command=rendered,
        purpose=purpose,
        output=output,
        output_summary=(str(output).strip().splitlines() or ["No console output"])[0][:300],
        status="Completed" if result is not None and result.returncode == 0 else "Failed",
        exit_code=returncode,
        started_at="",
        ended_at=scan_store.now(),
        target=target,
    )


def _run_sensitive(
    scan_id: str,
    argv: list[str],
    *,
    rendered_safe: list[str],
    purpose: str,
    timeout: int,
    target: str,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> str:
    """Run a command while logging only a redacted/safe representation."""
    rendered = shlex.join(rendered_safe)
    try:
        completed = subprocess.run(
            argv,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _safe_command_log(
            scan_id,
            rendered=rendered,
            purpose=purpose,
            result=None,
            error=str(exc),
            target=target,
        )
        raise InfrastructureDiscoveryError(f"{purpose} failed: {exc}") from exc

    _safe_command_log(
        scan_id,
        rendered=rendered,
        purpose=purpose,
        result=completed,
        target=target,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        summary = detail[0][:300] if detail else f"exit code {completed.returncode}"
        raise InfrastructureDiscoveryError(f"{purpose} failed: {summary}")
    return completed.stdout or ""


def _ssh_commands(platform: str) -> list[str]:
    if platform == "cisco_ios":
        return [
            "terminal length 0",
            "show ip interface brief",
            "show ip route connected",
            "show ip route static",
        ]
    if platform == "palo_alto":
        return [
            "set cli pager off",
            "show interface all",
            "show routing route",
        ]
    return ["ip -o addr show", "ip route show"]


def _collect_ssh(
    scan_id: str,
    host_ip: str,
    profile_ref: str,
    profile: dict[str, Any],
    *,
    runtime_secret: str = "",
) -> str:
    ssh = shutil.which("ssh")
    if not ssh:
        raise InfrastructureDiscoveryError("The ssh client is required for the selected topology profile.")

    username = str(profile.get("username") or "").strip()
    if not username or not _USERNAME_RE.fullmatch(username):
        raise InfrastructureDiscoveryError("The selected SSH profile has an invalid or missing username.")
    port = int(profile.get("port") or 22)
    if port < 1 or port > 65535:
        raise InfrastructureDiscoveryError("The selected SSH profile has an invalid port.")

    strict = "yes" if _truthy(profile.get("strict_host_key_checking")) else "accept-new"
    argv = [
        ssh,
        "-p",
        str(port),
        "-o",
        "ConnectTimeout=8",
        "-o",
        f"StrictHostKeyChecking={strict}",
        "-o",
        "LogLevel=ERROR",
    ]
    safe = list(argv)

    identity_file = str(profile.get("identity_file") or "").strip()
    secret_env = str(profile.get("secret_env") or "").strip()
    env = dict(os.environ)
    if identity_file:
        path = Path(identity_file).expanduser()
        if not path.exists():
            raise InfrastructureDiscoveryError(
                f"SSH identity file for profile {profile_ref!r} does not exist."
            )
        argv += ["-i", str(path), "-o", "BatchMode=yes"]
        safe += ["-i", str(path), "-o", "BatchMode=yes"]
    elif runtime_secret or secret_env:
        secret = str(runtime_secret or (os.getenv(secret_env) if secret_env else "") or "")
        if not secret:
            if secret_env:
                raise InfrastructureDiscoveryError(
                    f"The secret environment variable {secret_env} required by profile {profile_ref!r} is empty."
                )
            raise InfrastructureDiscoveryError(
                "A password is required for the on-demand SSH topology query."
            )
        sshpass = shutil.which("sshpass")
        if not sshpass:
            raise InfrastructureDiscoveryError(
                "sshpass is required for password-backed SSH topology access; install it or use a configured key-backed profile."
            )
        env["SSHPASS"] = secret
        argv = [sshpass, "-e", *argv]
        safe = [sshpass, "-e", *safe]
    else:
        argv += ["-o", "BatchMode=yes"]
        safe += ["-o", "BatchMode=yes"]

    destination = f"{username}@{host_ip}"
    argv.append(destination)
    safe.append(destination)
    commands = _ssh_commands(str(profile.get("platform") or "generic"))
    # Sending commands on stdin avoids embedding credentials or operator data in a shell command.
    stdin_text = "\n".join(commands) + "\nexit\n"
    return _run_sensitive(
        scan_id,
        argv,
        rendered_safe=[*safe, "<read-only topology commands via stdin>"],
        purpose="Read-only infrastructure topology query",
        timeout=int(profile.get("timeout_seconds") or 25),
        target=host_ip,
        env=env,
        stdin_text=stdin_text,
    )


def _snmp_walk(
    scan_id: str,
    host_ip: str,
    community: str,
    oid: str,
    purpose: str,
    timeout: int,
) -> str:
    snmpwalk = shutil.which("snmpwalk")
    if not snmpwalk:
        raise InfrastructureDiscoveryError("snmpwalk is required for the selected topology profile.")
    argv = [snmpwalk, "-v2c", "-c", community, "-t", "2", "-r", "1", host_ip, oid]
    safe = [snmpwalk, "-v2c", "-c", "<redacted>", "-t", "2", "-r", "1", host_ip, oid]
    return _run_sensitive(
        scan_id,
        argv,
        rendered_safe=safe,
        purpose=purpose,
        timeout=timeout,
        target=host_ip,
    )


def _collect_snmp(
    scan_id: str,
    host_ip: str,
    profile_ref: str,
    profile: dict[str, Any],
    *,
    runtime_secret: str = "",
) -> str:
    secret_env = str(profile.get("secret_env") or "").strip()
    community = str(runtime_secret or (os.getenv(secret_env) if secret_env else "") or "")
    if not community:
        if secret_env:
            raise InfrastructureDiscoveryError(
                f"The SNMP community environment variable for profile {profile_ref!r} is not configured."
            )
        raise InfrastructureDiscoveryError(
            "An SNMP community is required for the on-demand read-only topology query."
        )
    timeout = int(profile.get("timeout_seconds") or 20)
    addresses = _snmp_walk(
        scan_id,
        host_ip,
        community,
        ".1.3.6.1.2.1.4.20.1.1",
        "Read-only SNMP interface-address query",
        timeout,
    )
    masks = _snmp_walk(
        scan_id,
        host_ip,
        community,
        ".1.3.6.1.2.1.4.20.1.3",
        "Read-only SNMP interface-netmask query",
        timeout,
    )
    return f"[SNMP_ADDR]\n{addresses}\n[SNMP_MASK]\n{masks}"


def _network_ok(network: ipaddress._BaseNetwork) -> bool:
    return not (
        network.prefixlen == 0
        or network.is_loopback
        or network.is_multicast
        or network.is_unspecified
    )


def _interface_record(ip_text: str, prefix_or_mask: str, interface: str, source: str) -> dict[str, Any] | None:
    try:
        if "." in prefix_or_mask and "/" not in prefix_or_mask:
            iface = ipaddress.ip_interface(f"{ip_text}/{prefix_or_mask}")
        else:
            prefix = str(prefix_or_mask).lstrip("/")
            iface = ipaddress.ip_interface(f"{ip_text}/{prefix}")
    except ValueError:
        return None
    network = iface.network
    if network.is_loopback or network.is_multicast or network.is_unspecified:
        return None
    return {
        "interface": str(interface or ""),
        "address": str(iface.ip),
        "prefixlen": int(network.prefixlen),
        "network": str(network),
        "source": source,
    }


def _parse_cisco(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    interfaces: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    # show ip interface brief provides addresses but not prefixes. Route output supplies
    # connected networks and interface names; the two are reconciled below.
    brief: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+", line)
        if match and match.group(1).lower() not in {"interface", "internet"}:
            brief[match.group(1)] = match.group(2)
        route_match = re.search(
            r"^\s*[CSLORDBE*+ ]+\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}).*?(?:directly connected,\s*)?(\S+)?\s*$",
            line,
        )
        if route_match:
            try:
                network = ipaddress.ip_network(route_match.group(1), strict=False)
            except ValueError:
                continue
            interface = str(route_match.group(2) or "").rstrip(",")
            routes.append(
                {
                    "network": str(network),
                    "interface": interface,
                    "source": "device_route_table",
                    "route_kind": "connected_or_static",
                }
            )
    route_by_if = {row.get("interface"): row.get("network") for row in routes if row.get("interface")}
    for interface, address in brief.items():
        network_text = route_by_if.get(interface)
        if network_text:
            network = ipaddress.ip_network(str(network_text), strict=False)
            if ipaddress.ip_address(address) in network:
                row = _interface_record(address, str(network.prefixlen), interface, "device_interface")
                if row:
                    interfaces.append(row)
    return interfaces, routes


def _parse_palo_alto(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    interfaces: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    current_interface = ""
    for line in text.splitlines():
        interface_match = re.search(r"\b(ethernet\d+/\d+(?:\.\d+)?|ae\d+(?:\.\d+)?|vlan\.\d+|loopback\.\d+)\b", line, re.I)
        if interface_match:
            current_interface = interface_match.group(1)
        cidrs = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", line)
        for cidr in cidrs:
            try:
                iface = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            # PAN-OS route-table lines also contain CIDRs. A CIDR whose host
            # portion is the network address is route evidence, not an
            # interface address.
            if iface.ip == iface.network.network_address:
                continue
            row = _interface_record(str(iface.ip), str(iface.network.prefixlen), current_interface, "device_interface")
            if row and row not in interfaces:
                interfaces.append(row)
        route_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", line)
        if route_match and any(token in line.lower() for token in ("connect", "static", "route", "ethernet", "vlan")):
            try:
                network = ipaddress.ip_network(route_match.group(1), strict=False)
            except ValueError:
                continue
            routes.append(
                {
                    "network": str(network),
                    "interface": current_interface,
                    "source": "device_route_table",
                    "route_kind": "observed",
                }
            )
    return interfaces, routes


def _parse_generic(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    interfaces: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    for line in text.splitlines():
        iface = ""
        iface_match = re.match(r"^\s*\d+:\s*([^\s:]+)", line)
        if iface_match:
            iface = iface_match.group(1)
        for cidr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", line):
            try:
                ipif = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            if str(ipif.ip) != str(ipif.network.network_address):
                row = _interface_record(str(ipif.ip), str(ipif.network.prefixlen), iface, "device_interface")
                if row and row not in interfaces:
                    interfaces.append(row)
            elif not ipif.network.is_loopback:
                routes.append(
                    {
                        "network": str(ipif.network),
                        "interface": iface,
                        "source": "device_route_table",
                        "route_kind": "observed",
                    }
                )
    return interfaces, routes


def _parse_snmp(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    addresses: dict[str, str] = {}
    masks: dict[str, str] = {}
    section = ""
    for line in text.splitlines():
        if line.strip() == "[SNMP_ADDR]":
            section = "addr"
            continue
        if line.strip() == "[SNMP_MASK]":
            section = "mask"
            continue
        # Numeric IP-MIB index ends with the IPv4 address being described.
        index_match = re.search(r"(?:\.)(\d{1,3}(?:\.\d{1,3}){3})\s*=", line)
        value_match = re.search(r"(?:IpAddress|STRING|INTEGER):\s*([^\s]+)", line)
        if not index_match:
            continue
        index_ip = index_match.group(1)
        value = value_match.group(1) if value_match else ""
        if section == "addr":
            addresses[index_ip] = value if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value) else index_ip
        elif section == "mask" and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            masks[index_ip] = value
    interfaces = []
    for index_ip, address in addresses.items():
        mask = masks.get(index_ip)
        if not mask:
            continue
        row = _interface_record(address, mask, "", "device_snmp_interface")
        if row:
            interfaces.append(row)
    return interfaces, []


def parse_topology_output(platform: str, transport: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse collector output into interface and route observations."""
    if transport == "snmp_v2c":
        return _parse_snmp(text)
    if platform == "cisco_ios":
        interfaces, routes = _parse_cisco(text)
        # Cisco formats vary widely; merge generic CIDR parsing as a fallback.
        generic_interfaces, generic_routes = _parse_generic(text)
        interfaces.extend(row for row in generic_interfaces if row not in interfaces)
        routes.extend(row for row in generic_routes if row not in routes)
        return interfaces, routes
    if platform == "palo_alto":
        return _parse_palo_alto(text)
    return _parse_generic(text)


def _network_records(
    host_ip: str,
    interfaces: Iterable[dict[str, Any]],
    routes: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_network: dict[str, dict[str, Any]] = {}
    interface_by_network = {str(row.get("network") or ""): row for row in interfaces if row.get("network")}
    for source_row in [*interfaces, *routes]:
        network_text = str(source_row.get("network") or "").strip()
        if not network_text:
            continue
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            continue
        if network.prefixlen == network.max_prefixlen or not _network_ok(network):
            continue
        interface_row = interface_by_network.get(str(network)) or {}
        record = by_network.setdefault(
            str(network),
            {
                "destination_network": str(network),
                "device_ip": host_ip,
                "device_interface": str(interface_row.get("interface") or source_row.get("interface") or ""),
                "device_interface_ip": str(interface_row.get("address") or ""),
                "prefixlen": int(network.prefixlen),
                "address_count": int(network.num_addresses),
                "enumeration_eligible": int(network.num_addresses) <= int(Config.MAX_EXPANDED_TARGETS),
                "evidence_sources": [],
            },
        )
        source = str(source_row.get("source") or "device_control_plane")
        if source not in record["evidence_sources"]:
            record["evidence_sources"].append(source)
    return sorted(by_network.values(), key=lambda row: (ipaddress.ip_network(row["destination_network"]).version, row["destination_network"]))


def collect_device_topology(
    scan_id: str,
    host_ip: str,
    *,
    profile_ref: str = "",
    runtime_profile: dict[str, Any] | None = None,
    runtime_secret: str = "",
) -> dict[str, Any]:
    """Collect one device's read-only interfaces and connected/routed networks.

    ``runtime_profile`` is an operator-supplied, one-query access definition.
    It is intentionally never written to mission storage.  Only the resulting
    secret-free topology evidence is retained.
    """
    try:
        host_ip = str(ipaddress.ip_address(str(host_ip).strip()))
    except ValueError as exc:
        raise InfrastructureDiscoveryError("The selected infrastructure address is invalid.") from exc

    if runtime_profile is not None:
        profile = dict(runtime_profile)
        platform = str(profile.get("platform") or "generic").strip().lower()
        transport = str(profile.get("transport") or "ssh").strip().lower()
        if platform not in _ALLOWED_PLATFORMS:
            raise InfrastructureDiscoveryError("Unsupported on-demand infrastructure platform.")
        if transport not in _ALLOWED_TRANSPORTS:
            raise InfrastructureDiscoveryError("Unsupported on-demand infrastructure transport.")
        profile["platform"] = platform
        profile["transport"] = transport
        resolved_ref = "operator_ephemeral"
    else:
        resolved_ref, profile = resolve_profile(host_ip, profile_ref)
        platform = str(profile.get("platform") or "generic")
        transport = str(profile.get("transport") or "ssh")

    if transport == "ssh":
        raw = _collect_ssh(
            scan_id, host_ip, resolved_ref, profile, runtime_secret=runtime_secret
        )
    elif transport == "snmp_v2c":
        raw = _collect_snmp(
            scan_id, host_ip, resolved_ref, profile, runtime_secret=runtime_secret
        )
    else:
        raise InfrastructureDiscoveryError("Unsupported infrastructure topology transport.")

    interfaces, routes = parse_topology_output(platform, transport, raw)
    networks = _network_records(host_ip, interfaces, routes)
    observation_id = "infraobs_" + __import__("hashlib").sha256(
        f"{host_ip}|{resolved_ref}|{platform}|{transport}".encode("utf-8")
    ).hexdigest()[:16]
    return {
        "observation_id": observation_id,
        "device_ip": host_ip,
        "profile_ref": resolved_ref,
        "access_source": "operator_ephemeral" if runtime_profile is not None else "configured_profile",
        "platform": platform,
        "transport": transport,
        "collected_at": scan_store.now(),
        "interfaces": interfaces,
        "routes": routes,
        "networks": networks,
        "network_count": len(networks),
        "raw_output_persisted": True,
        "secret_material_persisted": False,
    }
