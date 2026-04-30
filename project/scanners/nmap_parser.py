"""
P2/P3 Scanner Module - Nmap XML Parser
Converts Nmap XML into structured Python dictionaries for UI display and downstream mapping.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


class NmapParseError(Exception):
    """Raised when Nmap XML parsing fails."""


def _attr(element: ET.Element | None, name: str, default: str = "") -> str:
    if element is None:
        return default
    return element.get(name, default)


def _text(element: ET.Element | None, default: str = "") -> str:
    if element is None or element.text is None:
        return default
    return element.text.strip()


def parse_host_address(host: ET.Element) -> dict[str, str]:
    ipv4 = ""
    ipv6 = ""
    mac = ""
    vendor = ""

    for address in host.findall("address"):
        addr_type = address.get("addrtype", "")
        if addr_type == "ipv4":
            ipv4 = address.get("addr", "")
        elif addr_type == "ipv6":
            ipv6 = address.get("addr", "")
        elif addr_type == "mac":
            mac = address.get("addr", "")
            vendor = address.get("vendor", "")

    return {
        "primary": ipv4 or ipv6 or mac or "Unknown",
        "ipv4": ipv4,
        "ipv6": ipv6,
        "mac": mac,
        "vendor": vendor,
    }


def parse_hostnames(host: ET.Element) -> list[str]:
    names = []
    for hostname in host.findall("hostnames/hostname"):
        name = hostname.get("name")
        if name:
            names.append(name)
    return names


def parse_os_info(host: ET.Element) -> dict[str, str]:
    osmatch = host.find("os/osmatch")
    if osmatch is None:
        return {"name": "Unknown", "accuracy": "", "line": ""}

    return {
        "name": osmatch.get("name", "Unknown"),
        "accuracy": osmatch.get("accuracy", ""),
        "line": osmatch.get("line", ""),
    }


def parse_scripts(port: ET.Element) -> list[dict[str, str]]:
    scripts = []
    for script in port.findall("script"):
        scripts.append({"id": script.get("id", ""), "output": script.get("output", "")})
    return scripts


def parse_cpe(service: ET.Element | None) -> list[str]:
    if service is None:
        return []
    return [_text(cpe) for cpe in service.findall("cpe") if _text(cpe)]


def classify_port_state(state: str) -> str:
    if state == "open":
        return "Accessible service detected"
    if state == "filtered":
        return "Likely blocked by firewall or packet filtering"
    if state == "closed":
        return "Host reachable, but no service listening"
    return "Unknown port state"


def parse_ports(host: ET.Element) -> list[dict[str, Any]]:
    findings = []

    for port in host.findall("ports/port"):
        state_element = port.find("state")
        service = port.find("service")
        state = _attr(state_element, "state", "unknown")

        if state not in {"open", "filtered", "closed"}:
            continue

        findings.append(
            {
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
                "state": state,
                "state_explanation": classify_port_state(state),
                "reason": _attr(state_element, "reason"),
                "service": _attr(service, "name", "unknown"),
                "product": _attr(service, "product"),
                "version": _attr(service, "version"),
                "extra_info": _attr(service, "extrainfo"),
                "ostype": _attr(service, "ostype"),
                "method": _attr(service, "method"),
                "confidence": _attr(service, "conf"),
                "cpe": parse_cpe(service),
                "scripts": parse_scripts(port),
            }
        )

    return findings


def parse_scan_metadata(root: ET.Element) -> dict[str, str]:
    finished = root.find("runstats/finished")
    hosts = root.find("runstats/hosts")

    return {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start": root.get("startstr", ""),
        "finished": _attr(finished, "timestr"),
        "elapsed": _attr(finished, "elapsed"),
        "hosts_up": _attr(hosts, "up", "0"),
        "hosts_down": _attr(hosts, "down", "0"),
        "hosts_total": _attr(hosts, "total", "0"),
    }


def parse_nmap_xml(xml_file: str | Path) -> dict[str, Any]:
    xml_path = Path(xml_file)

    if not xml_path.exists():
        raise NmapParseError(f"XML file not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise NmapParseError("Invalid Nmap XML file.") from exc

    root = tree.getroot()
    results: dict[str, Any] = {
        "scan_file": str(xml_path),
        "metadata": parse_scan_metadata(root),
        "hosts": [],
        "total_open_ports": 0,
        "total_filtered_ports": 0,
        "total_closed_ports": 0,
        "total_reported_ports": 0,
        "services": {},
    }

    for host in root.findall("host"):
        status = host.find("status")
        port_findings = parse_ports(host)

        host_data = {
            "address": parse_host_address(host),
            "hostnames": parse_hostnames(host),
            "status": _attr(status, "state", "unknown"),
            "status_reason": _attr(status, "reason"),
            "os": parse_os_info(host),
            "open_ports": [p for p in port_findings if p["state"] == "open"],
            "filtered_ports": [p for p in port_findings if p["state"] == "filtered"],
            "closed_ports": [p for p in port_findings if p["state"] == "closed"],
            "port_findings": port_findings,
        }

        for item in port_findings:
            if item["state"] == "open":
                results["total_open_ports"] += 1
            elif item["state"] == "filtered":
                results["total_filtered_ports"] += 1
            elif item["state"] == "closed":
                results["total_closed_ports"] += 1

            service_name = item.get("service") or "unknown"
            results["services"][service_name] = results["services"].get(service_name, 0) + 1

        results["total_reported_ports"] += len(port_findings)
        results["hosts"].append(host_data)

    return results