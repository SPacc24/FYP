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
    if osmatch is not None:
        return {
            "name": osmatch.get("name", "Unknown"),
            "accuracy": osmatch.get("accuracy", ""),
            "line": osmatch.get("line", ""),
        }

    smb_os = host.find("hostscript/script[@id='smb-os-discovery']/elem[@key='os']")
    if smb_os is not None and _text(smb_os):
        return {"name": _text(smb_os), "accuracy": "script", "line": ""}

    for service in host.findall("ports/port/service"):
        ostype = service.get("ostype", "")
        product = service.get("product", "")

        if ostype:
            if product and ostype.lower() in product.lower():
                return {"name": product, "accuracy": "service", "line": ""}
            return {"name": ostype, "accuracy": "service", "line": ""}

        for cpe in service.findall("cpe"):
            cpe_text = _text(cpe)
            if cpe_text.startswith("cpe:/o:"):
                return {"name": cpe_text.replace("cpe:/o:", "").replace(":", " "), "accuracy": "cpe", "line": ""}

    return {"name": "Unknown", "accuracy": "", "line": ""}


def parse_scripts(port: ET.Element) -> list[dict[str, str]]:
    scripts = []
    for script in port.findall("script"):
        scripts.append({"id": script.get("id", ""), "output": script.get("output", "")})
    return scripts


def parse_host_scripts(host: ET.Element) -> list[dict[str, Any]]:
    scripts = []

    for script in host.findall("hostscript/script"):
        elems = {
            elem.get("key", ""): _text(elem)
            for elem in script.findall("elem")
            if elem.get("key")
        }
        scripts.append({
            "id": script.get("id", ""),
            "output": script.get("output", ""),
            "elements": elems,
        })

    return scripts




def parse_os_identities(host: ET.Element) -> list[dict[str, Any]]:
    """Preserve every host-level OS observation from Nmap for fallback consumers."""
    identities: list[dict[str, Any]] = []
    for osmatch in host.findall("os/osmatch"):
        name = osmatch.get("name", "")
        match_accuracy = osmatch.get("accuracy", "")
        classes = osmatch.findall("osclass") or [None]
        for osclass in classes:
            cpes = [] if osclass is None else [_text(cpe) for cpe in osclass.findall("cpe") if _text(cpe)]
            identities.append({
                "scope": "host_os",
                "name": name,
                "vendor": "" if osclass is None else osclass.get("vendor", ""),
                "family": "" if osclass is None else osclass.get("osfamily", ""),
                "generation": "" if osclass is None else osclass.get("osgen", ""),
                "device_type": "" if osclass is None else osclass.get("type", ""),
                "accuracy": ("" if osclass is None else osclass.get("accuracy", "")) or match_accuracy,
                "cpe": cpes,
                "source": "nmap_os_detection",
                "evidence_kind": "probabilistic_fingerprint",
            })

    for script in parse_host_scripts(host):
        if str(script.get("id") or "").lower() != "smb-os-discovery":
            continue
        elems = script.get("elements") or {}
        os_name = str(elems.get("os") or elems.get("OS") or "").strip()
        if os_name:
            identities.append({
                "scope": "host_os",
                "name": os_name,
                "product": os_name,
                "source": "smb-os-discovery",
                "accuracy": "script",
                "cpe": [],
            })

    for service in host.findall("ports/port/service"):
        ostype = service.get("ostype", "")
        product = service.get("product", "")
        os_cpes = [
            _text(cpe) for cpe in service.findall("cpe")
            if _text(cpe).startswith(("cpe:/o:", "cpe:2.3:o:"))
        ]
        if ostype or os_cpes:
            identities.append({
                "scope": "host_os",
                "name": product if product and ostype and ostype.lower() in product.lower() else ostype,
                "product": product if product and ostype and ostype.lower() in product.lower() else ostype,
                "cpe": os_cpes,
                "source": "nmap_service_identity",
                "evidence_kind": "service_os_hint",
                "accuracy": "service",
            })
    return identities


def parse_cpe(service: ET.Element | None) -> list[str]:
    if service is None:
        return []
    return [_text(cpe) for cpe in service.findall("cpe") if _text(cpe)]


def classify_port_state(state: str) -> str:
    if state == "open":
        return "Accessible service detected"
    if state == "filtered":
        return "Likely blocked by firewall or packet filtering"
    if state == "open|filtered":
        return "No decisive response; endpoint remains open-or-filtered until recovery evidence resolves it"
    if state == "closed":
        return "Host reachable, but no service listening"
    return "Unknown port state"


def parse_ports(host: ET.Element) -> list[dict[str, Any]]:
    findings = []

    for port in host.findall("ports/port"):
        state_element = port.find("state")
        service = port.find("service")
        state = _attr(state_element, "state", "unknown")

        if state not in {"open", "open|filtered", "filtered", "closed"}:
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
        "total_open_filtered_ports": 0,
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
            "os_identities": parse_os_identities(host),
            "host_scripts": parse_host_scripts(host),
            "open_ports": [p for p in port_findings if p["state"] == "open"],
            "filtered_ports": [p for p in port_findings if p["state"] == "filtered"],
            "open_filtered_ports": [p for p in port_findings if p["state"] == "open|filtered"],
            "closed_ports": [p for p in port_findings if p["state"] == "closed"],
            "port_findings": port_findings,
        }

        for item in port_findings:
            if item["state"] == "open":
                results["total_open_ports"] += 1
            elif item["state"] == "filtered":
                results["total_filtered_ports"] += 1
            elif item["state"] == "open|filtered":
                results["total_open_filtered_ports"] += 1
            elif item["state"] == "closed":
                results["total_closed_ports"] += 1

            service_name = item.get("service") or "unknown"
            results["services"][service_name] = results["services"].get(service_name, 0) + 1

        results["total_reported_ports"] += len(port_findings)
        results["hosts"].append(host_data)

    if results["hosts"]:
        first_host = results["hosts"][0]
        results["os"] = first_host["os"]["name"]
        results["ports"] = first_host["port_findings"]
    else:
        results["os"] = "Unknown"
        results["ports"] = []
    return results
