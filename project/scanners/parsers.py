from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_XML_TAG_RE = re.compile(
    r"<(?![!?])(?P<closing>/)?(?P<name>[A-Za-z_][\w:.-]*)(?:\s[^<>]*?)?(?P<selfclose>/)?>",
    re.DOTALL,
)


def _read_text(path: str | Path) -> tuple[str, list[str]]:
    """Read a tool output file without discarding undecodable evidence."""
    warnings: list[str] = []
    output_path = Path(path)
    try:
        raw = output_path.read_bytes()
    except OSError as exc:
        return "", [f"Unable to read output file: {exc}"]

    if not raw:
        return "", ["Empty output file: scan may have failed"]

    try:
        return raw.decode("utf-8"), warnings
    except UnicodeDecodeError as exc:
        text = raw.decode("utf-8", errors="replace").replace("\ufffd", "?")
        warnings.append(
            f"Encoding error at byte {exc.start}: invalid UTF-8 replaced with '?'"
        )
        return text, warnings


def _attribute(fragment: str, name: str, default: str = "") -> str:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*(?:\"([^\"]*)\"|'([^']*)')",
        fragment,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return default
    return match.group(1) if match.group(1) is not None else match.group(2)


def _script_output(script_el: ET.Element) -> str:
    parts: list[str] = []
    if script_el.get("output"):
        parts.append(script_el.get("output") or "")
    for node in script_el.iter():
        if node is script_el:
            continue
        if node.text and node.text.strip():
            parts.append(node.text.strip())
        for value in node.attrib.values():
            if value and str(value).strip():
                parts.append(str(value).strip())
    return " ".join(parts)


def _empty_nmap_data(path: str | Path, status: str = "failed") -> dict[str, Any]:
    return {
        "scan_file": str(path),
        "parser_status": status,
        "partial": status == "partial",
        "hosts": [],
        "ports": [],
        "services": [],
        "extraports": [],
    }


def _service_details(
    service_el: ET.Element | None,
    scripts: list[dict[str, str]],
) -> tuple[str, str, str, str, list[str]]:
    service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
    product = service_el.get("product", "") if service_el is not None else ""
    version = service_el.get("version", "") if service_el is not None else ""
    extra = service_el.get("extrainfo", "") if service_el is not None else ""
    cpes = (
        [node.text for node in service_el.findall("cpe") if node.text]
        if service_el is not None
        else []
    )

    script_text = " ".join(str(item.get("output", "")) for item in scripts)
    if product.lower() == "unrealircd" and not version:
        match = re.search(
            r"Unreal(?:IRCd)?\s*([0-9]+(?:\.[0-9]+){2,})", script_text, re.I
        )
        if match:
            version = match.group(1)
    return service_name, product, version, extra, cpes


def _port_row(
    port_el: ET.Element,
    host_ip: str,
    path: str | Path,
    protocol_hint: str,
) -> dict[str, Any]:
    state_el = port_el.find("state")
    service_el = port_el.find("service")
    scripts = [
        {"id": script.get("id", ""), "output": _script_output(script)}
        for script in port_el.findall("script")
    ]
    service_name, product, version, extra, cpes = _service_details(service_el, scripts)
    try:
        port_number = int(port_el.get("portid") or 0)
    except (TypeError, ValueError):
        port_number = 0
    return {
        "host": host_ip,
        "port": port_number,
        "portid": str(port_el.get("portid") or ""),
        "protocol": port_el.get("protocol") or protocol_hint,
        "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
        "reason": state_el.get("reason", "") if state_el is not None else "",
        "reason_ttl": state_el.get("reason_ttl", "") if state_el is not None else "",
        "service": service_name,
        "product": product,
        "version": version,
        "extra": extra,
        "tunnel": service_el.get("tunnel", "") if service_el is not None else "",
        "fingerprint_method": service_el.get("method", "") if service_el is not None else "",
        "fingerprint_confidence": service_el.get("conf", "") if service_el is not None else "",
        "cpe": cpes,
        "evidence_sources": ["nmap"],
        "raw_evidence_file": str(path),
        "scripts": scripts,
    }


def _parse_root(
    root: ET.Element,
    path: str | Path,
    protocol_hint: str,
) -> dict[str, Any]:
    data = _empty_nmap_data(path, "success")
    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        host_ip = addr_el.get("addr", "") if addr_el is not None else ""
        status_el = host_el.find("status")
        host_data: dict[str, Any] = {
            "address": host_ip,
            "status": status_el.get("state", "unknown") if status_el is not None else "unknown",
            "status_reason": status_el.get("reason", "") if status_el is not None else "",
            "hostnames": [
                node.get("name", "")
                for node in host_el.findall("hostnames/hostname")
                if node.get("name")
            ],
            "ports": [],
        }
        for extra_el in host_el.findall("ports/extraports"):
            try:
                count = int(extra_el.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            extra_row = {
                "host": host_ip,
                "protocol": protocol_hint,
                "state": extra_el.get("state", "unknown"),
                "count": count,
                "reasons": [
                    {
                        "reason": reason.get("reason", ""),
                        "count": int(reason.get("count") or 0),
                    }
                    for reason in extra_el.findall("extrareasons")
                    if str(reason.get("count") or "0").isdigit()
                ],
            }
            data["extraports"].append(extra_row)
        for port_el in host_el.findall("ports/port"):
            row = _port_row(port_el, host_ip, path, protocol_hint)
            host_data["ports"].append(row)
            data["ports"].append(row)
            if row["state"] == "open":
                data["services"].append(dict(row))
        data["hosts"].append(host_data)
    return data


def _repair_truncated_xml(text: str) -> str:
    """Close a trailing incomplete tag and any still-open XML elements."""
    repaired = text
    last_lt = repaired.rfind("<")
    last_gt = repaired.rfind(">")
    if last_lt > last_gt:
        fragment = repaired[last_lt:]
        if re.match(r"</?[A-Za-z_][\w:.-]*(?:\s+[^<>]*)?$", fragment, re.DOTALL):
            repaired += ">" if fragment.startswith("</") else "/>"
        else:
            repaired = repaired[:last_lt]

    stack: list[str] = []
    for match in _XML_TAG_RE.finditer(repaired):
        name = match.group("name")
        if match.group("selfclose"):
            continue
        if match.group("closing"):
            if name in stack:
                while stack and stack[-1] != name:
                    stack.pop()
                if stack:
                    stack.pop()
            continue
        stack.append(name)
    if stack:
        repaired += "".join(f"</{name}>" for name in reversed(stack))
    return repaired


def _manual_port_row(
    segment: str,
    prefix: str,
    path: str | Path,
    protocol_hint: str,
) -> dict[str, Any] | None:
    port_start = re.search(r"<port\b(?P<attrs>[^>]*)", segment, re.I | re.S)
    if not port_start:
        return None
    attrs = port_start.group("attrs")
    portid = _attribute(attrs, "portid")
    if not portid.isdigit():
        return None
    protocol = _attribute(attrs, "protocol", protocol_hint)
    state_match = re.search(r"<state\b(?P<attrs>[^>]*)", segment, re.I | re.S)
    state_attrs = state_match.group("attrs") if state_match else ""
    service_match = re.search(r"<service\b(?P<attrs>[^>]*)", segment, re.I | re.S)
    service_attrs = service_match.group("attrs") if service_match else ""
    address_matches = list(re.finditer(r"<address\b(?P<attrs>[^>]*)", prefix, re.I | re.S))
    host_ip = ""
    if address_matches:
        ipv4 = [
            item
            for item in address_matches
            if _attribute(item.group("attrs"), "addrtype").lower() == "ipv4"
        ]
        selected = ipv4[-1] if ipv4 else address_matches[-1]
        host_ip = _attribute(selected.group("attrs"), "addr")

    scripts: list[dict[str, str]] = []
    for script_match in re.finditer(
        r"<script\b(?P<attrs>[^>]*?)(?:/>|>(?P<body>.*?)</script>)",
        segment,
        re.I | re.S,
    ):
        script_attrs = script_match.group("attrs")
        output = _attribute(script_attrs, "output")
        if script_match.group("body"):
            body = re.sub(r"<[^>]+>", " ", script_match.group("body"))
            output = " ".join(part for part in (output, body.strip()) if part)
        scripts.append({"id": _attribute(script_attrs, "id"), "output": output})

    product = _attribute(service_attrs, "product")
    version = _attribute(service_attrs, "version")
    cpes = re.findall(r"<cpe>\s*([^<]+?)\s*</cpe>", segment, re.I | re.S)
    script_text = " ".join(item["output"] for item in scripts)
    if product.lower() == "unrealircd" and not version:
        match = re.search(r"Unreal(?:IRCd)?\s*([0-9]+(?:\.[0-9]+){2,})", script_text, re.I)
        if match:
            version = match.group(1)
    return {
        "host": host_ip,
        "port": int(portid),
        "portid": portid,
        "protocol": protocol,
        "state": _attribute(state_attrs, "state", "unknown"),
        "reason": _attribute(state_attrs, "reason"),
        "reason_ttl": _attribute(state_attrs, "reason_ttl"),
        "service": _attribute(service_attrs, "name", "unknown"),
        "product": product,
        "version": version,
        "extra": _attribute(service_attrs, "extrainfo"),
        "cpe": cpes,
        "evidence_sources": ["nmap"],
        "raw_evidence_file": str(path),
        "scripts": scripts,
    }


def _recover_ports(
    text: str,
    path: str | Path,
    protocol_hint: str,
) -> list[dict[str, Any]]:
    starts = list(re.finditer(r"<port\b", text, re.I))
    recovered: list[dict[str, Any]] = []
    for index, start in enumerate(starts):
        next_start = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        closing = text.find("</port>", start.start(), next_start)
        end = closing + len("</port>") if closing >= 0 else next_start
        host_start = text.rfind("<host", 0, start.start())
        prefix = text[host_start:start.start()] if host_start >= 0 else text[: start.start()]
        row = _manual_port_row(text[start.start():end], prefix, path, protocol_hint)
        if row:
            recovered.append(row)
    return recovered


def _merge_recovered_ports(data: dict[str, Any], recovered: list[dict[str, Any]]) -> None:
    index = {
        (str(row.get("host")), str(row.get("protocol")), int(row.get("port") or 0)): row
        for row in data.get("ports", [])
    }
    for row in recovered:
        key = (str(row.get("host")), str(row.get("protocol")), int(row.get("port") or 0))
        if key not in index:
            data["ports"].append(row)
            index[key] = row
        else:
            current = index[key]
            for field in ("state", "reason", "service", "product", "version", "extra"):
                if (not current.get(field) or current.get(field) == "unknown") and row.get(field):
                    current[field] = row[field]
    data["services"] = [dict(row) for row in data["ports"] if row.get("state") == "open"]


def parse_nmap_xml(
    xml_path: str | Path,
    strict: bool = False,
    protocol_hint: str = "tcp",
) -> tuple[dict[str, Any], list[str]]:
    """Parse Nmap XML while retaining recoverable evidence and diagnostics.

    The returned dictionary contains ``ports`` for every reported state and
    ``services`` for confirmed-open ports. In non-strict mode, truncated XML is
    repaired where possible and incomplete port elements are recovered.

    >>> data, warnings = parse_nmap_xml("missing.xml")
    >>> data["parser_status"]
    'failed'
    >>> bool(warnings)
    True
    """
    path = Path(xml_path)
    if not str(xml_path) or not path.exists():
        if strict:
            raise FileNotFoundError(f"Nmap XML file not found: {path}")
        return _empty_nmap_data(path), [f"Nmap XML file not found: {path}"]

    text, warnings = _read_text(path)
    if not text.strip():
        if strict:
            raise ValueError("Empty Nmap XML output")
        return _empty_nmap_data(path), warnings or ["Empty output file: scan may have failed"]

    truncated = "<nmaprun" in text and "</nmaprun>" not in text
    unclosed_ports = max(0, len(re.findall(r"<port\b", text, re.I)) - len(re.findall(r"</port>", text, re.I)))
    if truncated:
        warnings.append("XML file is truncated: missing closing </nmaprun> tag")
    if unclosed_ports:
        warnings.append(f"XML truncated: missing closing tags for {unclosed_ports} ports")

    try:
        root = ET.fromstring(text)
        data = _parse_root(root, path, protocol_hint)
    except ET.ParseError as exc:
        if strict:
            raise
        warnings.append(f"XML parse error: {exc}; attempting partial recovery")
        data = _empty_nmap_data(path, "partial")
        repaired = _repair_truncated_xml(text)
        try:
            root = ET.fromstring(repaired)
            data = _parse_root(root, path, protocol_hint)
            data["parser_status"] = "partial"
            data["partial"] = True
        except ET.ParseError as recovery_exc:
            warnings.append(f"XML recovery parse error: {recovery_exc}; recovered complete port attributes only")
        _merge_recovered_ports(data, _recover_ports(text, path, protocol_hint))

    if truncated:
        data["parser_status"] = "partial"
        data["partial"] = True
        _merge_recovered_ports(data, _recover_ports(text, path, protocol_hint))

    if not data.get("ports"):
        if data.get("hosts") or "</nmaprun>" in text:
            data["parser_status"] = "empty" if data["parser_status"] == "success" else data["parser_status"]
            warnings.append("No ports found in output; scan completed without reported ports")
        else:
            data["parser_status"] = "failed" if data["parser_status"] != "partial" else "partial"
            warnings.append("No ports found in output; scan may have failed")
    return data, list(dict.fromkeys(warnings))


def parse_httpx_jsonl(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse ProjectDiscovery httpx JSONL and report malformed lines."""
    text, warnings = _read_text(path)
    rows: list[dict[str, Any]] = []
    malformed = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except (TypeError, ValueError) as exc:
            malformed += 1
            if malformed <= 10:
                warnings.append(f"Malformed httpx JSON at line {line_number}: {exc}")
            continue
        if not isinstance(data, dict):
            malformed += 1
            if malformed <= 10:
                warnings.append(f"Malformed httpx JSON at line {line_number}: expected an object")
            continue
        rows.append(
            {
                "url": data.get("url") or data.get("input"),
                "host": data.get("host", ""),
                "port": data.get("port"),
                "title": data.get("title", ""),
                "status_code": data.get("status_code"),
                "tech": data.get("tech") or [],
                "webserver": data.get("webserver", ""),
                "raw_evidence_file": str(path),
            }
        )
    if malformed > 10:
        warnings.append(f"{malformed - 10} additional malformed httpx lines were skipped")
    if text.strip() and not rows:
        warnings.append("No valid httpx records found; tool output may be malformed or incomplete")
    return rows, list(dict.fromkeys(warnings))


def parse_simple_lines(path: str | Path) -> tuple[list[str], list[str]]:
    text, warnings = _read_text(path)
    return [line.strip() for line in text.splitlines() if line.strip()], warnings


def parse_gobuster(
    path: str | Path,
    host: str = "",
    port: int | str | None = None,
    scheme: str = "http",
) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse Gobuster output while retaining partial results and warnings."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    text, warnings = _read_text(path)
    pattern = re.compile(
        r"^\s*(?P<raw>/?[\w.\-~/:%]+)\s+\(Status:\s*(?P<status>\d{3})\)"
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
        r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?",
        re.I,
    )
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        raw_path = match.group("raw").strip()
        if raw_path.startswith(("http://", "https://")):
            parsed = urlparse(raw_path)
            web_path = parsed.path or "/"
        else:
            web_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        status = int(match.group("status")) if match.group("status") else None
        key = (web_path, status)
        if key in seen:
            continue
        seen.add(key)
        size = match.group("size")
        url = ""
        if host and port:
            default_port = (scheme == "http" and str(port) == "80") or (
                scheme == "https" and str(port) == "443"
            )
            authority = str(host) if default_port else f"{host}:{port}"
            url = f"{scheme}://{authority}{web_path}"
        rows.append(
            {
                "host": host,
                "port": int(port) if str(port or "").isdigit() else port,
                "path": web_path,
                "url": url,
                "status_code": status,
                "size": int(size) if size and size.isdigit() else None,
                "redirect": (match.group("redirect") or "").strip(),
                "raw_evidence_file": str(path),
                "evidence_sources": ["gobuster"],
            }
        )
    if "timeout" in text.lower():
        warnings.append("Gobuster timed out; partial results were retained")
    if text.strip() and not rows:
        diagnosis = detect_tool_error("", text, "gobuster")
        warnings.append(diagnosis or "No Gobuster path records found")
    return rows, list(dict.fromkeys(warnings))


def detect_tool_error(stderr: str, stdout: str, tool_name: str) -> str | None:
    """Return a stable diagnosis for common scanner error signatures.

    The function classifies captured output only; it never infers a failure from
    the absence of a finding alone.

    >>> detect_tool_error("Permission denied", "", "nmap")
    'Nmap requires elevated privileges (run with sudo)'
    >>> detect_tool_error("", "scan complete", "nmap") is None
    True
    """
    combined = f"{stderr or ''}\n{stdout or ''}".lower()
    tool = Path(str(tool_name or "")).name.lower()

    if tool in {"nmap", "nmap.exe"}:
        if "permission denied" in combined or "requires root privileges" in combined:
            return "Nmap requires elevated privileges (run with sudo)"
        if "could not resolve hostname" in combined or "failed to resolve" in combined:
            return "Target hostname could not be resolved"
        if "no ports found" in combined or "0 hosts up" in combined:
            return "No open ports discovered (host may be unreachable)"
        if "read timed out" in combined or "timed out" in combined:
            return "Scan timed out; partial results may be available"
        if "failed to open device" in combined or "dnet: failed to open device" in combined:
            return "Nmap could not access the selected network interface"
        if "illegal option" in combined or "unrecognized option" in combined:
            return "Nmap command contains an unsupported option"

    if tool in {"gobuster", "gobuster.exe"}:
        if "error on line 1" in combined or "no such file" in combined:
            return "Wordlist file not found; check GOBUSTER_WORDLIST config"
        if "connection refused" in combined:
            return "HTTP service not responding"
        if "no such host" in combined or "could not resolve" in combined:
            return "Target hostname could not be resolved"
        if "timeout" in combined or "context deadline exceeded" in combined:
            return "HTTP discovery timed out; partial results may be available"

    if tool in {"httpx", "httpx-toolkit", "httpx.exe"}:
        if "connection refused" in combined:
            return "HTTP service not responding"
        if "no such host" in combined or "could not resolve" in combined:
            return "Target hostname could not be resolved"
        if "timeout" in combined or "deadline exceeded" in combined:
            return "HTTP probe timed out; partial results may be available"
        if "unknown flag" in combined or "flag provided but not defined" in combined:
            return "Installed httpx does not support the requested options"

    if tool in {"ssh-audit", "ssh-audit.py"}:
        if "connection refused" in combined:
            return "SSH service not responding"
        if "timed out" in combined or "timeout" in combined:
            return "SSH cryptographic probe timed out"
        if "name or service not known" in combined or "could not resolve" in combined:
            return "Target hostname could not be resolved"

    if tool in {"curl", "curl.exe"}:
        if "failed to connect" in combined or "connection refused" in combined:
            return "HTTP service not responding"
        if "could not resolve host" in combined:
            return "Target hostname could not be resolved"
        if "operation timed out" in combined:
            return "HTTP request timed out; partial headers may be available"

    return None
