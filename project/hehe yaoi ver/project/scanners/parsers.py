
from __future__ import annotations
import json, re, xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

def _text(path: str) -> str:
    try: return Path(path).read_text(encoding='utf-8', errors='ignore')
    except Exception: return ''


def _script_output(script_el: ET.Element) -> str:
    parts = []
    if script_el.get('output'):
        parts.append(script_el.get('output') or '')
    for node in script_el.iter():
        if node is script_el:
            continue
        if node.text and node.text.strip():
            parts.append(node.text.strip())
        for value in node.attrib.values():
            if value and str(value).strip():
                parts.append(str(value).strip())
    return ' '.join(parts)

def parse_nmap_xml(path: str, protocol_hint: str = 'tcp') -> list[dict[str, Any]]:
    if not path or not Path(path).exists(): return []
    try: root = ET.parse(path).getroot()
    except Exception: return []
    rows=[]
    for host in root.findall('host'):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find('address')
        host_ip = addr_el.get('addr') if addr_el is not None else ''
        for port in host.findall('.//port'):
            state_el = port.find('state')
            if state_el is None or state_el.get('state') != 'open': continue
            service_el = port.find('service')
            scripts = []
            for s in port.findall('script'):
                scripts.append({'id': s.get('id',''), 'output': _script_output(s)})
            cpes = [c.text for c in port.findall('service/cpe') if c.text] if service_el is not None else []
            service_name = service_el.get('name','unknown') if service_el is not None else 'unknown'
            product = service_el.get('product','') if service_el is not None else ''
            version = service_el.get('version','') if service_el is not None else ''
            extra = service_el.get('extrainfo','') if service_el is not None else ''
            script_text = ' '.join(str(x.get('output','')) for x in scripts)
            # Some services expose the real version only inside NSE script output
            # rather than the <service version=...> attribute. Keep this generic
            # and evidence-driven: infer only when the product name and script text
            # both contain a clear product/version marker.
            if product.lower() == 'unrealircd' and not version:
                match = re.search(r'Unreal(?:IRCd)?\s*([0-9]+(?:\.[0-9]+){2,})', script_text, re.I)
                if match:
                    version = match.group(1)
            if product.lower() == 'unrealircd' and version and not cpes:
                cpes.append(f'cpe:/a:unrealircd:unrealircd:{version}')


            rows.append({
                'host': host_ip,
                'port': int(port.get('portid') or 0),
                'protocol': port.get('protocol') or protocol_hint,
                'service': service_name,
                'product': product,
                'version': version,
                'extra': extra,
                'cpe': cpes,
                'evidence_sources': ['nmap'],
                'raw_evidence_file': path,
                'scripts': scripts,
            })
    return rows

def parse_httpx_jsonl(path: str) -> list[dict[str, Any]]:
    rows=[]
    for line in _text(path).splitlines():
        try: d=json.loads(line)
        except Exception: continue
        rows.append({'url':d.get('url') or d.get('input'), 'host':d.get('host',''), 'port':d.get('port'), 'title':d.get('title',''), 'status_code':d.get('status_code'), 'tech':d.get('tech') or [], 'webserver':d.get('webserver',''), 'raw_evidence_file':path})
    return rows

def parse_simple_lines(path: str) -> list[str]:
    return [l.strip() for l in _text(path).splitlines() if l.strip()]


def parse_gobuster(path: str, host: str = '', port: int | str | None = None, scheme: str = 'http') -> list[dict[str, Any]]:
    """Parse Gobuster/dir output into observed web paths.

    Parser is deliberately tolerant so partial output is preserved when the
    command times out. It extracts only paths/status/size/redirect evidence;
    it does not infer vulnerabilities or run follow-up requests.
    """
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    text = _text(path)
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
        raw_path = match.group('raw').strip()
        if raw_path.startswith(('http://', 'https://')):
            # Keep just the URL path if gobuster printed an absolute URL.
            from urllib.parse import urlparse
            parsed = urlparse(raw_path)
            web_path = parsed.path or '/'
        else:
            web_path = raw_path if raw_path.startswith('/') else f'/{raw_path}'
        status = int(match.group('status')) if match.group('status') else None
        key = (web_path, status)
        if key in seen:
            continue
        seen.add(key)
        size = match.group('size')
        url = ''
        if host and port:
            default_port = (scheme == 'http' and str(port) == '80') or (scheme == 'https' and str(port) == '443')
            authority = str(host) if default_port else f'{host}:{port}'
            url = f'{scheme}://{authority}{web_path}'
        rows.append({
            'host': host,
            'port': int(port) if str(port or '').isdigit() else port,
            'path': web_path,
            'url': url,
            'status_code': status,
            'size': int(size) if size and size.isdigit() else None,
            'redirect': (match.group('redirect') or '').strip(),
            'raw_evidence_file': path,
            'evidence_sources': ['gobuster'],
        })
    return rows
