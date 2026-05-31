
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

            # Some Nmap service probes report UnrealIRCd only in irc-info/banner
            # script output instead of the structured <service version=> field.
            # Preserve it as normal product/version evidence so official CVE
            # matching can evaluate CVE-2010-2075 from collected banner data.
            unreal = re.search(r'Unreal(?:IRCd)?\s*([0-9]+(?:\.[0-9]+){2,4})', ' '.join([product, version, extra, script_text]), flags=re.I)
            if unreal:
                product = product or 'UnrealIRCd'
                version = version or unreal.group(1)
                cpe_value = f'cpe:/a:unrealircd:unrealircd:{version}'
                if cpe_value not in cpes:
                    cpes.append(cpe_value)

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

def parse_gobuster(path: str, host: str, port: int) -> list[dict[str, Any]]:
    out=[]
    for line in _text(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('=') or stripped.startswith('['):
            continue
        m=re.search(r'^(?P<path>/?[^\s]+)\s+\(Status:\s*(?P<status>\d+).*?Size:\s*(?P<size>[0-9]+)', stripped)
        if m:
            path_value = m.group('path')
            if not path_value.startswith('/'):
                path_value = '/' + path_value
            out.append({'host':host,'port':port,'tool':'gobuster','path':path_value,'status_code':m.group('status'),'size':m.group('size'),'raw_evidence_file':path})
    return out

def parse_httpx_jsonl(path: str) -> list[dict[str, Any]]:
    rows=[]
    for line in _text(path).splitlines():
        try: d=json.loads(line)
        except Exception: continue
        rows.append({'url':d.get('url') or d.get('input'), 'host':d.get('host',''), 'port':d.get('port'), 'title':d.get('title',''), 'status_code':d.get('status_code'), 'tech':d.get('tech') or [], 'webserver':d.get('webserver',''), 'raw_evidence_file':path})
    return rows

def parse_simple_lines(path: str) -> list[str]:
    return [l.strip() for l in _text(path).splitlines() if l.strip()]
