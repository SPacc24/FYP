
from __future__ import annotations
import json, os, re, ipaddress, contextvars, threading, logging
from pathlib import Path
from typing import Any
from storage import scan_store
from config import Config
from .targets import expand_target_input, is_private_ip
from .tooling import which, outfile, run_cmd as _run_cmd
from .parsers import parse_nmap_xml, parse_gobuster, parse_httpx_jsonl, parse_simple_lines
from .mitre_cve import OFFICIAL_CVE_SOURCE, search_with_held as mitre_search_with_held, status as mitre_status
from .scan_profiles import normalise_scan_options, is_tool_enabled


_CURRENT_SCAN_ID = contextvars.ContextVar('current_scan_id', default='')

logger = logging.getLogger(__name__)

def _describe_command(cmd: list[str]) -> str:
    if not cmd:
        return 'No command executed.'
    exe = Path(str(cmd[0])).name.lower()
    joined = ' '.join(map(str, cmd)).lower()

    # Specific nmap script checks must be evaluated before generic -sV wording.
    if 'nmap' in exe and '--script' in cmd:
        script_text = joined
        if 'http-title' in script_text or 'http-headers' in script_text or 'http-enum' in script_text:
            if 'http-auth-finder' in script_text:
                return 'Checked Tomcat/HTTP titles, headers, auth hints, and exposed paths.'
            return 'Collected HTTP titles, headers, server banners, and known path evidence.'
        if 'ftp-anon' in script_text or 'ftp-syst' in script_text:
            return 'Checked FTP banner, anonymous-login, and system evidence.'
        if 'telnet-' in script_text:
            return 'Checked Telnet service exposure and protocol/security hints.'
        if 'smtp-commands' in script_text or 'smtp-open-relay' in script_text:
            return 'Checked SMTP commands, banner behaviour, and open-relay indication.'
        if 'dns-recursion' in script_text or 'dns-zone-transfer' in script_text or 'dns-nsid' in script_text:
            return 'Checked DNS recursion, NSID, and zone-transfer evidence.'
        if 'smb-enum' in script_text or 'smb-protocols' in script_text or 'smb-security-mode' in script_text:
            return 'Checked SMB shares, users, protocol, OS, and security-mode evidence.'
        if 'nfs-' in script_text or 'rpcinfo' in script_text:
            return 'Checked RPC/NFS program, export, and filesystem exposure evidence.'
        if 'rmi-dumpregistry' in script_text:
            return 'Checked Java RMI registry exposure evidence.'
        if 'mysql-' in script_text:
            return 'Checked MySQL information and empty-password evidence.'
        if 'pgsql-' in script_text or 'postgres' in script_text:
            return 'Checked PostgreSQL version and authentication exposure evidence.'
        if 'vnc-info' in script_text:
            return 'Checked VNC protocol and authentication evidence.'
        if 'x11-access' in script_text:
            return 'Checked X11 access-control exposure evidence.'
        if 'irc-info' in script_text:
            return 'Checked IRC banner and server information evidence.'
        if 'ajp-' in script_text:
            return 'Checked AJP headers and method exposure evidence.'
        if 'banner' in script_text:
            return 'Re-probed service banner evidence for exposed or unknown services.'

    if 'nmap' in exe and '-sn' in cmd:
        return 'Checked which target hosts are reachable.'
    if 'nmap' in exe and '-sU' in cmd:
        return 'Enumerated common UDP services.'
    if 'nmap' in exe and '-p-' in cmd:
        return 'Discovered open TCP ports across the full TCP range.'
    if 'nmap' in exe and '-sV' in cmd:
        return 'Fingerprinting service names, products, versions, and CPE evidence.'
    if exe == 'dig':
        return 'Looked up reverse DNS information for the target.'
    if exe in {'mtr','traceroute'}:
        return 'Captured the network route path to the target.'
    if exe == 'arp-scan':
        return 'Checked local ARP visibility for the target address or local range.'
    if exe in {'httpx', 'httpx-toolkit'}:
        return 'Probed HTTP service details such as status, title, server, and technology hints.'
    if exe == 'gobuster':
        return 'Enumerated web paths using the configured directory wordlist.'
    if exe == 'enum4linux-ng':
        return 'Enumerated SMB/NetBIOS information such as shares, users, domain, and OS hints.'
    if exe == 'smbclient':
        return 'Checked anonymous SMB share listing visibility.'
    if exe == 'smbmap':
        return 'Mapped SMB share visibility and permissions.'
    if exe == 'snmpwalk':
        return 'Attempted SNMP enumeration using the configured community string.'
    if exe == 'ssh-audit':
        return 'Collected SSH algorithm and configuration evidence.'
    if exe == 'ldapsearch':
        return 'Queried LDAP naming context information.'
    if exe == 'sslscan':
        return 'Collected TLS certificate and cipher evidence.'
    if exe == 'rdpscan':
        return 'Checked RDP-specific security evidence.'
    if exe == 'hydra':
        return 'Checked configured default credential exposure evidence.'
    if exe == 'rpcinfo':
        return 'Collected RPC program mapping evidence.'
    if exe == 'showmount':
        return 'Collected NFS export visibility evidence.'
    if exe == 'jq':
        return 'Formatted the normalised JSON evidence package.'
    return 'Executed enumeration command.'

def _text_has_ssh_audit_evidence(text: str) -> bool:
    evidence_tokens = [
        'algorithm to remove', 'key algorithm', 'enc algorithm', 'mac algorithm',
        'kex algorithm', 'ssh2', 'banner', 'recommendations', 'fingerprint',
        'cipher', 'server policy'
    ]
    lowered = (text or '').lower()
    return any(token in lowered for token in evidence_tokens)

def _result_has_output_evidence(result: dict[str, Any], output_file: Path | None = None) -> bool:
    text = ' '.join(str(result.get(k) or '') for k in ('stdout', 'stderr', 'error'))
    if output_file and Path(output_file).exists():
        try:
            text += '\n' + Path(output_file).read_text(encoding='utf-8', errors='ignore')[:12000]
        except Exception:
            pass
    return bool(text.strip())


def _coerce_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def _captured_command_output(result: dict[str, Any], output_file: Path | None = None, limit: int = 200000) -> tuple[str, bool]:
    """Return real captured command output for the UI command log."""
    parts: list[str] = []
    stdout = _coerce_text(result.get('stdout') or '')
    stderr = _coerce_text(result.get('stderr') or '')
    if stdout.strip():
        parts.append(stdout.rstrip())
    if stderr.strip():
        parts.append('[stderr]\n' + stderr.rstrip())
    path_value = output_file or result.get('output_file') or ''
    path = Path(path_value) if path_value else None
    if path and path.exists():
        try:
            file_text = path.read_text(encoding='utf-8', errors='ignore')
            current = '\n'.join(parts)
            if file_text.strip() and file_text.strip() not in current:
                parts.append(f'[evidence file: {path}]\n' + file_text.rstrip())
        except Exception as exc:
            parts.append(f'[evidence file: {path}]\nUnable to read evidence file: {exc}')
    output = '\n\n'.join(parts).strip()
    if not output:
        output = '[no console output captured]'
    truncated = len(output) > limit
    if truncated:
        output = output[:limit] + f"\n\n[output display truncated; full evidence file: {path or result.get('output_file') or 'not available'}]"
    return output, truncated

def run_cmd(cmd: list[str], output_file: Path | None = None, timeout: int = 300, tool_writes_file: bool = False) -> dict[str, Any]:
    sid = _CURRENT_SCAN_ID.get()
    command_text = ' '.join(map(str, cmd))
    exe = Path(str(cmd[0])).name.lower() if cmd else ''
    purpose = _describe_command(cmd)
    result = _run_cmd(cmd, output_file=output_file, timeout=timeout, tool_writes_file=tool_writes_file)

    if exe == 'ssh-audit' and not result.get('success'):
        combined = ' '.join(str(result.get(k) or '') for k in ('stdout', 'stderr', 'error'))
        if output_file and Path(output_file).exists():
            try:
                combined += '\n' + Path(output_file).read_text(encoding='utf-8', errors='ignore')[:12000]
            except Exception:
                pass
        if _text_has_ssh_audit_evidence(combined):
            result = dict(result)
            result['success'] = True
            result['status'] = 'success'
            result['error'] = ''
            result['stderr'] = result.get('stderr', '')

    if sid:
        output, truncated = _captured_command_output(result, output_file)
        status = 'Completed' if result.get('success') else ('Timed Out' if str(result.get('error','')).lower() == 'timeout' else 'Failed')
        scan_store.log_command(
            sid,
            command=command_text,
            purpose=purpose,
            output=output,
            status=status,
            exit_code=result.get('returncode',''),
            output_file=str(output_file or result.get('output_file') or ''),
            output_truncated=truncated,
        )
        if not result.get('success'):
            err = (result.get('error') or result.get('stderr') or 'command did not complete successfully')[:220]
            scan_store.log(sid, f'Command did not complete successfully: {err}', 'WARN')
    return result

def _publish_partial(scan_id: str, **kwargs: Any) -> None:
    current = scan_store.get(scan_id) or {}
    results = current.get('results') or {}
    results.update(kwargs)
    scan_store.update(scan_id, results=results)

TASKS = [
    'Target Preparation',
    'Host Availability Check',
    'TCP Service Discovery',
    'Service Fingerprinting',
    'UDP Service Discovery',
    'Web Evidence Collection',
    'SMB Evidence Collection',
    'SSH Configuration Review',
    'Focused Service Checks',
    'Evidence Consolidation',
    'CVE Review',
    'Handoff Preparation',
    'Report Preparation',
]

def _status_from_result(result: dict[str, Any], produced: bool = True) -> str:
    if not result.get('success'): return scan_store.STATUS_FAILED
    return scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY

def _finish(scan_id: str, task: str, status: str, summary: str = '') -> None:
    scan_store.set_task(scan_id, task, status, summary=summary)

def _coverage_display_status(tool: str, raw_status: str, note: str = '', result: dict[str, Any] | None = None) -> str:
    """Return clean user-facing status wording for evidence collection rows.

    A completed command must not be shown as timed out simply because its output
    contains the word "timeout". Timeout/failed states are based on command
    execution state first, then the collected evidence state.
    """
    result = result or {}
    tool_l = (tool or '').lower()
    raw_l = (raw_status or '').lower()
    note_l = (note or '').lower()
    err_l = ' '.join(str(result.get(k) or '') for k in ('stderr', 'error')).lower()
    command_l = str(result.get('command') or '').lower()
    result_success = bool(result.get('success', raw_status != scan_store.STATUS_FAILED))
    returncode = result.get('returncode')

    combined_context = ' '.join([tool_l, raw_l, note_l, err_l, command_l])

    if 'invalid line in colon file' in combined_context or 'missing colon' in combined_context or 'invalid credential combo' in combined_context:
        return 'Input Invalid'
    if tool_l == 'gobuster' and ('timeout' in err_l or result.get('error') == 'timeout'):
        m = re.search(r'(\d+)\s+path\(s\) observed', note_l)
        if m and int(m.group(1)) > 0:
            return 'Partial Results Captured'
    if 'credential wordlist missing' in combined_context or 'wordlist missing' in combined_context or 'configure a credential file' in combined_context:
        return 'Input Missing'
    if 'not available or incompatible' in combined_context or ('fallback' in combined_context and ('not available' in combined_context or 'incompatible' in combined_context)):
        return 'Tool Unavailable - Fallback Used'
    if 'disabled or binary unavailable' in combined_context:
        return 'Tool Disabled or Unavailable'
    if 'binary not found' in combined_context or 'command not found' in combined_context or 'tool binary was not found' in combined_context:
        return 'Tool Unavailable'
    if 'not observed' in combined_context or 'no http/https services observed' in combined_context or 'no smb service observed' in combined_context or 'no ldap service observed' in combined_context or 'no tls service observed' in combined_context or 'no rdp service observed' in combined_context or 'udp/161 not observed' in combined_context:
        return 'Not Applicable'

    if not result_success:
        if returncode == -1 or result.get('error') == 'timeout' or 'command timed out' in err_l or err_l.strip() == 'timeout':
            return 'Timed Out - Incomplete'
        return 'Failed - Incomplete'

    if tool_l == 'gobuster' and ('0 path' in note_l or 'zero path' in note_l):
        return 'No Web Paths Observed'
    if raw_status == scan_store.STATUS_EMPTY:
        return 'No Evidence Observed'
    if raw_status == scan_store.STATUS_SUCCESS:
        return 'Completed'
    return str(raw_status or 'Evidence Status Unknown')


def _coverage(tool: str, status: str, info: str, note: str = '', output_file: str = '', result: dict[str, Any] | None = None) -> dict[str, Any]:
    result = result or {}
    raw_status = status
    display_status = _coverage_display_status(tool, raw_status, note, result)
    stderr = (result.get('stderr') or result.get('error') or '')
    stderr = ' '.join(str(stderr).split())[:260]
    failure = ''
    if display_status.startswith(('Failed', 'Timed Out', 'Input Invalid')):
        if result.get('returncode') == -1 and 'timeout' in str(stderr).lower():
            failure = 'Command timed out.'
        elif 'binary not found' in str(stderr).lower():
            failure = 'Tool binary was not found in PATH.'
        elif stderr:
            failure = stderr
        else:
            failure = f"Command exited with code {result.get('returncode')}"
    output_text, output_truncated = ('', False)
    if result:
        try:
            output_text, output_truncated = _captured_command_output(result, Path(output_file or result.get('output_file','')) if (output_file or result.get('output_file')) else None)
        except Exception:
            output_text, output_truncated = ('', False)
    return {
        'tool': tool,
        'status': display_status,
        'raw_status': raw_status,
        'evidence_type': info,
        'information_added': info,
        'note': note,
        'output_file': output_file or result.get('output_file',''),
        'command': result.get('command',''),
        'output': output_text,
        'output_truncated': output_truncated,
        'exit_code': result.get('returncode',''),
        'stderr_summary': stderr if display_status.startswith(('Failed', 'Timed Out')) else '',
        'failure_reason': failure,
    }

def _add_raw(raw: list[dict[str, Any]], tool: str, host: str = '', port: int | str = '', path: str = '', parser: str = '', parsed: bool = False) -> None:
    raw.append({'tool': tool, 'host': host, 'port': port, 'file': path, 'parser': parser, 'parsed': parsed})

def _url_for(host: str, port: int, tls: bool=False) -> str:
    if tls or port in {443,8443,9443,636,993,995}: scheme='https'
    else: scheme='http'
    return f'{scheme}://{host}:{port}'

def _wordlist() -> str:
    # Prefer smaller, reliable Kali/SecLists wordlists for interactive recon.
    # Larger medium lists remain configurable through GOBUSTER_WORDLIST.
    candidates=[
        os.getenv('GOBUSTER_WORDLIST','').strip(),
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt',
        '/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt',
        Config.GOBUSTER_WORDLIST,
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    ]
    for c in candidates:
        if c and Path(c).exists(): return c
    return Config.GOBUSTER_WORDLIST


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def _extract_samba_versions_from_smb(smb_items: list[dict[str, Any]]) -> dict[str, str]:
    """Return host -> Samba version discovered from SMB tool output.

    Nmap often reports Samba as a broad range like 3.X - 4.X. smbclient and
    enum4linux-ng frequently expose the exact server string in comments,
    e.g. "metasploitable server (Samba 3.0.20-Debian)". That exact version
    must be fed back into CVE matching.
    """
    versions: dict[str, str] = {}
    for item in smb_items:
        host = str(item.get('host') or '')
        if not host:
            continue
        text = '\n'.join(item.get('lines') or [])
        if item.get('output_file'):
            text += '\n' + _read_text(item.get('output_file'))
        m = re.search(r'Samba\s+([0-9][A-Za-z0-9._~:+-]+)', text, flags=re.I)
        if m:
            versions[host] = m.group(1).strip(') ,.;')
    return versions


def _merge_smb_version_evidence(services: list[dict[str, Any]], smb_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    samba_versions = _extract_samba_versions_from_smb(smb_items)
    if not samba_versions:
        return services
    for row in services:
        host = str(row.get('host') or '')
        port = int(row.get('port') or 0)
        service = str(row.get('service') or '').lower()
        product = str(row.get('product') or '').lower()
        if host in samba_versions and (port in {139, 445} or 'samba' in product or 'netbios' in service or 'smb' in service):
            exact = samba_versions[host]
            row['product'] = 'Samba smbd'
            row['version'] = exact
            cpe = row.get('cpe') or []
            base_version = re.match(r'([0-9]+(?:\.[0-9]+){1,3})', exact)
            if base_version:
                samba_cpe = f"cpe:/a:samba:samba:{base_version.group(1)}"
                if samba_cpe not in cpe:
                    cpe.append(samba_cpe)
            row['cpe'] = cpe
            src = row.get('evidence_sources') or []
            for source in ('nmap', 'smbclient'):
                if source not in src:
                    src.append(source)
            row['evidence_sources'] = src
            row['smb_enriched_version'] = True
    return services



CVE_OUTCOMES = {
    'CVE-2011-2523': 'The affected vsftpd 2.3.4 distribution included a malicious backdoor that can expose an unauthorised shell on port 6200/tcp.',
    'CVE-2007-2447': 'The Samba username map script handling can allow remote command execution when the vulnerable configuration is present.',
    'CVE-2004-2687': 'The distcc daemon can execute attacker-supplied compilation commands when exposed without proper access controls.',
    'CVE-2010-2075': 'The affected UnrealIRCd 3.2.8.1 source distribution contained a backdoor that can execute attacker-supplied commands.',
    'CVE-2008-5161': 'CBC-mode SSH traffic may expose plaintext recovery weaknesses under the conditions described by the CVE record.',
    'CVE-2008-2364': 'Apache HTTP Server mod_proxy can be abused for memory-consumption denial of service via excessive interim responses.',
    'CVE-2008-0122': 'The affected BIND/libbind code can crash or corrupt memory when processing crafted input described in the CVE record.',
    'CVE-2009-0542': 'The affected ProFTPD mod_sql handling can permit SQL injection through crafted usernames.',
    'CVE-2009-0543': 'The affected ProFTPD SQL backend handling can bypass SQL injection protections through invalid encoded multibyte characters.',
    'CVE-2008-4242': 'The affected ProFTPD version can interpret long FTP client commands in a way that permits command abuse through crafted FTP URIs.',
    'CVE-2009-0922': 'The affected PostgreSQL versions can be crashed by authenticated users through encoding conversion error handling.',
}

CVE_REMEDIATIONS = {
    'CVE-2011-2523': 'Replace vsftpd 2.3.4 with a trusted clean package, verify package provenance, and restrict FTP exposure to required clients.',
    'CVE-2007-2447': 'Upgrade Samba and remove unsafe username-map script configuration; restrict SMB access to trusted hosts.',
    'CVE-2004-2687': 'Disable distccd if unnecessary, bind it to trusted interfaces, and enforce strict host-based access controls.',
    'CVE-2010-2075': 'Replace the UnrealIRCd build with a trusted clean release and verify source/package integrity.',
    'CVE-2008-5161': 'Disable weak CBC ciphers where possible and upgrade OpenSSH to a vendor-supported fixed version.',
    'CVE-2008-2364': 'Upgrade Apache HTTP Server and review exposed proxy modules and default web applications.',
    'CVE-2008-0122': 'Upgrade BIND/libbind packages and restrict DNS service exposure to required clients.',
    'CVE-2009-0542': 'Upgrade ProFTPD and review whether mod_sql is enabled; restrict FTP exposure.',
    'CVE-2009-0543': 'Upgrade ProFTPD and review mod_sql backend configuration and input handling.',
    'CVE-2008-4242': 'Upgrade ProFTPD and review client-facing FTP behaviour and exposed legacy modules.',
    'CVE-2009-0922': 'Upgrade PostgreSQL beyond the affected branch and restrict database access to trusted hosts.',
}

def _attacker_outcome(product: str, cve_id: str, description: str) -> str:
    if cve_id in CVE_OUTCOMES:
        return CVE_OUTCOMES[cve_id]
    desc = (description or '').strip()
    if desc:
        first = re.split(r'(?<=[.!?])\s+', desc)[0]
        return f'Official CVE description outcome: {first[:260]}'
    return 'Official CVE record did not include enough outcome text in the indexed description.'


def _remediation_direction(product: str, cve_id: str) -> str:
    if cve_id in CVE_REMEDIATIONS:
        return CVE_REMEDIATIONS[cve_id]
    p = (product or '').lower()
    if 'vsftpd' in p:
        return 'Upgrade vsftpd from trusted vendor packages and restrict FTP exposure.'
    if 'samba' in p:
        return 'Upgrade Samba from trusted vendor packages and restrict SMB exposure.'
    if 'distcc' in p or 'distccd' in p:
        return 'Disable distccd where unnecessary and restrict access to trusted build clients.'
    if 'apache' in p or 'httpd' in p:
        return 'Upgrade Apache HTTP Server and review exposed web modules and default applications.'
    if 'proftpd' in p:
        return 'Upgrade ProFTPD and review enabled modules.'
    if 'postgres' in p:
        return 'Upgrade PostgreSQL and restrict database access to trusted hosts.'
    if 'bind' in p or 'isc' in p:
        return 'Upgrade BIND and restrict DNS exposure to required clients.'
    return 'Review the vendor advisory in the CVE references and apply the vendor-supported fixed version or mitigation.'



def _build_security_observations(services: list[dict[str, Any]], smb_items: list[dict[str, Any]], web_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract pentester-facing exposure observations from collected evidence.

    These are not ranked or scored. They are grouped later so the report reads
    like a pentester workbench instead of a tool dump.
    """
    observations=[]; seen=set()
    def add(host, port, protocol, service, observation, evidence, category='Exposure'):
        key=(str(host), str(port), str(protocol), str(observation))
        if key not in seen:
            seen.add(key)
            observations.append({'host':host,'port':port,'protocol':protocol,'service':service,'observation':observation,'evidence':evidence,'category':category})
    for s in services:
        host=s.get('host'); port=s.get('port'); proto=s.get('protocol'); svc=str(s.get('service','')).lower(); prod=str(s.get('product',''))
        try: pnum = int(port or 0)
        except Exception: pnum = 0
        if svc == 'bindshell' or 'root shell' in prod.lower() or pnum == 1524:
            add(host, port, proto, s.get('service'), 'Shell-like service indicator observed on an exposed port.', 'Nmap service fingerprint identified a root-shell style service.', 'Remote Access')
        if pnum == 23 or svc == 'telnet':
            add(host, port, proto, s.get('service'), 'Plaintext remote administration service exposed.', 'Telnet service was identified on the target.', 'Remote Access')
        if pnum in {512,513,514} or svc in {'exec','login','shell'}:
            add(host, port, proto, s.get('service'), 'Legacy r-service remote access surface exposed.', 'rexec/rlogin/rsh-style service was observed.', 'Remote Access')
        if pnum in {2049} or svc == 'nfs':
            add(host, port, proto, s.get('service'), 'NFS/RPC file-sharing surface exposed.', 'Nmap identified an NFS or RPC-related service.', 'File Sharing')
        if pnum == 6000 or svc.lower() == 'x11':
            add(host, port, proto, s.get('service'), 'X11 display service exposed.', 'Nmap identified an X11 service response.', 'Remote GUI')
        if pnum == 5900 or svc == 'vnc':
            add(host, port, proto, s.get('service'), 'VNC remote desktop service exposed.', 'Nmap identified a VNC service response.', 'Remote GUI')
        if pnum in {3306,5432} or svc in {'mysql','postgresql'}:
            add(host, port, proto, s.get('service'), 'Database service exposed on the network.', 'Service fingerprinting identified a database listener.', 'Database')
        if pnum == 8009 or 'ajp' in svc:
            add(host, port, proto, s.get('service'), 'AJP connector exposed.', 'AJP service was identified and checked with AJP scripts where available.', 'Web')
        if svc == 'ftp' or pnum in {21, 2121}:
            script_text = ' '.join(str(x.get('output','')) for x in (s.get('scripts') or []))
            if 'anonymous ftp login allowed' in script_text.lower() or 'ftp code 230' in script_text.lower():
                add(host, port, proto, s.get('service'), 'Anonymous FTP access allowed.', 'ftp-anon reported anonymous FTP login was allowed.', 'File Transfer')
    for item in smb_items:
        text='\n'.join(item.get('lines') or [])
        if item.get('output_file'):
            text += '\n' + _read_text(item.get('output_file'))
        if 'Anonymous login successful' in text or re.search(r'\bSharename\b', text, re.I):
            add(item.get('host'), 445, 'tcp', 'smb', 'Anonymous SMB share listing available.', 'smbclient output includes anonymous access evidence or visible share names.', 'File Sharing')
    for item in web_items:
        if item.get('tool') == 'gobuster' or item.get('path'):
            path_value = str(item.get('path') or '').lower()
            evidence = f"Directory discovery reported {item.get('path')} with status {item.get('status_code')}."
            if 'phpmyadmin' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'phpMyAdmin path observed.', evidence, 'Web')
            if 'phpinfo' in path_value or 'release-notes' in path_value or path_value.endswith('.txt'):
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'Information-disclosure style web path observed.', evidence, 'Web')
            if 'admin' in path_value or 'manager' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'Admin or management web path observed.', evidence, 'Web')
            if 'webdav' in path_value:
                add(item.get('host'), item.get('port'), 'tcp', 'http', 'WebDAV path observed.', evidence, 'Web')
        rows=item.get('rows') or []
        for row in rows:
            for script in row.get('scripts') or []:
                out=script.get('output','') or ''
                low=out.lower()
                if 'phpmyadmin' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'phpMyAdmin path observed.', f"Nmap HTTP script {script.get('id')} reported phpMyAdmin-related content.", 'Web')
                if 'phpinfo.php' in low or 'possible information file' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Information-disclosure style web path observed.', f"Nmap HTTP script {script.get('id')} reported information file evidence.", 'Web')
                if 'directory listing' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Directory listing or browsable web path observed.', f"Nmap HTTP script {script.get('id')} reported directory listing evidence.", 'Web')
                if 'manager/html' in low or 'admin' in low:
                    add(row.get('host'), row.get('port'), row.get('protocol'), row.get('service'), 'Admin or management web path observed.', f"Nmap HTTP script {script.get('id')} reported admin/manager path evidence.", 'Web')
    return sorted(observations, key=lambda o: (str(o.get('category')), str(o.get('host')), str(o.get('port')), str(o.get('observation'))))


def _summarise_web_inventory(web_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    services: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    seen_services = set()
    seen_paths = set()
    for item in web_items:
        if item.get('tool') == 'gobuster' or item.get('path'):
            key = (item.get('host'), item.get('port'), item.get('path'))
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append({
                    'host': item.get('host'),
                    'port': item.get('port'),
                    'path': item.get('path'),
                    'status_code': item.get('status_code'),
                    'size': item.get('size'),
                    'source': item.get('tool') or 'gobuster',
                    'evidence_file': item.get('raw_evidence_file') or item.get('output_file') or '',
                })
        if item.get('tool') == 'nmap_http_scripts':
            for row in item.get('rows') or []:
                scripts = {s.get('id'): s.get('output') for s in row.get('scripts') or []}
                key = (row.get('host'), row.get('port'))
                if key not in seen_services:
                    seen_services.add(key)
                    services.append({
                        'host': row.get('host'),
                        'port': row.get('port'),
                        'service': row.get('service'),
                        'product': row.get('product'),
                        'version': row.get('version'),
                        'title': scripts.get('http-title', ''),
                        'server_header': scripts.get('http-server-header', ''),
                        'http_enum': scripts.get('http-enum', ''),
                        'evidence_file': item.get('output_file') or row.get('raw_evidence_file') or '',
                    })
    return {'services': services, 'paths': paths}


def _summarise_smb_inventory(smb_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    shares: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for item in smb_items:
        tool = item.get('tool')
        host = item.get('host')
        output_file = item.get('output_file') or ''
        tools.append({'tool': tool, 'host': host, 'evidence_file': output_file})
        if tool == 'smbclient':
            for line in item.get('lines') or []:
                m = re.match(r'^(?P<name>[A-Za-z0-9_$.-]+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*)$', line)
                if m and m.group('name').lower() not in {'sharename', '---------'}:
                    shares.append({
                        'host': host,
                        'share': m.group('name'),
                        'type': m.group('type'),
                        'comment': m.group('comment').strip(),
                        'source': 'smbclient',
                        'evidence_file': output_file,
                    })
    return {'shares': shares, 'tools': tools}


def _normalise_service_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out=[]; seen=set()
    for r in rows:
        key=(r.get('host'), int(r.get('port') or 0), r.get('protocol','tcp'))
        if key in seen: continue
        seen.add(key)
        missing=[]
        if not r.get('product'): missing.append('product')
        if not r.get('version'): missing.append('version')
        if not r.get('cpe'): missing.append('cpe')
        r['missing_information']=missing
        out.append(r)
    return sorted(out, key=lambda x:(str(x.get('host')), str(x.get('protocol')), int(x.get('port') or 0)))

STRICT_CVE_MATCH = 'Confirmed CVE Finding'
RELEVANT_VERSION_INFORMATION = 'Relevant Version / Exposure Information'
EVIDENCE_INCOMPLETE = 'Evidence Incomplete'
NOT_APPLICABLE_TO_CONTEXT = 'Not Applicable to Observed Context'
DUPLICATE_SERVICE_REFERENCE = 'Duplicate Service Reference'

EXACT_CVE_BASIS_TOKENS = (
    'exact_structured_version',
    'exact_observed_version_in_record_text',
    'exact_cpe_match',
)

# These service-side/backdoor/RCE-style CVEs remain official-CVE sourced.
# The matcher must still find the official CVE record and product/version match;
# this only stops exact service-side findings from being hidden behind context
# gates that recon cannot safely prove without exploitation.
REPORTABLE_EXACT_SERVICE_CVES = {
    'CVE-2011-2523',  # vsftpd 2.3.4 backdoor
    'CVE-2007-2447',  # Samba username map script RCE on affected 3.0.x builds
    'CVE-2010-2075',  # UnrealIRCd 3.2.8.1 backdoor
    'CVE-2008-4242',  # ProFTPD 1.3.1 long command handling
}


CONTEXT_GATE_RULES = [
    (re.compile(r'\bwindows\b|win32|mod_isapi|isapi', re.I), NOT_APPLICABLE_TO_CONTEXT, 'Not applicable to the observed service context.'),
    (re.compile(r'\bmod_(?:proxy|cache|dav|isapi|ssl|tls|sql|sql_mysql|sql_postgres)\b|\bmodule\b', re.I), EVIDENCE_INCOMPLETE, 'Specific module or backend was not confirmed by collected evidence.'),
    (re.compile(r'\bwhen configured\b|\bif configured\b|\bconfiguration\b|\boption is enabled\b|\bdirective\b', re.I), EVIDENCE_INCOMPLETE, 'Required configuration was not confirmed by collected evidence.'),
    (re.compile(r'\bauthenticated users?\b|\bremote authenticated\b|\brequires authentication\b', re.I), EVIDENCE_INCOMPLETE, 'Required authentication context was not established by collected evidence.'),
    (re.compile(r'\bclient certificate\b|\bx\.509\b|\btls option\b|\bcertificate\b', re.I), EVIDENCE_INCOMPLETE, 'Required TLS or certificate context was not confirmed by collected evidence.'),
    (re.compile(r'\bsql injection\b|\bmod_sql\b|\bsql backend\b|\bmod_sql_mysql\b|\bmod_sql_postgres\b', re.I), EVIDENCE_INCOMPLETE, 'Required SQL backend or module context was not confirmed by collected evidence.'),
    (re.compile(r'\bssh transport\b|\bopenssh extensions\b|\bsftp\b|\bterrapin\b', re.I), EVIDENCE_INCOMPLETE, 'Required SSH or SFTP context was not confirmed for this service.'),
    (re.compile(r'\bprimary or backup domain controller\b|\bdomain controller\b', re.I), EVIDENCE_INCOMPLETE, 'Required server role was not confirmed by collected evidence.'),
]


def _normalise_product_name(value: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', (value or '').lower()).strip()


def _strict_version_basis(match_basis: str) -> bool:
    basis = (match_basis or '').lower()
    return any(token in basis for token in EXACT_CVE_BASIS_TOKENS)


def _context_gate_for_cve(description: str, product: str = '', service: str = '') -> tuple[str | None, str]:
    text = ' '.join([description or '', product or '', service or ''])
    for pattern, classification, reason in CONTEXT_GATE_RULES:
        if pattern.search(text):
            return classification, reason
    return None, ''


def _classify_cve_match(service: dict[str, Any], match: dict[str, Any]) -> tuple[str, str]:
    """Classify a CVE correlation without scoring or prioritising it."""
    if match.get('source') != OFFICIAL_CVE_SOURCE:
        return 'Excluded - Non Official CVE Source', 'CVE source is not the official CVE Program / MITRE CVE List index.'
    basis = str(match.get('match_basis') or '')
    description = str(match.get('description') or '')
    product = str(service.get('product') or '')
    service_name = str(service.get('service') or '')
    cve_id = str(match.get('cve_id') or '')
    context_classification, context_reason = _context_gate_for_cve(description, product, service_name)
    if context_classification == NOT_APPLICABLE_TO_CONTEXT:
        return context_classification, context_reason
    if cve_id == 'CVE-2007-2447':
        return STRICT_CVE_MATCH, 'Observed product/version evidence places Samba within the official affected range; SMB service exposure was confirmed. Configuration-specific conditions were not proven by recon evidence.'
    if cve_id in REPORTABLE_EXACT_SERVICE_CVES:
        return STRICT_CVE_MATCH, 'Observed product/version and exposed service context match the official affected conditions.'
    if context_classification:
        return context_classification, context_reason
    if not _strict_version_basis(basis):
        return RELEVANT_VERSION_INFORMATION, 'Observed version falls within an official affected range; additional context was not established.'
    return STRICT_CVE_MATCH, 'Observed product and version match the official affected version.'




def _cve_finding_type(product: str, cve_id: str, description: str) -> str:
    text = ' '.join([product or '', cve_id or '', description or '']).lower()
    if 'backdoor' in text or 'shell' in text:
        return 'Direct service-side exposure'
    if 'execute arbitrary' in text or 'command' in text:
        return 'Command-execution related CVE'
    if 'denial of service' in text or 'crash' in text:
        return 'Availability-impact CVE'
    return 'Version-linked CVE'
def _build_cve_row(service: dict[str, Any], match: dict[str, Any], classification: str, reason: str) -> dict[str, Any]:
    observed_port = f"{service.get('port')}/{service.get('protocol')}"
    return {
        'host': service.get('host'), 'port': service.get('port'), 'protocol': service.get('protocol'),
        'observed_ports': [observed_port],
        'service': service.get('service'), 'product': service.get('product'), 'version': service.get('version'),
        'cve_id': match.get('cve_id'), 'vulnerability': match.get('description'),
        'match_source': OFFICIAL_CVE_SOURCE,
        'classification': classification,
        'classification_reason': reason,
        'match_reason': reason,
        'matched_product_tokens': match.get('matched_product_tokens', []),
        'matched_version_tokens': match.get('matched_version_tokens', []),
        'match_basis': match.get('match_basis',''),
        'source_cvss_score': match.get('cvss_score'),
        'source_cvss_severity': match.get('cvss_severity'),
        'source_cvss_vector': match.get('cvss_vector'),
        'source_cvss_version': match.get('cvss_version'),
        'source_cvss_source': match.get('cvss_source'),
        'attacker_outcome': _attacker_outcome(str(service.get('product','')), str(match.get('cve_id','')), str(match.get('description',''))),
        'remediation_direction': _remediation_direction(str(service.get('product','')), str(match.get('cve_id',''))),
        'finding_type': _cve_finding_type(str(service.get('product','')), str(match.get('cve_id','')), str(match.get('description',''))),
        'evidence_sources': service.get('evidence_sources',[]), 'references': match.get('references',[]),
    }


def _merge_cve_duplicate(existing: dict[str, Any], service: dict[str, Any]) -> None:
    port_ref = f"{service.get('port')}/{service.get('protocol')}"
    ports = existing.setdefault('observed_ports', [])
    if port_ref not in ports:
        ports.append(port_ref)
    existing['port'] = ', '.join(ports)
    existing['protocol'] = 'mixed' if len({p.split('/')[-1] for p in ports if '/' in p}) > 1 else (ports[0].split('/')[-1] if ports and '/' in ports[0] else existing.get('protocol'))


def _cve_dedupe_key(service: dict[str, Any], match: dict[str, Any], classification: str) -> tuple[str, str, str, str, str]:
    return (
        str(service.get('host') or ''),
        _normalise_product_name(str(service.get('product') or '')),
        str(service.get('version') or '').lower(),
        str(match.get('cve_id') or ''),
        classification,
    )


def _is_service(s: dict[str, Any], *, ports: set[int] | None = None, terms: set[str] | None = None, products: set[str] | None = None, protocol: str | None = None) -> bool:
    try:
        port = int(s.get('port') or 0)
    except Exception:
        port = 0
    proto = str(s.get('protocol') or '').lower()
    svc = str(s.get('service') or '').lower()
    prod = str(s.get('product') or '').lower()
    if protocol and proto != protocol:
        return False
    if not ports and not terms and not products:
        return True
    if ports and port in ports:
        return True
    if terms and any(t in svc for t in terms):
        return True
    if products and any(t in prod for t in products):
        return True
    return False


def _nmap_script_available(script_name: str) -> bool:
    """Return whether a named NSE script appears installed locally."""
    name = (script_name or '').strip()
    if not name:
        return False
    if '/' in name or name.endswith('.nse'):
        return Path(name).exists()
    script_path = Path('/usr/share/nmap/scripts') / f'{name}.nse'
    return script_path.exists()


def _resolve_nmap_scripts(scripts: str) -> tuple[str, list[str], list[str]]:
    """Filter requested NSE scripts to those installed on the Kali host.

    This prevents failed scans caused by one missing NSE script caused by missing optional NSE scripts. If none of the requested scripts exist, the caller falls back to
    service/version probing without --script.
    """
    requested = [x.strip() for x in (scripts or '').split(',') if x.strip()]
    available: list[str] = []
    missing: list[str] = []
    for script in requested:
        # Nmap categories are left alone; explicit script names are checked.
        if script in {'default', 'safe', 'auth', 'discovery', 'version', 'vuln'} or _nmap_script_available(script):
            available.append(script)
        else:
            missing.append(script)
    return ','.join(available), available, missing


def _run_nmap_grouped_check(checks: list[dict[str, Any]], coverage: list[dict[str, Any]], raw: list[dict[str, Any]], all_services: list[dict[str, Any]], *, name: str, info: str, selectors: dict[str, Any], scripts: str, extra_args: list[str] | None = None, timeout: int = 360) -> None:
    nmap = which('nmap')
    matched = [s for s in all_services if _is_service(s, **selectors)]
    if not matched:
        checks.append({'check': name, 'status': 'Not Applicable - Service Not Observed', 'note': 'Relevant service was not observed.', 'evidence_file': ''})
        return
    if not nmap:
        coverage.append(_coverage(name, scan_store.STATUS_EMPTY, info, 'nmap unavailable for service-level check', ''))
        for s in matched:
            checks.append({'host': s.get('host'), 'port': s.get('port'), 'protocol': s.get('protocol'), 'service': s.get('service'), 'check': name, 'status': 'Tool Unavailable - Evidence Incomplete', 'note': 'nmap unavailable for this service-level check.', 'evidence_file': ''})
        return
    grouped: dict[tuple[str, str], set[int]] = {}
    for s in matched:
        grouped.setdefault((str(s.get('host')), str(s.get('protocol') or 'tcp').lower()), set()).add(int(s.get('port') or 0))
    for (host, proto), ports in sorted(grouped.items()):
        port_arg = ','.join(str(p) for p in sorted(ports))
        p = outfile(name, f'{host}_{proto}_{port_arg}', 'xml')
        cmd = [nmap, '-sV']
        if proto == 'udp':
            cmd.append('-sU')
        scripts_to_run, available_scripts, missing_scripts = _resolve_nmap_scripts(scripts)
        if scripts_to_run:
            cmd += ['--script', scripts_to_run]
        if extra_args:
            cmd += extra_args
        cmd += ['-p', port_arg, '-oX', str(p), host]
        r = run_cmd(cmd, p, timeout, True)
        parsed_rows = parse_nmap_xml(str(p), proto)
        status_raw = _status_from_result(r, bool(parsed_rows))
        note_bits = [f'{host}:{port_arg}/{proto}']
        if available_scripts:
            note_bits.append('Scripts: ' + ', '.join(available_scripts))
        if missing_scripts:
            note_bits.append('Unavailable scripts skipped: ' + ', '.join(missing_scripts))
        note = ' | '.join(note_bits)
        coverage.append(_coverage(name, status_raw, info, note, str(p), r))
        _add_raw(raw, name, host, port_arg, str(p), 'nmap_xml', bool(parsed_rows))
        checks.append({'host': host, 'port': port_arg, 'protocol': proto, 'service': name, 'check': info, 'status': _coverage_display_status(name, status_raw, note, r), 'note': note, 'evidence_file': str(p), 'command': r.get('command','')})


def _run_service_level_checks(all_services: list[dict[str, Any]], coverage: list[dict[str, Any]], raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run obvious service-level exposure checks without scoring or exploit decisions."""
    checks: list[dict[str, Any]] = []
    specs = [
        ('nmap_ftp_checks', 'FTP anonymous/system evidence', {'ports': {21, 2121}, 'terms': {'ftp'}}, 'ftp-anon,ftp-syst'),
        ('nmap_telnet_checks', 'Telnet plaintext/configuration evidence', {'ports': {23}, 'terms': {'telnet'}}, 'telnet-encryption,telnet-ntlm-info'),
        ('nmap_smtp_checks', 'SMTP command and relay indication evidence', {'ports': {25}, 'terms': {'smtp'}}, 'smtp-commands,smtp-open-relay,smtp-ntlm-info'),
        ('nmap_dns_checks', 'DNS recursion, NSID, and zone-transfer evidence', {'ports': {53}, 'terms': {'domain', 'dns'}}, 'dns-recursion,dns-zone-transfer,dns-nsid'),
        ('nmap_rpc_nfs_checks', 'RPC/NFS program and export evidence', {'ports': {111, 2049}, 'terms': {'rpcbind', 'nfs'}}, 'rpcinfo,nfs-showmount,nfs-ls,nfs-statfs'),
        ('nmap_smb_checks', 'SMB shares, protocol, users, and security-mode evidence', {'ports': {139, 445}, 'terms': {'smb', 'netbios'}}, 'smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-security-mode'),
        ('nmap_rservices_checks', 'Legacy rsh/rexec/rlogin exposure evidence', {'ports': {512, 513, 514}, 'terms': {'exec', 'login', 'shell'}}, 'rusers,rpcinfo'),
        ('nmap_rmi_checks', 'Java RMI registry evidence', {'ports': {1099}, 'terms': {'rmi'}}, 'rmi-dumpregistry'),
        ('nmap_bindshell_checks', 'Bindshell service exposure evidence', {'ports': {1524}, 'terms': {'bindshell'}}, 'banner'),
        ('nmap_mysql_checks', 'MySQL version and authentication evidence', {'ports': {3306}, 'terms': {'mysql'}}, 'mysql-info,mysql-empty-password'),
        ('nmap_postgresql_checks', 'PostgreSQL version and authentication evidence', {'ports': {5432}, 'terms': {'postgresql', 'pgsql'}}, 'pgsql-empty-password,banner'),
        ('nmap_vnc_checks', 'VNC protocol and authentication evidence', {'ports': {5900}, 'terms': {'vnc'}}, 'vnc-info'),
        ('nmap_x11_checks', 'X11 access-control evidence', {'ports': {6000}, 'terms': {'x11'}}, 'x11-access'),
        ('nmap_irc_checks', 'IRC banner and service evidence', {'ports': {6667, 6697}, 'terms': {'irc'}}, 'irc-info'),
        ('nmap_ajp_checks', 'AJP method and header evidence', {'ports': {8009}, 'terms': {'ajp'}}, 'ajp-headers,ajp-methods'),
        ('nmap_tomcat_checks', 'Tomcat manager/admin HTTP evidence', {'ports': {8180}, 'products': {'tomcat', 'coyote'}}, 'http-title,http-headers,http-enum,http-auth-finder'),
        ('nmap_drb_checks', 'Ruby DRb service evidence', {'ports': {8787}, 'terms': {'drb'}, 'products': {'ruby'}}, 'banner'),
    ]
    for name, info, selectors, scripts in specs:
        _run_nmap_grouped_check(checks, coverage, raw, all_services, name=name, info=info, selectors=selectors, scripts=scripts)

    unknown_services = [s for s in all_services if str(s.get('service') or '').lower() in {'unknown', 'tcpwrapped'} or not s.get('product')]
    high_unknown = [s for s in unknown_services if int(s.get('port') or 0) >= 1024]
    if high_unknown:
        _run_nmap_grouped_check(checks, coverage, raw, high_unknown, name='nmap_unknown_high_ports', info='Unknown high-port service re-probe evidence', selectors={}, scripts='banner', extra_args=['--version-all'], timeout=420)
    else:
        checks.append({'check': 'nmap_unknown_high_ports', 'status': 'Not Applicable - Service Not Observed', 'note': 'No unknown high ports observed.', 'evidence_file': ''})

    # Non-nmap helpers where available. These add evidence without affecting CVE strictness.
    for host in sorted({str(s.get('host')) for s in all_services if _is_service(s, ports={111, 2049}, terms={'rpcbind', 'nfs'})}):
        if which('rpcinfo'):
            p = outfile('rpcinfo', host, 'txt')
            r = run_cmd([which('rpcinfo'), '-p', host], p, 180)
            coverage.append(_coverage('rpcinfo', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'RPC program mapping evidence', host, str(p), r))
            _add_raw(raw, 'rpcinfo', host, '', str(p), 'text', True)
            checks.append({'host': host, 'port': '111,2049', 'protocol': 'tcp/udp', 'service': 'rpc/nfs', 'check': 'RPC program mapping evidence', 'status': _coverage_display_status('rpcinfo', _status_from_result(r, bool(parse_simple_lines(str(p)))), host, r), 'note': 'rpcinfo -p executed.', 'evidence_file': str(p), 'command': r.get('command','')})
        if which('showmount'):
            p = outfile('showmount', host, 'txt')
            r = run_cmd([which('showmount'), '-e', host], p, 180)
            coverage.append(_coverage('showmount', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'NFS export evidence', host, str(p), r))
            _add_raw(raw, 'showmount', host, '', str(p), 'text', True)
            checks.append({'host': host, 'port': '2049', 'protocol': 'tcp/udp', 'service': 'nfs', 'check': 'NFS export evidence', 'status': _coverage_display_status('showmount', _status_from_result(r, bool(parse_simple_lines(str(p)))), host, r), 'note': 'showmount -e executed.', 'evidence_file': str(p), 'command': r.get('command','')})
    return checks


def _match_cves(services: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    strict_matches: list[dict[str, Any]] = []
    relevant_information: list[dict[str, Any]] = []
    strict_index: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    relevant_index: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}

    for s in services:
        cpe_text = ' '.join(s.get('cpe') or [])
        matches, held_refs = mitre_search_with_held(str(s.get('product','')), str(s.get('version','')), str(s.get('service','')), cpe_text)
        for m in matches:
            if m.get('source') != OFFICIAL_CVE_SOURCE:
                continue
            classification, reason = _classify_cve_match(s, m)
            row = _build_cve_row(s, m, classification, reason)
            key = _cve_dedupe_key(s, m, classification)
            if classification == NOT_APPLICABLE_TO_CONTEXT:
                continue
            if classification == STRICT_CVE_MATCH:
                if key in strict_index:
                    _merge_cve_duplicate(strict_index[key], s)
                else:
                    strict_index[key] = row
                    strict_matches.append(row)
            else:
                if key in relevant_index:
                    _merge_cve_duplicate(relevant_index[key], s)
                else:
                    relevant_index[key] = row
                    relevant_information.append(row)
        # held_refs intentionally not rendered as CVEs. They are weak/non-official references.

    return strict_matches, relevant_information



def _candidate_basis_label(match_basis: str) -> str:
    basis = (match_basis or '').lower()
    if 'named_branch_before' in basis:
        return 'Observed version is older than the fixed version named by the CVE record.'
    if 'explicit_same_product_text_range' in basis or 'structured_same_product_range' in basis:
        return 'Observed version is within an official affected range.'
    if 'exact' in basis:
        return 'Observed version appears in the official CVE record.'
    return 'Product/version evidence was retained for analyst review.'


def _candidate_reason_label(row: dict[str, Any]) -> str:
    text = ' '.join(str(row.get(k) or '') for k in ('classification_reason', 'classification')).lower()
    if 'module' in text or 'backend' in text:
        return 'Specific module/backend evidence was not confirmed.'
    if 'configuration' in text:
        return 'Required configuration evidence was not confirmed.'
    if 'authentication' in text:
        return 'Authentication context was not established.'
    if 'tls' in text or 'certificate' in text:
        return 'Required TLS/certificate context was not confirmed.'
    if 'ssh' in text or 'sftp' in text:
        return 'Required SSH/SFTP context was not confirmed for this service.'
    if 'role' in text:
        return 'Required server role was not confirmed.'
    return 'Candidate reference retained because the observed version matches an official affected range, but confirmation conditions were incomplete.'


def _is_user_visible_candidate(row: dict[str, Any]) -> bool:
    combined = ' '.join(str(row.get(k) or '') for k in ('classification', 'classification_reason', 'match_reason')).lower()
    if 'mismatch' in combined or 'not applicable' in combined:
        return False
    return True


def _build_candidate_cve_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows or []:
        if not _is_user_visible_candidate(row):
            continue
        key = (str(row.get('host') or ''), str(row.get('service') or ''), str(row.get('product') or ''), str(row.get('version') or ''))
        group = groups.setdefault(key, {
            'host': row.get('host'),
            'service': row.get('service'),
            'product': row.get('product'),
            'version': row.get('version'),
            'ports': [],
            'references': [],
        })
        for port in row.get('observed_ports') or [f"{row.get('port')}/{row.get('protocol')}"]:
            if port and port not in group['ports']:
                group['ports'].append(port)
        group['references'].append({
            'cve_id': row.get('cve_id'),
            'reason': _candidate_reason_label(row),
            'basis': _candidate_basis_label(str(row.get('match_basis') or '')),
        })
    out = list(groups.values())
    for group in out:
        group['reference_count'] = len(group.get('references') or [])
        group['ports'] = sorted(group.get('ports') or [])
    return sorted(out, key=lambda g: (str(g.get('host')), str(g.get('service')), str(g.get('product')), str(g.get('version'))))


_INTERNAL_REPORT_TOOLS = {'jq', 'python_normaliser'}

def _public_tool_coverage(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    hydra_rows: list[dict[str, Any]] = []
    for row in rows or []:
        tool_name = str(row.get('tool') or '').lower()
        if tool_name in _INTERNAL_REPORT_TOOLS:
            continue
        if tool_name == 'hydra':
            hydra_rows.append(row)
            continue
        public.append(row)

    if hydra_rows:
        statuses = [str(r.get('status') or '') for r in hydra_rows]
        notes = [str(r.get('note') or '') for r in hydra_rows if r.get('note')]
        affected = []
        for note in notes:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+/[A-Za-z0-9_-]+)', note)
            if m:
                affected.append(m.group(1))
            elif note:
                affected.append(note)
        if any('Completed' in s for s in statuses):
            status = 'Completed'
        elif any('Input Invalid' in s for s in statuses):
            status = 'Input Invalid'
        elif any('Input Missing' in s for s in statuses):
            status = 'Input Missing'
        elif any('Timed Out' in s for s in statuses):
            status = 'Timed Out - Incomplete'
        else:
            status = 'Failed - Incomplete'
        output_files = [str(r.get('output_file') or '') for r in hydra_rows if r.get('output_file')]
        commands = [str(r.get('command') or '') for r in hydra_rows if r.get('command')]
        outputs = []
        for r in hydra_rows:
            out = str(r.get('output') or '')
            if out:
                outputs.append(out)
        note = 'Affected services: ' + ', '.join(sorted(set(affected))) if affected else 'Default credential checks were selected.'
        if status == 'Input Invalid':
            note = 'Credential combo file was invalid. ' + note
        public.append({
            'tool': 'Default credential checks',
            'status': status,
            'raw_status': status,
            'evidence_type': 'Default credential check evidence',
            'information_added': 'Default credential check evidence',
            'note': note,
            'output_file': ', '.join(Path(x).name for x in output_files[:5]),
            'command': '\n'.join(commands[:5]),
            'output': '\n\n---\n\n'.join(outputs[:5]),
            'output_truncated': any(r.get('output_truncated') for r in hydra_rows),
            'exit_code': ', '.join(str(r.get('exit_code','')) for r in hydra_rows[:5]),
            'stderr_summary': '; '.join(str(r.get('stderr_summary') or '') for r in hydra_rows if r.get('stderr_summary'))[:260],
            'failure_reason': '; '.join(str(r.get('failure_reason') or '') for r in hydra_rows if r.get('failure_reason'))[:260],
        })
    return public


def _build_service_summary(services: list[dict[str, Any]], cve_matches: list[dict[str, Any]], candidate_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confirmed_ports = {(str(c.get('host')), str(p)) for c in cve_matches or [] for p in (c.get('observed_ports') or [])}
    candidate_keys = {(str(g.get('host')), str(g.get('service')), str(g.get('product')), str(g.get('version'))) for g in candidate_groups or []}
    rows = []
    for s in services or []:
        port_ref = f"{s.get('port')}/{s.get('protocol')}"
        key = (str(s.get('host')), str(s.get('service')), str(s.get('product')), str(s.get('version')))
        if (str(s.get('host')), port_ref) in confirmed_ports:
            status = 'Confirmed CVE linked'
        elif key in candidate_keys:
            status = 'Candidate CVE references retained'
        elif s.get('product') or s.get('version'):
            status = 'Service identified'
        else:
            status = 'Service observed; identity incomplete'
        rows.append({'host': s.get('host'), 'port': s.get('port'), 'protocol': s.get('protocol'), 'service': s.get('service'), 'product': s.get('product'), 'version': s.get('version'), 'status': status, 'evidence_gaps': ', '.join(s.get('missing_information') or [])})
    return rows


def _status_sort_key(status: str) -> tuple[int, str]:
    s = (status or '').lower()
    if s == 'completed' or s.startswith('completed'):
        return (0, s)
    if 'partial results' in s:
        return (1, s)
    if 'no evidence' in s or 'not applicable' in s or 'no web paths' in s:
        return (2, s)
    if 'input missing' in s or 'input invalid' in s or 'unavailable' in s or 'disabled' in s:
        return (3, s)
    if 'timed out' in s or 'failed' in s or 'incomplete' in s:
        return (4, s)
    return (4, s)

def _sort_coverage(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: (_status_sort_key(str(r.get('status',''))), str(r.get('tool','')), str(r.get('note',''))))



def _attack_surface_category(service: dict[str, Any]) -> str:
    svc = str(service.get('service') or '').lower()
    prod = str(service.get('product') or '').lower()
    try: port = int(service.get('port') or 0)
    except Exception: port = 0
    if port in {21, 2121} or 'ftp' in svc or 'ftp' in prod:
        return 'File Transfer Surface'
    if port in {23,22,512,513,514,1524,5900,6000} or any(x in svc for x in ['ssh','telnet','exec','login','bindshell','vnc','x11']):
        return 'Remote Access Surface'
    if any(x in svc for x in ['http','ajp']) or any(x in prod for x in ['apache','tomcat','coyote']):
        return 'Web Surface'
    if port in {139,445,137,2049,111} or any(x in svc for x in ['smb','netbios','nfs','rpcbind']):
        return 'File Sharing and RPC Surface'
    if port in {3306,5432} or any(x in svc for x in ['mysql','postgresql']):
        return 'Database Surface'
    if port in {25,53,6667,6697,1099,8787,3632} or any(x in svc for x in ['smtp','domain','irc','rmi','drb','distccd']):
        return 'Application Service Surface'
    return 'Other Observed Services'


def _gap_label(gap: str) -> str:
    value = str(gap or '').strip().lower()
    labels = {
        'product': 'Product name not identified',
        'version': 'Version not identified',
        'cpe': 'CPE not collected',
    }
    return labels.get(value, gap)


def _ports_intersect(card_ports: list[str], other_ports: list[str]) -> bool:
    card = {str(p).split('/')[0] for p in card_ports if p}
    other = {str(p).split('/')[0] for p in other_ports if p}
    return bool(card & other)


def _service_card_identity(s: dict[str, Any]) -> tuple[tuple[str, str, str, str], str, str, str, str]:
    host = str(s.get('host') or '')
    svc = str(s.get('service') or 'unknown')
    prod = str(s.get('product') or '')
    ver = str(s.get('version') or '')
    try:
        port = int(s.get('port') or 0)
    except Exception:
        port = 0
    svc_l = svc.lower()
    prod_l = prod.lower()
    if port in {137, 139, 445} or 'samba' in prod_l or 'netbios' in svc_l or 'smb' in svc_l:
        prod = prod or 'Samba/SMB'
        return (host, 'smb', prod, ver), 'smb', prod, ver, 'File Sharing and RPC Surface'
    if port in {111, 2049} or svc_l in {'rpcbind', 'nfs'}:
        label = 'NFS/RPC'
        return (host, 'nfs-rpc', label, ''), 'nfs-rpc', label, '', 'File Sharing and RPC Surface'
    return (host, svc, prod, ver), svc, prod, ver, _attack_surface_category(s)


def _dedupe_dicts(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for row in rows or []:
        key = tuple(str(row.get(k) or '') for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _build_service_workbench(services: list[dict[str, Any]], cve_matches: list[dict[str, Any]], candidate_groups: list[dict[str, Any]], observations: list[dict[str, Any]], web_summary: dict[str, Any], smb_summary: dict[str, Any], service_checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for s in services or []:
        key, card_service, card_product, card_version, category = _service_card_identity(s)
        card = cards.setdefault(key, {
            'host': s.get('host'),
            'service': card_service or 'unknown',
            'product': card_product or '',
            'version': card_version or '',
            'category': category,
            'ports': [],
            'confirmed_cves': [],
            'candidate_references': [],
            'observations': [],
            'evidence_gaps': [],
            'checks': [],
            'web_evidence': [],
            'web_paths': [],
            'smb_shares': [],
            'state': 'Identified Service',
        })
        port_ref = f"{s.get('port')}/{s.get('protocol')}"
        if port_ref not in card['ports']:
            card['ports'].append(port_ref)
        for gap in s.get('missing_information') or []:
            label = _gap_label(gap)
            if label and label not in card['evidence_gaps']:
                card['evidence_gaps'].append(label)
    for card in cards.values():
        card_port_nums = {p.split('/')[0] for p in card.get('ports', [])}
        for cve in cve_matches or []:
            if str(cve.get('host')) != str(card.get('host')):
                continue
            product_match = str(cve.get('product') or '').lower() == str(card.get('product') or '').lower() and str(cve.get('version') or '').lower() == str(card.get('version') or '').lower()
            port_match = bool(set(str(p).split('/')[0] for p in (cve.get('observed_ports') or [])) & card_port_nums)
            if product_match or port_match:
                card['confirmed_cves'].append(cve)
        for cand in candidate_groups or []:
            if str(cand.get('host')) != str(card.get('host')):
                continue
            product_match = str(cand.get('product') or '').lower() == str(card.get('product') or '').lower() and str(cand.get('version') or '').lower() == str(card.get('version') or '').lower()
            port_match = _ports_intersect(card.get('ports', []), cand.get('ports') or [])
            if product_match or port_match:
                card['candidate_references'].append(cand)
        for obs in observations or []:
            if str(obs.get('host')) == str(card.get('host')) and str(obs.get('port')) in card_port_nums:
                card['observations'].append(obs)
        for check in service_checks or []:
            if str(check.get('host')) != str(card.get('host')):
                continue
            if str(check.get('status','')).lower().startswith('not applicable'):
                continue
            check_ports = re.findall(r'\d+', str(check.get('port') or ''))
            if _ports_intersect(card.get('ports', []), check_ports):
                card['checks'].append(check)
        if str(card.get('service','')).lower() in {'http','https','http-proxy','ajp13'} or 'apache' in str(card.get('product','')).lower() or 'tomcat' in str(card.get('product','')).lower():
            for w in (web_summary or {}).get('services') or []:
                if str(w.get('host')) == str(card.get('host')) and str(w.get('port')) in card_port_nums:
                    card['web_evidence'].append(w)
            for path in (web_summary or {}).get('paths') or []:
                if str(path.get('host')) == str(card.get('host')) and str(path.get('port')) in card_port_nums:
                    card['web_paths'].append(path)
        if card.get('service') == 'smb' or any(p.split('/')[0] in {'139','445','137'} for p in card.get('ports', [])):
            card['smb_shares'] = (smb_summary or {}).get('shares') or []
        card['observations'] = _dedupe_dicts(card['observations'], ('observation', 'evidence'))
        card['checks'] = _dedupe_dicts(card['checks'], ('check', 'status', 'evidence_file'))
        card['candidate_references'] = _dedupe_dicts(card['candidate_references'], ('host', 'service', 'product', 'version'))
        card['confirmed_cves'] = _dedupe_dicts(card['confirmed_cves'], ('cve_id', 'product', 'version'))
        card['web_paths'] = _dedupe_dicts(card['web_paths'], ('path', 'status_code'))
        if card['confirmed_cves']:
            card['state'] = 'CVE Finding Supported'
        elif card['observations']:
            card['state'] = 'Security-Relevant Exposure'
        elif card['candidate_references']:
            card['state'] = 'Candidate References Available'
        elif card['evidence_gaps']:
            card['state'] = 'Identity Incomplete'
    state_order = {'CVE Finding Supported':0, 'Security-Relevant Exposure':1, 'Candidate References Available':2, 'Identity Incomplete':3, 'Identified Service':4}
    return sorted(cards.values(), key=lambda c: (c.get('category',''), state_order.get(c.get('state'),9), str(c.get('host')), str(c.get('ports'))))


def _build_attack_surface_sections(service_cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sections: dict[str, list[dict[str, Any]]] = {}
    for card in service_cards or []:
        sections.setdefault(str(card.get('category') or 'Other Observed Services'), []).append(card)
    order = ['Remote Access Surface', 'File Transfer Surface', 'Web Surface', 'File Sharing and RPC Surface', 'Database Surface', 'Application Service Surface', 'Other Observed Services']
    return [{'category': cat, 'services': sections[cat]} for cat in order if cat in sections]


def _build_key_exposure_indicators(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated exposure indicators into pentester-readable rows."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}

    def family(o: dict[str, Any]) -> tuple[str, str]:
        obs = str(o.get('observation','')).lower()
        svc = str(o.get('service','')).lower()
        if 'anonymous ftp' in obs:
            return ('File Transfer', 'Anonymous FTP access allowed')
        if 'legacy r-service' in obs or svc in {'exec', 'login', 'shell', 'tcpwrapped'}:
            return ('Remote Access', 'Legacy r-services exposed')
        if 'nfs/rpc' in obs:
            return ('File Sharing', 'NFS/RPC file-sharing surface exposed')
        if 'database service' in obs:
            return ('Database', 'Database services exposed on the network')
        if 'admin or management web path' in obs:
            return ('Web', 'Admin or management web paths observed')
        if 'directory listing' in obs:
            return ('Web', 'Directory listing or browsable web path observed')
        if 'information-disclosure' in obs:
            return ('Web', 'Information-disclosure style web path observed')
        if 'phpmyadmin' in obs:
            return ('Web', 'phpMyAdmin path observed')
        if 'anonymous smb' in obs:
            return ('File Sharing', 'Anonymous SMB share listing available')
        if 'shell-like' in obs:
            return ('Remote Access', 'Shell-like service indicator observed')
        if 'plaintext' in obs:
            return ('Remote Access', 'Plaintext remote administration service exposed')
        if 'vnc' in obs:
            return ('Remote GUI', 'VNC remote desktop service exposed')
        if 'x11' in obs:
            return ('Remote GUI', 'X11 display service exposed')
        if 'webdav' in obs:
            return ('Web', 'WebDAV path observed')
        if 'ajp' in obs:
            return ('Web', 'AJP connector exposed')
        return (str(o.get('category') or 'Exposure'), str(o.get('observation') or 'Exposure observed'))

    for o in observations or []:
        cat, title = family(o)
        key = (str(o.get('host') or ''), cat, title)
        row = groups.setdefault(key, {
            'host': o.get('host'),
            'category': cat,
            'service': o.get('service'),
            'observation': title,
            'evidence': o.get('evidence'),
            'ports': [],
            'protocols': [],
        })
        port_ref = f"{o.get('port')}/{o.get('protocol')}" if o.get('protocol') else str(o.get('port') or '')
        if port_ref and port_ref not in row['ports']:
            row['ports'].append(port_ref)
        if o.get('protocol') and o.get('protocol') not in row['protocols']:
            row['protocols'].append(o.get('protocol'))
    def sort_key(o: dict[str, Any]) -> tuple[int, str, str]:
        text = str(o.get('observation','')).lower()
        if 'shell' in text: rank = 0
        elif 'plaintext' in text or 'legacy' in text: rank = 1
        elif 'anonymous smb' in text: rank = 2
        elif 'admin' in text or 'phpmyadmin' in text or 'information' in text: rank = 3
        else: rank = 4
        return (rank, str(o.get('host')), ','.join(o.get('ports') or []))
    return sorted(groups.values(), key=sort_key)


def _build_pentester_summary(results: dict[str, Any]) -> list[str]:
    """Short human summary for the report header; no scoring or prioritisation."""
    points: list[str] = []
    cves = results.get('cve_matches') or []
    indicators = results.get('key_exposure_indicators') or []
    services = results.get('service_inventory') or []
    if cves:
        products = []
        for c in cves:
            label = f"{c.get('product','').strip()} {c.get('version','').strip()}".strip()
            if label and label not in products:
                products.append(label)
        if products:
            points.append('CVE-supported findings were linked to: ' + ', '.join(products) + '.')
    indicator_titles = [str(i.get('observation') or '') for i in indicators]
    if indicator_titles:
        wanted = []
        for title in indicator_titles:
            if title and title not in wanted:
                wanted.append(title)
        points.append('Security-relevant exposure indicators include: ' + '; '.join(wanted[:8]) + ('.' if len(wanted) <= 8 else '; and additional observed surfaces.'))
    exposed_ports = []
    for s in services:
        if s.get('port') and s.get('protocol'):
            ref = f"{s.get('port')}/{s.get('protocol')}"
            if ref not in exposed_ports:
                exposed_ports.append(ref)
    if exposed_ports:
        points.append(f"The target presented {len(exposed_ports)} observed service endpoints across TCP/UDP evidence collection.")
    candidates = results.get('candidate_cve_groups') or []
    if candidates:
        points.append(f"{len(candidates)} candidate CVE reference group(s) were retained for analyst review where additional context was not established.")
    return points[:4]

def _start_cve_prefetch(scan_id: str, services: list[dict[str, Any]]) -> tuple[threading.Thread | None, dict[str, Any]]:
    holder: dict[str, Any] = {'ready': False, 'strict': [], 'relevant': []}
    if not services or not mitre_status().get('available'):
        return None, holder
    snapshot = [dict(s) for s in services]
    def worker() -> None:
        try:
            strict, relevant = _match_cves(snapshot)
            holder.update({'ready': True, 'strict': strict, 'relevant': relevant})
            _publish_partial(scan_id, cve_matches=strict, relevant_cve_information=relevant, cve_review_status='CVE review started')
        except Exception as exc:
            holder.update({'ready': True, 'error': str(exc)})
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, holder

def _sanitize_hydra_combo_file(path: str) -> str:
    """Create a Hydra -C compatible combo file: username:password only."""
    source = Path(path)
    if not source.exists():
        return ''
    valid: list[str] = []
    try:
        for line in source.read_text(encoding='utf-8', errors='ignore').splitlines():
            item = line.strip()
            if not item or item.startswith('#') or ':' not in item:
                continue
            user, password = item.split(':', 1)
            user = user.strip()
            password = password.strip()
            if not user or not password:
                continue
            valid.append(f'{user}:{password}')
    except Exception:
        return ''
    if not valid:
        return ''
    out = Path('storage/scans') / 'hydra_combo_autopentest_sanitized.txt'
    out.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    clean = []
    for item in valid:
        if item not in seen:
            seen.add(item)
            clean.append(item)
    out.write_text('\n'.join(clean) + '\n', encoding='utf-8')
    return str(out)


def _credential_combo_file() -> str:
    """Return a sanitized hydra -C compatible credential combo file."""
    configured = os.getenv('HYDRA_CREDENTIAL_FILE', '').strip()
    candidates = []
    if configured:
        candidates.append(configured)
    candidates.extend([
        '/usr/share/seclists/Passwords/Default-Credentials/default_credentials_for_services_unhashed.txt',
        '/usr/share/seclists/Passwords/Default-Credentials/default_credentials_for_services.txt',
        '/usr/share/seclists/Passwords/Common-Credentials/top-20.txt',
    ])
    packaged = Path(__file__).resolve().parents[1] / 'wordlists' / 'default_credentials_autopentest.txt'
    candidates.append(str(packaged))
    for item in candidates:
        sanitized = _sanitize_hydra_combo_file(item) if item and Path(item).exists() and Path(item).stat().st_size > 0 else ''
        if sanitized:
            return sanitized
    return ''

def run_pipeline(scan_id: str, target_input: str, scan_options: dict[str, Any] | None = None) -> None:
    _token = _CURRENT_SCAN_ID.set(scan_id)
    # Debug logging at pipeline start
    try:
        logger.info(f"[run_pipeline] starting scan_id={scan_id} target={target_input} options={scan_options}")
    except Exception:
        pass
    try:
        scan_store.log(scan_id, f"Pipeline started for target={target_input}")
    except Exception:
        pass
    scan_options = normalise_scan_options((scan_options or {}).get('profile', 'fast'), (scan_options or {}).get('enabled_tools'))
    scan_store.update(scan_id, scan_options=scan_options)
    def enabled(tool_id: str) -> bool:
        return is_tool_enabled(scan_options, tool_id)
    scan_store.init_tasks(scan_id, TASKS)
    coverage=[]; raw=[]; observations=[]; web=[]; smb=[]; services=[]; udp_services=[]; service_level_checks=[]; cve_prefetch_thread=None; cve_prefetch={}
    try:
        # 1
        task='Target Preparation'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        targets=expand_target_input(target_input, Config.MAX_EXPANDED_TARGETS)
        private_all=all(is_private_ip(t) for t in targets)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(targets)} target(s) accepted. Private cyber-range addresses: {private_all}')

        # Optional context footprinting is disabled in the essential profile.
        if enabled('context_footprinting'):
            task='Target Preparation'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
            for host in targets:
                dig=which('dig')
                if dig:
                    p=outfile('dig_reverse',host,'txt'); r=run_cmd([dig,'-x',host,'+short'],p,60); coverage.append(_coverage('dig', _status_from_result(r, bool((Path(r.get('output_file','')).read_text(errors='ignore').strip() if r.get('output_file') and Path(r.get('output_file')).exists() else ''))), 'reverse DNS', 'private IP reverse lookup', r.get('output_file',''), r)); _add_raw(raw,'dig',host,'',r.get('output_file',''),'dig',False)
                route=which('mtr') or which('traceroute')
                if route:
                    p=outfile('route_trace',host,'txt'); cmd=[route,'-r','-c','3',host] if Path(route).name=='mtr' else [route,host]
                    r=run_cmd(cmd,p,120); coverage.append(_coverage(Path(route).name, _status_from_result(r), 'Route path evidence', 'Optional context check', r.get('output_file',''), r)); _add_raw(raw,Path(route).name,host,'',r.get('output_file',''),Path(route).name,False)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Target context collected')

        # 3 live host discovery
        task='Host Availability Check'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        live=[]
        if enabled('arp_scan') and private_all and which('arp-scan'):
            # per /24-ish network: use arp-scan localnet, then filter to targets
            p=outfile('arp_scan','target_range','txt'); arp_cmd=[which('arp-scan'),'--localnet'] if len(targets)>1 else [which('arp-scan'), targets[0]]; r=run_cmd(arp_cmd,p,240); text=Path(r.get('output_file','')).read_text(errors='ignore') if r.get('output_file') else ''
            found=set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text)); live=[t for t in targets if t in found]
            coverage.append(_coverage('arp-scan', _status_from_result(r, bool(live)), 'local live host discovery', f'{len(live)} live host(s) found', r.get('output_file',''), r)); _add_raw(raw,'arp-scan','','',r.get('output_file',''),'arp-scan',False)
        if not live:
            nmap=which('nmap')
            if nmap:
                p=outfile('nmap_host_discovery',target_input,'xml'); r=run_cmd([nmap,'-sn','-oX',str(p)] + targets,p,600,True)
                # parse live hosts from XML
                try:
                    import xml.etree.ElementTree as ET
                    root=ET.parse(p).getroot(); live=[]
                    for h in root.findall('host'):
                        st=h.find('status')
                        if st is not None and st.get('state')=='up':
                            addr=h.find("address[@addrtype='ipv4']") or h.find('address')
                            if addr is not None: live.append(addr.get('addr'))
                except Exception: live=[]
                coverage.append(_coverage('nmap_host_discovery', _status_from_result(r, bool(live)), 'live host discovery', f'{len(live)} live host(s) found', str(p), r)); _add_raw(raw,'nmap_host_discovery','','',str(p),'nmap_xml',bool(live))
        if not live and len(targets)==1: live=targets
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if live else scan_store.STATUS_EMPTY, f'{len(live)} live host(s) selected for enumeration')
        _publish_partial(scan_id, hosts=live)

        # 4 TCP port discovery
        task='TCP Service Discovery'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        nmap=which('nmap'); open_map={h:[] for h in live}
        if enabled('tcp_discovery') and nmap and live:
            for host in live:
                p=outfile('nmap_tcp_ports',host,'xml'); r=run_cmd([nmap,'-p-','--open','-T4','--min-rate','3000','-oX',str(p),host],p,1800,True)
                rows=parse_nmap_xml(str(p)); ports=[x['port'] for x in rows]
                open_map[host]=ports
                coverage.append(_coverage('nmap_tcp_port_discovery', _status_from_result(r, bool(ports)), 'TCP open ports', f'{len(ports)} open TCP port(s)', str(p), r)); _add_raw(raw,'nmap_tcp_port_discovery',host,'',str(p),'nmap_xml',True)
        elif not enabled('tcp_discovery'):
            scan_store.log(scan_id, 'Full TCP discovery was not selected for this scan.', 'INFO')
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if any(open_map.values()) else scan_store.STATUS_EMPTY, f'{sum(len(v) for v in open_map.values())} TCP port(s) observed')
        _publish_partial(scan_id, tcp_ports_observed=sum(len(v) for v in open_map.values()))

        # 5 service fingerprint
        task='Service Fingerprinting'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        if enabled('service_fingerprint'):
            for host, ports in open_map.items():
                if not ports: continue
                p=outfile('nmap_service_fingerprint',host,'xml'); port_arg=','.join(map(str,ports))
                r=run_cmd([nmap,'-sV','--version-light','-O','--osscan-guess','-p',port_arg,'-oX',str(p),host],p,1200,True)
                rows=parse_nmap_xml(str(p)); services.extend(rows)
                coverage.append(_coverage('nmap_service_fingerprint', _status_from_result(r, bool(rows)), 'service product version cpe', f'{len(rows)} service row(s)', str(p), r)); _add_raw(raw,'nmap_service_fingerprint',host,'',str(p),'nmap_xml',True)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if services else scan_store.STATUS_EMPTY, f'{len(services)} service record(s) extracted')
        _publish_partial(scan_id, service_inventory=services)
        if services:
            cve_prefetch_thread, cve_prefetch = _start_cve_prefetch(scan_id, _normalise_service_rows([dict(x) for x in services]))

        # 6 UDP
        task='UDP Service Discovery'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        if enabled('udp_discovery'):
            udp_count = '200' if scan_options.get('profile') == 'full' else '50'
            for host in live:
                p=outfile('nmap_udp_top_' + udp_count,host,'xml'); r=run_cmd([nmap,'-sU','--top-ports',udp_count,'-sV','--version-intensity','0','-T4','-oX',str(p),host],p,1200 if udp_count == '200' else 900,True)
                rows=parse_nmap_xml(str(p),'udp'); udp_services.extend(rows)
                coverage.append(_coverage('nmap_udp_top_' + udp_count, _status_from_result(r, bool(rows)), 'UDP service evidence', f'{len(rows)} UDP service row(s)', str(p), r)); _add_raw(raw,'nmap_udp_top_' + udp_count,host,'',str(p),'nmap_xml',True)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if udp_services else scan_store.STATUS_EMPTY, f'{len(udp_services)} UDP service record(s) extracted')

        all_services=services + udp_services
        _publish_partial(scan_id, service_inventory=all_services)
        if all_services and (not cve_prefetch_thread):
            cve_prefetch_thread, cve_prefetch = _start_cve_prefetch(scan_id, _normalise_service_rows([dict(x) for x in all_services]))
        http_ports=[]; smb_ports=[]
        for s in all_services:
            svc=str(s.get('service','')).lower(); port=int(s.get('port') or 0)
            if svc in {'http','https','http-proxy','ssl/http'} or (port in {80,443,8080,8443} and svc not in {'unknown','tcpwrapped'}):
                http_ports.append(s)
            if port in {139,445} or 'smb' in svc or 'netbios' in svc:
                smb_ports.append(s)

        # 7 HTTP
        task='Web Evidence Collection'
        scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        if http_ports:
            for s in http_ports:
                host = s['host']
                port = int(s['port'])
                url = _url_for(host, port, 'ssl' in str(s.get('service','')).lower())
                nmap_http_rows = []
                if enabled('web_scripts') and which('nmap'):
                    p = outfile('nmap_http_scripts', f'{host}_{port}', 'xml')
                    r = run_cmd([which('nmap'), '-sV', '--script', 'http-title,http-headers,http-server-header,http-enum', '-p', str(port), '-oX', str(p), host], p, 300, True)
                    nmap_http_rows = parse_nmap_xml(str(p))
                    for row in nmap_http_rows:
                        row['evidence_sources'] = ['nmap_http_scripts']
                    web.append({'tool':'nmap_http_scripts','host':host,'port':port,'output_file':str(p),'rows':nmap_http_rows[:3]})
                    coverage.append(_coverage('nmap_http_scripts', _status_from_result(r, bool(nmap_http_rows)), 'HTTP title headers and server script evidence', url, str(p), r))
                    _add_raw(raw, 'nmap_http_scripts', host, port, str(p), 'nmap_xml', bool(nmap_http_rows))

                httpx_bin = which('httpx-toolkit', ['httpx']) if enabled('httpx') else None
                if httpx_bin:
                    # Capability probe only; do not show this as a user-facing enumeration command.
                    probe = _run_cmd([httpx_bin, '-h'], timeout=20)
                    probe_text = (probe.get('stdout','') + probe.get('stderr','')).lower()
                    if ('-json' in probe_text or '-jsonl' in probe_text) and '-title' in probe_text and ('-tech-detect' in probe_text or '-td' in probe_text):
                        p = outfile('httpx', f'{host}_{port}', 'jsonl')
                        r = run_cmd([httpx_bin, '-json', '-title', '-tech-detect', '-status-code', '-server', '-follow-redirects', '-u', url], p, 180)
                        parsed_httpx = parse_httpx_jsonl(str(p))
                        web.extend(parsed_httpx)
                        coverage.append(_coverage('httpx', _status_from_result(r, bool(parsed_httpx)), 'HTTP probe technology title status', url, str(p), r))
                        _add_raw(raw, 'httpx', host, port, str(p), 'jsonl', True)
                    else:
                        r = {'success': True, 'status':'empty', 'command': httpx_bin + ' -h', 'returncode': 0, 'stderr':'', 'error':'', 'output_file':'', 'stdout':'Installed httpx CLI is not ProjectDiscovery httpx or does not support the required flags; Nmap HTTP scripts are used as fallback.'}
                        coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', 'ProjectDiscovery httpx not available or incompatible; nmap HTTP scripts used as fallback', '', r))

                confirmed_web = bool(nmap_http_rows) or str(s.get('service','')).lower() in {'http','https','http-proxy','ssl/http'}
                if enabled('deep_web_discovery') and confirmed_web and which('gobuster'):
                    p = outfile('gobuster', f'{host}_{port}', 'txt')
                    r = run_cmd([which('gobuster'), 'dir', '-u', url, '-w', _wordlist(), '-t', '30', '--timeout', '2s', '-x', 'php,txt,html,jsp', '-k', '-q'], p, 480)
                    paths = parse_gobuster(str(p), host, port)
                    web.extend(paths)
                    coverage.append(_coverage('gobuster', _status_from_result(r, bool(paths)), 'web path discovery', f'{len(paths)} path(s) observed on {url}', str(p), r))
                    _add_raw(raw, 'gobuster', host, port, str(p), 'gobuster_text', True)
        else:
            coverage.append(_coverage('nmap_http_scripts', scan_store.STATUS_EMPTY, 'HTTP evidence', 'No HTTP/HTTPS services observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if web else scan_store.STATUS_EMPTY, f'{len(web)} web evidence item(s) captured')
        _publish_partial(scan_id, web_inventory=web)

        # 8 SMB
        task='SMB Evidence Collection'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        if enabled('smb_enum') and smb_ports:
            for host in sorted({str(s['host']) for s in smb_ports}):
                if which('enum4linux-ng'):
                    p=outfile('enum4linux_ng',host,'json'); r=run_cmd([which('enum4linux-ng'),'-A','-oJ',str(p.with_suffix('')),host],p,600,True)
                    actual=str(p) if Path(p).exists() else str(p)+'.json'
                    smb.append({'tool':'enum4linux-ng','host':host,'output_file':actual}); coverage.append(_coverage('enum4linux-ng', _status_from_result(r), 'SMB domain shares users OS hints', host, actual, r)); _add_raw(raw,'enum4linux-ng',host,445,actual,'json',Path(actual).exists())
                if which('smbclient'):
                    p=outfile('smbclient',host,'txt'); r=run_cmd([which('smbclient'),'-L',f'//{host}/','-N'],p,180)
                    smb.append({'tool':'smbclient','host':host,'output_file':str(p),'lines':parse_simple_lines(str(p))[:50]}); coverage.append(_coverage('smbclient', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'anonymous share listing result', host, str(p), r)); _add_raw(raw,'smbclient',host,445,str(p),'text',True)
                if enabled('smbmap') and which('smbmap'):
                    p=outfile('smbmap',host,'txt'); r=run_cmd([which('smbmap'),'-H',host,'--no-pass'],p,45)
                    smb.append({'tool':'smbmap','host':host,'output_file':str(p),'lines':parse_simple_lines(str(p))[:50]}); coverage.append(_coverage('smbmap', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'SMB share permission evidence', host, str(p), r)); _add_raw(raw,'smbmap',host,445,str(p),'text',True)
        else:
            if enabled('smb_enum'):
                for tool in ['enum4linux-ng','smbclient']: coverage.append(_coverage(tool, scan_store.STATUS_EMPTY, 'SMB evidence', 'No SMB service observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if smb else scan_store.STATUS_EMPTY, f'{len(smb)} SMB evidence item(s) captured')
        _publish_partial(scan_id, smb_inventory=smb)

        # 9 SNMP
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        snmp_targets=[s for s in all_services if int(s.get('port') or 0)==161 and str(s.get('protocol','')).lower()=='udp']
        snmp=[]
        if enabled('snmp') and snmp_targets and which('snmpwalk'):
            for s in snmp_targets:
                p=outfile('snmpwalk',s['host'],'txt'); r=run_cmd([which('snmpwalk'),'-v2c','-c','public',s['host']],p,180); snmp.append({'host':s['host'],'output_file':str(p)}); coverage.append(_coverage('snmpwalk', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'SNMP public community walk', s['host'], str(p), r)); _add_raw(raw,'snmpwalk',s['host'],161,str(p),'text',True)
        elif enabled('snmp'): coverage.append(_coverage('snmpwalk', scan_store.STATUS_EMPTY, 'SNMP enumeration', 'UDP/161 not observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if snmp else scan_store.STATUS_EMPTY, f'{len(snmp)} SNMP output file(s) captured')

        # 10 SSH
        task='SSH Configuration Review'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        ssh=[s for s in all_services if int(s.get('port') or 0)==22 or s.get('service')=='ssh']; ssh_items=[]
        if enabled('ssh_audit') and ssh and which('ssh-audit'):
            for s in ssh:
                p=outfile('ssh_audit',s['host'],'txt'); r=run_cmd([which('ssh-audit'),'-n','-p',str(s['port']),s['host']],p,240);
                if not r.get('success'):
                    r=run_cmd([which('ssh-audit'),f"{s['host']}:{s['port']}"],p,240)
                
                ssh_lines = parse_simple_lines(str(p))
                if ssh_lines and not r.get('success'):
                    r = dict(r); r['success'] = True; r['status'] = 'success'; r['error'] = ''; r['stderr'] = ''
                ssh_items.append({'host':s['host'],'port':s['port'],'output_file':str(p)})
                coverage.append(_coverage('ssh-audit', _status_from_result(r, bool(ssh_lines)), 'SSH algorithm and configuration evidence', f"{s['host']}:{s['port']}", str(p), r))
                _add_raw(raw,'ssh-audit',s['host'],s['port'],str(p),'text',bool(ssh_lines))
        elif enabled('ssh_audit'): coverage.append(_coverage('ssh-audit', scan_store.STATUS_EMPTY, 'SSH configuration evidence', 'No SSH service observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if ssh_items else scan_store.STATUS_EMPTY, f'{len(ssh_items)} SSH audit file(s) captured')

        # 11 LDAP
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        ldap=[s for s in all_services if int(s.get('port') or 0) in {389,636}]; ldap_items=[]
        if enabled('ldap') and ldap and which('ldapsearch'):
            for s in ldap:
                uri=('ldaps' if int(s['port'])==636 else 'ldap')+f"://{s['host']}:{s['port']}"
                p=outfile('ldapsearch',f"{s['host']}_{s['port']}",'txt'); r=run_cmd([which('ldapsearch'),'-x','-H',uri,'-s','base','namingContexts'],p,180); ldap_items.append({'host':s['host'],'port':s['port'],'output_file':str(p)}); coverage.append(_coverage('ldapsearch', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'LDAP naming contexts', uri, str(p), r)); _add_raw(raw,'ldapsearch',s['host'],s['port'],str(p),'text',True)
        elif enabled('ldap'): coverage.append(_coverage('ldapsearch', scan_store.STATUS_EMPTY, 'LDAP evidence', 'No LDAP service observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if ldap_items else scan_store.STATUS_EMPTY, f'{len(ldap_items)} LDAP output file(s) captured')

        # 12 TLS
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        tls=[s for s in all_services if int(s.get('port') or 0) in {443,8443,9443,636,993,995,465,587} or 'ssl' in str(s.get('service','')).lower() or 'https' in str(s.get('service','')).lower()]; tls_items=[]
        if enabled('tls') and tls and which('sslscan'):
            for s in tls:
                p=outfile('sslscan',f"{s['host']}_{s['port']}",'txt'); r=run_cmd([which('sslscan'),f"{s['host']}:{s['port']}"],p,240); tls_items.append({'host':s['host'],'port':s['port'],'output_file':str(p)}); coverage.append(_coverage('sslscan', _status_from_result(r), 'TLS certificate and cipher evidence', f"{s['host']}:{s['port']}", str(p), r)); _add_raw(raw,'sslscan',s['host'],s['port'],str(p),'text',False)
        elif enabled('tls'): coverage.append(_coverage('sslscan', scan_store.STATUS_EMPTY, 'TLS certificate and cipher evidence', 'No TLS service observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if tls_items else scan_store.STATUS_EMPTY, f'{len(tls_items)} TLS output file(s) captured')

        # 13 RDP
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        rdp=[s for s in all_services if int(s.get('port') or 0)==3389]; rdp_items=[]
        rdpscan_bin=which('rdpscan')
        if enabled('rdp') and rdp and rdpscan_bin:
            for s in rdp:
                p=outfile('rdpscan',s['host'],'txt')
                r=run_cmd([rdpscan_bin,s['host']],p,180)
                rdp_items.append({'host':s['host'],'tool':'rdpscan','output_file':str(p)})
                coverage.append(_coverage('rdpscan', _status_from_result(r), 'RDP service security evidence', s['host'], str(p), r))
                _add_raw(raw,'rdpscan',s['host'],3389,str(p),'text',False)
        elif enabled('rdp') and rdp and which('nmap'):
            for s in rdp:
                p=outfile('nmap_rdp',s['host'],'xml')
                r=run_cmd([which('nmap'),'-sV','--script','rdp-enum-encryption,rdp-ntlm-info','-p','3389','-oX',str(p),s['host']],p,240,True)
                rdp_items.append({'host':s['host'],'tool':'nmap_rdp_scripts','output_file':str(p)})
                coverage.append(_coverage('nmap_rdp_scripts', _status_from_result(r), 'RDP encryption and NTLM evidence fallback', s['host'], str(p), r))
                _add_raw(raw,'nmap_rdp_scripts',s['host'],3389,str(p),'nmap_xml',True)
        elif enabled('rdp') and rdp:
            coverage.append(_coverage('rdpscan', scan_store.STATUS_FAILED, 'RDP evidence', 'RDP observed but rdpscan and nmap were unavailable', ''))
        elif enabled('rdp'):
            coverage.append(_coverage('rdpscan', scan_store.STATUS_EMPTY, 'RDP evidence', 'No RDP service observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if rdp_items else scan_store.STATUS_EMPTY, f'{len(rdp_items)} RDP output file(s) captured')

        # 14 Hydra
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        hydra_items=[]
        hydra_services={'ssh':22,'ftp':21,'telnet':23,'mysql':3306}
        if enabled('default_credential_checks') and which('hydra'):
            for s in all_services:
                svc=str(s.get('service','')).lower(); port=int(s.get('port') or 0)
                mod=None
                for name,pn in hydra_services.items():
                    if svc==name or port==pn: mod=name; break
                if not mod: continue
                wl = _credential_combo_file()
                if not wl:
                    coverage.append(_coverage('hydra', scan_store.STATUS_EMPTY, 'Default credential check evidence', f'Default credential check skipped for {s["host"]}:{port}/{mod}; configure HYDRA_CREDENTIAL_FILE or install SecLists to enable this optional check.', ''))
                    continue
                p=outfile('hydra',f"{s['host']}_{port}_{mod}",'txt'); r=run_cmd([which('hydra'),'-C',wl,'-t','4','-f','-o',str(p),s['host'],mod,'-s',str(port)],p,600,True)
                hydra_items.append({'host':s['host'],'port':port,'service':mod,'output_file':str(p)})
                coverage.append(_coverage('hydra', _status_from_result(r, bool(parse_simple_lines(str(p)))), 'Default credential check evidence', f"{s['host']}:{port}/{mod}", str(p), r)); _add_raw(raw,'hydra',s['host'],port,str(p),'text',True)
        else: pass
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if hydra_items else scan_store.STATUS_EMPTY, f'{len(hydra_items)} credential-check output file(s) captured')

        # 15 Service-level exposure checks
        task='Focused Service Checks'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        service_level_checks = _run_service_level_checks(all_services, coverage, raw) if enabled('focused_service_checks') else []
        completed_checks = [x for x in service_level_checks if not str(x.get('status','')).startswith('Not Applicable')]
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if completed_checks else scan_store.STATUS_EMPTY, f'{len(completed_checks)} service-level check output item(s) captured')
        _publish_partial(scan_id, service_level_checks=service_level_checks)

        # 16 Evidence consolidation
        task='Evidence Consolidation'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        all_services=_merge_smb_version_evidence(all_services, smb)
        all_services=_normalise_service_rows(all_services)
        security_observations=_build_security_observations(all_services, smb, web)
        normalised={'hosts':live,'services':all_services,'web':web,'smb':smb,'snmp':snmp,'ssh':ssh_items,'ldap':ldap_items,'tls':tls_items,'rdp':rdp_items,'hydra':hydra_items,'service_level_checks':service_level_checks,'security_observations':security_observations}
        p=Path('storage/scans') / f'normalised_{scan_id}.json'; p.write_text(json.dumps(normalised, indent=2, default=str), encoding='utf-8')
        # Normalised evidence is already written as formatted JSON. Internal formatting helpers are not shown as user-facing recon tools.
        _add_raw(raw,'python_normaliser','','',str(p),'json',True)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(all_services)} service record(s) normalised')

        # 17 MITRE matching
        task='CVE Review'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        mitre=mitre_status(); cve_matches, relevant_cve_information = _match_cves(all_services) if mitre.get('available') else ([], [])
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if cve_matches else scan_store.STATUS_EMPTY, f'{len(cve_matches)} confirmed CVE finding(s) linked; {len(relevant_cve_information)} additional relevant record(s) retained.')
        _publish_partial(scan_id, cve_matches=cve_matches, relevant_cve_information=relevant_cve_information, possible_cve_references=relevant_cve_information, mitre_source=mitre)

        # 18 Caldera Handoff
        task='Handoff Preparation'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        caldera_handoff={'enabled_for_execution': False, 'note':'Recon package prepared for teammate Caldera module. Execution is disabled unless ENABLE_CALDERA_EXECUTION=1.', 'services': [{'host':s['host'],'port':s['port'],'protocol':s['protocol'],'service':s['service'],'product':s.get('product',''),'version':s.get('version','')} for s in all_services], 'cve_matches': cve_matches}
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Caldera handoff context prepared')

        # 19 Report
        task='Report Preparation'; scan_store.set_task(scan_id, task, scan_store.STATUS_RUNNING)
        candidate_cve_groups = _build_candidate_cve_groups(relevant_cve_information)
        public_coverage = _public_tool_coverage(_sort_coverage(coverage))
        service_summary = _build_service_summary(all_services, cve_matches, candidate_cve_groups)
        web_summary = _summarise_web_inventory(web)
        smb_summary = _summarise_smb_inventory(smb)
        key_exposure_indicators = _build_key_exposure_indicators(security_observations)
        service_workbench = _build_service_workbench(all_services, cve_matches, candidate_cve_groups, security_observations, web_summary, smb_summary, service_level_checks)
        attack_surface_sections = _build_attack_surface_sections(service_workbench)
        package={'scan_id':scan_id,'target_input':target_input,'scan_options':scan_options,'hosts':live,'mitre_source':mitre,'tool_coverage':public_coverage,'service_inventory':all_services,'service_summary':service_summary,'service_workbench':service_workbench,'attack_surface_sections':attack_surface_sections,'cve_matches':cve_matches,'relevant_cve_information':relevant_cve_information,'candidate_cve_groups':candidate_cve_groups,'possible_cve_references':relevant_cve_information,'service_level_checks':service_level_checks,'security_relevant_observations':security_observations,'key_exposure_indicators':key_exposure_indicators,'tcp_service_count':len([x for x in all_services if x.get('protocol')=='tcp']),'udp_service_count':len([x for x in all_services if x.get('protocol')=='udp']),'web_inventory':web,'web_summary':web_summary,'smb_inventory':smb,'smb_summary':smb_summary,'raw_evidence_index':raw,'caldera_handoff':caldera_handoff}
        package['pentester_summary'] = _build_pentester_summary(package)
        analysis_fields = {}
        try:
            from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
            from ai.technique_planner import generate_ai_technique_plan

            services_by_host = {}
            for service in all_services:
                host = str(service.get('host') or target_input or 'Unknown')
                services_by_host.setdefault(host, []).append({
                    'port': service.get('port'),
                    'protocol': service.get('protocol', 'tcp'),
                    'state': service.get('state', 'open'),
                    'service': service.get('service', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', ''),
                    'cpe': service.get('cpe', []),
                    'scripts': service.get('scripts', []),
                })
            parsed_for_mapping = {
                'target_ip': target_input,
                'os': 'Unknown',
                'hosts': [
                    {'address': {'primary': host}, 'os': {'name': 'Unknown'}, 'port_findings': ports}
                    for host, ports in services_by_host.items()
                ],
                'ports': [
                    {
                        'port': service.get('port'),
                        'protocol': service.get('protocol', 'tcp'),
                        'state': service.get('state', 'open'),
                        'service': service.get('service', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                    }
                    for service in all_services
                ],
            }
            mapping_result = map_vulnerabilities(parsed_for_mapping)
            mode = str(scan_options.get('technique_mode') or 'hybrid').lower()
            ai_plan = generate_ai_technique_plan(mapping_result, preferred_mode=mode)
            selected_ids = ai_plan.get('selected_technique_ids') or []
            mode_plan = select_attack_mode(mapping_result, mode, selected_ids)
            analysis_fields = {
                'mapping': mapping_result,
                'ai_plan': ai_plan,
                'attack_plan': {
                    'mode': mode_plan.get('mode', mode),
                    'description': mode_plan.get('description', ''),
                    'techniques': mode_plan.get('attack_plan') or mode_plan.get('recommended') or [],
                    'available_techniques': mapping_result.get('recommended_techniques', []),
                },
                'technique_mode': mode,
            }
        except Exception as analysis_exc:
            logger.warning('Scan analysis post-processing failed: %s', analysis_exc)
        out=Path('storage/results') / f'{scan_id}_handoff.json'; out.write_text(json.dumps(package, indent=2, default=str), encoding='utf-8')
        package['handoff_file']=str(out)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Report and handoff package assembled')
        scan_store.update(scan_id,status=scan_store.STATUS_SUCCESS,completed_at=scan_store.now(),results=package,**analysis_fields)
        scan_store.persist(scan_id)
    except Exception as e:
        scan_store.log(scan_id, f'Pipeline error: {e}', 'ERROR')
        scan_store.update(scan_id,status=scan_store.STATUS_FAILED,error=str(e),completed_at=scan_store.now())
        scan_store.persist(scan_id)
