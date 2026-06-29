
from __future__ import annotations
import json, os, re, ipaddress, contextvars, threading, logging, time, random, socket
from pathlib import Path
from typing import Any
from storage import scan_store
from config import Config
from .targets import expand_target_input, is_private_ip
from .tooling import which, outfile, run_cmd as _run_cmd
from .parsers import parse_nmap_xml, parse_httpx_jsonl
from .mitre_cve import OFFICIAL_CVE_SOURCE, search_with_held as mitre_search_with_held, status as mitre_status
from .scan_profiles import normalise_scan_options, is_tool_enabled
from .objectives import infer_objectives, evidence_gaps_for_service
from .passive_intel import (
    build_passive_summary, build_relationship_graph, candidate_domains, collect_certificate_transparency,
    collect_dns, collect_reverse_dns, collect_tls, infer_passive_findings, load_fingerprints,
    build_dns_relationships, build_certificate_correlation, load_passive_policy, write_passive_package,
)
from .active_validation import (
    build_active_summary, collect_api_discovery, collect_container_exposure, collect_kubernetes_exposure,
    collect_targeted_web_discovery, collect_vpn_validation, collect_federation_detection, collect_tls_intelligence, build_noise_evaluation, load_active_policy, write_active_package, service_url, _fetch, parse_external_validation, build_information_gathering_summary,
)
from .enterprise_readiness import (
    EnterprisePolicyError, build_decision_register, build_enterprise_readiness_summary,
    build_evidence_manifest, load_engagement_policy,
    load_enterprise_review_policy, validate_scope,
)
from enumeration import build_enumeration_intelligence, build_operational_maturity_package


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
            return 'Collected HTTP titles, headers, and server banner evidence.'
        if 'ftp-anon' in script_text or 'ftp-syst' in script_text:
            return 'Checked FTP banner, anonymous-login, and system evidence.'
        if 'telnet-' in script_text:
            return 'Checked Telnet service exposure and protocol/security hints.'
        if 'smtp-commands' in script_text or 'smtp-open-relay' in script_text:
            return 'Checked SMTP command and banner behaviour.'
        if 'dns-recursion' in script_text or 'dns-zone-transfer' in script_text or 'dns-nsid' in script_text:
            return 'Checked DNS recursion, NSID, and zone-transfer evidence.'
        if 'smb-enum' in script_text or 'smb-protocols' in script_text or 'smb-security-mode' in script_text:
            return 'Checked SMB protocol and security-mode evidence.'
        if 'rmi-dumpregistry' in script_text:
            return 'Checked Java RMI registry exposure evidence.'
        if 'mysql-' in script_text:
            return 'Checked MySQL version and service information evidence.'
        if 'pgsql-' in script_text or 'postgres' in script_text:
            return 'Checked PostgreSQL banner and pgsql-empty-password evidence where enabled by policy.'
        if 'vnc-info' in script_text:
            return 'Checked VNC protocol and authentication evidence.'
        if 'x11-access' in script_text:
            return 'Checked X11 access-control exposure evidence.'
        if 'irc-info' in script_text:
            return 'Checked IRC banner and server information evidence.'
        if 'ajp-' in script_text:
            return 'Checked AJP header evidence.'
        if 'ldap-rootdse' in script_text:
            return 'Checked LDAP RootDSE naming-context evidence without authentication.'
        if 'krb5-info' in script_text:
            return 'Checked Kerberos realm/service evidence without credential use.'
        if 'ssl-enum-ciphers' in script_text:
            return 'Checked TLS protocol and cipher evidence.'
        if 'rdp-enum-encryption' in script_text:
            return 'Checked RDP encryption and NLA negotiation evidence.'
        if 'banner' in script_text:
            return 'Re-probed service banner evidence for exposed or unknown services.'

    if 'nmap' in exe and '-sn' in cmd:
        return 'Target Reachability Validation.'
    if 'nmap' in exe and '-sU' in cmd:
        return 'Targeted UDP Service Discovery.'
    if 'nmap' in exe and '-p-' in cmd:
        return 'Discovered open TCP ports across a full-range follow-up scan.'
    if 'nmap' in exe and '-sV' in cmd:
        return 'Service Identity Fingerprinting.'
    if exe == 'dig':
        return 'Collected DNS context evidence such as SOA/NS/version.bind where applicable.'
    if exe in {'mtr','traceroute'}:
        return 'Captured the network route path to the target.'
    if exe == 'arp-scan':
        return 'Checked local ARP visibility for the target address or local range.'
    if exe in {'httpx', 'httpx-toolkit'}:
        return 'Probed HTTP service details such as status, title, server, and technology hints.'
    if exe == 'snmpget':
        return 'Collected targeted SNMP system identity OIDs only.'
    if exe == 'ldapsearch':
        return 'Collected LDAP RootDSE naming-context and capability evidence without authentication.'
    if exe == 'rpcinfo':
        return 'Collected RPC program mapping evidence.'
    if exe == 'showmount':
        return 'Collected NFS export readiness evidence without mounting shares.'
    if exe == 'ssh-audit':
        return 'Collected SSH cryptographic algorithm evidence without login attempts.'
    if exe == 'curl':
        return 'Collected HTTP header/security context with a single metadata request.'
    if exe == 'jq':
        return 'Formatted the normalised JSON evidence package.'
    return 'Protocol / Service Evidence Collection.'

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



def _summarise_command_output_for_ui(output: str, command: str = '', output_file: str = '') -> str:
    """Return a concise operator-facing summary while preserving raw output separately."""
    text = str(output or '').strip()
    cmd = str(command or '').lower()
    if not text or text == '[no console output captured]':
        return 'No console output was returned. Check the evidence file if one was generated.'

    # Nmap XML should never be shown as the first thing an operator reads.
    if '<nmaprun' in text or 'Starting Nmap' in text:
        open_lines = []
        for m in re.finditer(r'(\d{1,5})/(tcp|udp)\s+open\s+([^\s<]+)', text, re.I):
            open_lines.append(f"{m.group(1)}/{m.group(2)} open {m.group(3)}")
        if not open_lines:
            for m in re.finditer(r'<port protocol="(tcp|udp)" portid="(\d+)">.*?<state state="open".*?(?:<service name="([^"]+)")?', text, re.I | re.S):
                service = m.group(3) or 'unknown'
                open_lines.append(f"{m.group(2)}/{m.group(1)} open {service}")
        if open_lines:
            return 'Open service findings:\n' + '\n'.join(open_lines[:30])
        if '0 hosts up' in text.lower() or 'no open ports' in text.lower():
            return 'No open service findings were returned by this Nmap command.'
        return 'Nmap completed. Raw XML output is available below.'

    if 'tshark' in cmd or 'passive_packet_inventory' in str(output_file).lower():
        ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:20]
        protocols = []
        for p in ('ARP','DHCP','LLMNR','MDNS','NBNS'):
            if p.lower() in text.lower():
                protocols.append(p)
        summary = []
        if protocols:
            summary.append('Observed protocols: ' + ', '.join(protocols))
        if ips:
            summary.append('Observed IP hints: ' + ', '.join(ips))
        m = re.search(r'(\d+) packets captured', text, re.I)
        if m:
            summary.append(f"Packets captured: {m.group(1)}")
        return '\n'.join(summary) if summary else 'Passive capture completed; no protocol summary could be extracted.'

    if 'ssh-audit' in cmd:
        lines=[]
        for pat in (r'\(gen\) banner:\s*([^\n\r]+)', r'\(gen\) software:\s*([^\n\r]+)', r'\(fin\) ([^\n\r]+)'):
            for m in re.finditer(pat, text):
                lines.append(m.group(1).strip())
        fails=len(re.findall(r'\[fail\]', text))
        warns=len(re.findall(r'\[warn\]', text))
        if fails or warns:
            lines.append(f'SSH posture observations: {fails} fail marker(s), {warns} warning marker(s).')
        return '\n'.join(lines[:12]) if lines else 'SSH audit completed; raw output is available below.'

    # Generic concise first lines for normal text tools.
    useful=[]
    for line in text.splitlines():
        clean=line.strip()
        if not clean or clean.startswith('<?xml') or clean.startswith('<!DOCTYPE'):
            continue
        useful.append(clean)
        if len(useful) >= 12:
            break
    return '\n'.join(useful) if useful else 'Command completed. Raw output is available below.'

def _active_command_delay() -> None:
    """Policy-driven spacing between active probes. This is for authorised low-noise operation, not bypassing monitoring."""
    try:
        policy = _load_recon_policy()
        guard = _policy_required(policy, 'active_command_guardrails')
        if not bool(guard.get('enabled', True)):
            return
        base = float(guard.get('min_delay_seconds', 0))
        jitter = float(guard.get('max_jitter_seconds', 0))
        delay = max(0.0, base) + (random.random() * max(0.0, jitter))
        if delay > 0:
            time.sleep(delay)
    except Exception:
        return


def run_cmd(cmd: list[str], output_file: Path | None = None, timeout: int = 300, tool_writes_file: bool = False) -> dict[str, Any]:
    sid = _CURRENT_SCAN_ID.get()
    command_text = ' '.join(map(str, cmd))
    exe = Path(str(cmd[0])).name.lower() if cmd else ''
    purpose = _describe_command(cmd)
    _active_command_delay()
    result = _run_cmd(cmd, output_file=output_file, timeout=timeout, tool_writes_file=tool_writes_file)

    if sid:
        output, truncated = _captured_command_output(result, output_file)
        status = 'Completed Successfully' if result.get('success') else ('Timed Out - Partial Results Retained' if str(result.get('error','')).lower() == 'timeout' else 'Failed - Command Error')
        scan_store.log_command(
            sid,
            command=command_text,
            purpose=purpose,
            output=output,
            output_summary=_summarise_command_output_for_ui(output, command_text, str(output_file or result.get('output_file') or '')),
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



class ReconPolicyError(RuntimeError):
    pass

def _load_recon_policy() -> dict[str, Any]:
    """Load policy values controlling recon behaviour. Fail closed if unavailable."""
    candidates = [Path('project/policies/recon_policy.json'), Path('policies/recon_policy.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        raise ReconPolicyError('Recon policy file is missing; scan aborted rather than using hardcoded defaults.')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise ReconPolicyError(f'Recon policy could not be parsed: {exc}') from exc

    # Optional external TCP micro-batch profile. This keeps port coverage policy-owned
    # instead of embedded in scanner logic, while preserving backwards compatibility.
    profile_file = data.get('tcp_micro_batch_profile_file')
    if profile_file:
        profile_candidates = [Path(profile_file), Path('project') / profile_file]
        profile_path = next((p for p in profile_candidates if p.exists()), None)
        if profile_path:
            try:
                profile_data = json.loads(profile_path.read_text(encoding='utf-8'))
                profile_name = str(data.get('tcp_micro_batch_profile') or profile_data.get('default_profile') or 'full')
                selected = (profile_data.get('profiles') or {}).get(profile_name) or {}
                if selected.get('tcp_micro_batches'):
                    data['tcp_micro_batches'] = selected['tcp_micro_batches']
            except Exception as exc:
                raise ReconPolicyError(f'TCP port profile could not be parsed: {exc}') from exc

    required = ['tcp_discovery_stages', 'critical_banner_ports', 'stop_conditions', 'scan_postures', 'ttl_hints', 'acl_detection', 'httpx_options', 'active_command_guardrails', 'active_validation_guardrails']
    missing = [k for k in required if k not in data]
    if missing:
        raise ReconPolicyError(f'Recon policy is incomplete; missing keys: {missing}')
    return data


def _policy_required(policy: dict[str, Any], key: str) -> Any:
    if key not in policy:
        raise ReconPolicyError(f'Recon policy is incomplete; missing key: {key}')
    return policy[key]


def _policy_nested(policy: dict[str, Any], section: str, key: str) -> Any:
    data = _policy_required(policy, section)
    if not isinstance(data, dict) or key not in data:
        raise ReconPolicyError(f'Recon policy is incomplete; missing key: {section}.{key}')
    return data[key]



def _load_collector_registry() -> dict[str, Any]:
    candidates = [Path('project/policies/collector_registry.json'), Path('policies/collector_registry.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        raise ReconPolicyError('Collector registry is missing; scan aborted rather than using hardcoded collector logic.')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise ReconPolicyError(f'Collector registry could not be parsed: {exc}') from exc


def _collector_required(collector_id: str) -> dict[str, Any]:
    registry = _load_collector_registry()
    if collector_id not in registry:
        raise ReconPolicyError(f'Collector registry is incomplete; missing collector: {collector_id}')
    item = registry[collector_id]
    if not isinstance(item, dict):
        raise ReconPolicyError(f'Collector registry entry is invalid: {collector_id}')
    return item


def _collector_scripts(collector_id: str) -> list[str]:
    item = _collector_required(collector_id)
    scripts = item.get('nmap_scripts') or []
    if not isinstance(scripts, list) or not all(isinstance(x, str) and x.strip() for x in scripts):
        raise ReconPolicyError(f'Collector {collector_id} must define nmap_scripts as a non-empty string list.')
    return [x.strip() for x in scripts]


def _collector_ports(collector_id: str) -> set[int]:
    item = _collector_required(collector_id)
    ports = item.get('ports') or []
    if not isinstance(ports, list):
        raise ReconPolicyError(f'Collector {collector_id} must define ports as a list.')
    return {int(x) for x in ports}


def _script_output_for_host_port(service_level_checks: list[dict[str, Any]], host: str, port: int) -> str:
    chunks: list[str] = []
    for item in service_level_checks or []:
        if str(item.get('host')) != str(host):
            continue
        if item.get('port') not in (None, '', port, str(port)) and str(item.get('port')) != str(port):
            continue
        for row in item.get('rows') or []:
            if str(row.get('host')) != str(host) or int(row.get('port') or 0) != int(port):
                continue
            for script in row.get('scripts') or []:
                chunks.append(str(script.get('id') or ''))
                chunks.append(str(script.get('output') or ''))
        if item.get('output_file'):
            chunks.append(_read_text(item.get('output_file'))[:12000])
        if item.get('output'):
            chunks.append(str(item.get('output'))[:12000])
    return '\n'.join(chunks)


def _parse_http_forms_from_html(html: str) -> dict[str, Any]:
    """Extract low-impact form/input hints. This does not send payloads."""
    forms: list[dict[str, Any]] = []
    for m in re.finditer(r'<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>', html or '', flags=re.I|re.S):
        attrs = m.group('attrs') or ''
        body = m.group('body') or ''
        def attr(name: str, text: str = attrs) -> str:
            q = re.search(rf'{name}\s*=\s*["\']([^"\']+)["\']', text, flags=re.I)
            if q:
                return q.group(1)
            q = re.search(rf'{name}\s*=\s*([^\s>]+)', text, flags=re.I)
            return q.group(1) if q else ''
        inputs = []
        for im in re.finditer(r'<(?:input|textarea|select)\b(?P<attrs>[^>]*)>', body, flags=re.I|re.S):
            ia = im.group('attrs') or ''
            inputs.append({'name': attr('name', ia), 'type': (attr('type', ia) or im.group(0).split()[0].strip('<')).lower()})
        forms.append({'method': (attr('method') or 'GET').upper(), 'action': attr('action'), 'inputs': inputs})
    links = sorted(set(re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html or '', flags=re.I)))[:50]
    return {'forms': forms, 'links': links}


def _collect_single_page_form_hints(host: str, port: int, url: str) -> dict[str, Any]:
    curl_bin = which('curl')
    if not curl_bin:
        return {'success': False, 'forms': [], 'links': [], 'error': 'curl not found'}
    p = outfile('web_form_hints', f'{host}_{port}', 'html')
    
    guard = _policy_required(_load_recon_policy(), 'http_probe_guardrails')
    result = run_cmd([curl_bin, '-sS', '--max-time', str(_policy_required(guard, 'curl_timeout_seconds')), '-L', '--max-redirs', str(_policy_required(guard, 'max_redirects')), url], p, 30)
    html = Path(p).read_text(encoding='utf-8', errors='ignore') if Path(p).exists() else str(result.get('stdout') or '')
    parsed = _parse_http_forms_from_html(html)
    return {**result, **parsed, 'output_file': str(p), 'url': url}


def _host_environment_items(environment: list[dict[str, Any]], host: str) -> list[dict[str, Any]]:
    return [x for x in environment or [] if str(x.get('host')) == str(host)]


def _host_ttl(environment: list[dict[str, Any]], host: str) -> int | None:
    for item in _host_environment_items(environment, host):
        if item.get('ttl') is not None:
            try:
                return int(item.get('ttl'))
            except Exception:
                return None
    return None




def _classify_network_layer(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> dict[str, Any]:
    """Classify a target dynamically from observed evidence, never from hardcoded IP ranges."""
    ttl = _host_ttl(environment or [], host)
    pset = set(int(p) for p in (ports or []))
    policy = _load_recon_policy()
    role = 'unclassified_target'
    posture = 'default'
    evidence: list[str] = []
    if ttl is not None:
        evidence.append(f'ttl:{ttl}')
    if pset:
        evidence.append('ports:' + ','.join(map(str, sorted(pset)[:20])))
    ttl_cfg = _policy_required(policy, 'ttl_hints')
    infra_min = int(_policy_nested(policy, 'ttl_hints', 'network_device_min'))
    win_min = int(_policy_nested(policy, 'ttl_hints', 'windows_family_min'))
    linux_min = int(_policy_nested(policy, 'ttl_hints', 'linux_unix_min'))
    if ttl is not None and ttl >= infra_min and len(pset) <= 3 and pset & {22, 80, 443}:
        role = 'infrastructure_candidate'
        posture = 'infrastructure_observed'
    elif ttl is not None and ttl >= win_min and pset & {135, 139, 445, 5985, 5986}:
        role = 'windows_like_candidate'
        posture = 'windows_like_observed'
    elif ttl is not None and linux_min <= ttl < win_min and pset & {21, 22, 23, 25, 53, 80, 111, 2049}:
        role = 'linux_unix_like_candidate'
        posture = 'default'
    elif len(pset) >= int(_policy_nested(policy, 'stop_conditions', 'high_density_after_top20')):
        role = 'high_service_density_candidate'
        posture = 'default'
    try:
        ip = ipaddress.ip_address(str(host))
        address_scope = 'private' if ip.is_private else 'public'
    except Exception:
        address_scope = 'hostname_or_unparsed'
    return {'host': host, 'role': role, 'scan_posture': posture, 'matched_cidr': '', 'description': 'Dynamic evidence-based classification; no IP ranges are hardcoded.', 'address_scope': address_scope, 'evidence': evidence}

def _scan_posture(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> dict[str, Any]:
    policy = _load_recon_policy()
    layer = _classify_network_layer(host, environment, ports)
    postures = _policy_required(policy, 'scan_postures')
    if 'default' not in postures:
        raise ReconPolicyError('Recon policy is incomplete; missing scan_postures.default')
    selected = layer.get('scan_posture') or 'default'
    if selected not in postures:
        raise ReconPolicyError(f'Recon policy is incomplete; missing scan posture: {selected}')
    return {**dict(postures['default']), **dict(postures[selected]), 'network_layer': layer, 'scan_posture': selected}

def _is_infrastructure_target(host: str, environment: list[dict[str, Any]] | None = None, ports: list[int] | None = None) -> bool:
    layer = _classify_network_layer(host, environment, ports)
    if layer.get('scan_posture') == 'infrastructure_observed':
        return True
    ttl = _host_ttl(environment or [], host)
    pset = set(int(p) for p in (ports or []))
    policy = _load_recon_policy()
    infra_min = int(_policy_nested(policy, 'ttl_hints', 'network_device_min'))
    return bool(ttl is not None and ttl >= infra_min and len(pset) <= 3 and bool(pset & {22,80,443}))

def _acl_filtering_indicator(host: str, filtered_count: int, closed_count: int, total_sampled: int) -> dict[str, Any] | None:
    policy = _load_recon_policy()
    cfg = _policy_required(policy, 'acl_detection')
    threshold = float(_policy_nested(policy, 'acl_detection', 'filtered_ratio_threshold'))
    min_sampled = int(_policy_nested(policy, 'acl_detection', 'min_sampled_ports'))
    if total_sampled < min_sampled:
        return None
    ratio = float(filtered_count) / float(max(total_sampled, 1))
    if ratio >= threshold:
        return {'host': host, 'indicator': 'acl_or_firewall_filtering_suspected', 'evidence': f'{filtered_count}/{total_sampled} sampled TCP ports were filtered/no-response.', 'interpretation': 'An intermediate ACL/firewall may be filtering results. Treat negative scan results as incomplete.'}
    return None

def _build_network_topology_summary(hosts: list[str], environment: list[dict[str, Any]], open_map: dict[str, list[int]], environment_context_indicators: list[dict[str, Any]]) -> dict[str, Any]:
    layers: dict[str, dict[str, Any]] = {}
    for host in hosts or []:
        layer = _classify_network_layer(host, environment, open_map.get(host) or [])
        role = str(layer.get('role') or 'unknown')
        item = layers.setdefault(role, {'role': role, 'scan_posture': layer.get('scan_posture') or 'default', 'description': layer.get('description',''), 'hosts': []})
        host_indicators = [d for d in environment_context_indicators or [] if str(d.get('host')) == str(host)]
        item['hosts'].append({'host': host, 'ttl': _host_ttl(environment, host), 'open_tcp_ports': sorted(set(int(p) for p in (open_map.get(host) or []))), 'environment_context_indicators': host_indicators, 'reliability': 'environment_context_observed' if host_indicators else 'baseline_observed'})
    return {'layers': list(layers.values()), 'classification_mode': 'dynamic_evidence_based_no_hardcoded_ip_ranges'}

def _host_profile_from_observations(host: str, ports: list[int], environment: list[dict[str, Any]]) -> dict[str, Any]:
    ttl = _host_ttl(environment, host)
    pset = set(int(p) for p in ports or [])
    hints: list[str] = []
    if ttl is not None and ttl >= 100 and {135,139,445} & pset:
        hints.append('windows_like')
    if ttl is not None and ttl >= 40 and ttl < 100 and ({21,22,23,25,53,80,111,2049} & pset):
        hints.append('linux_unix_like')
    if len(pset) > 10:
        hints.append('high_service_density')
    if len(pset) <= 3 and ({22,80,443} & pset):
        hints.append('perimeter_or_management_like')
    return {'host': host, 'ttl': ttl, 'ports': sorted(pset), 'hints': hints}


def _should_stop_discovery(host: str, ports: list[int], environment: list[dict[str, Any]], topn: int, policy: dict[str, Any]) -> tuple[bool, str]:
    """Full Recon does not stop just because a lab/legacy host is dense.

    High service density is still recorded as an environment context indicator, but it
    must not cause Telnet, RPC, VNC, NFS, Tomcat/AJP, SNMP, AD, database or
    cloud-native validation to be skipped. Filtering is treated as likely
    segmentation/ACL evidence rather than proof of environment context.
    """
    profile = _host_profile_from_observations(host, ports, environment)
    pset = set(int(p) for p in ports or [])
    stop_cfg = _policy_required(policy, 'stop_conditions')
    if not bool(stop_cfg.get('stop_on_high_density_in_full', False)):
        if _classify_network_layer(host, environment, ports).get('scan_posture') == 'infrastructure_observed':
            return True, 'Infrastructure-like target observed; top-port expansion complete; service validation will remain policy-gated.'
        return False, ''
    high_density = int(_policy_nested(policy, 'stop_conditions', 'high_density_after_top20'))
    windows_ports = set(int(x) for x in _policy_nested(policy, 'stop_conditions', 'windows_like_min_ports_to_stop'))
    if topn >= 20 and profile.get('ttl') is not None and int(profile['ttl']) >= 100 and windows_ports.issubset(pset):
        return True, 'Windows-like host surface identified from TTL and SMB/MSRPC ports; further top-port stages deferred.'
    if topn >= 20 and len(pset) >= high_density:
        return True, f'High service density observed after top-{topn}; high-value validation continues within policy.'
    sufficient_after_top50 = int(_policy_nested(policy, 'stop_conditions', 'sufficient_services_after_top50'))
    if _classify_network_layer(host, environment, ports).get('scan_posture') == 'infrastructure_observed':
        return True, 'Infrastructure-like target observed; further top-port expansion deferred.'
    if topn >= 50 and len(pset) >= sufficient_after_top50:
        return True, f'Sufficient attack-surface evidence collected by top-{topn}; further top-port expansion deferred.'
    return False, ''


def _has_host_indicator(environment_context_indicators: list[dict[str, Any]], host: str, name: str) -> bool:
    return any(str(x.get('host')) == str(host) and str(x.get('indicator')) == name for x in environment_context_indicators or [])



def _default_capture_interface() -> str:
    """Return the default outbound interface without probing the network."""
    env_iface = os.getenv('AUTOPENTEST_PASSIVE_INTERFACE', '').strip()
    if env_iface:
        return env_iface
    try:
        # /proc/net/route is local host state, not network probing.
        for line in Path('/proc/net/route').read_text(errors='ignore').splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == '00000000':
                return parts[0]
    except Exception:
        pass
    return ''


def _collect_passive_local_inventory(scan_id: str, coverage: list[dict[str, Any]], raw: list[dict[str, Any]], enabled_fn) -> dict[str, Any]:
    """Listen-only local inventory. No target packets are generated."""
    result = {'tshark': {}, 'p0f': {}, 'summary': []}
    policy = _load_recon_policy().get('passive_local_inventory') or {}
    if not policy.get('enabled', True):
        coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Passive local inventory disabled', 'Listen-only packet inventory disabled by policy.', ''))
        coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Passive OS fingerprinting disabled', 'Listen-only p0f fingerprinting disabled by policy.', ''))
        return result
    iface = _default_capture_interface()
    if not iface:
        msg = 'No approved capture interface configured; set AUTOPENTEST_PASSIVE_INTERFACE to enable listen-only passive inventory.'
        if enabled_fn('passive_packet_inventory'):
            coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Suggested follow-up', msg, ''))
        if enabled_fn('passive_os_fingerprinting'):
            coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Suggested follow-up', msg, ''))
        return result
    if enabled_fn('passive_packet_inventory'):
        tshark_bin = which('tshark')
        if tshark_bin:
            p = outfile('passive_packet_inventory', iface, 'txt')
            duration = str(int(policy.get('duration_seconds') or 120))
            filt = str(policy.get('tshark_filter') or 'arp or mdns or dhcp or llmnr')
            cmd = [tshark_bin, '-i', iface, '-a', f'duration:{duration}', '-Y', filt]
            r = run_cmd(cmd, p, int(duration)+30)
            output, _ = _captured_command_output(r, Path(p))
            ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)))[:200]
            result['tshark'] = {'interface': iface, 'duration_seconds': int(duration), 'filter': filt, 'observed_ips': ips, 'output_file': str(p)}
            if ips:
                result['summary'].append(f'Passive local packet inventory observed {len(ips)} IP address hint(s) on {iface}.')
            coverage.append(_coverage('passive_packet_inventory', _status_from_result(r, bool(output.strip())), 'Listen-only ARP/mDNS/DHCP/LLMNR inventory', f'{len(ips)} IP hint(s) retained from ambient traffic; no target probes generated.', str(p), r))
            _add_raw(raw, 'passive_packet_inventory', '', '', str(p), 'text', bool(output.strip()))
        else:
            coverage.append(_coverage('passive_packet_inventory', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'tshark not available for listen-only packet inventory.', ''))
    if enabled_fn('passive_os_fingerprinting'):
        p0f_bin = which('p0f')
        if p0f_bin:
            p = outfile('passive_os_fingerprinting', iface, 'txt')
            duration = int(policy.get('p0f_duration_seconds') or policy.get('duration_seconds') or 120)
            # timeout is used to stop p0f after a bounded passive window.
            timeout_bin = which('timeout')
            cmd = ([timeout_bin, str(duration), p0f_bin, '-i', iface, '-p'] if timeout_bin else [p0f_bin, '-i', iface, '-p'])
            r = run_cmd(cmd, p, duration+30)
            output, _ = _captured_command_output(r, Path(p))
            result['p0f'] = {'interface': iface, 'duration_seconds': duration, 'output_file': str(p), 'observed': bool(output.strip())}
            if output.strip():
                result['summary'].append('Passive OS fingerprinting retained p0f ambient traffic hints.')
            coverage.append(_coverage('passive_os_fingerprinting', _status_from_result(r, bool(output.strip())), 'Listen-only p0f passive OS hints', 'p0f passive capture completed; no target probes generated.', str(p), r))
            _add_raw(raw, 'passive_os_fingerprinting', '', '', str(p), 'text', bool(output.strip()))
        else:
            coverage.append(_coverage('passive_os_fingerprinting', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'p0f not available for passive OS fingerprinting.', ''))
    return result

TASKS = [
    'Scope and Target Validation',
    'Passive Network Observation',
    'Passive Intelligence Correlation',
    'TCP Service Discovery',
    'Service Identity Fingerprinting',
    'Preliminary Attack Surface Assembly',
    'Protocol-Specific Evidence Collection',
    'Evidence Gap Review',
    'Evidence Normalisation and Merge',
    'MITRE CVE Correlation',
    'Handoff Package Preparation',
    'Final Report Data Assembly',
]
_TASK_ALIASES = {
    'Target Preparation': 'Scope and Target Validation',
    'Environment Characterisation': 'Passive Network Observation',
    'Host Availability Check': 'Scope and Target Validation',
    'Passive Intelligence Collection': 'Passive Intelligence Correlation',
    'Low-Impact Service Discovery': 'TCP Service Discovery',
    'Service Identity Collection': 'Service Identity Fingerprinting',
    'Preliminary Attack Surface Report': 'Preliminary Attack Surface Assembly',
    'Objective-Based Evidence Collection': 'Protocol-Specific Evidence Collection',
    'Modern Active Validation': 'Protocol-Specific Evidence Collection',
    'Native Protocol Metadata Enrichment': 'Protocol-Specific Evidence Collection',
    'Evidence Consolidation': 'Evidence Normalisation and Merge',
    'CVE Review': 'MITRE CVE Correlation',
    'Handoff Preparation': 'Handoff Package Preparation',
    'Report Preparation': 'Final Report Data Assembly',
}

def _task_name(name: str) -> str:
    return _TASK_ALIASES.get(name, name)


def _status_from_result(result: dict[str, Any], produced: bool = True) -> str:
    if not result.get('success'): return scan_store.STATUS_FAILED
    return scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY

def _finish(scan_id: str, task: str, status: str, summary: str = '') -> None:
    scan_store.set_task(scan_id, _task_name(task), status, summary=summary)

def _extract_ttl(text: str) -> int | None:
    m = re.search(r'ttl[= ](\d+)', text or '', re.I)
    return int(m.group(1)) if m else None

def _environment_role_hint(ttl: int | None, service_count: int = 0) -> str:
    if ttl is not None and ttl >= 200:
        return 'network_infrastructure_indicator'
    if ttl is not None and ttl >= 100:
        return 'windows_family_indicator'
    if ttl is not None and ttl >= 40:
        return 'linux_unix_family_indicator'
    if service_count > 20:
        return 'high_service_density_lab_or_legacy_indicator'
    return 'undetermined'

def _detect_environment_context_indicators(open_ports: list[int], banners: dict[int, str] | None = None, ttl: int | None = None, filtered_count: int = 0, retransmission_warning: bool = False, host_profile: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    port_count = len(open_ports or [])
    if port_count > 10:
        indicators.append({
            'indicator': 'high_service_density',
            'evidence': f'{port_count} open TCP ports were observed during staged discovery.',
            'interpretation': 'This can indicate a lab-style host, exposed legacy server, infrastructure concentration, or possible lab-style or synthetic service behaviour. Full Recon continues high-value validation and records the observation.',
        })
    if filtered_count >= 10:
        indicators.append({
            'indicator': 'filtered_no_response_pattern',
            'evidence': f'{filtered_count} ports were reported as filtered/no-response.',
            'interpretation': 'Filtering/no-response behaviour can indicate firewall policy, endpoint filtering, or scan handling controls.',
        })
    if retransmission_warning:
        indicators.append({
            'indicator': 'retransmission_cap_hit',
            'evidence': 'Nmap reported retransmission cap behaviour during staged discovery.',
            'interpretation': 'The target or path may be filtering, rate-limiting, or dropping probes. Treat negative evidence as incomplete and continue only policy-approved validation.',
        })
    banners = banners or {}
    non_empty = [b for b in banners.values() if b]
    if len(non_empty) > 5 and len(set(non_empty)) <= 2:
        indicators.append({
            'indicator': 'repeated_banner_pattern',
            'evidence': 'Multiple services returned highly similar banner text.',
            'interpretation': 'Repeated banners may indicate synthetic service behaviour or an environment context pattern.',
        })
    if ttl is not None and ttl >= 200 and port_count > 10:
        indicators.append({
            'indicator': 'infrastructure_ttl_with_many_services',
            'evidence': f'TTL {ttl} was observed with {port_count} open ports.',
            'interpretation': 'Network-device TTL combined with high service density is unusual and should be reviewed.',
        })
    if host_profile and 'windows_like' in (host_profile.get('hints') or []) and any(p in set(open_ports or []) for p in [21,22,23,25,111,2049]):
        indicators.append({
            'indicator': 'mixed_host_profile',
            'evidence': 'Windows-like TTL/SMB evidence was observed with non-Windows legacy service exposure.',
            'interpretation': 'Mixed host traits can indicate NAT, proxying, lab-style context, or evidence contamination and should be reviewed.',
        })
    return indicators



def _environment_is_local_or_internal(host: str, environment: list[dict[str, Any]]) -> bool:
    """Return True when evidence suggests the scanner is operating inside the lab/internal segment."""
    try:
        if ipaddress.ip_address(host).is_private:
            return True
    except Exception:
        pass
    # Keep this conservative; absence of proof does not make a target external.
    return False

def _critical_banner_ports(open_ports: list[int], environment_context_observed: bool = False) -> list[int]:
    """Return all observed ports for Full Recon when policy requests full identity coverage."""
    ports = sorted(set(int(p) for p in (open_ports or []) if str(p).isdigit() or isinstance(p, int)))
    policy = _load_recon_policy()
    if bool(policy.get('full_fingerprint_all_observed_ports', True)):
        return ports
    preferred = [int(p) for p in _policy_required(policy, 'critical_banner_ports')]
    selected = [p for p in preferred if p in set(ports)]
    if not selected:
        selected = ports[:3 if environment_context_observed else 6]
    return selected

def _build_follow_up_objectives(open_map: dict[str, list[int]], environment_context_indicators: list[dict[str, Any]], services: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Suggested follow-up only; recon does not execute noisy validation by default."""
    suggestions: list[dict[str, Any]] = []
    all_ports = sorted({int(p) for ports in (open_map or {}).values() for p in ports})
    environment_context_present = bool(environment_context_indicators)
    def add(name: str, reason: str, trigger: str, noise: str = 'medium') -> None:
        suggestions.append({'objective': name, 'reason': reason, 'trigger': trigger, 'noise': noise, 'execution': 'not_auto_executed'})
    if environment_context_present:
        add('Environment context review', 'High-density, filtering, or mixed-profile observations were retained for interpretation. Full Recon still validates high-value services within policy.', 'environment_context_indicator', 'medium')
    if all_ports:
        add('Full TCP coverage', 'Full 65k TCP sweep was deferred; Full Recon uses micro-batched high-value coverage plus targeted expansion instead.', 'port_coverage_gap', 'high')
    if any(p in all_ports for p in [80,443,8080,8180,8009]):
        add('Web path discovery', 'Directory/content discovery was deferred; use only if web evidence remains insufficient.', 'web_surface_observed', 'high')
        add('Web exploitation validation', 'SQL injection, command injection, upload and authentication testing are deferred to downstream web-validation modules.', 'web_surface_observed', 'high')
    if any(p in all_ports for p in [139,445]):
        add('Deep SMB enumeration', 'Broad SMB enumeration and permission mapping were deferred; use only after approval.', 'smb_surface_observed', 'medium-high')
        add('SMB/WinRM authentication surface validation', 'SMB exposure was observed. Credential validation and WinRM checks are deferred to downstream validation modules.', 'smb_or_windows_surface_observed', 'high')
    if any(p in all_ports for p in [22]):
        add('SSH cryptographic posture review', 'SSH posture review is deferred to downstream validation.', 'ssh_observed', 'medium')
    if any(p in all_ports for p in [111,2049]):
        add('NFS/RPC export validation', 'NFS deep listing/statfs checks were deferred.', 'nfs_rpc_surface_observed', 'medium-high')
    if any(p in all_ports for p in [3306,5432,1433,1521]):
        add('Database authentication validation', 'Empty-password/default credential checks were deferred to downstream validation.', 'database_surface_observed', 'high')
    if any(p in all_ports for p in [53,161,123,137,138,2049]):
        add('Targeted UDP follow-up', 'Broad UDP discovery is deferred by default; run only where service evidence justifies it.', 'udp_relevance_possible', 'medium-high')
    return suggestions

def _build_environment_summary(environment: list[dict[str, Any]], environment_context_indicators: list[dict[str, Any]]) -> dict[str, Any]:
    ttl_values = [x.get('ttl') for x in environment if x.get('ttl') is not None]
    return {
        'items': environment,
        'ttl_values': ttl_values,
        'role_hints': sorted({str(x.get('role_hint')) for x in environment if x.get('role_hint')}),
        'environment_context_indicators': environment_context_indicators,
    }



def _build_authentication_surface_readiness(services: list[dict[str, Any]], environment: list[dict[str, Any]], smb_summary: dict[str, Any], service_level_checks: list[dict[str, Any]] | None = None, credential_validation_items: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    service_level_checks = service_level_checks or []
    credential_validation_items = credential_validation_items or []
    for s in services or []:
        host = s.get('host')
        port = int(s.get('port') or 0)
        svc = str(s.get('service') or '').lower()
        prod = str(s.get('product') or '')
        check_text = _script_output_for_host_port(service_level_checks, str(host), port).lower()
        if port in {21,2121} or svc == 'ftp':
            anonymous_allowed = any(x in check_text for x in ['anonymous ftp login allowed', 'ftp code 230', 'logged in as ftp'])
            anonymous_denied = any(x in check_text for x in ['anonymous ftp login allowed' if False else 'anonymous ftp login allowed']) is False and 'ftp-anon' in check_text and not anonymous_allowed
            evidence = 'FTP exposed; anonymous access status checked where safe.'
            if anonymous_allowed:
                evidence = 'FTP exposed; anonymous access appears allowed from collected ftp-anon evidence.'
            elif 'ftp-anon' in check_text:
                evidence = 'FTP exposed; ftp-anon check did not confirm anonymous access.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'ftp','candidate_type':'authentication_surface_candidate','anonymous_allowed': anonymous_allowed, 'safe_recon_checks':['ftp-anon','ftp-syst'] if check_text else [], 'evidence': evidence, 'recommended_downstream_module':'credential_validation','recon_boundary':'Recon checked anonymous/system hints only; no brute force or password attempts performed.'})
        if port == 22 or svc == 'ssh':
            auth_methods = sorted(set(re.findall(r'\b(publickey|password|keyboard-interactive|gssapi[^,\s]*)\b', check_text, flags=re.I)))
            password_auth = any(str(x).lower() == 'password' for x in auth_methods)
            evidence = f'SSH exposed ({prod or "banner available"}); auth-method readiness collected where available.'
            if auth_methods:
                evidence += ' Advertised auth methods: ' + ', '.join(auth_methods) + '.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'ssh','candidate_type':'authentication_surface_candidate','password_auth_advertised': password_auth, 'auth_methods': auth_methods, 'safe_recon_checks':['ssh-auth-methods'] if check_text else [], 'evidence':evidence,'recommended_downstream_module':'credential_validation','recon_boundary':'Recon requests advertised authentication methods only; no login attempts performed.'})
        if port in {139,445} or 'smb' in svc or 'netbios' in svc or 'microsoft-ds' in svc:
            signing_required = None
            if 'message signing enabled and required' in check_text or 'signing enabled and required' in check_text:
                signing_required = True
            elif 'message signing enabled but not required' in check_text or 'not required' in check_text:
                signing_required = False
            dialect_hints = sorted(set(re.findall(r'\bSMBv?\s*([123](?:\.[0-9])?)\b', check_text, flags=re.I)))
            evidence = 'SMB/NetBIOS surface exposed; dialect/signing readiness collected where safe. Share/user enumeration deferred.'
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'smb','candidate_type':'authentication_surface_candidate','smb_signing_required': signing_required, 'smb_dialect_hints': dialect_hints, 'safe_recon_checks':['smb2-security-mode','smb-protocols'] if check_text else [], 'evidence':evidence,'recommended_downstream_module':'credential_validation','recon_boundary':'Recon checks SMB protocol/signing only; no share, user, RID, password, or permission enumeration performed.'})
        if port in {5985,5986} or svc == 'winrm':
            related = [x for x in credential_validation_items if str(x.get('host')) == str(host) and int(x.get('port') or 0) == port]
            auth_headers = []
            for item in related:
                if item.get('auth_headers'):
                    auth_headers.extend(item.get('auth_headers') or [])
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':'winrm','candidate_type':'authentication_surface_candidate','auth_headers': sorted(set(auth_headers)), 'safe_recon_checks':['wsman_head'] if related else [], 'evidence':'WinRM management surface exposed; listener/header readiness collected where available. Authentication validation deferred.','recommended_downstream_module':'credential_validation','recon_boundary':'Recon probes the WSMan endpoint only; no authentication attempts performed.'})
    return _dedupe_dicts(rows, ('host','port','service','candidate_type'))



def _split_technology_hints(tech_items: list[Any]) -> tuple[list[str], list[str]]:
    """Split web technology hints into evidence-backed and unverified buckets.

    ProjectDiscovery/httpx fingerprints can include false-positive CPE/tech hints.
    Only conservative server/framework hints remain in evidence-backed conclusions;
    noisy guesses such as bun/phpMyAdmin/metasploit are retained as unverified hints.
    """
    observed: list[str] = []
    unverified: list[str] = []
    noisy_terms = {'bun', 'phpmyadmin', 'metasploit'}
    conservative_terms = ('apache', 'nginx', 'iis', 'php', 'ubuntu', 'debian', 'tomcat', 'mod_dav', 'openssh')
    for item in tech_items or []:
        value = str(item or '').strip()
        if not value:
            continue
        low = value.lower()
        if any(term in low for term in noisy_terms):
            unverified.append(value)
        elif any(term in low for term in conservative_terms):
            observed.append(value)
        else:
            unverified.append(value)
    return sorted(set(observed)), sorted(set(unverified))

def _build_web_exploitation_readiness(services: list[dict[str, Any]], web_summary: dict[str, Any], web_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    web_ports = {80,443,8080,8180,8009,8443}
    for s in services or []:
        port = int(s.get('port') or 0)
        svc = str(s.get('service') or '').lower()
        prod = str(s.get('product') or '')
        if port in web_ports or 'http' in svc or 'ajp' in svc or 'apache' in prod.lower() or 'tomcat' in prod.lower():
            host = s.get('host')
            tech = []
            auth_pages = []
            input_surfaces = []
            upload_surfaces = []
            for item in web_items or []:
                if str(item.get('host')) != str(host):
                    continue
                if item.get('port') and str(item.get('port')) != str(port):
                    continue
                if item.get('tech'):
                    raw_tech = item.get('tech') if isinstance(item.get('tech'), list) else [str(item.get('tech'))]
                    observed_tech, _unverified_tech = _split_technology_hints(raw_tech)
                    tech.extend(observed_tech)
                path = str(item.get('path') or '').lower()
                if any(x in path for x in ['login','admin','manager','phpmyadmin']):
                    auth_pages.append(item.get('path'))
                if any(x in path for x in ['search','query','id=','user','login']):
                    input_surfaces.append(item.get('path'))
                if 'upload' in path:
                    upload_surfaces.append(item.get('path'))
            rows.append({'host':host,'port':port,'protocol':s.get('protocol'),'service':s.get('service'),'candidate_type':'web_exploitation_candidate','framework_or_technology_hints':sorted(set([x for x in tech if x]))[:12], 'auth_surfaces':sorted(set([x for x in auth_pages if x]))[:12], 'input_surfaces':sorted(set([x for x in input_surfaces if x]))[:12], 'upload_surfaces':sorted(set([x for x in upload_surfaces if x]))[:12], 'evidence':'Web/application surface exposed; SQLi/command-injection/content discovery validation deferred to downstream module.', 'recommended_downstream_module':'web_validation', 'recon_boundary':'No SQLi, command injection, vulnerability scanner, or large path discovery executed by recon.'})
    return _dedupe_dicts(rows, ('host','port','service','candidate_type'))

def _build_exploit_validation_candidates(services: list[dict[str, Any]], cves: list[dict[str, Any]], observations: list[dict[str, Any]], web_summary: dict[str, Any], smb_summary: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for c in cves or []:
        candidates.append({
            'category': 'cve_supported_service_candidate',
            'host': c.get('host'),
            'ports': c.get('ports') or c.get('port'),
            'service': c.get('service'),
            'product': c.get('product'),
            'version': c.get('version'),
            'cve': c.get('cve_id') or c.get('id'),
            'handoff_stage': 'exploit_validation_candidate',
            'recon_boundary': 'Recon evidence only; no exploitation executed by recon module.',
        })
    for o in observations or []:
        obs = str(o.get('observation') or '').lower()
        if any(k in obs for k in ['anonymous ftp', 'anonymous smb', 'admin or management web path', 'phpmyadmin', 'database service exposed']):
            candidates.append({
                'category': 'exposure_validation_candidate',
                'host': o.get('host'),
                'ports': f"{o.get('port')}/{o.get('protocol')}" if o.get('port') else '',
                'service': o.get('service'),
                'evidence': o.get('evidence'),
                'handoff_stage': 'controlled_validation_candidate',
                'recon_boundary': 'Candidate prepared for downstream validation; recon does not attempt access.',
            })
    return candidates

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
    if tool_l in {'directory_discovery', 'gobuster'} and ('timeout' in err_l or result.get('error') == 'timeout'):
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

    if tool_l == 'directory_discovery' and ('0 path' in note_l or 'zero path' in note_l):
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


def _native_collector_result(tool: str, command: str, output_file: str, produced: bool, note: str = '') -> dict[str, Any]:
    """Result-like object for Python-native passive collectors so coverage and command logs stay consistent."""
    output = ''
    try:
        if output_file and Path(output_file).exists():
            output = Path(output_file).read_text(encoding='utf-8', errors='ignore')[:200000]
    except Exception as exc:
        output = f'Unable to read passive evidence file: {exc}'
    return {
        'success': True,
        'returncode': 0,
        'command': command,
        'stdout': output or note or '[no passive evidence observed]',
        'stderr': '',
        'error': '',
        'output_file': output_file,
        'tool': tool,
        'produced': produced,
    }


def _log_native_collector(scan_id: str, tool: str, command: str, purpose: str, output_file: str, produced: bool) -> dict[str, Any]:
    result = _native_collector_result(tool, command, output_file, produced)
    try:
        output, truncated = _captured_command_output(result, Path(output_file) if output_file else None)
    except Exception:
        output, truncated = (result.get('stdout') or '', False)
    scan_store.log_command(
        scan_id,
        command=command,
        purpose=purpose,
        output=output,
        status='Completed' if produced else 'No Evidence Observed',
        exit_code=0,
        output_file=output_file,
        output_truncated=truncated,
    )
    return result


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

    Nmap often reports Samba as a broad range like 3.X - 4.X. smb_share_listing and
    broad_smb_enumeration frequently expose the exact server string in comments,
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




def _native_tcp_probe(host: str, port: int, payload: bytes = b'', read_bytes: int = 4096, timeout: float = 4.0) -> tuple[str, str]:
    """Perform one bounded protocol metadata probe without authentication or writes."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            try:
                data = sock.recv(read_bytes)
            except socket.timeout:
                data = b''
        return data.decode('utf-8', errors='replace'), ''
    except Exception as exc:
        return '', str(exc)[:180]


def _parse_mysql_handshake(text: str) -> dict[str, Any]:
    # MySQL handshake begins with protocol byte 0x0a followed by a NUL-terminated version string.
    m = re.search(r'\x0a?\s*([0-9]+(?:\.[0-9A-Za-z_+~:-]+)+)', text)
    if not m:
        m = re.search(r'([0-9]+\.[0-9]+\.[0-9A-Za-z_+~:-]+)', text)
    if m:
        return {'product': 'MySQL', 'version': m.group(1).strip(), 'protocol_family': 'mysql'}
    return {}


def _parse_postgres_probe(text: str) -> dict[str, Any]:
    m = re.search(r'PostgreSQL\s+([0-9]+(?:\.[0-9]+){0,3})', text, re.I)
    if m:
        return {'product': 'PostgreSQL', 'version': m.group(1), 'protocol_family': 'postgresql'}
    if 'accepting connections' in text.lower() or 'no response' in text.lower() or 'rejecting connections' in text.lower():
        return {'product': 'PostgreSQL', 'protocol_family': 'postgresql', 'readiness': text.strip()[:200]}
    return {}


def _parse_irc_probe(text: str) -> dict[str, Any]:
    m = re.search(r'(UnrealIRCd)\s+([0-9]+(?:\.[0-9]+){1,4})', text, re.I)
    if m:
        return {'product': 'UnrealIRCd', 'version': m.group(2), 'protocol_family': 'irc'}
    if 'irc' in text.lower():
        return {'product': 'IRC', 'protocol_family': 'irc'}
    return {}


def _parse_vnc_probe(text: str) -> dict[str, Any]:
    m = re.search(r'RFB\s+([0-9]{3})\.([0-9]{3})', text)
    if m:
        return {'product': 'RFB', 'version': f"{int(m.group(1))}.{int(m.group(2))}", 'protocol_family': 'vnc'}
    return {}


def _parse_ftp_probe(text: str) -> dict[str, Any]:
    m = re.search(r'(vsFTPd|vsftpd)\s+([0-9][A-Za-z0-9._~:+-]+)', text, re.I)
    if m:
        return {'product': 'vsftpd', 'version': m.group(2), 'protocol_family': 'ftp'}
    m = re.search(r'(ProFTPD)\s+([0-9][A-Za-z0-9._~:+-]+)', text, re.I)
    if m:
        return {'product': 'ProFTPD', 'version': m.group(2), 'protocol_family': 'ftp'}
    return {}


def _parse_smtp_probe(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {'protocol_family': 'smtp'}
    if 'postfix' in text.lower():
        out['product'] = 'Postfix smtpd'
    caps = []
    for line in text.splitlines():
        line=line.strip()
        m = re.match(r'250[-\s]([A-Z0-9][A-Z0-9_-]+)', line, re.I)
        if m:
            caps.append(m.group(1).upper())
    if caps:
        out['capabilities'] = sorted(set(caps))
    return out if len(out) > 1 else {}


def _collect_native_protocol_enrichment(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Low-noise protocol-specific metadata probes that improve depth without brute force or exploitation."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for svc in services or []:
        host = str(svc.get('host') or '')
        try:
            port = int(svc.get('port') or 0)
        except Exception:
            continue
        name = str(svc.get('service') or '').lower()
        product = str(svc.get('product') or '').lower()
        if not host or not port:
            continue
        tool = ''
        payload = b''
        parser = None
        if port in {21, 2121} or name == 'ftp':
            tool, payload, parser = 'ftp_native_banner', b'SYST\r\nFEAT\r\nQUIT\r\n', _parse_ftp_probe
        elif port == 25 or 'smtp' in name:
            tool, payload, parser = 'smtp_native_ehlo', b'EHLO autopentest.local\r\nQUIT\r\n', _parse_smtp_probe
        elif port == 3306 or 'mysql' in name or 'mysql' in product:
            tool, payload, parser = 'mysql_native_handshake', b'', _parse_mysql_handshake
        elif port == 5432 or 'postgres' in name or 'postgres' in product:
            # PostgreSQL seldom discloses version without auth; capture protocol response/readiness only.
            tool, payload, parser = 'postgres_native_probe', b'\x00\x00\x00\x08\x04\xd2\x16/', _parse_postgres_probe
        elif port == 6667 or 'irc' in name or 'irc' in product:
            tool, payload, parser = 'irc_native_version', b'VERSION\r\nQUIT\r\n', _parse_irc_probe
        elif port == 5900 or 'vnc' in name or 'rfb' in product:
            tool, payload, parser = 'vnc_native_banner', b'', _parse_vnc_probe
        else:
            continue
        key = (host, port, tool)
        if key in seen:
            continue
        seen.add(key)
        text, error = _native_tcp_probe(host, port, payload=payload)
        parsed = parser(text) if parser else {}
        rows.append({'tool': tool, 'host': host, 'port': port, 'service': svc.get('service'), 'raw': text[:4000], 'error': error, 'parsed': parsed, 'recon_boundary': 'Single bounded protocol metadata probe only; no authentication, brute force, writes, mounting, or exploitation.'})
    return rows


def _apply_native_protocol_enrichment(services: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows or []:
        parsed = row.get('parsed') or {}
        if not parsed:
            continue
        host = str(row.get('host') or '')
        port = int(row.get('port') or 0)
        for svc in services or []:
            if str(svc.get('host') or '') != host:
                continue
            try:
                svc_port = int(svc.get('port') or 0)
            except Exception:
                continue
            if svc_port != port:
                continue
            if parsed.get('product') and (not svc.get('product') or str(svc.get('product')).lower() in {'mysql', 'postgresql', 'irc', 'vnc', 'rfb', 'unknown'}):
                svc['product'] = parsed['product']
            if parsed.get('version') and not svc.get('version'):
                svc['version'] = parsed['version']
            details = svc.setdefault('protocol_metadata', {})
            details[row.get('tool') or 'native_protocol'] = parsed
            src = svc.setdefault('evidence_sources', [])
            if row.get('tool') and row.get('tool') not in src:
                src.append(row.get('tool'))
    # Tomcat/AJP correlation: if 8180 identifies Tomcat, allow 8009 AJP on same host to inherit application identity.
    tomcat_by_host = {}
    for svc in services or []:
        if 'tomcat' in str(svc.get('product') or '').lower():
            tomcat_by_host[str(svc.get('host') or '')] = (svc.get('product'), svc.get('version'))
    for svc in services or []:
        try:
            port = int(svc.get('port') or 0)
        except Exception:
            port = 0
        if port == 8009 or 'ajp' in str(svc.get('service') or '').lower():
            product, version = tomcat_by_host.get(str(svc.get('host') or ''), ('', ''))
            if product:
                svc['product'] = product
            if version and not svc.get('version'):
                svc['version'] = version
    return services


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
            for source in ('nmap', 'smb_share_listing'):
                if source not in src:
                    src.append(source)
            row['evidence_sources'] = src
            row['smb_enriched_version'] = True
    return services



def _attacker_outcome(product: str, cve_id: str, description: str) -> str:
    desc = (description or '').strip()
    if desc:
        first = re.split(r'(?<=[.!?])\s+', desc)[0]
        return f'Official CVE description outcome: {first[:260]}'
    return 'Official CVE record did not include enough outcome text in the indexed description.'


def _remediation_direction(product: str, cve_id: str) -> str:
    return 'Review the official CVE record and vendor advisory; apply the vendor-supported fixed version or documented mitigation.'



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
        if pnum in {2049, 111} or svc in {'nfs', 'rpcbind'}:
            add(host, port, proto, s.get('service'), 'RPC/NFS file-sharing surface observed.', 'RPC/NFS services were observed through rpcbind and NFS-related ports. Vendor identity is not asserted unless sufficient identifying evidence is collected.', 'File Sharing')
        if pnum == 6000 or svc.lower() == 'x11':
            add(host, port, proto, s.get('service'), 'X11 display service exposed.', 'Nmap identified an X11 service response.', 'Remote GUI')
        if pnum == 5900 or svc == 'vnc':
            add(host, port, proto, s.get('service'), 'VNC remote desktop service exposed.', 'Nmap identified a VNC service response.', 'Remote GUI')
        if pnum in {3306,5432} or svc in {'mysql','postgresql'}:
            add(host, port, proto, s.get('service'), 'Database service exposed on the network.', 'Service fingerprinting identified a database listener.', 'Database')
        if pnum == 8009 or 'ajp' in svc:
            add(host, port, proto, s.get('service'), 'AJP connector exposed.', 'AJP service was identified and checked with AJP scripts where available.', 'Web')
        if pnum in {8180, 8080, 8081, 8443} and (svc in {'unknown', ''} or not prod):
            add(host, port, proto, s.get('service'), 'Unknown application service observed.', 'Application service observed on this TCP port. Sufficient evidence was not available to confidently identify the underlying product; follow-up HTTP/Tomcat validation may be appropriate if in scope.', 'Web')
        if svc == 'ftp' or pnum in {21, 2121}:
            script_text = ' '.join(str(x.get('output','')) for x in (s.get('scripts') or []))
            if 'anonymous ftp login allowed' in script_text.lower() or 'ftp code 230' in script_text.lower():
                add(host, port, proto, s.get('service'), 'Anonymous FTP access allowed.', 'ftp-anon reported anonymous FTP login was allowed.', 'File Transfer')
    for item in smb_items:
        text='\n'.join(item.get('lines') or [])
        if item.get('output_file'):
            text += '\n' + _read_text(item.get('output_file'))
        if 'Anonymous login successful' in text or re.search(r'\bSharename\b', text, re.I):
            add(item.get('host'), 445, 'tcp', 'smb', 'Anonymous SMB share listing available.', 'smb_share_listing output includes anonymous access evidence or visible share names.', 'File Sharing')
    for item in web_items:
        if item.get('tool') == 'directory_discovery' or item.get('path'):
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
    unverified_hints: list[dict[str, Any]] = []
    seen_services = set()
    seen_paths = set()
    seen_hints = set()
    for item in web_items:
        if item.get('tech'):
            raw_tech = item.get('tech') if isinstance(item.get('tech'), list) else [str(item.get('tech'))]
            _observed_tech, unverified_tech = _split_technology_hints(raw_tech)
            for hint in unverified_tech:
                key = (item.get('host'), item.get('port'), hint)
                if key not in seen_hints:
                    seen_hints.add(key)
                    unverified_hints.append({'host': item.get('host'), 'port': item.get('port'), 'hint': hint, 'source': 'httpx', 'interpretation': 'Unverified technology hint; excluded from MITRE matching and evidence-backed conclusions.'})
        if item.get('tool') == 'directory_discovery' or item.get('path'):
            key = (item.get('host'), item.get('port'), item.get('path'))
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append({
                    'host': item.get('host'),
                    'port': item.get('port'),
                    'path': item.get('path'),
                    'status_code': item.get('status_code'),
                    'size': item.get('size'),
                    'source': item.get('tool') or 'directory_discovery',
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
    return {'services': services, 'paths': paths, 'unverified_technology_hints': unverified_hints}


def _summarise_smb_inventory(smb_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    shares: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for item in smb_items:
        tool = item.get('tool')
        host = item.get('host')
        output_file = item.get('output_file') or ''
        tools.append({'tool': tool, 'host': host, 'evidence_file': output_file})
        if tool == 'smb_share_listing':
            for line in item.get('lines') or []:
                m = re.match(r'^(?P<name>[A-Za-z0-9_$.-]+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*)$', line)
                if m and m.group('name').lower() not in {'sharename', '---------'}:
                    shares.append({
                        'host': host,
                        'share': m.group('name'),
                        'type': m.group('type'),
                        'comment': m.group('comment').strip(),
                        'source': 'smb_share_listing',
                        'evidence_file': output_file,
                    })
    return {'shares': shares, 'tools': tools}


def _detect_cross_host_evidence_contamination(smb_summary: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    shares = smb_summary.get('shares') or []
    hosts = {str(s.get('host')) for s in shares if s.get('host')}
    for host in hosts:
        host_shares = {str(s.get('share')) for s in shares if str(s.get('host')) == host}
        for other in hosts - {host}:
            other_shares = {str(s.get('share')) for s in shares if str(s.get('host')) == other}
            overlap = sorted((host_shares & other_shares) - {'IPC$', 'print$'})
            if len(overlap) >= 2:
                findings.append({'host': host, 'indicator': 'possible_cross_host_evidence_overlap', 'evidence': f'SMB share names overlap with {other}: {", ".join(overlap[:5])}', 'interpretation': 'Evidence should be reviewed to ensure artefacts were not reused across hosts.'})
    return findings


def _normalise_service_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[Any, int, str], dict[str, Any]] = {}
    for r in rows or []:
        key=(r.get('host'), int(r.get('port') or 0), r.get('protocol','tcp'))
        if key not in merged:
            merged[key] = dict(r)
            continue
        current = merged[key]
        # Preserve strongest identity evidence instead of letting earlier generic rows win.
        for field in ('service','product','version'):
            val = r.get(field)
            if val and (not current.get(field) or str(current.get(field)).lower() in {'unknown', 'unidentified product', 'dns service', 'mysql', 'postgresql', 'irc', 'vnc', 'rfb'}):
                current[field] = val
        for field in ('cpe','scripts','evidence_sources'):
            values = current.get(field) or []
            incoming = r.get(field) or []
            if not isinstance(values, list): values=[values]
            if not isinstance(incoming, list): incoming=[incoming]
            for item in incoming:
                if item and item not in values:
                    values.append(item)
            current[field]=values
        for field in ('protocol_metadata',):
            if isinstance(r.get(field), dict):
                current.setdefault(field, {}).update(r.get(field) or {})
    out=[]
    for r in merged.values():
        missing=[]
        if not r.get('product'): missing.append('product')
        if not r.get('version'): missing.append('version')
        if not r.get('cpe'): missing.append('cpe')
        r['missing_information']=missing
        out.append(r)
    return sorted(out, key=lambda x:(str(x.get('host')), str(x.get('protocol')), int(x.get('port') or 0)))

STRICT_CVE_MATCH = 'Validated MITRE Reference'
RELEVANT_VERSION_INFORMATION = 'Relevant Version / Exposure Information'
EVIDENCE_INCOMPLETE = 'Evidence Incomplete'
NOT_APPLICABLE_TO_CONTEXT = 'Not Applicable to Observed Context'
DUPLICATE_SERVICE_REFERENCE = 'Duplicate Service Reference'

EXACT_CVE_BASIS_TOKENS = (
    'exact_structured_version',
    'exact_observed_version_in_record_text',
    'exact_cpe_match',
    'explicit_same_product_text_range',
)

# These service-side/backdoor/RCE-style CVEs remain official-CVE sourced.
# The matcher must still find the official CVE record and product/version match;
# this only stops exact service-side findings from being hidden behind context
# gates that recon cannot safely prove without exploitation.


CONTEXT_GATE_RULES = [
    (re.compile(r'\bresolver\b|\blame cache\b|\bflooding\b|\bperformance\b|\bdegradation\b', re.I), EVIDENCE_INCOMPLETE, 'Required DNS resolver role or runtime behaviour was not confirmed by collected recon evidence.'),
    (re.compile(r'\bfreebsd\b|\blibbind\b|context-dependent attackers', re.I), EVIDENCE_INCOMPLETE, 'Required OS/library context was not confirmed by collected recon evidence.'),
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
    if context_classification:
        return context_classification, context_reason
    if not _strict_version_basis(basis):
        return RELEVANT_VERSION_INFORMATION, 'Observed version falls within an official affected range; additional context was not established.'
    if re.search(r'\bdenial of service\b|\bcrash\b|\bterminate\b|\bassertion\b|\bcontext-dependent\b|\brange header\b|\bcrafted input\b', description, re.I):
        return RELEVANT_VERSION_INFORMATION, 'Exact product/version evidence was observed, but the CVE requires contextual validation and remains a candidate reference.'
    return STRICT_CVE_MATCH, 'Official CVE product/version evidence matched the observed service; product/version condition is directly supported by recon evidence.'




def _cve_finding_type(product: str, cve_id: str, description: str) -> str:
    text = ' '.join([product or '', cve_id or '', description or '']).lower()
    if 'backdoor' in text or 'shell' in text:
        return 'Product/version condition observed; backdoor applicability depends on package provenance'
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


# Service-level active collectors were intentionally removed from recon.
# Downstream validation modules own deeper protocol, credential, and exploit checks.

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
    credential_validation_rows: list[dict[str, Any]] = []
    for row in rows or []:
        tool_name = str(row.get('tool') or '').lower()
        if tool_name in _INTERNAL_REPORT_TOOLS:
            continue
        if tool_name == 'credential_validation':
            credential_validation_rows.append(row)
            continue
        public.append(row)

    if credential_validation_rows:
        statuses = [str(r.get('status') or '') for r in credential_validation_rows]
        notes = [str(r.get('note') or '') for r in credential_validation_rows if r.get('note')]
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
        output_files = [str(r.get('output_file') or '') for r in credential_validation_rows if r.get('output_file')]
        commands = [str(r.get('command') or '') for r in credential_validation_rows if r.get('command')]
        outputs = []
        for r in credential_validation_rows:
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
            'output_truncated': any(r.get('output_truncated') for r in credential_validation_rows),
            'exit_code': ', '.join(str(r.get('exit_code','')) for r in credential_validation_rows[:5]),
            'stderr_summary': '; '.join(str(r.get('stderr_summary') or '') for r in credential_validation_rows if r.get('stderr_summary'))[:260],
            'failure_reason': '; '.join(str(r.get('failure_reason') or '') for r in credential_validation_rows if r.get('failure_reason'))[:260],
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
            status = 'Validated MITRE Reference'
        elif key in candidate_keys:
            status = 'MITRE candidate references retained'
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
    if port in {137, 139, 445} or 'samba' in prod_l or 'netbios' in svc_l or 'smb' in svc_l or 'microsoft-ds' in svc_l:
        prod = prod or 'Samba/SMB'
        # One host-level SMB/NetBIOS card prevents UDP/137 and TCP/139/445 from
        # appearing as fragmented findings while preserving all observed ports.
        return (host, 'smb', '', ''), 'smb', prod, ver, 'File Sharing and RPC Surface'
    if port == 53 or svc_l in {'domain', 'dns'} or 'bind' in prod_l:
        prod = prod or 'DNS service'
        return (host, 'domain', prod, ver), 'domain', prod, ver, 'Application Service Surface'
    if port in {111, 2049} or svc_l in {'rpcbind', 'nfs'}:
        label = 'NFS/RPC'
        return (host, 'nfs-rpc', label, ''), 'nfs-rpc', label, '', 'File Sharing and RPC Surface'
    if port in {8180, 8080, 8081, 8443} and (svc_l in {'unknown', ''} or not prod):
        return (host, 'unknown-application', 'Unknown application service', ''), 'unknown-application', 'Unknown application service', '', 'Web Surface'
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
        # Prefer stronger identity evidence when merged service cards start with
        # generic UDP/unknown rows and later TCP/banner evidence provides product/version.
        if card_product and (not card.get('product') or card.get('product') in {'Samba/SMB', 'Unknown application service', 'DNS service'}):
            card['product'] = card_product
        if card_version and not card.get('version'):
            card['version'] = card_version
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
            card['smb_shares'] = [sh for sh in ((smb_summary or {}).get('shares') or []) if str(sh.get('host')) == str(card.get('host'))]
        card['observations'] = _dedupe_dicts(card['observations'], ('observation', 'evidence'))
        card['checks'] = _dedupe_dicts(card['checks'], ('check', 'status', 'evidence_file'))
        card['candidate_references'] = _dedupe_dicts(card['candidate_references'], ('host', 'service', 'product', 'version'))
        card['confirmed_cves'] = _dedupe_dicts(card['confirmed_cves'], ('cve_id', 'product', 'version'))
        card['web_paths'] = _dedupe_dicts(card['web_paths'], ('path', 'status_code'))
        # Recompute merged-card identity gaps from the final merged identity instead of
        # inheriting weaker UDP/unknown gaps after TCP/banner evidence improved the card.
        final_gaps = []
        if not str(card.get('product') or '').strip() or str(card.get('product') or '').strip().lower() in {'unidentified product', 'dns service'}:
            final_gaps.append('Product name not identified')
        if not str(card.get('version') or '').strip() and card.get('service') not in {'smb', 'nfs-rpc', 'unknown-application'}:
            final_gaps.append('Version not identified')
        if card.get('service') == 'smb' and str(card.get('product') or '').strip() and str(card.get('version') or '').strip():
            final_gaps = []
        if card.get('service') == 'domain' and str(card.get('product') or '').strip().lower() not in {'dns service', 'unidentified product'}:
            final_gaps = [g for g in final_gaps if g != 'Product name not identified']
        card['evidence_gaps'] = final_gaps
        if card['confirmed_cves']:
            card['state'] = 'Validated MITRE Reference'
        elif card['observations']:
            card['state'] = 'Security-Relevant Exposure'
        elif card['candidate_references']:
            card['state'] = 'Candidate References Available'
        elif card['evidence_gaps']:
            card['state'] = 'Identity Incomplete'
    state_order = {'Validated MITRE Reference':0, 'Security-Relevant Exposure':1, 'Candidate References Available':2, 'Identity Incomplete':3, 'Identified Service':4}
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
        if 'nfs/rpc' in obs or 'rpc/nfs' in obs:
            return ('File Sharing', 'RPC/NFS file-sharing surface observed')
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
    passive = results.get('passive_intelligence') or {}
    if passive.get('summary'):
        points.extend([str(x) for x in passive.get('summary')[:2]])
    indicators = results.get('key_exposure_indicators') or []
    services = results.get('service_inventory') or []
    if cves:
        products = []
        for c in cves:
            label = f"{c.get('product','').strip()} {c.get('version','').strip()}".strip()
            if label and label not in products:
                products.append(label)
        if products:
            points.append('Validated MITRE references were linked to: ' + ', '.join(products) + '.')
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

def _text_has_ssh_audit_evidence(text: str) -> bool:
    """Detect whether ssh-audit output contains usable recommendation/finding text."""
    value = str(text or '').strip().lower()
    if not value:
        return False
    markers = ('(rec)', 'algorithm to remove', 'key algorithm', 'enc algorithm', 'kex algorithm', 'mac algorithm', 'warning', 'fail', 'remove')
    return any(marker in value for marker in markers)


# Recon ownership boundary: credential-combo sanitisation and brute-force preparation
# were removed from the recon package. Downstream credential validation, if any,
# belongs to teammate-owned modules and is not invoked or prepared here.


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
    scan_options = normalise_scan_options((scan_options or {}).get('profile', 'full'), (scan_options or {}).get('enabled_tools'))
    scan_store.update(scan_id, scan_options=scan_options)
    def enabled(tool_id: str) -> bool:
        return is_tool_enabled(scan_options, tool_id)
    scan_store.init_tasks(scan_id, TASKS)
    coverage=[]; raw=[]; observations=[]; web=[]; smb=[]; services=[]; udp_services=[]; service_level_checks=[]; environment_intelligence=[]; environment_context_indicators=[]; selected_objectives=[]; evidence_gaps=[]; cve_prefetch_thread=None; cve_prefetch={}; scope_validation={}; enterprise_review_policy={}; passive_intelligence={}; modern_active_validation={}
    try:
        # 1
        task='Target Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        targets=expand_target_input(target_input, Config.MAX_EXPANDED_TARGETS)
        engagement_policy = load_engagement_policy()
        enterprise_review_policy = load_enterprise_review_policy()
        scope_validation = validate_scope(targets, target_input, engagement_policy)
        scan_store.audit_event(scan_id, 'system', 'scope_validated', scope_validation)
        private_all=all(is_private_ip(t) for t in targets)
        scope_note = scope_validation.get('scope_mode', 'unknown')
        warning_note = '; '.join(scope_validation.get('warnings') or [])
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(targets)} target(s) accepted under {scope_note}. Private cyber-range addresses: {private_all}. {warning_note}')
        _publish_partial(scan_id, scope_validation=scope_validation)

        # Stage 0A: listen-only passive local inventory before any active validation.
        passive_local_inventory = _collect_passive_local_inventory(scan_id, coverage, raw, enabled)
        if passive_local_inventory.get('summary'):
            environment_intelligence.append({'type': 'passive_local_inventory', 'summary': passive_local_inventory.get('summary'), 'source': 'tshark_p0f_listen_only'})

        # Stage 0: environment characterisation always runs before heavier enumeration.
        if enabled('environment_characterisation'):
            task='Environment Characterisation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
            for host in targets:
                ping_bin = which('ping')
                active_reachability = bool(_load_recon_policy().get('active_reachability_probe', False))
                if ping_bin and active_reachability:
                    p=outfile('ping_ttl',host,'txt'); r=run_cmd([ping_bin,'-c','1','-W','2',host],p,20); txt=Path(p).read_text(errors='ignore') if Path(p).exists() else ''; ttl=_extract_ttl(txt); environment_intelligence.append({'host':host,'type':'ttl_latency','ttl':ttl,'role_hint':_environment_role_hint(ttl),'network_layer':_classify_network_layer(host),'evidence_file':str(p)}); coverage.append(_coverage('ping', _status_from_result(r, ttl is not None), 'TTL and reachability evidence', f'{host} ttl={ttl if ttl is not None else "not observed"}', str(p), r)); _add_raw(raw,'ping',host,'',str(p),'text',ttl is not None)
                else:
                    coverage.append(_coverage('ping', scan_store.STATUS_EMPTY, 'Passive-first posture', f'Active ping reachability probe skipped for {host}; scoped single-host validation can assume target availability before low-noise service checks.', ''))
                # HTTP HEAD, reverse DNS and route tracing are deferred from Stage 0.
                # They are observable on Wireshark/firewall logs and are now collected only when the
                # target surface justifies them (for example, HTTP HEAD after port 80 is observed).
                coverage.append(_coverage('curl', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'HTTP HEAD deferred for {host} until HTTP service is confirmed.', ''))
                coverage.append(_coverage('dig', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'Reverse DNS lookup deferred for {host}; private-address PTR lookups often add little value.', ''))
                coverage.append(_coverage('route_trace', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'Route tracing deferred for {host}; traceroute/mtr is visible to network monitoring.', ''))
            _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Environment characterisation evidence collected')
            _publish_partial(scan_id, environment_summary=_build_environment_summary(environment_intelligence, environment_context_indicators))

        # 3 live host discovery
        task='Host Availability Check'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        live=[]
        if enabled('arp_scan') and private_all and which('arp-scan'):
            # per /24-ish network: use arp-scan localnet, then filter to targets
            p=outfile('arp_scan','target_range','txt'); arp_cmd=[which('arp-scan'),'--localnet'] if len(targets)>1 else [which('arp-scan'), targets[0]]; r=run_cmd(arp_cmd,p,240); text=Path(r.get('output_file','')).read_text(errors='ignore') if r.get('output_file') else ''
            found=set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text)); live=[t for t in targets if t in found]
            coverage.append(_coverage('arp-scan', _status_from_result(r, bool(live)), 'local live host discovery', f'{len(live)} live host(s) found', r.get('output_file',''), r)); _add_raw(raw,'arp-scan','','',r.get('output_file',''),'arp-scan',False)
        if not live and len(targets) == 1 and bool(_load_recon_policy().get('skip_active_host_discovery_for_single_target', True)):
            live = list(targets)
            coverage.append(_coverage('nmap_host_discovery', scan_store.STATUS_EMPTY, 'Passive-first posture', 'Single in-scope target accepted without active host sweep; service discovery uses -Pn micro-batches.', '', {'success': True, 'cmd': 'not executed; assumed live for scoped single target'}))
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
        task='Low-Impact Service Discovery'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        nmap=which('nmap'); open_map={h:[] for h in live}
        if enabled('tcp_discovery') and nmap and live:
            for host in live:
                # Category-A discovery: step through top-20 -> top-50 -> top-100 and evaluate after each pass.
                # This avoids a single obvious burst against Palo Alto Zone Protection/DoS policies.
                ttl_value = next((x.get('ttl') for x in environment_intelligence if x.get('host')==host and x.get('ttl') is not None), None)
                ports: list[int] = []
                host_environment_context: list[dict[str, Any]] = []
                policy = _load_recon_policy()
                posture = _scan_posture(host, environment_intelligence, ports)
                layer = posture.get('network_layer') or _classify_network_layer(host, environment_intelligence, ports)
                if layer.get('scan_posture') == 'infrastructure_observed' or posture.get('scan_posture') == 'infrastructure_observed':
                    # Infrastructure links/firewalls/routers: do not top-port sweep. Probe only management ports at near-zero rate.
                    infra_ports = [str(p) for p in _policy_required(posture, 'tcp_ports')]
                    p = outfile('nmap_tcp_infrastructure_fingerprint', host, 'xml')
                    cmd = [nmap, '-sS', '-p', ','.join(infra_ports), '--open'] + list(_policy_required(posture, 'nmap_timing')) + ['-oX', str(p), host]
                    r = run_cmd(cmd, p, 600, True)
                    rows = parse_nmap_xml(str(p))
                    ports = sorted({int(x['port']) for x in rows if x.get('port')})
                    coverage.append(_coverage('nmap_tcp_infrastructure_fingerprint', _status_from_result(r, bool(ports)), 'Infrastructure-safe TCP fingerprint', f'{len(ports)} management/service port(s) observed; application-layer collectors suppressed for {layer.get("role")}.', str(p), r))
                    _add_raw(raw, 'nmap_tcp_infrastructure_fingerprint', host, '', str(p), 'nmap_xml', True)
                    host_environment_context.append({'indicator':'infrastructure_scan_posture','evidence':f'{host} matched {layer.get("role")} ({layer.get("matched_cidr")}).','interpretation':'Target treated as router/firewall/infrastructure; application-layer enumeration suppressed.'})
                else:
                    # Full Recon micro-batched TCP discovery. This replaces a single top-100 burst
                    # with small policy-defined batches while preserving high-value coverage.
                    micro_cfg = policy.get('tcp_micro_batching') or {}
                    batches = policy.get('tcp_micro_batches') or []
                    if micro_cfg.get('enabled', True) and batches:
                        all_seen: set[int] = set()
                        timing = list(micro_cfg.get('nmap_options') or ['-Pn','-sS','--open','-T2','--max-retries','1','--max-rate','5'])
                        for batch_index, batch_ports in enumerate(batches, start=1):
                            clean_batch = sorted({int(x) for x in batch_ports if str(x).isdigit() or isinstance(x, int)})
                            if not clean_batch:
                                continue
                            p = outfile(f'nmap_tcp_microbatch_{batch_index}', host, 'xml')
                            cmd = [nmap] + timing + ['-p', ','.join(map(str, clean_batch)), '-oX', str(p), host]
                            r = run_cmd(cmd, p, 600, True)
                            rows = parse_nmap_xml(str(p))
                            batch_open = sorted({int(x['port']) for x in rows if x.get('port')})
                            all_seen.update(batch_open)
                            xml_text = Path(p).read_text(encoding='utf-8', errors='ignore') if Path(p).exists() else ''
                            filtered_count = sum(int(x) for x in re.findall(r'extraports state="filtered" count="(\d+)"', xml_text))
                            closed_count = sum(int(x) for x in re.findall(r'extraports state="closed" count="(\d+)"', xml_text))
                            combined_out = ' '.join(str(r.get(k) or '') for k in ('stdout','stderr','error'))
                            retransmission_warning = 'retransmission cap hit' in combined_out.lower() or 'giving up on port' in combined_out.lower()
                            cumulative_ports = sorted(all_seen)
                            profile = _host_profile_from_observations(host, cumulative_ports, environment_intelligence)
                            stage_indicators = _detect_environment_context_indicators(cumulative_ports, ttl=ttl_value, filtered_count=filtered_count, retransmission_warning=retransmission_warning, host_profile=profile)
                            acl_indicator = _acl_filtering_indicator(host, filtered_count, closed_count, len(clean_batch))
                            if acl_indicator:
                                stage_indicators.append(acl_indicator)
                            coverage.append(_coverage(f'nmap_tcp_microbatch_{batch_index}', _status_from_result(r, bool(batch_open)), f'TCP Service Discovery Batch {batch_index}', f'{len(batch_open)} open TCP port(s) observed from {len(clean_batch)} policy ports; {filtered_count} filtered/no-response.', str(p), r))
                            _add_raw(raw, f'nmap_tcp_microbatch_{batch_index}', host, '', str(p), 'nmap_xml', True)
                            if stage_indicators:
                                host_environment_context = stage_indicators
                            min_sleep = float(micro_cfg.get('sleep_between_batches_seconds_min') or 0)
                            max_sleep = float(micro_cfg.get('sleep_between_batches_seconds_max') or min_sleep)
                            if batch_index < len(batches) and max_sleep > 0:
                                time.sleep(random.uniform(min_sleep, max_sleep))
                        ports = sorted(all_seen)
                        coverage.append(_coverage('nmap_tcp_top100', scan_store.STATUS_SUCCESS if ports else scan_store.STATUS_EMPTY, 'TCP Service Discovery Summary', f'{len(ports)} open TCP port(s) observed through micro-batched Full Recon discovery.', '', {'success': True, 'cmd': 'micro-batched top/high-value TCP discovery'}))
                    else:
                        stages = _policy_required(posture, 'tcp_discovery_stages')
                        max_stages = int(_policy_required(posture, 'max_stages'))
                        for stage_index, topn in enumerate(stages[:max_stages], start=1):
                            p = outfile(f'nmap_tcp_top{topn}', host, 'xml')
                            timing = list(_policy_required(posture, 'nmap_timing'))
                            r = run_cmd([nmap,'-sS','--top-ports',str(topn),'--open'] + timing + ['-oX',str(p),host], p, 600, True)
                            rows = parse_nmap_xml(str(p))
                            ports = sorted({int(x['port']) for x in rows if x.get('port')})
                            coverage.append(_coverage(f'nmap_tcp_top{topn}', _status_from_result(r, bool(ports)), f'TCP discovery - top {topn}', f'{len(ports)} open TCP port(s) observed.', str(p), r))
                            _add_raw(raw, f'nmap_tcp_top{topn}', host, '', str(p), 'nmap_xml', True)
                if host_environment_context:
                    environment_context_indicators.extend([{**d,'host':host} for d in host_environment_context])
                    scan_store.log(scan_id, f'Environment context indicators observed on {host}; Full Recon continues high-value validation within policy.', 'INFO')
                # Targeted legacy/lab-port expansion is never automatic in the quiet baseline.
                expanded_ports = list(ports)
                targeted_extra = sorted(set(int(x) for x in (_load_recon_policy().get('follow_up_only_ports') or [])) - set(ports))
                if targeted_extra:
                    coverage.append(_coverage('nmap_tcp_targeted_expansion', scan_store.STATUS_EMPTY, 'Full Recon coverage', 'Targeted legacy/application port expansion handled by policy-defined micro-batches and high-value validation.', ''))
                # Full Recon targeted expansion: not a 65k sweep, but it must not
                # miss enterprise/legacy ports that senior reviewers expect.
                expansion_ports = [int(x) for x in (_load_recon_policy().get('targeted_expansion_ports') or [])]
                missing_expansion = sorted(set(expansion_ports) - set(expanded_ports))
                if missing_expansion and enabled('tcp_discovery'):
                    p_exp = outfile('nmap_tcp_targeted_expansion', host, 'xml')
                    timing_exp = list(_policy_required(_load_recon_policy().get('scan_postures', {}).get('default', {}), 'nmap_timing')) if isinstance(_load_recon_policy().get('scan_postures', {}).get('default', {}), dict) else ['-T2','--max-retries','1']
                    r_exp = run_cmd([nmap, '-sS', '-p', ','.join(map(str, missing_expansion)), '--open'] + timing_exp + ['-oX', str(p_exp), host], p_exp, 600, True)
                    rows_exp = parse_nmap_xml(str(p_exp))
                    ports_exp = sorted({int(x['port']) for x in rows_exp if x.get('port')})
                    if ports_exp:
                        expanded_ports = sorted(set(expanded_ports) | set(ports_exp))
                    coverage.append(_coverage('nmap_tcp_targeted_expansion', _status_from_result(r_exp, bool(ports_exp)), 'Targeted high-value TCP expansion', f'{len(ports_exp)} additional high-value TCP port(s) observed; no full 65k sweep performed.', str(p_exp), r_exp))
                    _add_raw(raw, 'nmap_tcp_targeted_expansion', host, '', str(p_exp), 'nmap_xml', True)
                coverage.append(_coverage('full_tcp_sweep', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'Full 65k TCP sweep remains deferred; Full Recon uses top-100 plus targeted high-value expansion instead.', ''))
                open_map[host]=expanded_ports
        elif not enabled('tcp_discovery'):
            scan_store.log(scan_id, 'Full TCP discovery was not selected for this scan.', 'INFO')
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if any(open_map.values()) else scan_store.STATUS_EMPTY, f'{sum(len(v) for v in open_map.values())} TCP port(s) observed')
        _publish_partial(scan_id, tcp_ports_observed=sum(len(v) for v in open_map.values()))

        # 5 service fingerprint
        task='Service Identity Collection'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if enabled('service_fingerprint'):
            for host, ports in open_map.items():
                if not ports: continue
                host_environment_context_present = any(str(d.get('host')) == str(host) for d in environment_context_indicators)
                banner_ports = _critical_banner_ports(ports, environment_context_observed=host_environment_context_present)
                if not banner_ports:
                    coverage.append(_coverage('nmap_service_fingerprint', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'No ports selected for banner-first service identity collection.', ''))
                    continue
                p=outfile('nmap_service_fingerprint',host,'xml'); port_arg=','.join(map(str,banner_ports))
                r=run_cmd([nmap,'-sV','--version-intensity','0','--script','banner','-p',port_arg] + list(_policy_required(_load_recon_policy(), 'service_fingerprint_timing')) + ['-oX',str(p),host],p,900,True)
                rows=parse_nmap_xml(str(p)); services.extend(rows)
                skipped = sorted(set(ports) - set(banner_ports))
                note = f'{len(rows)} service row(s); critical-first banner set used'
                if skipped:
                    note += f'; {len(skipped)} port(s) retained for service-specific validation where applicable'
                coverage.append(_coverage('nmap_service_fingerprint', _status_from_result(r, bool(rows)), 'all observed service product version cpe', note, str(p), r)); _add_raw(raw,'nmap_service_fingerprint',host,'',str(p),'nmap_xml',True)
                if skipped:
                    coverage.append(_coverage('deferred_banner_ports', scan_store.STATUS_EMPTY, 'Service validation note', f'Non-banner service-specific validators will handle applicable ports: {", ".join(map(str, skipped[:20]))}', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if services else scan_store.STATUS_EMPTY, f'{len(services)} service record(s) extracted')
        _publish_partial(scan_id, service_inventory=services)
        if services:
            cve_prefetch_thread, cve_prefetch = _start_cve_prefetch(scan_id, _normalise_service_rows([dict(x) for x in services]))

        # 6 targeted UDP discovery for Full Recon. This is not broad UDP; it is
        # limited to policy-defined infrastructure/service ports.
        task='Low-Impact Service Discovery'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if enabled('udp_discovery') and nmap:
            for host in live:
                udp_ports = [int(x) for x in (_load_recon_policy().get('udp_target_ports') or [])]
                if not udp_ports:
                    continue
                p_udp = outfile('nmap_udp_targeted', host, 'xml')
                r_udp = run_cmd([nmap, '-sU', '-p', ','.join(map(str, udp_ports)), '--open', '-T2', '--max-retries', '1', '-oX', str(p_udp), host], p_udp, 900, True)
                rows_udp = parse_nmap_xml(str(p_udp))
                udp_services.extend(rows_udp)
                coverage.append(_coverage('udp_discovery', _status_from_result(r_udp, bool(rows_udp)), 'Targeted UDP discovery', f'{len(rows_udp)} UDP service row(s) observed from policy-defined high-value UDP ports.', str(p_udp), r_udp))
                _add_raw(raw, 'udp_discovery', host, '', str(p_udp), 'nmap_xml', bool(rows_udp))
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if udp_services else scan_store.STATUS_EMPTY, f'{len(udp_services)} UDP service row(s) observed')
        else:
            coverage.append(_coverage('udp_discovery', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'Targeted UDP discovery disabled by profile/policy or nmap unavailable.', ''))
            _finish(scan_id, task, scan_store.STATUS_EMPTY, 'UDP discovery deferred')

        all_services=services + udp_services
        selected_objectives = infer_objectives(all_services)
        preliminary_report = {
            'status': 'preliminary',
            'target_input': target_input,
            'observed_hosts': live,
            'observed_services': len(all_services),
            'attack_surface_objectives': selected_objectives,
            'environment_summary': _build_environment_summary(environment_intelligence, environment_context_indicators),
            'network_topology_summary': _build_network_topology_summary(live, environment_intelligence, open_map, environment_context_indicators),
        }
        _publish_partial(scan_id, service_inventory=all_services, preliminary_report=preliminary_report, attack_surface_objectives=selected_objectives, environment_summary=preliminary_report['environment_summary'], network_topology_summary=preliminary_report.get('network_topology_summary'))
        _finish(scan_id, 'Preliminary Attack Surface Report', scan_store.STATUS_SUCCESS, f'{len(selected_objectives)} attack-surface objective(s) selected from observed services')
        if all_services and (not cve_prefetch_thread):
            cve_prefetch_thread, cve_prefetch = _start_cve_prefetch(scan_id, _normalise_service_rows([dict(x) for x in all_services]))
        http_ports=[]; smb_ports=[]
        for s in all_services:
            svc=str(s.get('service','')).lower(); port=int(s.get('port') or 0)
            if svc in {'http','https','http-proxy','ssl/http'} or port in {80,443,8080,8081,8180,8443,9443}:
                http_ports.append(s)
            if port in {139,445} or 'smb' in svc or 'netbios' in svc:
                smb_ports.append(s)

        # 7 HTTP
        task='Application Fingerprinting'
        scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        if http_ports:
            for s in http_ports:
                host = s['host']
                if _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])):
                    coverage.append(_coverage('nmap_http_scripts', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'HTTP objective deferred for infrastructure target {host}; management-interface probing requires approval.', ''))
                    continue
                port = int(s['port'])
                url = _url_for(host, port, 'ssl' in str(s.get('service','')).lower())
                httpx_bin = which('httpx-toolkit', ['httpx']) if enabled('httpx') else None
                if httpx_bin:
                    # Capability probe only; do not show this as a user-facing enumeration command.
                    probe = _run_cmd([httpx_bin, '-h'], timeout=20)
                    probe_text = (probe.get('stdout','') + probe.get('stderr','')).lower()
                    if ('-json' in probe_text or '-jsonl' in probe_text) and '-title' in probe_text and ('-tech-detect' in probe_text or '-td' in probe_text):
                        p = outfile('httpx', f'{host}_{port}', 'jsonl')
                        httpx_opts = _policy_required(_load_recon_policy(), 'httpx_options')
                        httpx_cmd = [httpx_bin, '-json', '-title', '-tech-detect', '-status-code', '-server', '-follow-redirects']
                        httpx_cmd += ['-rl', str(_policy_required(httpx_opts, 'rate_limit_per_second')), '-t', str(_policy_required(httpx_opts, 'threads')), '-timeout', str(_policy_required(httpx_opts, 'timeout_seconds')), '-u', url]
                        r = run_cmd(httpx_cmd, p, 180)
                        parsed_httpx = parse_httpx_jsonl(str(p))
                        web.extend(parsed_httpx)
                        coverage.append(_coverage('httpx', _status_from_result(r, bool(parsed_httpx)), 'HTTP probe technology title status', url, str(p), r))
                        _add_raw(raw, 'httpx', host, port, str(p), 'jsonl', True)
                    else:
                        r = {'success': True, 'status':'empty', 'command': httpx_bin + ' -h', 'returncode': 0, 'stderr':'', 'error':'', 'output_file':'', 'stdout':'Installed httpx CLI is not ProjectDiscovery httpx or does not support the required flags; Nmap HTTP scripts are used as fallback.'}
                        coverage.append(_coverage('httpx', scan_store.STATUS_EMPTY, 'HTTP probe technology title status', 'ProjectDiscovery httpx not available or incompatible; nmap HTTP scripts used as fallback', '', r))

        else:
            coverage.append(_coverage('nmap_http_scripts', scan_store.STATUS_EMPTY, 'HTTP evidence', 'No HTTP/HTTPS services observed', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if web else scan_store.STATUS_EMPTY, f'{len(web)} web evidence item(s) captured')
        _publish_partial(scan_id, web_inventory=web)

        # 8 Credential/Web readiness evidence collection.
        # These collectors support teammate weak-credential and web-validation modules without
        # performing brute force, share/user enumeration, SQLi, command injection, or exploitation.
        task='Application Fingerprinting'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        service_level_checks = []
        ssh_items=[]; ldap_items=[]; tls_items=[]; rdp_items=[]; credential_validation_items=[]; snmp=[]

        def _service_is_infra(row: dict[str, Any]) -> bool:
            return _is_infrastructure_target(str(row.get('host')), environment_intelligence, open_map.get(str(row.get('host')), []))

        # SSH readiness: advertised auth methods only; no login attempts.
        if enabled('ssh_auth_methods') and nmap:
            ssh_surfaces = [s for s in all_services if int(s.get('port') or 0) == 22 or str(s.get('service','')).lower() == 'ssh']
            for s in ssh_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 22)
                if _service_is_infra(s):
                    coverage.append(_coverage('ssh_auth_methods', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'SSH auth-method readiness deferred for infrastructure-like target {host}.', ''))
                    continue
                scripts = ','.join(_collector_scripts('ssh_auth_methods'))
                p = outfile('nmap_ssh_auth_methods', f'{host}_{port}', 'xml')
                r = run_cmd([nmap, '--script', scripts, '-p', str(port)] + list(_policy_required(_load_recon_policy(), 'nmap_script_timing')) + ['-oX', str(p), host], p, 180, True)
                rows = parse_nmap_xml(str(p))
                service_level_checks.append({'tool':'ssh_auth_methods','host':host,'port':port,'output_file':str(p),'rows':rows})
                ssh_items.append({'tool':'ssh_auth_methods','host':host,'port':port,'output_file':str(p),'rows':rows})
                coverage.append(_coverage('ssh_auth_methods', _status_from_result(r, bool(rows)), 'SSH advertised authentication-method evidence', f'{host}:{port}/tcp; no login attempt performed.', str(p), r))
                _add_raw(raw, 'ssh_auth_methods', host, port, str(p), 'nmap_xml', bool(rows))

        # FTP readiness: anonymous/system status only; no brute force.
        if enabled('ftp_anonymous_status') and nmap:
            ftp_surfaces = [s for s in all_services if int(s.get('port') or 0) in _collector_ports('ftp_anonymous_status') or str(s.get('service','')).lower() == 'ftp']
            for s in ftp_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                if _service_is_infra(s):
                    coverage.append(_coverage('ftp_anonymous_status', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'FTP readiness deferred for infrastructure-like target {host}.', ''))
                    continue
                scripts = ','.join(_collector_scripts('ftp_anonymous_status'))
                p = outfile('nmap_ftp_readiness', f'{host}_{port}', 'xml')
                r = run_cmd([nmap, '--script', scripts, '-p', str(port)] + list(_policy_required(_load_recon_policy(), 'nmap_script_timing')) + ['-oX', str(p), host], p, 180, True)
                rows = parse_nmap_xml(str(p))
                service_level_checks.append({'tool':'ftp_anonymous_status','host':host,'port':port,'output_file':str(p),'rows':rows})
                credential_validation_items.append({'tool':'ftp_anonymous_status','host':host,'port':port,'output_file':str(p),'rows':rows})
                coverage.append(_coverage('ftp_anonymous_status', _status_from_result(r, bool(rows)), 'FTP anonymous/system readiness evidence', f'{host}:{port}/tcp; no brute force performed.', str(p), r))
                _add_raw(raw, 'ftp_anonymous_status', host, port, str(p), 'nmap_xml', bool(rows))

        # SMB readiness: dialect/signing only; no shares, users, RID cycling or credential attempts.
        if enabled('smb_protocol_security') and nmap:
            smb_readiness_surfaces = [s for s in all_services if int(s.get('port') or 0) == 445 or str(s.get('service','')).lower() in {'microsoft-ds','smb'}]
            for s in smb_readiness_surfaces:
                host = str(s.get('host'))
                port = int(s.get('port') or 445)
                if _service_is_infra(s):
                    coverage.append(_coverage('smb_protocol_security', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'SMB protocol/signing readiness deferred for infrastructure-like target {host}.', ''))
                    continue
                scripts = ','.join(_collector_scripts('smb_protocol_security'))
                p = outfile('nmap_smb_protocol_security', f'{host}_{port}', 'xml')
                r = run_cmd([nmap, '--script', scripts, '-p', str(port)] + list(_policy_required(_load_recon_policy(), 'nmap_script_timing')) + ['-oX', str(p), host], p, 240, True)
                rows = parse_nmap_xml(str(p))
                item = {'tool':'smb_protocol_security','host':host,'port':port,'output_file':str(p),'rows':rows}
                smb.append(item)
                service_level_checks.append(item)
                credential_validation_items.append(item)
                coverage.append(_coverage('smb_protocol_security', _status_from_result(r, bool(rows)), 'SMB dialect/signing readiness evidence', f'{host}:{port}/tcp; share/user enumeration not performed.', str(p), r))
                _add_raw(raw, 'smb_protocol_security', host, port, str(p), 'nmap_xml', bool(rows))
        if smb_ports:
            coverage.append(_coverage('file_sharing_exposure', scan_store.STATUS_EMPTY, 'Downstream handoff', 'SMB/file-sharing exposure observed. Share listing, user enumeration, password validation and permission mapping are deferred.', ''))

        # WinRM readiness: WSMan endpoint/header check only; no authentication.
        if enabled('winrm_wsman_probe'):
            curl_bin = which('curl')
            winrm_surfaces = [s for s in all_services if int(s.get('port') or 0) in _collector_ports('winrm_wsman_probe') or str(s.get('service','')).lower() == 'winrm']
            for s in winrm_surfaces:
                if not curl_bin:
                    coverage.append(_coverage('winrm_wsman_probe', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'curl not available for WinRM WSMan readiness check.', ''))
                    break
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                scheme = 'https' if port == 5986 else 'http'
                url = f'{scheme}://{host}:{port}/wsman'
                p = outfile('winrm_wsman_probe', f'{host}_{port}', 'txt')
                guard = _policy_required(_load_recon_policy(), 'http_probe_guardrails')
                cmd = [curl_bin, '-sS', '--max-time', str(_policy_required(guard, 'curl_timeout_seconds')), '-I']
                if scheme == 'https':
                    cmd.append('-k')
                cmd.append(url)
                r = run_cmd(cmd, p, 30)
                output, _ = _captured_command_output(r, Path(p))
                auth_headers = re.findall(r'(?im)^WWW-Authenticate:\s*(.+)$', output)
                item = {'tool':'winrm_wsman_probe','host':host,'port':port,'url':url,'auth_headers':auth_headers,'output_file':str(p),'output':output[:4000]}
                credential_validation_items.append(item)
                service_level_checks.append(item)
                coverage.append(_coverage('winrm_wsman_probe', _status_from_result(r, bool(output.strip())), 'WinRM WSMan listener/header readiness evidence', f'{host}:{port}/tcp; no authentication performed.', str(p), r))
                _add_raw(raw, 'winrm_wsman_probe', host, port, str(p), 'text', bool(output.strip()))

        # Web handoff readiness: one-page form/input/link extraction only; no crawling or payloads.
        if enabled('html_form_parser') and http_ports:
            for s in http_ports:
                host = str(s.get('host'))
                port = int(s.get('port') or 0)
                if _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])):
                    coverage.append(_coverage('html_form_parser', scan_store.STATUS_EMPTY, 'Suggested follow-up', f'Web form parsing deferred for infrastructure target {host}.', ''))
                    continue
                url = _url_for(host, port, 'ssl' in str(s.get('service','')).lower())
                result = _collect_single_page_form_hints(host, port, url)
                item = {'tool':'html_form_parser','host':host,'port':port,'url':url,'forms':result.get('forms') or [],'links':result.get('links') or [],'output_file':result.get('output_file','')}
                web.append(item)
                coverage.append(_coverage('html_form_parser', _status_from_result(result, bool(item['forms'] or item['links'])), 'Web form/input/link readiness evidence', f'{url}; one page fetched; no attack payloads or directory brute force.', result.get('output_file',''), result))
                _add_raw(raw, 'html_form_parser', host, port, result.get('output_file',''), 'html', bool(item['forms'] or item['links']))

        credential_surfaces=[s for s in all_services if int(s.get('port') or 0) in {21,22,23,139,445,5985,5986} or str(s.get('service','')).lower() in {'ftp','ssh','telnet','smb','netbios-ssn','microsoft-ds','winrm'}]
        if credential_surfaces:
            coverage.append(_coverage('credential_validation_handoff', scan_store.STATUS_EMPTY, 'Downstream handoff', f'Credential validation deferred for {len(credential_surfaces)} service surface(s); recon collected readiness evidence only and does not perform login attempts.', ''))
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if (service_level_checks or credential_validation_items) else scan_store.STATUS_EMPTY, f'{len(service_level_checks)} readiness evidence item(s) collected; validation collectors deferred')
        _publish_partial(scan_id, smb_inventory=smb, service_level_checks=service_level_checks, credential_validation=credential_validation_items)


        # Modern active validation: adaptive, evidence-only checks for enterprise services.
        # These collectors stay inside recon: no brute force, no exploitation, no authenticated access.
        task='Modern Active Validation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        passive_intelligence = {'dns': [], 'reverse_dns': [], 'tls': [], 'certificate_transparency': [], 'findings': {}, 'relationships': [], 'dns_relationships': [], 'certificate_correlation': [], 'summary': [], 'policy': {}}
        modern_active_validation = {'ldap_rootdse': [], 'kerberos_info': [], 'tls_cipher_validation': [], 'rdp_negotiation': [], 'api_discovery': [], 'targeted_web_discovery': [], 'kubernetes_exposure': [], 'container_exposure': [], 'vpn_validation': [], 'nuclei_safe': [], 'telnet_readiness': [], 'snmp_readiness': [], 'mssql_info': [], 'vnc_info': [], 'tomcat_ajp_readiness': [], 'redis_info': [], 'elasticsearch_info': [], 'ldapsearch_rootdse': [], 'snmp_targeted_oids': [], 'dns_context': [], 'http_security_context': [], 'rpcinfo_native': [], 'showmount_native': [], 'ssh_audit_native': [], 'federation_detection': [], 'tls_intelligence': [], 'noise_evaluation': {}, 'information_gathering_summary': [], 'summary': [], 'policy': {}, 'budget': {}}
        try:
            active_policy = load_active_policy()
            modern_active_validation['policy'] = {'nuclei_enabled_by_default': bool((active_policy.get('nuclei') or {}).get('enabled_by_default')), 'detection_budget_enabled': bool((active_policy.get('detection_budget') or {}).get('enabled', True))}
            budget_cfg = active_policy.get('detection_budget') or {}
            per_host_http_budget = int(budget_cfg.get('max_native_http_requests_per_host') or 18)
            modern_active_validation['budget'] = {'native_http_budget_per_host': per_host_http_budget, 'nmap_script_budget_per_host': int(budget_cfg.get('max_nmap_script_groups_per_host') or 5), 'enforced': bool(budget_cfg.get('enabled', True))}

            nmap_bin = which('nmap')
            timing = list(_policy_required(_load_recon_policy(), 'nmap_script_timing'))

            def run_nmap_validation(tool_id: str, surfaces: list[dict[str, Any]], scripts: list[str], evidence_label: str) -> None:
                if not enabled(tool_id):
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'{tool_id} disabled by scan profile or policy.', ''))
                    return
                if not surfaces:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'No {tool_id.replace("_", " ")} service observed.', ''))
                    return
                if not nmap_bin:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', 'nmap not available for modern active validation.', ''))
                    return
                for svc in surfaces:
                    host = str(svc.get('host'))
                    port = int(svc.get('port') or 0)
                    if _is_infrastructure_target(host, environment_intelligence, open_map.get(host, [])) and tool_id not in {'tls_cipher_validation'}:
                        coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'{tool_id} deferred for infrastructure-like target {host}.', ''))
                        continue
                    p = outfile(tool_id, f'{host}_{port}', 'xml')
                    r = run_cmd([nmap_bin, '--script', ','.join(scripts), '-p', str(port)] + timing + ['-oX', str(p), host], p, int(active_policy.get('timeouts', {}).get('nmap_seconds', 180)), True)
                    rows = parse_nmap_xml(str(p))
                    item = {'tool': tool_id, 'host': host, 'port': port, 'scripts': scripts, 'rows': rows, 'output_file': str(p), 'recon_boundary': 'Evidence-only protocol validation; no credential use or exploitation.'}
                    modern_active_validation.setdefault(tool_id, []).append(item)
                    service_level_checks.append(item)
                    coverage.append(_coverage(tool_id, _status_from_result(r, bool(rows)), evidence_label, f'{host}:{port}/tcp; no credentials, brute force, or exploitation performed.', str(p), r))
                    _add_raw(raw, tool_id, host, port, str(p), 'nmap_xml', bool(rows))

            ldap_surfaces = [s for s in all_services if int(s.get('port') or 0) in {389, 636, 3268, 3269} or 'ldap' in str(s.get('service','')).lower()]
            kerberos_surfaces = [s for s in all_services if int(s.get('port') or 0) == 88 or 'kerberos' in str(s.get('service','')).lower()]
            tls_surfaces = [s for s in all_services if int(s.get('port') or 0) in {443, 636, 989, 990, 993, 995, 8443, 9443, 5986, 2376, 6443} or any(x in str(s.get('service','')).lower() for x in ['ssl','https','tls'])]
            rdp_surfaces = [s for s in all_services if int(s.get('port') or 0) == 3389 or 'rdp' in str(s.get('service','')).lower() or 'ms-wbt' in str(s.get('service','')).lower()]
            scripts = active_policy.get('nmap_script_sets') or {}
            run_nmap_validation('ldap_rootdse', ldap_surfaces, scripts.get('ldap_rootdse') or ['ldap-rootdse'], 'LDAP RootDSE naming-context evidence')
            run_nmap_validation('kerberos_info', kerberos_surfaces, scripts.get('kerberos_info') or ['krb5-info'], 'Kerberos realm/service evidence')
            run_nmap_validation('tls_cipher_validation', tls_surfaces, scripts.get('tls_cipher_validation') or ['ssl-enum-ciphers'], 'TLS cipher/protocol validation evidence')
            run_nmap_validation('rdp_negotiation', rdp_surfaces, scripts.get('rdp_negotiation') or ['rdp-enum-encryption'], 'RDP encryption/NLA negotiation evidence')

            # Policy-driven Full Recon service coverage. Ports/services live in
            # active_validation_policy.json so reviewers can amend coverage without
            # changing scanner code.
            def policy_surfaces(tool_id: str) -> tuple[list[dict[str, Any]], str]:
                cfg = (active_policy.get('service_validation') or {}).get(tool_id) or {}
                ports = {int(x) for x in (cfg.get('ports') or [])}
                names = {str(x).lower() for x in (cfg.get('services') or [])}
                label = str(cfg.get('label') or tool_id.replace('_', ' ') + ' evidence')
                rows = []
                for svc in all_services:
                    port = int(svc.get('port') or 0)
                    name = str(svc.get('service') or '').lower()
                    product = str(svc.get('product') or '').lower()
                    if port in ports or name in names or any(n and n in product for n in names):
                        rows.append(svc)
                return rows, label

            for tool_id in ['telnet_readiness','snmp_readiness','mssql_info','vnc_info','tomcat_ajp_readiness']:
                surfaces, label = policy_surfaces(tool_id)
                run_nmap_validation(tool_id, surfaces, scripts.get(tool_id) or [], label)

            # Native targeted information-gathering collectors. These add depth
            # while staying recon-only: no auth attempts, no brute force, no
            # mounting, no writes, and no exploitation.
            def run_external_validation(tool_id: str, surfaces: list[dict[str, Any]], command_builder, label: str, timeout: int = 60) -> None:
                if not enabled(tool_id):
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'{tool_id} disabled by scan profile or policy.', ''))
                    return
                if not surfaces:
                    coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'No {tool_id.replace("_", " ")} service observed.', ''))
                    return
                for svc in surfaces:
                    host = str(svc.get('host'))
                    port = int(svc.get('port') or 0)
                    cmd = command_builder(host, port)
                    if not cmd or not which(str(cmd[0])):
                        coverage.append(_coverage(tool_id, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'{cmd[0] if cmd else tool_id} not available for {tool_id}.', ''))
                        continue
                    out = outfile(tool_id, f'{host}_{port}', 'txt')
                    r = run_cmd(cmd, out, timeout, False)
                    output_text = (r.get('stdout') or '') + '\n' + (r.get('stderr') or '')
                    parsed = parse_external_validation(tool_id, output_text)
                    item = {'tool': tool_id, 'host': host, 'port': port, 'command': ' '.join(map(str, cmd)), 'parsed': parsed, 'output_file': str(out), 'recon_boundary': 'Targeted information gathering only; no credentials, brute force, writes, mounting, or exploitation.'}
                    modern_active_validation.setdefault(tool_id, []).append(item)
                    service_level_checks.append(item)
                    coverage.append(_coverage(tool_id, _status_from_result(r, bool(output_text.strip())), label, f'{host}:{port}/tcp; targeted information-gathering evidence only.', str(out), r))
                    _add_raw(raw, tool_id, host, port, str(out), 'text', bool(output_text.strip()))

            ssh_surfaces, _ = policy_surfaces('ssh_crypto_audit')
            # Prefer native protocol tools over Nmap NSE where they provide the same evidence with less noise.
            dns_surfaces = [s for s in all_services if int(s.get('port') or 0) == 53]
            snmp_surfaces, _ = policy_surfaces('snmp_readiness')
            rpc_surfaces = [s for s in all_services if int(s.get('port') or 0) == 111]
            nfs_surfaces = [s for s in all_services if int(s.get('port') or 0) == 2049]
            if enabled('ssh_audit_native'):
                run_external_validation('ssh_audit_native', ssh_surfaces, lambda h,p: ['ssh-audit', h], 'Optional SSH cryptographic posture audit', 90)
            run_external_validation('dns_context', dns_surfaces[:1], lambda h,p: ['dig', '+nocmd', '+noall', '+answer', '@' + h, 'version.bind', 'CHAOS', 'TXT'], 'DNS context collection using version.bind', 30)
            run_external_validation('snmp_targeted_oids', snmp_surfaces, lambda h,p: ['snmpget', '-v2c', '-c', 'public', h, '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0', '1.3.6.1.2.1.1.4.0'], 'SNMP targeted system identity OID evidence', 45)
            run_external_validation('rpcinfo_native', rpc_surfaces[:1], lambda h,p: ['rpcinfo', '-p', h], 'Native RPC program mapping evidence', 45)
            run_external_validation('showmount_native', nfs_surfaces[:1], lambda h,p: ['showmount', '-e', h], 'Native NFS export readiness evidence', 45)
            run_external_validation('ldapsearch_rootdse', ldap_surfaces, lambda h,p: ['ldapsearch', '-x', '-H', ('ldaps://' if p in {636,3269} else 'ldap://') + h + ('' if p in {389,636} else ':' + str(p)), '-s', 'base', '+'], 'Native LDAP RootDSE capability/naming-context evidence', 60)
            postgres_surfaces = [s for s in all_services if int(s.get('port') or 0) == 5432]
            run_external_validation('postgres_readiness_native', postgres_surfaces[:1], lambda h,p: ['pg_isready', '-h', h, '-p', str(p), '-t', '4'], 'Native PostgreSQL readiness evidence', 30)

            web_services = [s for s in all_services if int(s.get('port') or 0) in {80,443,8080,8081,8180,8443,9000,9443} or 'http' in str(s.get('service','')).lower()]
            run_external_validation('http_security_context', web_services, lambda h,p: ['curl', '-k', '-I', '-sS', '--max-time', '5', service_url({'host': h, 'port': p})], 'HTTP security-header/authentication/cookie context evidence', 30)
            native_sets = []
            if enabled('federation_detection'):
                modern_active_validation['federation_detection'] = collect_federation_detection(web_services, active_policy)
                native_sets.append(('federation_detection', modern_active_validation['federation_detection'], 'Federation/OIDC/SAML metadata and authentication-surface markers only.'))
            if enabled('tls_intelligence'):
                modern_active_validation['tls_intelligence'] = collect_tls_intelligence(all_services, active_policy)
                native_sets.append(('tls_intelligence', modern_active_validation['tls_intelligence'], 'TLS handshake, ALPN, cipher and certificate metadata only.'))
            if enabled('targeted_web_discovery'):
                modern_active_validation['targeted_web_discovery'] = collect_targeted_web_discovery(web_services, active_policy)
                native_sets.append(('targeted_web_discovery', modern_active_validation['targeted_web_discovery'], 'Policy-limited robots/sitemap/security/admin marker checks; no wordlist brute force.'))
            else:
                coverage.append(_coverage('targeted_web_discovery', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'Targeted web discovery disabled by profile or policy.', ''))
            if enabled('api_discovery'):
                modern_active_validation['api_discovery'] = collect_api_discovery(web_services, active_policy)
                native_sets.append(('api_discovery', modern_active_validation['api_discovery'], 'OpenAPI/Swagger/GraphQL documentation discovery only.'))
            else:
                coverage.append(_coverage('api_discovery', scan_store.STATUS_EMPTY, 'Suggested follow-up', 'API documentation discovery disabled by profile or policy.', ''))
            if enabled('kubernetes_exposure'):
                modern_active_validation['kubernetes_exposure'] = collect_kubernetes_exposure(all_services, active_policy)
                native_sets.append(('kubernetes_exposure', modern_active_validation['kubernetes_exposure'], 'Kubernetes unauthenticated metadata endpoint checks only.'))
            if enabled('container_exposure'):
                modern_active_validation['container_exposure'] = collect_container_exposure(all_services, active_policy)
                native_sets.append(('container_exposure', modern_active_validation['container_exposure'], 'Container/registry metadata endpoint checks only.'))
            if enabled('vpn_validation'):
                modern_active_validation['vpn_validation'] = collect_vpn_validation(web_services, (passive_intelligence or {}).get('findings') if isinstance(passive_intelligence, dict) else {}, active_policy)
                native_sets.append(('vpn_validation', modern_active_validation['vpn_validation'], 'VPN portal marker validation only; no authentication.'))

            # Native HTTP metadata checks for modern data stores/search services
            # such as Redis proxies and Elasticsearch. They are evidence-only,
            # policy-path based, and perform no writes/authentication.
            for native_tool, cfg in (active_policy.get('native_http_services') or {}).items():
                if not enabled(native_tool):
                    coverage.append(_coverage(native_tool, scan_store.STATUS_EMPTY, 'Suggested follow-up', f'{native_tool} disabled by profile or policy.', ''))
                    continue
                ports = {int(x) for x in (cfg.get('ports') or [])}
                candidates = [s for s in all_services if int(s.get('port') or 0) in ports or native_tool.split('_')[0] in str(s.get('service','')).lower() or native_tool.split('_')[0] in str(s.get('product','')).lower()]
                rows_native = []
                for svc in candidates:
                    base = service_url(svc).rstrip('/')
                    for path in cfg.get('paths') or ['/']:
                        row = _fetch(base + str(path), timeout=float(active_policy.get('timeouts', {}).get('http_seconds', 4)))
                        blob = str(row).lower()
                        if int(row.get('status') or 0) in {200, 401, 403} or any(str(m).lower() in blob for m in (cfg.get('markers') or [])):
                            row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': native_tool, 'collection_method':'metadata_endpoint_probe', 'recon_boundary':'Metadata exposure check only; no writes, queries, authentication, or exploitation.'})
                            rows_native.append(row)
                modern_active_validation[native_tool] = rows_native
                native_sets.append((native_tool, rows_native, str(cfg.get('label') or native_tool.replace('_',' ') + ' evidence')))

            # Nuclei is enabled in Full Recon but constrained to safe info/low
            # fingerprint and misconfiguration evidence; intrusive/exploit tags are excluded.
            nuclei_bin = which('nuclei')
            if enabled('nuclei_safe') and nuclei_bin and web_services and bool((active_policy.get('nuclei') or {}).get('enabled_by_default', False)):
                nuclei_cfg = active_policy.get('nuclei') or {}
                urls_file = outfile('nuclei_safe_targets', 'web', 'txt')
                urls_file.write_text('\n'.join(sorted({service_url(s) for s in web_services})) + '\n', encoding='utf-8')
                out = outfile('nuclei_safe', 'web', 'jsonl')
                cmd = [nuclei_bin, '-list', str(urls_file), '-jsonl', '-silent', '-severity', ','.join(nuclei_cfg.get('allowed_severities') or ['info','low']), '-tags', ','.join(nuclei_cfg.get('allowed_tags') or ['tech','fingerprint','misconfig']), '-exclude-tags', ','.join(nuclei_cfg.get('excluded_tags') or []), '-rate-limit', str(nuclei_cfg.get('rate_limit_per_second') or 1), '-retries', str(nuclei_cfg.get('retries') or 0), '-o', str(out)]
                templates_dir = os.getenv(str(nuclei_cfg.get('templates_directory_env') or 'NUCLEI_TEMPLATES_DIR'), '').strip()
                if templates_dir:
                    cmd.extend(['-templates', templates_dir])
                r = run_cmd(cmd, out, int(active_policy.get('timeouts', {}).get('nuclei_seconds', 240)), True)
                rows = []
                try:
                    for line in out.read_text(encoding='utf-8', errors='ignore').splitlines():
                        if line.strip():
                            rows.append(json.loads(line))
                except Exception:
                    rows = []
                modern_active_validation['nuclei_safe'] = rows
                coverage.append(_coverage('nuclei_safe', _status_from_result(r, bool(rows)), 'Nuclei safe informational/fingerprint/misconfiguration templates only', f'{len(rows)} safe nuclei evidence item(s) retained; intrusive/exploit/default-login tags excluded.', str(out), r))
                _add_raw(raw, 'nuclei_safe', '', '', str(out), 'jsonl', bool(rows))
            else:
                reason = 'nuclei not available, disabled by profile/policy, evidence-trigger disabled by default, or no web services observed.'
                coverage.append(_coverage('nuclei_safe', scan_store.STATUS_EMPTY, 'Suggested follow-up', reason, ''))

            for tool_name, rows, note in native_sets:
                path = Path('storage/scans') / f'{tool_name}_{scan_id}.json'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(rows, indent=2, default=str), encoding='utf-8')
                produced = bool(rows)
                native_result = _log_native_collector(scan_id, tool_name, f'python-native active_validation {tool_name} items={len(rows)}', note, str(path), produced)
                coverage.append(_coverage(tool_name, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, note, f'{len(rows)} evidence item(s) retained.', str(path), native_result))
                _add_raw(raw, tool_name, '', '', str(path), 'json', produced)

            modern_active_validation['noise_evaluation'] = build_noise_evaluation(modern_active_validation)
            modern_active_validation['information_gathering_summary'] = build_information_gathering_summary(modern_active_validation)
            modern_active_validation['summary'] = build_active_summary(modern_active_validation) + modern_active_validation.get('information_gathering_summary', [])
            if modern_active_validation.get('noise_evaluation', {}).get('summary'):
                modern_active_validation['summary'].append(modern_active_validation['noise_evaluation']['summary'])
            active_path = write_active_package(scan_id, modern_active_validation)
            produced = bool(modern_active_validation.get('summary'))
            native_result = _log_native_collector(scan_id, 'modern_active_validation', 'python-native active_validation consolidate', 'Consolidated modern active validation evidence and budget metadata.', active_path, produced)
            coverage.append(_coverage('modern_active_validation', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Modern active enterprise validation summary', f'{len(modern_active_validation.get("summary") or [])} active validation summary item(s) retained.', active_path, native_result))
            _add_raw(raw, 'modern_active_validation', '', '', active_path, 'json', produced)
            scan_store.audit_event(scan_id, 'system', 'modern_active_validation_collected', {'summary_count': len(modern_active_validation.get('summary') or []), 'nuclei_enabled': enabled('nuclei_safe')})
            _publish_partial(scan_id, modern_active_validation=modern_active_validation)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(modern_active_validation.get("summary") or [])} modern active validation summary item(s) retained')
        except Exception as exc:
            scan_store.log(scan_id, f'Modern active validation incomplete: {exc}', 'WARN')
            _finish(scan_id, task, scan_store.STATUS_FAILED, f'Modern active validation incomplete: {exc}')

        # Native protocol metadata enrichment. This is a low-volume depth pass:
        # one bounded metadata probe per observed service where the protocol can
        # safely disclose product, version, capability or banner information.
        task='Native Protocol Metadata Enrichment'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        try:
            native_protocol_rows = _collect_native_protocol_enrichment(all_services)
            all_services = _apply_native_protocol_enrichment(all_services, native_protocol_rows)
            modern_active_validation['native_protocol_enrichment'] = native_protocol_rows
            native_protocol_path = Path('storage/scans') / f'native_protocol_enrichment_{scan_id}.json'
            native_protocol_path.parent.mkdir(parents=True, exist_ok=True)
            native_protocol_path.write_text(json.dumps(native_protocol_rows, indent=2, default=str), encoding='utf-8')
            produced = bool(native_protocol_rows)
            native_result = _log_native_collector(scan_id, 'native_protocol_enrichment', f'python-native native_protocol_enrichment services={len(all_services)}', 'Collected single-connection protocol metadata for FTP, SMTP, MySQL, PostgreSQL, IRC and VNC where observed.', str(native_protocol_path), produced)
            coverage.append(_coverage('native_protocol_enrichment', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Native protocol product/version/capability enrichment', f'{len(native_protocol_rows)} native protocol metadata item(s) retained.', str(native_protocol_path), native_result))
            _add_raw(raw, 'native_protocol_enrichment', '', '', str(native_protocol_path), 'json', produced)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(native_protocol_rows)} native protocol metadata item(s) retained')
        except Exception as exc:
            scan_store.log(scan_id, f'Native protocol metadata enrichment incomplete: {exc}', 'WARN')
            _finish(scan_id, task, scan_store.STATUS_FAILED, f'Native protocol metadata enrichment incomplete: {exc}')


        # Passive intelligence collection: evidence-only, policy-controlled and recon-scoped.
        task='Passive Intelligence Collection'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        passive_intelligence = {'dns': [], 'reverse_dns': [], 'tls': [], 'certificate_transparency': [], 'findings': {}, 'relationships': [], 'dns_relationships': [], 'certificate_correlation': [], 'summary': [], 'policy': {}}
        try:
            passive_policy = load_passive_policy()
            passive_intelligence['policy'] = {'ct_lookup_enabled': bool((passive_policy.get('ct_lookup') or {}).get('enabled')), 'dns_record_types': passive_policy.get('dns_record_types') or []}
            domains = candidate_domains(target_input, all_services, web, tls_items if 'tls_items' in locals() else [])
            if enabled('passive_dns'):
                dns_rows = collect_dns(domains, passive_policy)
                reverse_rows = collect_reverse_dns(live, passive_policy)
                passive_intelligence['dns'] = dns_rows
                passive_intelligence['reverse_dns'] = reverse_rows
            if enabled('passive_tls'):
                passive_intelligence['tls'] = collect_tls(live, all_services, passive_policy)
            if enabled('certificate_transparency'):
                passive_intelligence['certificate_transparency'] = collect_certificate_transparency(domains, passive_policy)
            passive_intelligence['dns_relationships'] = build_dns_relationships(passive_intelligence.get('dns') or [], passive_intelligence.get('reverse_dns') or [])
            passive_intelligence['certificate_correlation'] = build_certificate_correlation(passive_intelligence.get('tls') or [], all_services)
            if enabled('passive_fingerprinting'):
                findings = infer_passive_findings(passive_intelligence.get('dns') or [], passive_intelligence.get('tls') or [], web, load_fingerprints())
                passive_intelligence['findings'] = findings
                passive_intelligence['relationships'] = build_relationship_graph(domains, passive_intelligence.get('dns') or [], passive_intelligence.get('tls') or [], findings, passive_intelligence.get('certificate_transparency') or [])
            passive_intelligence['summary'] = build_passive_summary(passive_intelligence)
            passive_path = write_passive_package(scan_id, passive_intelligence)
            produced = bool(passive_intelligence.get('summary') or passive_intelligence.get('dns') or passive_intelligence.get('reverse_dns') or passive_intelligence.get('tls') or passive_intelligence.get('relationships'))
            cmd_parts = []
            if enabled('passive_dns'):
                cmd_parts.append('collect_dns')
            if enabled('passive_tls'):
                cmd_parts.append('collect_tls')
            if enabled('passive_fingerprinting'):
                cmd_parts.append('infer_passive_findings')
            if enabled('certificate_transparency'):
                cmd_parts.append('collect_certificate_transparency')
            native_command = 'python-native passive_intel ' + ','.join(cmd_parts or ['disabled']) + f' domains={len(domains)} hosts={len(live)}'
            native_result = _log_native_collector(scan_id, 'passive_intelligence', native_command, 'Collected passive DNS/TLS/authentication/cloud/VPN/CDN/email/relationship evidence within recon scope.', passive_path, produced)
            coverage.append(_coverage('passive_intelligence', scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, 'Passive DNS/TLS/authentication/cloud/VPN/CDN/email/relationship intelligence', f'{len(passive_intelligence.get("summary") or [])} passive summary item(s) retained.', passive_path, native_result))
            _add_raw(raw, 'passive_intelligence', '', '', passive_path, 'json', produced)
            scan_store.audit_event(scan_id, 'system', 'passive_intelligence_collected', {'summary_count': len(passive_intelligence.get('summary') or []), 'ct_enabled': bool((passive_policy.get('ct_lookup') or {}).get('enabled'))})
            _publish_partial(scan_id, passive_intelligence=passive_intelligence)
            _finish(scan_id, task, scan_store.STATUS_SUCCESS if produced else scan_store.STATUS_EMPTY, f'{len(passive_intelligence.get("summary") or [])} passive intelligence summary item(s) retained')
        except Exception as exc:
            scan_store.log(scan_id, f'Passive intelligence collection incomplete: {exc}', 'WARN')
            _finish(scan_id, task, scan_store.STATUS_FAILED, f'Passive intelligence collection incomplete: {exc}')


        # 16 Evidence consolidation
        task='Evidence Consolidation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        all_services=_merge_smb_version_evidence(all_services, smb)
        all_services=_normalise_service_rows(all_services)
        security_observations=_build_security_observations(all_services, smb, web)
        evidence_gaps=[{'host':s.get('host'),'port':s.get('port'),'protocol':s.get('protocol'),'service':s.get('service'),'gaps':evidence_gaps_for_service(s)} for s in all_services if evidence_gaps_for_service(s)]
        normalised={'hosts':live,'services':all_services,'environment_intelligence':environment_intelligence,'attack_surface_objectives':selected_objectives,'evidence_gaps':evidence_gaps,'web':web,'smb':smb,'snmp':snmp,'ssh':ssh_items,'ldap':ldap_items,'tls':tls_items,'rdp':rdp_items,'credential_validation':credential_validation_items,'service_level_checks':service_level_checks,'security_observations':security_observations,'passive_intelligence':passive_intelligence,'passive_local_inventory': locals().get('passive_local_inventory', {}),'modern_active_validation':modern_active_validation}
        p=Path('storage/scans') / f'normalised_{scan_id}.json'; p.write_text(json.dumps(normalised, indent=2, default=str), encoding='utf-8')
        # Normalised evidence is already written as formatted JSON. Internal formatting helpers are not shown as user-facing recon tools.
        _add_raw(raw,'python_normaliser','','',str(p),'json',True)
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, f'{len(all_services)} service record(s) normalised; {len(evidence_gaps)} evidence gap item(s) retained')
        _finish(scan_id, 'Evidence Gap Review', scan_store.STATUS_SUCCESS if evidence_gaps else scan_store.STATUS_EMPTY, f'{len(evidence_gaps)} evidence gap item(s) identified')

        # 17 MITRE matching
        task='CVE Review'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        mitre=mitre_status(); cve_matches, relevant_cve_information = _match_cves(all_services) if mitre.get('available') else ([], [])
        _finish(scan_id, task, scan_store.STATUS_SUCCESS if cve_matches else scan_store.STATUS_EMPTY, f'{len(cve_matches)} validated MITRE reference item(s) linked; {len(relevant_cve_information)} additional relevant record(s) retained.')
        _publish_partial(scan_id, cve_matches=cve_matches, relevant_cve_information=relevant_cve_information, possible_cve_references=relevant_cve_information, mitre_source=mitre)

        # 18 Caldera Handoff
        task='Handoff Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        exploit_validation_candidates=_build_exploit_validation_candidates(all_services, cve_matches, security_observations, web_summary if 'web_summary' in locals() else {}, smb_summary if 'smb_summary' in locals() else {})
        # Detailed readiness is finalised during report preparation after web/SMB summaries are built.
        caldera_handoff={'enabled_for_execution': False, 'note':'Recon package prepared for teammate exploitation/AI/CALDERA modules. Recon does not execute exploits or obtain access.', 'services': [{'host':s['host'],'port':s['port'],'protocol':s['protocol'],'service':s['service'],'product':s.get('product',''),'version':s.get('version','')} for s in all_services], 'cve_matches': cve_matches, 'exploit_validation_candidates': exploit_validation_candidates}
        _finish(scan_id, task, scan_store.STATUS_SUCCESS, 'Caldera handoff context prepared')

        # 19 Report
        task='Report Preparation'; scan_store.set_task(scan_id, _task_name(task), scan_store.STATUS_RUNNING)
        candidate_cve_groups = _build_candidate_cve_groups(relevant_cve_information)
        public_coverage = _public_tool_coverage(_sort_coverage(coverage))
        service_summary = _build_service_summary(all_services, cve_matches, candidate_cve_groups)
        web_summary = _summarise_web_inventory(web)
        smb_summary = _summarise_smb_inventory(smb)
        contamination_indicators = _detect_cross_host_evidence_contamination(smb_summary)
        if contamination_indicators:
            environment_context_indicators.extend(contamination_indicators)
        key_exposure_indicators = _build_key_exposure_indicators(security_observations)
        service_workbench = _build_service_workbench(all_services, cve_matches, candidate_cve_groups, security_observations, web_summary, smb_summary, service_level_checks)
        attack_surface_sections = _build_attack_surface_sections(service_workbench)
        follow_up_objectives = _build_follow_up_objectives(open_map, environment_context_indicators, all_services)
        authentication_surface_readiness = _build_authentication_surface_readiness(all_services, environment_intelligence, smb_summary, service_level_checks, credential_validation_items)
        web_exploitation_readiness = _build_web_exploitation_readiness(all_services, web_summary, web)
        enumeration_intelligence = build_enumeration_intelligence(
            all_services,
            modern_active_validation=modern_active_validation,
            passive_intelligence=passive_intelligence,
            web_inventory=web,
            smb_summary=smb_summary,
        )
        knowledge_graph_path = Path('storage/results') / f'{scan_id}_knowledge_graph.json'
        knowledge_graph_path.parent.mkdir(parents=True, exist_ok=True)
        knowledge_graph_path.write_text(json.dumps(enumeration_intelligence.get('knowledge_graph') or {}, indent=2, default=str), encoding='utf-8')
        enumeration_intelligence['knowledge_graph_file'] = str(knowledge_graph_path)
        _add_raw(raw, 'knowledge_graph', '', '', str(knowledge_graph_path), 'json', True)
        enum_path = Path('storage/results') / f'{scan_id}_enumeration_intelligence.json'
        enum_path.write_text(json.dumps(enumeration_intelligence, indent=2, default=str), encoding='utf-8')
        enumeration_intelligence['enumeration_intelligence_file'] = str(enum_path)
        _add_raw(raw, 'enumeration_intelligence', '', '', str(enum_path), 'json', True)
        operational_maturity = build_operational_maturity_package(
            scan_id,
            target_input,
            all_services,
            raw,
            modern_active_validation,
            passive_intelligence,
            enumeration_intelligence,
            scan_store.get(scan_id).get('started_at') if scan_store.get(scan_id) else None,
        )
        _add_raw(raw, 'operational_maturity', '', '', operational_maturity.get('operational_maturity_file', ''), 'json', True)
        exploit_validation_candidates = _dedupe_dicts((exploit_validation_candidates or []) + authentication_surface_readiness + web_exploitation_readiness, ('host','port','service','category','candidate_type'))
        caldera_handoff['exploit_validation_candidates'] = exploit_validation_candidates
        caldera_handoff['authentication_surface_readiness'] = authentication_surface_readiness
        caldera_handoff['web_exploitation_readiness'] = web_exploitation_readiness
        decision_register = build_decision_register(all_services, selected_objectives, environment_context_indicators, evidence_gaps, enterprise_review_policy)
        evidence_manifest = build_evidence_manifest(scan_id, raw)
        enterprise_readiness = build_enterprise_readiness_summary(scope_validation, decision_register, evidence_manifest, enterprise_review_policy)
        scan_store.audit_event(scan_id, 'system', 'enterprise_readiness_compiled', {'decision_register_count': len(decision_register), 'evidence_manifest': evidence_manifest.get('manifest_file')})
        package={'scan_id':scan_id,'target_input':target_input,'scan_options':scan_options,'hosts':live,'scope_validation':scope_validation,'enterprise_readiness':enterprise_readiness,'passive_intelligence':passive_intelligence,'passive_local_inventory': locals().get('passive_local_inventory', {}),'modern_active_validation':modern_active_validation,'enumeration_intelligence':enumeration_intelligence,'operational_maturity':operational_maturity,'decision_register':decision_register,'evidence_manifest':evidence_manifest,'mitre_source':mitre,'tool_coverage':public_coverage,'service_inventory':all_services,'service_summary':service_summary,'service_workbench':service_workbench,'attack_surface_sections':attack_surface_sections,'cve_matches':cve_matches,'relevant_cve_information':relevant_cve_information,'candidate_cve_groups':candidate_cve_groups,'possible_cve_references':relevant_cve_information,'service_level_checks':service_level_checks,'security_relevant_observations':security_observations,'key_exposure_indicators':key_exposure_indicators,'tcp_service_count':len([x for x in all_services if x.get('protocol')=='tcp']),'udp_service_count':len([x for x in all_services if x.get('protocol')=='udp']),'web_inventory':web,'web_summary':web_summary,'smb_inventory':smb,'smb_summary':smb_summary,'raw_evidence_index':raw,'caldera_handoff':caldera_handoff,'environment_summary':_build_environment_summary(environment_intelligence, environment_context_indicators),'attack_surface_objectives':selected_objectives,'evidence_gaps':evidence_gaps,'exploit_validation_candidates':exploit_validation_candidates,'authentication_surface_readiness':authentication_surface_readiness,'web_exploitation_readiness':web_exploitation_readiness,'suggested_follow_up_objectives':follow_up_objectives,'escalation_paused':False}
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
