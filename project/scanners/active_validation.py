from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class ActiveValidationError(RuntimeError):
    pass


def _read_json(paths: list[Path], default: dict[str, Any] | None = None) -> dict[str, Any]:
    for path in paths:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
                return data if isinstance(data, dict) else (default or {})
            except Exception as exc:
                raise ActiveValidationError(f'Active validation policy could not be loaded from {path}: {exc}') from exc
    return default or {}


def load_active_policy() -> dict[str, Any]:
    policy = _read_json([Path('project/policies/active_validation_policy.json'), Path('policies/active_validation_policy.json')])
    required = ['timeouts', 'api_paths', 'kubernetes_paths', 'container_paths', 'vpn_paths', 'targeted_web_paths', 'detection_budget']
    missing = [k for k in required if k not in policy]
    if missing:
        raise ActiveValidationError(f'Active validation policy missing keys: {missing}')
    return policy


def write_active_package(scan_id: str, data: dict[str, Any]) -> str:
    path = Path('storage/scans') / f'modern_active_validation_{scan_id}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    return str(path)


def is_web_service(service: dict[str, Any]) -> bool:
    port = int(service.get('port') or 0)
    name = str(service.get('service') or '').lower()
    product = str(service.get('product') or '').lower()
    return port in {80, 443, 8080, 8081, 8180, 8443, 8009, 9000, 9443} or 'http' in name or 'tomcat' in product


def service_url(service: dict[str, Any], force_https: bool | None = None) -> str:
    host = str(service.get('host') or '')
    port = int(service.get('port') or 0)
    name = str(service.get('service') or '').lower()
    scheme = 'https' if (force_https is True or port in {443, 8443, 9443, 5986, 2376, 6443} or 'ssl' in name or 'https' in name) else 'http'
    default = (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)
    return f'{scheme}://{host}{"" if default else f":{port}"}'


def _fetch(url: str, method: str = 'GET', timeout: float = 4, max_bytes: int = 32768) -> dict[str, Any]:
    request = urllib.request.Request(url, method=method, headers={'User-Agent': 'AutoPenTest-Authorised-Recon/1.0'})
    try:
        ctx = ssl._create_unverified_context() if url.lower().startswith('https://') else None
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:  # nosec - authorised recon to in-scope host
            body = response.read(max_bytes).decode('utf-8', errors='replace')
            headers = {k.lower(): v for k, v in response.headers.items()}
            return {'url': url, 'method': method, 'status': response.status, 'headers': headers, 'body_sample': body[:max_bytes], 'success': True}
    except urllib.error.HTTPError as exc:
        body = exc.read(max_bytes).decode('utf-8', errors='replace') if exc.fp else ''
        return {'url': url, 'method': method, 'status': exc.code, 'headers': {k.lower(): v for k, v in exc.headers.items()}, 'body_sample': body[:max_bytes], 'success': exc.code < 500}
    except Exception as exc:
        return {'url': url, 'method': method, 'error': str(exc)[:180], 'success': False}


def _interesting_response(row: dict[str, Any], markers: list[str]) -> bool:
    blob = '\n'.join([str(row.get('status') or ''), str(row.get('headers') or ''), str(row.get('body_sample') or '')]).lower()
    return any(marker.lower() in blob for marker in markers) or int(row.get('status') or 0) in {200, 301, 302, 401, 403}


def collect_api_discovery(web_services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_active_policy()
    timeout = float(policy['timeouts'].get('http_seconds', 4))
    markers = ['openapi', 'swagger', 'graphql', 'api-docs', 'schema']
    rows: list[dict[str, Any]] = []
    for svc in web_services:
        base = service_url(svc).rstrip('/')
        for path in policy.get('api_paths') or []:
            url = base + str(path)
            row = _fetch(url, timeout=timeout)
            if _interesting_response(row, markers):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'api_discovery', 'collection_method': 'single_request_documentation_probe', 'recon_boundary': 'Documentation/schema discovery only; no attack payloads or authentication attempts.'})
                rows.append(row)
    return rows


def collect_targeted_web_discovery(web_services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_active_policy()
    timeout = float(policy['timeouts'].get('http_seconds', 4))
    markers = ['robots', 'sitemap', 'security.txt', 'humans.txt', 'admin', 'manager', 'login']
    rows: list[dict[str, Any]] = []
    for svc in web_services:
        base = service_url(svc).rstrip('/')
        for path in policy.get('targeted_web_paths') or []:
            row = _fetch(base + str(path), timeout=timeout)
            if _interesting_response(row, markers):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'targeted_web_discovery', 'collection_method': 'policy_limited_known_path_probe', 'recon_boundary': 'Small policy-defined known-path checks only; no brute-force wordlist discovery.'})
                rows.append(row)
    return rows


def collect_kubernetes_exposure(services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_active_policy()
    timeout = float(policy['timeouts'].get('http_seconds', 4))
    candidates = [s for s in services if int(s.get('port') or 0) in {6443, 8001, 10250, 10255} or 'kubernetes' in str(s.get('product') or s.get('service') or '').lower()]
    rows: list[dict[str, Any]] = []
    for svc in candidates:
        base = service_url(svc, force_https=int(svc.get('port') or 0) in {6443, 10250}).rstrip('/')
        for path in policy.get('kubernetes_paths') or []:
            row = _fetch(base + str(path), timeout=timeout)
            if _interesting_response(row, ['kubernetes', 'apiVersion', 'Unauthorized', 'forbidden']):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'kubernetes_exposure', 'collection_method': 'unauthenticated_metadata_probe', 'recon_boundary': 'Unauthenticated metadata endpoint check only; no token use or workload access.'})
                rows.append(row)
    return rows


def collect_container_exposure(services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_active_policy()
    timeout = float(policy['timeouts'].get('http_seconds', 4))
    candidates = [s for s in services if int(s.get('port') or 0) in {2375, 2376, 5000} or any(x in str(s.get('product') or s.get('service') or '').lower() for x in ['docker','podman','registry'])]
    rows: list[dict[str, Any]] = []
    for svc in candidates:
        base = service_url(svc, force_https=int(svc.get('port') or 0) == 2376).rstrip('/')
        for path in policy.get('container_paths') or []:
            row = _fetch(base + str(path), timeout=timeout)
            if _interesting_response(row, ['docker', 'podman', 'registry', 'ApiVersion']):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'container_exposure', 'collection_method': 'unauthenticated_metadata_probe', 'recon_boundary': 'Metadata/version endpoint check only; no container or image operations.'})
                rows.append(row)
    return rows


def collect_vpn_validation(web_services: list[dict[str, Any]], passive_findings: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_active_policy()
    timeout = float(policy['timeouts'].get('http_seconds', 4))
    vpn_hints = passive_findings and passive_findings.get('vpn')
    likely_ports = {443, 8443, 9443, 10443}
    candidates = [s for s in web_services if vpn_hints or int(s.get('port') or 0) in likely_ports]
    rows: list[dict[str, Any]] = []
    for svc in candidates:
        base = service_url(svc, force_https=True).rstrip('/')
        for path in policy.get('vpn_paths') or []:
            row = _fetch(base + str(path), timeout=timeout)
            if _interesting_response(row, ['global-protect', 'fortinet', 'anyconnect', 'citrix', 'pulse', 'openvpn', 'vpn']):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'vpn_validation', 'collection_method': 'portal_marker_probe', 'recon_boundary': 'Portal marker validation only; no credentials or session establishment.'})
                rows.append(row)
    return rows


def build_active_summary(data: dict[str, Any]) -> list[str]:
    labels = {
        'api_discovery': 'API documentation/schema surface',
        'targeted_web_discovery': 'targeted known web paths',
        'kubernetes_exposure': 'Kubernetes metadata surface',
        'container_exposure': 'container/registry metadata surface',
        'vpn_validation': 'VPN portal markers',
        'ldap_rootdse': 'LDAP RootDSE evidence',
        'kerberos_info': 'Kerberos realm/service evidence',
        'tls_cipher_validation': 'TLS cipher/protocol evidence',
        'rdp_negotiation': 'RDP/NLA negotiation evidence',
        'nuclei_safe': 'safe nuclei template evidence',
        'telnet_readiness': 'Telnet exposure evidence',
        'snmp_readiness': 'SNMP service evidence',
        'mssql_info': 'MSSQL information evidence',
        'vnc_info': 'VNC protocol evidence',
        'tomcat_ajp_readiness': 'Tomcat/AJP readiness evidence',
        'redis_info': 'Redis exposure evidence',
        'elasticsearch_info': 'Elasticsearch metadata evidence',
        'federation_detection': 'federation/authentication metadata evidence',
        'tls_intelligence': 'TLS handshake/certificate intelligence',
    }
    summary = []
    for key, label in labels.items():
        count = len(data.get(key) or [])
        if count:
            summary.append(f'{label}: {count} evidence item(s) retained.')
    if data.get('budget'):
        summary.append('Detection-budget governance was applied to modern active validation collectors.')
    return summary


def _extract_key_values(text: str, keys: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        for key in keys:
            if line.lower().startswith(key.lower() + ':') or line.lower().startswith(key.lower() + '='):
                values[key] = line.split(':', 1)[-1].split('=', 1)[-1].strip()
    return values


def parse_external_validation(tool_id: str, output: str) -> dict[str, Any]:
    """Extract safe, review-friendly facts from external recon tool output.

    This parser intentionally records information-gathering evidence only. It does
    not infer severity, priority, exploitability, or risk scores.
    """
    text = output or ''
    low = text.lower()
    parsed: dict[str, Any] = {'tool': tool_id, 'evidence_state': 'observed'}

    if tool_id == 'snmp_targeted_oids':
        parsed['fields'] = {}
        for label in ['sysDescr', 'sysName', 'sysLocation', 'sysContact']:
            match = re.search(label + r'(?:\.0)?\s*=\s*(?:STRING:\s*)?"?([^"\n]+)', text, re.I)
            if match:
                parsed['fields'][label] = match.group(1).strip()
        parsed['information_gained'] = 'SNMP system identity metadata from targeted low-volume OID queries.'
    elif tool_id == 'dns_context':
        parsed['fields'] = {
            'version_bind_disclosed': 'version.bind' in low and bool(re.search(r'"[^"]+"', text)),
            'has_soa_answer': '\tSOA\t' in text or ' soa ' in low,
            'has_ns_answer': '\tNS\t' in text or ' ns ' in low,
        }
        parsed['information_gained'] = 'DNS context evidence: authority hints, SOA/NS records, and optional version.bind disclosure.'
    elif tool_id == 'ldapsearch_rootdse':
        fields = {}
        for key in ['defaultNamingContext','rootDomainNamingContext','configurationNamingContext','schemaNamingContext','namingContexts','dnsHostName','forestFunctionality','domainFunctionality','supportedLDAPVersion','supportedCapabilities','supportedSASLMechanisms']:
            vals = re.findall(r'^' + re.escape(key) + r':\s*(.+)$', text, re.M)
            if vals:
                fields[key] = vals if len(vals) > 1 else vals[0]
        parsed['fields'] = fields
        parsed['information_gained'] = 'LDAP RootDSE directory naming context and capability evidence without authentication.'
    elif tool_id == 'rpcinfo_native':
        programs = []
        for line in text.splitlines():
            if re.match(r'\s*\d+\s+\d+\s+(tcp|udp)\s+\d+', line):
                programs.append(' '.join(line.split()))
        parsed['fields'] = {'program_count': len(programs), 'programs': programs[:40]}
        parsed['information_gained'] = 'RPC program mapping evidence for service relationship analysis.'
    elif tool_id == 'showmount_native':
        exports = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('/'):
                exports.append(line)
        parsed['fields'] = {'exports': exports}
        parsed['information_gained'] = 'NFS export path evidence without mounting or file access.'
    elif tool_id == 'ssh_audit_native':
        banner = re.search(r'banner:\s*([^\n\r]+)', text, re.I)
        software = re.search(r'software:\s*([^\n\r]+)', text, re.I)
        sections = {
            'kex': re.findall(r'\(kex\)\s+([^\s]+)', text),
            'key': re.findall(r'\(key\)\s+([^\s]+)', text),
            'enc': re.findall(r'\(enc\)\s+([^\s]+)', text),
            'mac': re.findall(r'\(mac\)\s+([^\s]+)', text),
        }
        parsed['fields'] = {
            'banner': banner.group(1).strip() if banner else '',
            'software': software.group(1).strip() if software else '',
            'weak_terms_observed': [term for term in ['cbc', 'sha1', 'diffie-hellman-group1', 'arcfour'] if term in low],
            'algorithm_families': {k: sorted(set(v))[:30] for k,v in sections.items() if v},
            'has_algorithm_output': any(x in low for x in ['key exchange algorithms', 'encryption algorithms', 'mac algorithms'])
        }
        parsed['information_gained'] = 'SSH banner, software and cryptographic algorithm posture evidence without login attempts.'
    elif tool_id == 'postgres_readiness_native':
        parsed['fields'] = {'readiness': text.strip()[:300], 'accepting_connections': 'accepting connections' in low, 'rejecting_connections': 'rejecting connections' in low}
        parsed['information_gained'] = 'PostgreSQL readiness evidence without authentication.'
    elif tool_id == 'http_security_context':
        headers = {}
        for raw in text.splitlines():
            if ':' in raw:
                k, v = raw.split(':', 1)
                if k.lower() in {'server','x-powered-by','location','set-cookie','www-authenticate','strict-transport-security','content-security-policy','x-frame-options','x-content-type-options'}:
                    headers[k.strip()] = v.strip()
        caps = []
        server = headers.get('Server') or headers.get('server') or ''
        x_powered = headers.get('X-Powered-By') or headers.get('x-powered-by') or ''
        if 'DAV' in server: caps.append('WebDAV/DAV header observed')
        if x_powered: caps.append('Application runtime header observed: ' + x_powered)
        parsed['fields'] = {'headers': headers, 'capabilities': caps}
        parsed['information_gained'] = 'HTTP header, runtime, authentication challenge, cookie, redirect, WebDAV and security-header evidence.'
    else:
        parsed['information_gained'] = 'External information-gathering evidence retained.'
    return parsed


def build_information_gathering_summary(data: dict[str, Any]) -> list[str]:
    """Create concise information-gathering summary lines for reports and handoff."""
    summary: list[str] = []
    for key in ['ldapsearch_rootdse','snmp_targeted_oids','dns_context','http_security_context','rpcinfo_native','showmount_native','ssh_audit_native','postgres_readiness_native','native_protocol_enrichment','federation_detection','tls_intelligence']:
        rows = data.get(key) or []
        if rows:
            summary.append(f'{key.replace("_", " ")}: {len(rows)} targeted information-gathering item(s) retained.')
    return summary


def collect_federation_detection(web_services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Collect low-volume federation/authentication metadata indicators from known paths and headers."""
    policy = policy or load_active_policy()
    timeout = float(policy.get('timeouts', {}).get('http_seconds', 4))
    paths = policy.get('federation_paths') or ['/.well-known/openid-configuration','/adfs/.well-known/openid-configuration','/saml/metadata']
    markers = ['openid-configuration','issuer','authorization_endpoint','token_endpoint','saml','adfs','oauth2','okta','pingfederate','keycloak']
    rows: list[dict[str, Any]] = []
    for svc in web_services:
        base = service_url(svc).rstrip('/')
        # Header-only root check first for WWW-Authenticate / redirects.
        root = _fetch(base + '/', method='HEAD', timeout=timeout)
        auth_blob = '\n'.join([str(root.get('headers') or {}), str(root.get('status') or '')]).lower()
        if any(marker in auth_blob for marker in ['www-authenticate','negotiate','saml','oauth','oidc','bearer']):
            root.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'federation_detection', 'collection_method': 'header_only_auth_surface_probe', 'recon_boundary': 'Authentication surface metadata only; no credentials or session establishment.'})
            rows.append(root)
        for path in paths:
            row = _fetch(base + str(path), timeout=timeout, max_bytes=16384)
            if _interesting_response(row, markers):
                row.update({'host': svc.get('host'), 'port': svc.get('port'), 'category': 'federation_detection', 'collection_method': 'well_known_federation_metadata_probe', 'recon_boundary': 'Federation metadata discovery only; no login attempts.'})
                rows.append(row)
    return rows


def collect_tls_intelligence(services: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Collect TLS handshake intelligence from observed TLS-like services with one connection per endpoint."""
    policy = policy or load_active_policy()
    timeout = float(policy.get('timeouts', {}).get('http_seconds', 4))
    alpn = ((policy.get('tls_intelligence') or {}).get('alpn_protocols') or ['h2','http/1.1'])
    candidates = [s for s in services if int(s.get('port') or 0) in {443,636,8443,9443,5986,2376,6443,993,995,465,853} or any(x in str(s.get('service') or '').lower() for x in ['https','ssl','tls','ldaps'])]
    rows: list[dict[str, Any]] = []
    for svc in candidates:
        host = str(svc.get('host') or '')
        port = int(svc.get('port') or 0)
        if not host or not port:
            continue
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols([str(x) for x in alpn])
        except Exception:
            pass
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    row = {
                        'host': host,
                        'port': port,
                        'category': 'tls_intelligence',
                        'tls_version': ssock.version() or '',
                        'cipher': (ssock.cipher() or ('',))[0],
                        'alpn': ssock.selected_alpn_protocol() or '',
                        'certificate_subject': str(cert.get('subject') or ''),
                        'certificate_issuer': str(cert.get('issuer') or ''),
                        'not_before': cert.get('notBefore',''),
                        'not_after': cert.get('notAfter',''),
                        'collection_method': 'single_tls_handshake',
                        'recon_boundary': 'TLS handshake metadata only; no authentication or application actions.'
                    }
                    rows.append(row)
        except Exception as exc:
            rows.append({'host': host, 'port': port, 'category': 'tls_intelligence', 'error': str(exc)[:180], 'collection_method': 'single_tls_handshake'})
    return rows


def build_noise_evaluation(modern_active: dict[str, Any]) -> dict[str, Any]:
    categories = {
        'passive': {'passive_local_inventory'},
        'low': {'api_discovery','targeted_web_discovery','kubernetes_exposure','container_exposure','vpn_validation','federation_detection','tls_intelligence','ldapsearch_rootdse','snmp_targeted_oids','dns_context','http_security_context','rpcinfo_native','showmount_native','ssh_audit_native','postgres_readiness_native','native_protocol_enrichment','ldap_rootdse','kerberos_info','rdp_negotiation','mssql_info','redis_info','elasticsearch_info'},
        'medium': {'tls_cipher_validation','telnet_readiness','snmp_readiness','vnc_info','tomcat_ajp_readiness','nuclei_safe'},
        'high': {'large_content_discovery'},
        'very_high': {'credential_attack_tools','intrusive_vulnerability_scanners','broad_content_discovery'}
    }
    information_value = {
        'ldapsearch_rootdse': 'very_high', 'ldap_rootdse': 'very_high', 'tls_intelligence': 'very_high',
        'dns_context': 'high', 'snmp_targeted_oids': 'high', 'http_security_context': 'high',
        'ssh_audit_native': 'high', 'postgres_readiness_native': 'medium', 'native_protocol_enrichment': 'high', 'smb_protocol_security': 'high',
        'api_discovery': 'high', 'federation_detection': 'high', 'targeted_web_discovery': 'medium',
        'nuclei_safe': 'medium', 'rpcinfo_native': 'medium', 'showmount_native': 'medium',
        'kubernetes_exposure': 'medium', 'container_exposure': 'medium', 'vpn_validation': 'medium',
    }
    counts = {k: 0 for k in categories}
    highest = []
    high_yield = []
    lower_yield = []
    for key, value in (modern_active or {}).items():
        if not isinstance(value, list) or not value:
            continue
        level = 'low'
        for cat, names in categories.items():
            if key in names:
                level = cat
                break
        counts[level] = counts.get(level, 0) + len(value)
        if level in {'medium','high','very_high'}:
            highest.append(key)
        value_label = information_value.get(key, 'medium')
        row = {'check': key, 'noise': level, 'information_value': value_label, 'items': len(value)}
        if level in {'passive','low'} and value_label in {'high','very_high'}:
            high_yield.append(row)
        elif level in {'medium','high','very_high'} and value_label in {'low','medium'}:
            lower_yield.append(row)
    overall = 'passive'
    for level in ['very_high','high','medium','low','passive']:
        if counts.get(level):
            overall = level
            break
    excluded = ['credential_attack_tools','intrusive_vulnerability_scanners','broad_content_discovery','broad_udp_discovery','broad_template_sweeps','unauthenticated_share_user_enumeration']
    summary = f'Overall validation noise level: {overall}. High-noise tooling is excluded; low-noise/high-yield metadata, TLS, DNS, identity and targeted protocol checks are preferred.'
    recommendations = []
    if counts.get('high') or counts.get('very_high'):
        recommendations.append('Review high-noise checks before repeating this scan.')
    if counts.get('medium', 0) > counts.get('low', 0) + counts.get('passive', 0):
        recommendations.append('Increase passive/cache reuse or reduce medium-noise validators on repeated scans.')
    if not recommendations:
        recommendations.append('Current execution favours low-noise/high-yield enumeration; repeat scans should reuse cached evidence where possible.')
    return {'overall': overall, 'counts': counts, 'highest_noise_checks': sorted(set(highest)), 'excluded_checks': excluded, 'high_yield_checks': high_yield[:10], 'lower_yield_checks': lower_yield[:10], 'recommendations': recommendations, 'summary': summary}
