from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from storage import scan_store


class PassiveIntelError(RuntimeError):
    pass


def _read_json_candidates(paths: list[Path], default: dict[str, Any] | None = None) -> dict[str, Any]:
    for path in paths:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
                if isinstance(data, dict):
                    return data
            except Exception as exc:
                raise PassiveIntelError(f'Passive intelligence policy could not be loaded from {path}: {exc}') from exc
    return default or {}


def load_passive_policy() -> dict[str, Any]:
    policy = _read_json_candidates([
        Path('project/policies/passive_recon_policy.json'),
        Path('policies/passive_recon_policy.json'),
    ])
    required = ['dns_record_types', 'srv_prefixes', 'tls_ports', 'ct_lookup', 'max_dns_answers', 'timeout_seconds']
    missing = [k for k in required if k not in policy]
    if missing:
        raise PassiveIntelError(f'Passive intelligence policy missing keys: {missing}')
    return policy


def load_fingerprints() -> dict[str, Any]:
    return _read_json_candidates([
        Path('project/policies/passive_fingerprints.json'),
        Path('policies/passive_fingerprints.json'),
    ], default={})


def is_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False


def normalise_domain(value: str) -> str:
    value = (value or '').strip()
    if not value:
        return ''
    if '://' in value:
        value = urllib.parse.urlparse(value).hostname or value
    value = value.split('/')[0].split(':')[0].strip().strip('.')
    if not value or is_ip(value):
        return ''
    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9*_.-]+', value):
        return ''
    return value.lower()


def base_domain(domain: str) -> str:
    parts = [p for p in normalise_domain(domain).split('.') if p]
    if len(parts) <= 2:
        return '.'.join(parts)
    # Conservative default without public-suffix dependency; evidence retains the original domain too.
    return '.'.join(parts[-2:])


def candidate_domains(target_input: str, services: list[dict[str, Any]] | None = None, web_items: list[dict[str, Any]] | None = None, tls_items: list[dict[str, Any]] | None = None) -> list[str]:
    domains: list[str] = []
    def add(value: str) -> None:
        d = normalise_domain(value)
        if d and d not in domains:
            domains.append(d)
    for token in re.split(r'[\s,]+', target_input or ''):
        add(token)
    for item in services or []:
        for key in ('hostname', 'host'):
            add(str(item.get(key) or ''))
    for item in web_items or []:
        url = str(item.get('url') or '')
        if url:
            add(urllib.parse.urlparse(url).hostname or '')
        for key in ('host', 'title'):
            add(str(item.get(key) or ''))
    for item in tls_items or []:
        add(str(item.get('subject_common_name') or ''))
        for san in item.get('subject_alt_names') or []:
            add(str(san))
    # Add base domains after exact names to support MX/TXT/CT lookups while preserving evidence.
    for d in list(domains):
        b = base_domain(d)
        if b and b not in domains:
            domains.append(b)
    return domains


def _dns_query_dnspython(name: str, record_type: str, timeout: float) -> list[str]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except Exception:
        return []
    rows: list[str] = []
    for answer in answers:
        text = answer.to_text().strip().strip('"')
        if text:
            rows.append(text)
    return rows


def _dns_query_socket(name: str, record_type: str, timeout: float) -> list[str]:
    if record_type not in {'A', 'AAAA'}:
        return []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        family = socket.AF_INET6 if record_type == 'AAAA' else socket.AF_INET
        return sorted({x[4][0] for x in socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)})
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)


def collect_dns(domains: list[str], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_passive_policy()
    record_types = [str(x).upper() for x in policy.get('dns_record_types') or []]
    srv_prefixes = [str(x).strip() for x in policy.get('srv_prefixes') or []]
    timeout = float(policy.get('timeout_seconds') or 3)
    limit = int(policy.get('max_dns_answers') or 25)
    rows: list[dict[str, Any]] = []
    for domain in domains:
        d = normalise_domain(domain)
        if not d:
            continue
        for rtype in record_types:
            names = [d]
            if rtype == 'SRV':
                names = [f'{prefix}.{d}'.strip('.') for prefix in srv_prefixes]
            for name in names:
                answers = _dns_query_dnspython(name, rtype, timeout) or _dns_query_socket(name, rtype, timeout)
                if answers:
                    rows.append({'domain': d, 'query': name, 'record_type': rtype, 'answers': sorted(set(answers))[:limit], 'collection_method': 'resolver_lookup'})
    return rows


def collect_reverse_dns(hosts: list[str], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_passive_policy()
    timeout = float(policy.get('timeout_seconds') or 3)
    rows: list[dict[str, Any]] = []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for host in hosts:
            if not is_ip(str(host)):
                continue
            try:
                name, aliases, _ = socket.gethostbyaddr(str(host))
                rows.append({'host': str(host), 'ptr': name, 'aliases': aliases, 'collection_method': 'reverse_dns'})
            except Exception:
                continue
    finally:
        socket.setdefaulttimeout(old_timeout)
    return rows


def _parse_cert_names(cert: dict[str, Any]) -> tuple[str, list[str], str]:
    subject_cn = ''
    issuer_cn = ''
    for item in cert.get('subject') or []:
        for key, value in item:
            if key == 'commonName':
                subject_cn = value
    for item in cert.get('issuer') or []:
        for key, value in item:
            if key == 'commonName':
                issuer_cn = value
    sans = []
    for key, value in cert.get('subjectAltName') or []:
        if key.lower() == 'dns':
            sans.append(value)
    return subject_cn, sorted(set(sans)), issuer_cn


def collect_tls(hosts: list[str], services: list[dict[str, Any]] | None = None, policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_passive_policy()
    tls_ports = {int(x) for x in policy.get('tls_ports') or []}
    timeout = float(policy.get('timeout_seconds') or 3)
    targets: list[tuple[str, int, str]] = []
    for service in services or []:
        port = int(service.get('port') or 0)
        svc = str(service.get('service') or '').lower()
        product = str(service.get('product') or '').lower()
        if port in tls_ports or 'ssl' in svc or 'https' in svc or 'tls' in product:
            host = str(service.get('host') or '')
            server_name = normalise_domain(host) or None
            if host:
                targets.append((host, port, server_name or host))
    if not targets:
        for host in hosts:
            if normalise_domain(str(host)):
                targets.append((str(host), 443, normalise_domain(str(host))))
    rows: list[dict[str, Any]] = []
    seen = set()
    for host, port, server_name in targets:
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name if normalise_domain(server_name) else None) as ssock:
                    cert = ssock.getpeercert() or {}
                    subject_cn, sans, issuer_cn = _parse_cert_names(cert)
                    cipher = ssock.cipher() or ()
                    rows.append({
                        'host': host,
                        'port': port,
                        'protocol': 'tcp',
                        'tls_version': ssock.version() or '',
                        'cipher': cipher[0] if cipher else '',
                        'cipher_protocol': cipher[1] if len(cipher) > 1 else '',
                        'cipher_bits': cipher[2] if len(cipher) > 2 else '',
                        'subject_common_name': subject_cn,
                        'subject_alt_names': sans,
                        'issuer_common_name': issuer_cn,
                        'not_before': cert.get('notBefore', ''),
                        'not_after': cert.get('notAfter', ''),
                        'wildcard_certificate': any(str(x).startswith('*.') for x in ([subject_cn] + sans)),
                        'internal_ca_indicator': bool(issuer_cn and not re.search(r'(DigiCert|Let\'?s Encrypt|GlobalSign|Sectigo|Entrust|Go Daddy|Google Trust|Amazon|Microsoft|Cloudflare)', issuer_cn, re.I)),
                        'collection_method': 'tls_handshake_certificate_only',
                    })
        except Exception as exc:
            rows.append({'host': host, 'port': port, 'protocol': 'tcp', 'error': str(exc)[:160], 'collection_method': 'tls_handshake_certificate_only'})
    return rows


def _match_rules(text_values: list[str], rules: dict[str, Any]) -> list[dict[str, Any]]:
    blob = '\n'.join(str(x) for x in text_values if x).lower()
    matches: list[dict[str, Any]] = []
    for category, providers in (rules or {}).items():
        if not isinstance(providers, dict):
            continue
        for name, spec in providers.items():
            indicators = [str(x).lower() for x in (spec.get('indicators') or [])]
            evidence = sorted({ind for ind in indicators if ind and ind in blob})
            if evidence:
                matches.append({'category': category, 'name': name, 'evidence': evidence, 'collection_method': 'passive_fingerprint_rule'})
    return matches


def infer_passive_findings(dns_rows: list[dict[str, Any]], tls_rows: list[dict[str, Any]], web_items: list[dict[str, Any]] | None = None, fingerprints: dict[str, Any] | None = None) -> dict[str, Any]:
    fingerprints = fingerprints or load_fingerprints()
    text_values: list[str] = []
    for row in dns_rows or []:
        text_values.extend([row.get('domain',''), row.get('query',''), row.get('record_type','')])
        text_values.extend(row.get('answers') or [])
    for row in tls_rows or []:
        text_values.extend([row.get('subject_common_name',''), row.get('issuer_common_name',''), row.get('tls_version',''), row.get('cipher','')])
        text_values.extend(row.get('subject_alt_names') or [])
    for item in web_items or []:
        text_values.extend([item.get('url',''), item.get('title',''), item.get('server',''), item.get('tech','') if isinstance(item.get('tech'), str) else ' '.join(item.get('tech') or [])])
        for key in ('headers', 'response_headers'):
            if isinstance(item.get(key), dict):
                text_values.extend([f'{k}: {v}' for k, v in item.get(key).items()])
        text_values.extend([str(item.get('path') or ''), str(item.get('http_enum') or '')])
    rule_matches = _match_rules(text_values, fingerprints.get('rules') or {})
    grouped: dict[str, list[dict[str, Any]]] = {}
    for match in rule_matches:
        grouped.setdefault(match['category'], []).append(match)

    ad_records = []
    for row in dns_rows or []:
        q = str(row.get('query') or '').lower()
        if any(prefix in q for prefix in ('_ldap._tcp', '_kerberos._tcp', '_gc._tcp', '_kpasswd._tcp')):
            ad_records.append(row)

    auth_surfaces = grouped.get('authentication', [])
    return {
        'email_security': grouped.get('email_security', []),
        'authentication': auth_surfaces,
        'vpn': grouped.get('vpn', []),
        'reverse_proxy': grouped.get('reverse_proxy', []),
        'cdn': grouped.get('cdn', []),
        'cloud': grouped.get('cloud', []),
        'technologies': grouped.get('technology', []),
        'network_device': grouped.get('network_device', []),
        'virtualisation': grouped.get('virtualisation', []),
        'message_broker': grouped.get('message_broker', []),
        'active_directory': {
            'detected': bool(ad_records),
            'evidence': ad_records,
            'collection_method': 'dns_srv_records_only',
        },
    }


def collect_certificate_transparency(domains: list[str], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or load_passive_policy()
    ct_cfg = policy.get('ct_lookup') or {}
    if not bool(ct_cfg.get('enabled', False)):
        return []
    timeout = float(policy.get('timeout_seconds') or 3)
    limit = int(ct_cfg.get('max_results') or 50)
    rows: list[dict[str, Any]] = []
    for domain in domains:
        d = base_domain(domain)
        if not d:
            continue
        url = f'https://crt.sh/?q=%25.{urllib.parse.quote(d)}&output=json'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': str(ct_cfg.get('user_agent') or 'AutoPenTest Passive Recon')})
            with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec - policy-controlled public CT lookup
                data = json.loads(response.read().decode('utf-8', errors='ignore'))
            names = []
            for item in data if isinstance(data, list) else []:
                for name in str(item.get('name_value') or '').split('\n'):
                    n = normalise_domain(name.replace('*.', ''))
                    if n and n not in names:
                        names.append(n)
            rows.append({'domain': d, 'source': 'crt.sh', 'discovered_names': names[:limit], 'collection_method': 'certificate_transparency_public_lookup'})
        except Exception as exc:
            rows.append({'domain': d, 'source': 'crt.sh', 'error': str(exc)[:160], 'collection_method': 'certificate_transparency_public_lookup'})
    # de-duplicate per base domain
    seen = set(); deduped=[]
    for row in rows:
        key = row.get('domain')
        if key in seen:
            continue
        seen.add(key); deduped.append(row)
    return deduped


def build_relationship_graph(domains: list[str], dns_rows: list[dict[str, Any]], tls_rows: list[dict[str, Any]], findings: dict[str, Any], ct_rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    def add(source: str, relation: str, target: str, evidence: str) -> None:
        if source and target:
            row = {'source': source, 'relation': relation, 'target': target, 'evidence': evidence}
            if row not in relationships:
                relationships.append(row)
    for row in dns_rows or []:
        domain = row.get('domain') or row.get('query') or ''
        rtype = row.get('record_type') or 'DNS'
        for answer in row.get('answers') or []:
            add(domain, f'DNS {rtype}', str(answer), row.get('query') or domain)
    for row in tls_rows or []:
        host = row.get('host') or ''
        if row.get('issuer_common_name'):
            add(host, 'TLS issuer', row.get('issuer_common_name'), f'{host}:{row.get("port")}')
        for san in row.get('subject_alt_names') or []:
            add(host, 'TLS SAN', san, f'{host}:{row.get("port")}')
    for category in ('email_security', 'authentication', 'vpn', 'reverse_proxy', 'cdn', 'cloud', 'technologies', 'network_device', 'virtualisation', 'message_broker'):
        for item in findings.get(category) or []:
            add(category, 'passive fingerprint', item.get('name'), ', '.join(item.get('evidence') or []))
    if findings.get('active_directory', {}).get('detected'):
        for row in findings.get('active_directory', {}).get('evidence') or []:
            for answer in row.get('answers') or []:
                add(row.get('domain'), 'AD SRV', str(answer), row.get('query'))
    for row in ct_rows or []:
        for name in row.get('discovered_names') or []:
            add(row.get('domain'), 'Certificate Transparency name', name, row.get('source', 'ct'))
    return relationships


def build_passive_summary(passive: dict[str, Any]) -> list[str]:
    points: list[str] = []
    dns_count = sum(len(x.get('answers') or []) for x in passive.get('dns', []))
    if dns_count:
        points.append(f'Passive DNS evidence retained {dns_count} DNS answer(s) across approved record types.')
    tls_good = [x for x in passive.get('tls', []) if x.get('subject_common_name') or x.get('subject_alt_names')]
    if tls_good:
        points.append(f'TLS certificate intelligence retained {len(tls_good)} certificate-backed endpoint record(s).')
    findings = passive.get('findings') or {}
    named_categories = []
    for key, label in [('active_directory','Active Directory SRV'),('email_security','email security'),('authentication','authentication/federation'),('vpn','VPN'),('reverse_proxy','reverse proxy/WAF context'),('cdn','CDN'),('cloud','cloud'),('technologies','technology'),('network_device','network device'),('virtualisation','virtualisation'),('message_broker','message broker')]:
        val = findings.get(key)
        if isinstance(val, dict) and val.get('detected'):
            named_categories.append(label)
        elif isinstance(val, list) and val:
            named_categories.append(label)
    if named_categories:
        points.append('Passive fingerprinting identified: ' + ', '.join(named_categories) + '.')
    rel_count = len(passive.get('relationships') or [])
    if rel_count:
        points.append(f'Asset relationship graph retained {rel_count} evidence relationship(s).')
    dns_rel_count = len(passive.get('dns_relationships') or [])
    if dns_rel_count:
        points.append(f'DNS relationship engine retained {dns_rel_count} forward/reverse/authority relationship(s).')
    cert_corr_count = len(passive.get('certificate_correlation') or [])
    if cert_corr_count:
        points.append(f'Certificate correlation retained {cert_corr_count} certificate identity relationship(s).')
    ct = passive.get('certificate_transparency') or []
    ct_names = sum(len(x.get('discovered_names') or []) for x in ct)
    if ct_names:
        points.append(f'Certificate Transparency lookup retained {ct_names} public certificate name(s) under the engagement policy.')
    return points


def write_passive_package(scan_id: str, passive: dict[str, Any]) -> str:
    path = scan_store.scan_path(f'passive_intelligence_{scan_id}.json')
    path.write_text(json.dumps(passive, indent=2, default=str), encoding='utf-8')
    return str(path)


def build_dns_relationships(dns_rows: list[dict[str, Any]], reverse_rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Build low-noise DNS relationship evidence from already collected records."""
    relationships: list[dict[str, Any]] = []
    def add(source: str, relation: str, target: str, evidence: str) -> None:
        source = str(source or '').strip()
        target = str(target or '').strip()
        if not source or not target:
            return
        row = {'source': source, 'relation': relation, 'target': target, 'evidence': evidence}
        if row not in relationships:
            relationships.append(row)
    for row in dns_rows or []:
        rtype = str(row.get('record_type') or '').upper()
        q = str(row.get('query') or row.get('domain') or '')
        d = str(row.get('domain') or q)
        for answer in row.get('answers') or []:
            ans = str(answer)
            if rtype in {'A','AAAA'}:
                add(d, 'resolves_to', ans, q)
            elif rtype == 'PTR':
                add(d, 'ptr_name', ans, q)
            elif rtype == 'MX':
                add(d, 'mail_exchanger', ans, q)
            elif rtype == 'NS':
                add(d, 'name_server', ans, q)
            elif rtype == 'SOA':
                add(d, 'soa_record', ans, q)
            elif rtype == 'CNAME':
                add(d, 'canonical_name', ans, q)
            elif rtype == 'SRV':
                add(d, 'service_record', ans, q)
            else:
                add(d, f'dns_{rtype.lower()}', ans, q)
    for row in reverse_rows or []:
        add(str(row.get('host') or ''), 'reverse_dns_ptr', str(row.get('ptr') or ''), 'reverse_dns')
    return relationships


def build_certificate_correlation(tls_rows: list[dict[str, Any]], services: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Correlate certificate identities to observed hosts/services without extra probing."""
    correlations: list[dict[str, Any]] = []
    service_by_host: dict[str, list[str]] = {}
    for svc in services or []:
        host = str(svc.get('host') or '')
        if not host:
            continue
        label = f"{svc.get('service') or 'service'}:{svc.get('port') or ''}/{svc.get('protocol') or 'tcp'}"
        service_by_host.setdefault(host, []).append(label)
    for row in tls_rows or []:
        host = str(row.get('host') or '')
        identities = [str(row.get('subject_common_name') or '')] + [str(x) for x in row.get('subject_alt_names') or []]
        identities = sorted({x for x in identities if x})
        if not host or not identities:
            continue
        correlations.append({
            'host': host,
            'port': row.get('port'),
            'certificate_identities': identities,
            'issuer': row.get('issuer_common_name') or '',
            'related_observed_services': sorted(set(service_by_host.get(host, []))),
            'collection_method': 'certificate_identity_correlation_no_extra_probe',
        })
    return correlations
