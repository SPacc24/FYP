from __future__ import annotations

from collections import defaultdict
from typing import Any


def _norm(value: Any) -> str:
    return str(value or '').strip()


def _lower(value: Any) -> str:
    return _norm(value).lower()


def _port(service: dict[str, Any]) -> int | None:
    try:
        return int(service.get('port'))
    except Exception:
        return None


def _svc_key(service: dict[str, Any]) -> tuple[str, str]:
    return (_norm(service.get('host')), _norm(service.get('port')))


def _service_text(service: dict[str, Any]) -> str:
    parts = [service.get('service'), service.get('product'), service.get('version'), service.get('extrainfo')]
    cpe = service.get('cpe') or []
    if isinstance(cpe, list):
        parts.extend(cpe)
    return ' '.join(_norm(x) for x in parts).lower()


def _host_services(services: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for svc in services or []:
        grouped[_norm(svc.get('host'))].append(svc)
    return dict(grouped)


def _has_port(rows: list[dict[str, Any]], ports: set[int]) -> bool:
    return any((_port(row) in ports) for row in rows or [])


def _has_text(rows: list[dict[str, Any]], *needles: str) -> bool:
    text = ' '.join(_service_text(row) for row in rows or [])
    return any(n.lower() in text for n in needles)


def _functional_group(service: dict[str, Any]) -> str:
    port = _port(service)
    text = _service_text(service)
    name = _lower(service.get('service'))
    if port in {88, 389, 636, 3268, 3269} or any(x in text for x in ['ldap', 'kerberos', 'active directory']):
        return 'Likely Identity Infrastructure'
    if port in {21, 22, 23, 3389, 5985, 5986, 5900} or any(x in text for x in ['openssh', 'telnet', 'rdp', 'winrm', 'vnc']):
        return 'Remote Administration'
    if port in {80, 443, 8009, 8080, 8180, 8443, 9443} or any(x in text for x in ['http', 'apache', 'nginx', 'tomcat', 'ajp']):
        return 'Web and Applications'
    if port in {3306, 5432, 1433, 1521, 6379, 9200, 9300} or any(x in text for x in ['mysql', 'postgres', 'mssql', 'redis', 'elasticsearch', 'oracle']):
        return 'Data Services'
    if port in {53, 111, 135, 139, 445, 161, 162, 2049} or any(x in text for x in ['dns', 'bind', 'rpc', 'nfs', 'samba', 'snmp', 'netbios']):
        return 'Infrastructure Services'
    if port in {2375, 2376, 5000, 6443, 10250, 10255} or any(x in text for x in ['docker', 'kubernetes', 'registry']):
        return 'Container and Orchestration'
    return 'Other Observed Services'


def build_functional_service_groups(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for svc in services or []:
        groups[_functional_group(svc)].append({
            'host': svc.get('host'),
            'port': svc.get('port'),
            'protocol': svc.get('protocol', 'tcp'),
            'service': svc.get('service'),
            'product': svc.get('product'),
            'version': svc.get('version'),
            'state': svc.get('state', 'open'),
        })
    order = ['Likely Identity Infrastructure', 'Remote Administration', 'Web and Applications', 'Data Services', 'Infrastructure Services', 'Container and Orchestration', 'Other Observed Services']
    return [{'group': name, 'services': groups[name], 'service_count': len(groups[name])} for name in order if groups.get(name)]


def _active_rows(modern_active_validation: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in keys:
        value = (modern_active_validation or {}).get(key) or []
        if isinstance(value, list):
            for row in value:
                if isinstance(row, dict):
                    rows.append(row)
    return rows


def build_identity_correlation(services: list[dict[str, Any]], modern_active_validation: dict[str, Any], smb_summary: dict[str, Any]) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    by_host = _host_services(services)
    ldap_rows = _active_rows(modern_active_validation, 'ldapsearch_rootdse', 'ldap_rootdse')
    kerberos_rows = _active_rows(modern_active_validation, 'kerberos_info')
    for host, rows in by_host.items():
        has_ldap = _has_port(rows, {389, 636, 3268, 3269}) or _has_text(rows, 'ldap')
        has_kerberos = _has_port(rows, {88}) or _has_text(rows, 'kerberos')
        has_smb = _has_port(rows, {139, 445}) or _has_text(rows, 'samba', 'microsoft-ds', 'netbios')
        if not any([has_ldap, has_kerberos, has_smb]):
            continue
        fields: dict[str, Any] = {}
        evidence_sources: list[str] = []
        for row in ldap_rows:
            if _norm(row.get('host')) == host:
                parsed = row.get('parsed') or row.get('fields') or {}
                if isinstance(parsed, dict):
                    fields.update({k: v for k, v in parsed.items() if k in {'defaultNamingContext', 'rootDomainNamingContext', 'dnsHostName', 'supportedLDAPVersion', 'supportedCapabilities'}})
                evidence_sources.append('LDAP RootDSE')
        for row in kerberos_rows:
            if _norm(row.get('host')) == host:
                fields.setdefault('kerberos_observed', True)
                evidence_sources.append('Kerberos service information')
        if has_smb:
            evidence_sources.append('SMB protocol/service evidence')
            if isinstance(smb_summary, dict):
                workgroups = smb_summary.get('workgroups') or smb_summary.get('domains') or []
                if workgroups:
                    fields.setdefault('smb_domain_or_workgroup', workgroups[0] if isinstance(workgroups, list) else workgroups)
        role = 'Directory or identity-adjacent service'
        if has_ldap and has_kerberos and has_smb:
            role = 'Likely directory services node (supported, not confirmed)'
        elif has_ldap and has_kerberos:
            role = 'Likely identity infrastructure node (supported, not confirmed)'
        identities.append({
            'host': host,
            'role': role,
            'signals': {'ldap': has_ldap, 'kerberos': has_kerberos, 'smb': has_smb},
            'fields': fields,
            'evidence_sources': sorted(set(evidence_sources)),
            'what_it_means': 'Identity-related services were observed together. This helps define authentication and directory boundaries without performing credentialed enumeration.',
        })
    return identities


def build_service_relationships(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    for host, rows in _host_services(services).items():
        def add(name: str, source: str, target: str, meaning: str, evidence: list[str]):
            relationships.append({'host': host, 'relationship': name, 'source': source, 'target': target, 'what_it_means': meaning, 'evidence_sources': evidence})
        if _has_port(rows, {111, 135}) and _has_port(rows, {2049}):
            add('RPC to NFS relationship', 'RPC/Portmapper', 'NFS', 'RPC mapping and NFS exposure indicate Unix-style file service discovery surface.', ['RPC', 'NFS'])
        if _has_port(rows, {389, 636}) and _has_port(rows, {88}):
            add('LDAP to Kerberos relationship', 'LDAP', 'Kerberos', 'Directory and realm services were observed on the same host or service cluster.', ['LDAP', 'Kerberos'])
        if _has_port(rows, {139, 445}) and _has_port(rows, {88, 389, 636}):
            add('SMB to Identity relationship', 'SMB', 'Identity Services', 'File sharing or Windows networking appears adjacent to identity infrastructure.', ['SMB', 'LDAP/Kerberos'])
        if _has_port(rows, {8009}) and _has_port(rows, {8080, 8180, 8443, 80, 443}):
            add('AJP to Web application relationship', 'AJP', 'HTTP/Tomcat', 'AJP and web services suggest an application-server surface.', ['AJP', 'HTTP'])
        if _has_port(rows, {3389}) and _has_port(rows, {5985, 5986}):
            add('Windows management relationship', 'RDP', 'WinRM', 'Remote desktop and remote management services were observed together.', ['RDP', 'WinRM'])
        if _has_port(rows, {23}) and _has_port(rows, {161, 162}):
            add('Legacy network management relationship', 'Telnet', 'SNMP', 'Legacy administration protocols appear together.', ['Telnet', 'SNMP'])
        if _has_port(rows, {2375, 2376, 5000}) or _has_port(rows, {6443, 10250, 10255}):
            add('Container management relationship', 'Container API', 'Orchestration/Registry', 'Container or orchestration management surface was observed.', ['Docker/Kubernetes'])
    return relationships


def build_role_inferences(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roles: list[dict[str, Any]] = []
    for host, rows in _host_services(services).items():
        signals: list[str] = []
        role = None
        if _has_port(rows, {389, 636, 88}) and _has_port(rows, {139, 445}):
            role = 'Likely Identity Infrastructure'
            signals = ['LDAP/Kerberos', 'SMB']
        elif _has_port(rows, {80, 443, 8080, 8180, 8443, 8009}):
            role = 'Likely Web or Application Platform'
            signals = ['HTTP/HTTPS', 'Application ports']
        elif _has_port(rows, {3306, 5432, 1433, 6379, 9200}):
            role = 'Likely Data Service Host'
            signals = ['Database or data-store listener']
        elif _has_port(rows, {22, 3389, 5985, 5986, 5900, 23}):
            role = 'Likely Remote Administration Surface'
            signals = ['Remote administration listener']
        elif _has_port(rows, {53, 111, 161, 2049}):
            role = 'Likely Infrastructure Service Host'
            signals = ['DNS/RPC/SNMP/NFS']
        if role:
            roles.append({'host': host, 'role': role, 'signals': signals, 'basis': 'Role inferred from service combination only; no scoring or exploitation performed.'})
    return roles


def build_web_context(web_inventory: list[dict[str, Any]], modern_active_validation: dict[str, Any]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    security_rows = _active_rows(modern_active_validation, 'http_security_context')
    api_rows = _active_rows(modern_active_validation, 'api_discovery')
    targeted_rows = _active_rows(modern_active_validation, 'targeted_web_discovery')
    by_host: dict[tuple[str, str], dict[str, Any]] = {}
    for row in web_inventory or []:
        host = _norm(row.get('host') or row.get('input') or row.get('url'))
        port = _norm(row.get('port') or '')
        key = (host, port)
        by_host.setdefault(key, {'host': host, 'port': port, 'observed': [], 'learned': [], 'meaning': [], 'evidence_sources': []})
        if row.get('title'):
            by_host[key]['observed'].append('Page title observed: ' + _norm(row.get('title')))
        if row.get('server_header') or row.get('webserver'):
            by_host[key]['learned'].append('Server header: ' + _norm(row.get('server_header') or row.get('webserver')))
        if row.get('technologies') or row.get('tech'):
            by_host[key]['learned'].append('Technology hints retained as unverified unless independently supported.')
        by_host[key]['evidence_sources'].append('HTTP probe')
    for row in security_rows + api_rows + targeted_rows:
        host = _norm(row.get('host'))
        port = _norm(row.get('port'))
        key = (host, port)
        by_host.setdefault(key, {'host': host, 'port': port, 'observed': [], 'learned': [], 'meaning': [], 'evidence_sources': []})
        category = _norm(row.get('category') or row.get('tool') or 'web context')
        by_host[key]['observed'].append(category.replace('_', ' ').title() + ' evidence retained.')
        by_host[key]['evidence_sources'].append(category)
    for item in by_host.values():
        if item['learned'] or item['observed']:
            item['meaning'].append('Web context supports application surface understanding without sending attack payloads.')
            item['evidence_sources'] = sorted(set(item['evidence_sources']))
            contexts.append(item)
    return contexts


def build_network_device_context(services: list[dict[str, Any]], modern_active_validation: dict[str, Any]) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    snmp_rows = _active_rows(modern_active_validation, 'snmp_targeted_oids', 'snmp_readiness')
    snippets_by_host: dict[str, list[str]] = defaultdict(list)
    for row in snmp_rows:
        host = _norm(row.get('host'))
        parsed = row.get('parsed') or row.get('fields') or {}
        if isinstance(parsed, dict):
            fields = parsed.get('fields') if isinstance(parsed.get('fields'), dict) else parsed
            for value in fields.values():
                snippets_by_host[host].append(_norm(value))
    for host, rows in _host_services(services).items():
        text = ' '.join([_service_text(r) for r in rows] + snippets_by_host.get(host, [])).lower()
        device_type = None
        evidence: list[str] = []
        if 'cisco' in text or 'ios' in text:
            device_type = 'Likely Cisco infrastructure'
            evidence.append('Cisco/IOS indicator')
        elif 'palo alto' in text or 'pan-os' in text or 'globalprotect' in text:
            device_type = 'Likely Palo Alto network appliance'
            evidence.append('Palo Alto/PAN-OS indicator')
        elif 'fortinet' in text or 'fortigate' in text:
            device_type = 'Likely Fortinet network appliance'
            evidence.append('Fortinet indicator')
        elif _has_port(rows, {22, 23, 161}) and not _has_port(rows, {80, 443, 3306, 5432}):
            device_type = 'Possible network or management appliance'
            evidence.append('Management protocols without common application/database listeners')
        if device_type:
            contexts.append({'host': host, 'device_context': device_type, 'evidence_sources': evidence, 'what_it_means': 'Network device context is inferred only from existing banners/SNMP/headers; no additional probing is required.'})
    return contexts


def build_enumeration_confidence(services: list[dict[str, Any]], modern_active_validation: dict[str, Any], passive_intelligence: dict[str, Any]) -> list[dict[str, Any]]:
    active_by_host: dict[str, set[str]] = defaultdict(set)
    for key, value in (modern_active_validation or {}).items():
        if isinstance(value, list):
            for row in value:
                if isinstance(row, dict) and row.get('host'):
                    active_by_host[_norm(row.get('host'))].add(key)
    passive_hosts = set()
    if isinstance(passive_intelligence, dict):
        for row in passive_intelligence.get('findings') or []:
            if isinstance(row, dict) and row.get('host'):
                passive_hosts.add(_norm(row.get('host')))
    rows: list[dict[str, Any]] = []
    for host, svcs in _host_services(services).items():
        sources = {'Service banner'} if svcs else set()
        if active_by_host.get(host):
            sources.add('Validator')
        if host in passive_hosts:
            sources.add('Passive observation')
        service_names = ', '.join(sorted({_norm(s.get('service')) for s in svcs if s.get('service')}))
        state = 'Observed'
        if 'Validator' in sources and 'Service banner' in sources:
            state = 'Validated'
        elif 'Service banner' in sources:
            state = 'Observed'
        rows.append({'host': host, 'evidence_state': state, 'evidence_sources': sorted(sources), 'services': service_names, 'explanation': 'Confidence reflects evidence diversity, not risk or severity.'})
    return rows


def build_knowledge_graph(services: list[dict[str, Any]], relationships: list[dict[str, Any]], roles: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[tuple[str, str]] = set()

    def add_node(node_id: str, label: str, kind: str):
        key = (kind, node_id)
        if key not in seen_nodes:
            nodes.append({'id': node_id, 'label': label, 'type': kind})
            seen_nodes.add(key)

    for host, rows in _host_services(services).items():
        add_node(host, host, 'host')
        for svc in rows:
            sid = f"{host}:{svc.get('port')}/{svc.get('protocol', 'tcp')}"
            label = f"{svc.get('service') or 'service'}:{svc.get('port')}"
            add_node(sid, label, 'service')
            edges.append({'source': host, 'target': sid, 'relationship': 'exposes'})
    for role in roles:
        rid = 'role:' + _norm(role.get('role'))
        add_node(rid, _norm(role.get('role')), 'role')
        edges.append({'source': _norm(role.get('host')), 'target': rid, 'relationship': 'inferred_as'})
    for rel in relationships:
        source = f"{_norm(rel.get('host'))}:{_norm(rel.get('source'))}"
        target = f"{_norm(rel.get('host'))}:{_norm(rel.get('target'))}"
        add_node(source, _norm(rel.get('source')), 'relationship_source')
        add_node(target, _norm(rel.get('target')), 'relationship_target')
        edges.append({'source': source, 'target': target, 'relationship': _norm(rel.get('relationship'))})
    return {'nodes': nodes, 'edges': edges, 'summary': f'{len(nodes)} node(s) and {len(edges)} relationship edge(s) retained.'}


def build_detection_budget_summary(modern_active_validation: dict[str, Any]) -> dict[str, Any]:
    budget = (modern_active_validation or {}).get('budget') or {}
    return {
        'status': 'Governed' if budget else 'Not recorded',
        'authentication_attempts': 'None performed by recon module',
        'service_validation': 'Completed within configured recon boundary' if budget else 'Not recorded',
        'operator_checkpoints': 'Generated only when configured thresholds are exceeded',
        'details': budget,
    }


def build_executive_recon_summary(intelligence: dict[str, Any], services: list[dict[str, Any]]) -> list[dict[str, str]]:
    discovered = f"{len(_host_services(services))} host(s) with {len(services or [])} service record(s) were retained for recon analysis."
    validated = f"{len(intelligence.get('confidence') or [])} host-level evidence confidence row(s) generated from banners, validators, passive observations, or correlations."
    uncertain = 'Uncertainty is retained as Information Gaps, Negative Evidence, Unresolved Hypotheses, or MITRE Candidate References when supporting context is incomplete.'
    boundary = 'Open ports are treated as transport reachability evidence, not absolute proof of application permission, firewall policy, or exploitable exposure.'
    return [
        {'question': 'What was discovered?', 'answer': discovered},
        {'question': 'What was validated?', 'answer': validated},
        {'question': 'What remains uncertain?', 'answer': uncertain},
        {'question': 'What evidence boundary was applied?', 'answer': boundary},
        {'question': 'How was information gathered?', 'answer': 'Information gathering used passive, metadata, protocol capability, hypothesis tracking and targeted validation evidence. Per-command visibility modelling is intentionally excluded from the recon report.'},
    ]



def build_dns_naming_intelligence(passive_intelligence: dict[str, Any], services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract naming-pattern intelligence from existing DNS/PTR evidence.

    No network activity is performed here. This helps the recon output explain
    likely roles suggested by names such as dc01, vpn, fw, mail, sql, etc.
    """
    rows: list[dict[str, Any]] = []
    service_hosts = {_norm(s.get('host')) for s in services or [] if s.get('host')}
    ptr_rows = (passive_intelligence or {}).get('reverse_dns') or []
    dns_rows = (passive_intelligence or {}).get('dns') or []
    names_by_host: dict[str, set[str]] = defaultdict(set)
    for row in ptr_rows:
        host = _norm(row.get('host'))
        if host:
            if row.get('ptr'):
                names_by_host[host].add(_norm(row.get('ptr')))
            for alias in row.get('aliases') or []:
                names_by_host[host].add(_norm(alias))
    for row in dns_rows:
        for ans in row.get('answers') or []:
            ans_s = _norm(ans).strip('.')
            # Keep naming intelligence only; do not create new targets.
            for host in service_hosts:
                if host and host in ans_s:
                    names_by_host[host].add(_norm(row.get('query')))
    patterns = {
        'identity infrastructure naming': ['dc', 'ldap', 'kerb', 'adfs', 'domain'],
        'network/security appliance naming': ['fw', 'firewall', 'router', 'rtr', 'vpn', 'pan', 'palo', 'forti', 'asa'],
        'web/application naming': ['web', 'app', 'api', 'portal', 'www', 'tomcat'],
        'data service naming': ['db', 'sql', 'mysql', 'postgres', 'redis', 'elastic'],
        'mail/service edge naming': ['mail', 'smtp', 'mx', 'owa', 'exchange'],
    }
    for host, names in names_by_host.items():
        joined = ' '.join(sorted(names)).lower()
        matches = [label for label, terms in patterns.items() if any(term in joined for term in terms)]
        if matches:
            rows.append({
                'host': host,
                'observed_names': sorted(names),
                'naming_context': sorted(set(matches)),
                'what_it_means': 'Existing DNS/PTR names suggest service roles. This is a naming hint only and does not assert ownership or vulnerability.',
                'evidence_sources': ['reverse DNS', 'DNS records'],
            })
    return rows


def build_tls_trust_intelligence(modern_active_validation: dict[str, Any], passive_intelligence: dict[str, Any]) -> list[dict[str, Any]]:
    """Correlate TLS certificate reuse, issuers, subjects, ALPN and expiry metadata.

    This uses already-collected TLS evidence from active and passive collectors.
    """
    rows: list[dict[str, Any]] = []
    tls_rows: list[dict[str, Any]] = []
    tls_rows.extend((modern_active_validation or {}).get('tls_intelligence') or [])
    tls_rows.extend((passive_intelligence or {}).get('tls') or [])
    by_subject: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_issuer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in tls_rows:
        subject = _norm(row.get('certificate_subject') or row.get('subject') or row.get('subject_cn'))
        issuer = _norm(row.get('certificate_issuer') or row.get('issuer') or row.get('issuer_cn'))
        if subject:
            by_subject[subject].append(row)
        if issuer:
            by_issuer[issuer].append(row)
    for subject, items in by_subject.items():
        if len(items) > 1:
            rows.append({
                'relationship': 'Certificate subject reused across services',
                'subject': subject,
                'endpoints': [f"{_norm(i.get('host'))}:{_norm(i.get('port'))}" for i in items],
                'what_it_means': 'Repeated certificate subject can indicate shared infrastructure, a load-balanced surface, or reused service identity.',
                'evidence_sources': ['TLS certificate metadata'],
            })
    for issuer, items in by_issuer.items():
        if issuer and len(items) > 1:
            rows.append({
                'relationship': 'Common certificate issuer observed',
                'issuer': issuer,
                'endpoint_count': len(items),
                'what_it_means': 'Common issuer evidence helps cluster services under the same trust boundary. This is not a vulnerability claim.',
                'evidence_sources': ['TLS certificate metadata'],
            })
    for row in tls_rows:
        alpn = _norm(row.get('alpn'))
        version = _norm(row.get('tls_version'))
        cipher = _norm(row.get('cipher'))
        if alpn or version or cipher:
            rows.append({
                'relationship': 'TLS protocol context observed',
                'endpoint': f"{_norm(row.get('host'))}:{_norm(row.get('port'))}",
                'tls_version': version,
                'alpn': alpn,
                'cipher': cipher,
                'what_it_means': 'TLS protocol metadata supports application and gateway context without content probing.',
                'evidence_sources': ['single TLS handshake'],
            })
    return rows[:30]


def build_inference_decision_plan(services: list[dict[str, Any]], passive_intelligence: dict[str, Any], modern_active_validation: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe the inference-first decisions that should drive future recon.

    This does not execute anything. It explains what the platform learned and
    which minimal validation was justified by observed evidence.
    """
    plan: list[dict[str, Any]] = []
    for host, rows in _host_services(services).items():
        observations: list[str] = []
        justified: list[str] = []
        if _has_port(rows, {80, 443, 8080, 8180, 8443, 9443}):
            observations.append('Web/application surface observed')
            justified.append('Prefer HTTPX, headers, TLS and metadata paths before any directory enumeration')
        if _has_port(rows, {389, 636, 88, 139, 445}):
            observations.append('Identity or Windows networking surface observed')
            justified.append('Correlate LDAP RootDSE, Kerberos realm and SMB identity before wider enumeration')
        if _has_port(rows, {53}):
            observations.append('DNS surface observed')
            justified.append('Use SOA/NS/PTR/context queries before additional service discovery')
        if _has_port(rows, {161}):
            observations.append('SNMP surface observed')
            justified.append('Use targeted system identity OIDs only')
        if _has_port(rows, {111, 2049}):
            observations.append('RPC/NFS relationship observed')
            justified.append('Use rpcinfo/showmount only; do not mount shares')
        if _has_port(rows, {22, 23, 3389, 5900, 5985, 5986}):
            observations.append('Remote administration surface observed')
            justified.append('Collect protocol posture and banners only; no login attempts')
        if observations:
            plan.append({
                'host': host,
                'hypothesis_basis': observations,
                'minimal_next_validation': justified,
                'architecture': 'inference_first_then_targeted_validation',
                'what_it_means': 'The platform should prioritise evidence relationships before broad follow-up scans.',
            })
    return plan


def build_enumeration_memory_guidance(services: list[dict[str, Any]], modern_active_validation: dict[str, Any]) -> dict[str, Any]:
    """Return cache guidance for repeated scans.

    It avoids actual skipping in the current run but provides deterministic TTLs
    for future resume/differential work.
    """
    ttl_hours = {
        'ldap_rootdse': 24,
        'kerberos_info': 24,
        'tls_intelligence': 12,
        'dns_context': 12,
        'snmp_targeted_oids': 24,
        'http_security_context': 6,
        'service_fingerprint': 6,
    }
    observed_tools = [k for k, v in (modern_active_validation or {}).items() if isinstance(v, list) and v]
    return {
        'enabled_for_future_runs': True,
        'recommended_ttl_hours': {k: v for k, v in ttl_hours.items() if k in observed_tools or k == 'service_fingerprint'},
        'repeat_scan_guidance': 'Reuse unchanged low-noise metadata evidence within TTL and re-run active validators only when service inventory changes.',
        'what_it_means': 'Enumeration memory reduces repeat noise without reducing first-run coverage.',
    }


def build_information_yield_model(modern_active_validation: dict[str, Any]) -> dict[str, Any]:
    """Summarise information yield by collector without risk/severity scoring."""
    yield_labels = {
        'ldapsearch_rootdse': 'exceptional', 'ldap_rootdse': 'exceptional', 'tls_intelligence': 'exceptional',
        'dns_context': 'high', 'snmp_targeted_oids': 'high', 'http_security_context': 'high', 'ssh_audit_native': 'high',
        'kerberos_info': 'high', 'api_discovery': 'high', 'federation_detection': 'high', 'smb_protocol_security': 'high',
        'rpcinfo_native': 'medium', 'showmount_native': 'medium', 'nuclei_safe': 'conditional', 'targeted_web_discovery': 'conditional',
    }
    rows: list[dict[str, Any]] = []
    for key, label in yield_labels.items():
        value = (modern_active_validation or {}).get(key)
        if isinstance(value, list) and value:
            rows.append({'collector': key, 'yield_level': label, 'items': len(value), 'explanation': 'Information yield reflects environment understanding gained, not risk or priority.'})
    preferred = [r['collector'] for r in rows if r['yield_level'] in {'exceptional', 'high'}]
    conditional = [r['collector'] for r in rows if r['yield_level'] == 'conditional']
    return {'retained_collectors': rows, 'preferred_collectors': preferred, 'conditional_collectors': conditional, 'summary': f'{len(preferred)} high-yield collector(s) and {len(conditional)} conditional-yield collector(s) produced evidence.'}




def build_negative_evidence_register(services: list[dict[str, Any]], modern_active_validation: dict[str, Any], topology_aware_context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Record checks that produced no positive evidence without treating absence as proof.

    This is deliberately conservative: a non-response can mean filtered, absent,
    blocked by policy, time-bound scheduled rule behaviour, or UDP ambiguity.
    """
    rows: list[dict[str, Any]] = []
    services = services or []
    observed_ports = {(_norm(s.get('host')), str(s.get('port')), _norm(s.get('protocol') or 'tcp').lower()) for s in services if s.get('host') and s.get('port')}
    checks = [
        ('ldap_rootdse', {'389','636','3268','3269'}, 'tcp', 'LDAP/Directory context not observed or not reachable.'),
        ('kerberos_info', {'88'}, 'tcp', 'Kerberos realm evidence not observed or not reachable.'),
        ('snmp_targeted_oids', {'161'}, 'udp', 'SNMP identity OID evidence not observed, blocked, or ambiguous.'),
        ('tls_intelligence', {'443','8443','9443','5986'}, 'tcp', 'TLS certificate/trust evidence not observed on checked endpoints.'),
        ('rdp_negotiation', {'3389'}, 'tcp', 'RDP negotiation evidence not observed or not reachable.'),
        ('winrm_validation', {'5985','5986'}, 'tcp', 'WinRM listener evidence not observed or not reachable.'),
        ('rpcinfo_native', {'111'}, 'tcp', 'Native RPC program map evidence not observed or not reachable.'),
        ('showmount_native', {'2049'}, 'tcp', 'NFS export evidence not observed or not reachable.'),
    ]
    active_keys = set(k for k, v in (modern_active_validation or {}).items() if isinstance(v, list) and v)
    for host in sorted({_norm(s.get('host')) for s in services if s.get('host')}):
        for key, ports, proto, meaning in checks:
            port_present = any((host, p, proto) in observed_ports for p in ports)
            evidence_present = key in active_keys
            if port_present and not evidence_present:
                rows.append({
                    'host': host,
                    'check': key,
                    'negative_observation': meaning,
                    'interpretation': 'No conclusion drawn from absence alone.',
                    'possible_causes': ['service absent', 'filtered by policy', 'not selected in Custom Recon', 'tool unavailable', 'time-bound access condition'],
                    'evidence_state': 'Not Observed',
                })
    # Topology path no-response/filtered context also becomes negative evidence.
    for path in (topology_aware_context or {}).get('paths') or []:
        reach = path.get('reachability_interpretation') or {}
        if any(k in reach for k in ['segmentation_or_policy_likely', 'udp_ambiguous', 'filtered']):
            rows.append({
                'host': path.get('target'),
                'check': 'topology_reachability',
                'negative_observation': 'Some reachability results were filtered, ambiguous, or policy-shaped.',
                'interpretation': 'Treat as topology evidence, not proof that services do not exist.',
                'possible_causes': ['firewall policy', 'router ACL', 'scheduled rule', 'App-ID/application allowance', 'service absence'],
                'evidence_state': 'Context Required',
            })
    return rows[:40]


def build_hypothesis_ledger(services: list[dict[str, Any]], intelligence_seed: dict[str, Any], topology_aware_context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Track generated, supported, rejected and unresolved recon hypotheses."""
    rows: list[dict[str, Any]] = []
    roles = intelligence_seed.get('service_roles') or []
    identities = intelligence_seed.get('identity_correlation') or []
    relationships = intelligence_seed.get('cross_service_relationships') or []
    negative = intelligence_seed.get('negative_evidence_register') or []
    neg_by_host: dict[str, list[str]] = defaultdict(list)
    for n in negative:
        if n.get('host'):
            neg_by_host[_norm(n.get('host'))].append(_norm(n.get('check')))
    for role in roles:
        host = _norm(role.get('host'))
        hypothesis = _norm(role.get('role'))
        evidence = role.get('signals') or []
        status = 'supported'
        blockers = neg_by_host.get(host, [])
        if hypothesis.lower().find('identity') >= 0 and any(x in blockers for x in ['ldap_rootdse','kerberos_info']):
            status = 'unresolved'
        rows.append({
            'host': host,
            'hypothesis': hypothesis,
            'status': status,
            'supporting_evidence': evidence,
            'contradicting_or_missing_evidence': blockers,
            'confidence_language': 'Likely' if status == 'supported' else 'Unresolved',
            'what_it_means': 'Hypotheses explain environment role inference and are not vulnerability confirmations.',
        })
    for item in identities:
        host = _norm(item.get('host'))
        status = 'supported' if item.get('evidence_sources') else 'unresolved'
        rows.append({
            'host': host,
            'hypothesis': item.get('role') or 'Identity-related surface',
            'status': status,
            'supporting_evidence': item.get('evidence_sources') or [],
            'contradicting_or_missing_evidence': neg_by_host.get(host, []),
            'confidence_language': 'Consistent with',
            'what_it_means': 'Identity conclusions require multiple signals; single banners are treated as insufficient for confirmation.',
        })
    for item in intelligence_seed.get('dns_naming_intelligence') or []:
        host = _norm(item.get('host'))
        contexts = item.get('naming_context') or []
        if not host or not contexts:
            continue
        supporting = item.get('evidence_sources') or ['DNS naming']
        service_text = ' '.join(_service_text(s) for s in services if _norm(s.get('host')) == host)
        for ctx in contexts[:3]:
            status = 'supported'
            confidence = 'Likely'
            missing = neg_by_host.get(host, [])
            if 'identity' in ctx and not any(x in service_text for x in ['ldap','kerberos','samba','netbios','microsoft-ds']):
                status = 'rejected'
                confidence = 'Rejected'
                missing = missing + ['expected identity service evidence not observed']
            elif 'network/security' in ctx and not any(x in service_text for x in ['ssh','snmp','https','http']):
                status = 'unresolved'
                confidence = 'Unresolved'
            rows.append({
                'host': host,
                'hypothesis': ctx,
                'status': status,
                'supporting_evidence': supporting + item.get('observed_names', [])[:3],
                'contradicting_or_missing_evidence': missing,
                'confidence_language': confidence,
                'what_it_means': 'DNS naming can suggest roles, but role hypotheses are downgraded or rejected when service evidence does not support the name.',
            })

    # If there are negative-only entries with no supported role, show explicit unresolved hypotheses.
    known = {(r.get('host'), r.get('hypothesis')) for r in rows}
    for host, blockers in neg_by_host.items():
        if not any(r.get('host') == host for r in rows):
            rows.append({
                'host': host,
                'hypothesis': 'Environment role could not be inferred from available evidence',
                'status': 'unresolved',
                'supporting_evidence': [],
                'contradicting_or_missing_evidence': blockers,
                'confidence_language': 'Not established',
                'what_it_means': 'The platform retains the information gap instead of guessing.',
            })
    return rows[:50]


def build_decision_timeline(services: list[dict[str, Any]], intelligence_seed: dict[str, Any], modern_active_validation: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose the inference-first decision process to reviewers."""
    timeline: list[dict[str, Any]] = []
    timeline.append({'stage': '1. Scope and evidence boundary', 'decision': 'Use observed evidence only.', 'basis': 'Rules-of-engagement and fixed collection policy.', 'outcome': 'No cyber-range configuration changes.'})
    timeline.append({'stage': '2. Passive and metadata-first evidence', 'decision': 'Prefer passive, DNS, TLS, HTTP metadata and low-noise protocol context before broad validation.', 'basis': 'Low noise / high information yield.', 'outcome': 'Initial hypotheses generated.'})
    service_count = len(services or [])
    timeline.append({'stage': '3. Service inventory', 'decision': 'Use micro-batched, scoped discovery only where inventory is still needed.', 'basis': f'{service_count} service record(s) retained.', 'outcome': 'Open services converted into functional groups.'})
    for item in (intelligence_seed.get('inference_decision_plan') or [])[:8]:
        timeline.append({'stage': '4. Hypothesis-driven validation', 'decision': '; '.join(item.get('minimal_next_validation') or []), 'basis': '; '.join(item.get('hypothesis_basis') or []), 'outcome': item.get('what_it_means') or 'Targeted validation selected.'})
    high = (modern_active_validation or {}).get('noise_evaluation', {}).get('high_yield_checks') if isinstance((modern_active_validation or {}).get('noise_evaluation'), dict) else []
    if high:
        timeline.append({'stage': '5. Noise/yield checkpoint', 'decision': 'Retain high-yield checks and suppress broad low-yield expansion.', 'basis': ', '.join(str(x.get('check')) for x in high[:6] if isinstance(x, dict)), 'outcome': 'Information yield favoured over tool volume.'})
    timeline.append({'stage': '6. Evidence normalisation', 'decision': 'Classify outcomes as Observed, Candidate, Validated, Not Observed, or Context Required.', 'basis': 'Evidence diversity and explicit information gaps.', 'outcome': 'No unsupported confirmation language.'})
    return timeline[:30]


def build_adaptive_information_yield_model(modern_active_validation: dict[str, Any], services: list[dict[str, Any]], negative_evidence: list[dict[str, Any]], hypothesis_ledger: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate information yield based on context, not static tool labels.

    This is not risk scoring and not prioritisation. It explains whether a
    collector produced useful environment understanding for this run.
    """
    rows: list[dict[str, Any]] = []
    service_text = ' '.join(_service_text(s) for s in services or [])
    context_bonus = {
        'identity': any(x in service_text for x in ['ldap','kerberos','samba','netbios','microsoft-ds']),
        'web': any(x in service_text for x in ['http','apache','nginx','tomcat','ajp']),
        'infra': any(x in service_text for x in ['dns','bind','snmp','rpc','nfs']),
        'remote': any(x in service_text for x in ['ssh','telnet','rdp','vnc','winrm']),
        'data': any(x in service_text for x in ['mysql','postgres','mssql','redis','elastic']),
    }
    collector_context = {
        'ldapsearch_rootdse': 'identity', 'ldap_rootdse': 'identity', 'kerberos_info': 'identity', 'smb_protocol_security': 'identity',
        'http_security_context': 'web', 'api_discovery': 'web', 'federation_detection': 'web', 'httpx': 'web',
        'tls_intelligence': 'web', 'dns_context': 'infra', 'snmp_targeted_oids': 'infra', 'rpcinfo_native': 'infra', 'showmount_native': 'infra',
        'ssh_audit_native': 'remote', 'rdp_negotiation': 'remote', 'winrm_validation': 'remote', 'vnc_info': 'remote',
        'mysql_info': 'data', 'postgres_info': 'data', 'mssql_info': 'data', 'redis_info': 'data',
    }
    negative_checks = {n.get('check') for n in negative_evidence or []}
    for key, value in (modern_active_validation or {}).items():
        if not isinstance(value, list) or not value:
            continue
        ctx = collector_context.get(key, 'general')
        count = len(value)
        if key in negative_checks:
            level = 'low'
            reason = 'Collector produced limited positive evidence in this run.'
        elif ctx != 'general' and context_bonus.get(ctx):
            level = 'exceptional' if count >= 1 and ctx in {'identity','web','infra'} else 'high'
            reason = f'Collector matched observed {ctx} context and produced run-specific evidence.'
        elif count >= 3:
            level = 'medium'
            reason = 'Collector produced evidence, but context linkage was limited.'
        else:
            level = 'conditional'
            reason = 'Collector retained evidence for analyst context only.'
        rows.append({'collector': key, 'yield_level': level, 'items': count, 'context': ctx, 'explanation': reason})
    unresolved = [h for h in hypothesis_ledger or [] if h.get('status') == 'unresolved']
    return {
        'retained_collectors': rows,
        'preferred_collectors': [r['collector'] for r in rows if r['yield_level'] in {'exceptional','high'}],
        'conditional_collectors': [r['collector'] for r in rows if r['yield_level'] == 'conditional'],
        'unresolved_hypotheses_count': len(unresolved),
        'summary': f"{len([r for r in rows if r['yield_level'] in {'exceptional','high'}])} high-yield collector(s), {len([r for r in rows if r['yield_level']=='conditional'])} conditional collector(s), and {len(unresolved)} unresolved hypothesis item(s) retained.",
        'boundary': 'Information yield explains evidence value only; it is not severity, risk, priority, or exploitation guidance.',
    }


def build_evidence_boundary_summary(topology_aware_context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """State what recon evidence can and cannot prove without scanner-location assumptions."""
    return [
        {
            'boundary': 'Transport reachability',
            'applies_to': 'Nmap, TCP/UDP discovery, banner collection',
            'interpretation': 'Open or responsive ports show reachability at scan time only; they do not prove application-layer permission, exploitability, firewall rule intent, or persistent accessibility.',
            'confidence_language': 'Observed',
        },
        {
            'boundary': 'Time-window aggregation',
            'applies_to': 'Micro-batched TCP/UDP discovery and repeated validation checks',
            'interpretation': 'Lowering packet frequency reduces immediate burst behaviour but extended IDS/SIEM correlation windows may still flag one source probing multiple distinct ports over several minutes.',
            'confidence_language': 'Detection Context',
        },
        {
            'boundary': 'Connection-state anomalies',
            'applies_to': 'SYN scanning, banner checks, validators that do not complete normal application workflows',
            'interpretation': 'Traffic that does not follow normal completed application sessions can remain visible to stateful monitoring even when packet volume is low.',
            'confidence_language': 'Detection Context',
        },
        {
            'boundary': 'Administrative and non-standard service context',
            'applies_to': 'Management, print, alternate web/proxy, database, RPC/NFS and legacy remote administration services',
            'interpretation': 'Traffic to sensitive destination services may alert because of destination context rather than velocity.',
            'confidence_language': 'Detection Context',
        },
        {
            'boundary': 'Correlation and role inference',
            'applies_to': 'Identity, network device, certificate, DNS naming and service role conclusions',
            'interpretation': 'Role labels are likely/supported/unresolved descriptions based on collected evidence; they are not confirmations unless multiple independent evidence sources agree.',
            'confidence_language': 'Likely / Supported / Unresolved',
        },
        {
            'boundary': 'Negative evidence',
            'applies_to': 'Filtered, closed, no-response, open|filtered and missing validator output',
            'interpretation': 'Absence of evidence is retained as an information gap and is not treated as proof that the service or control does not exist.',
            'confidence_language': 'Not Observed / Context Required',
        },
    ]

def build_recon_acceptance_matrix(intelligence: dict[str, Any], services: list[dict[str, Any]], modern_active_validation: dict[str, Any], topology_aware_context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Review-readiness checklist for recon quality.

    This is deliberately not a risk score, severity score, priority, or ranking.
    It is a pass/checkpoint matrix for evidence quality and presentation readiness.
    """
    topo = topology_aware_context or {}
    noise_eval = (modern_active_validation or {}).get('noise_evaluation') or {}
    checks = [
        ('Enumeration coverage', bool(services), f'{len(services or [])} service record(s) retained.'),
        ('Information yield', bool((intelligence.get('information_yield_model') or {}).get('retained_collectors')), (intelligence.get('information_yield_model') or {}).get('summary') or 'No adaptive yield model recorded.'),
        ('Noise discipline', bool(noise_eval), (noise_eval.get('summary') if isinstance(noise_eval, dict) else '') or 'No broad high-noise expansion recorded in this section.'),
        ('Evidence accuracy', bool(intelligence.get('evidence_boundary_summary')) and bool(intelligence.get('confidence')), 'Evidence boundaries and confidence sources are recorded.'),
        ('Hypothesis discipline', bool(intelligence.get('hypothesis_ledger')) and bool(intelligence.get('negative_evidence_register')), 'Hypotheses and negative evidence are retained separately.'),
        ('Defensive interpretation', bool(topo.get('detection_mechanics')), 'Detection mechanics are retained without operator-declared path assumptions.'),
        ('Report readability', bool(intelligence.get('decision_timeline')) and bool(intelligence.get('executive_summary')), 'Decision timeline and executive summary are front-loaded.'),
        ('Scope discipline', True, 'No brute force, exploitation, evasion, decoy, spoofing, or teammate-module execution added by recon.'),
    ]
    out = []
    for area, passed, evidence in checks:
        out.append({'area': area, 'status': 'meets_target' if passed else 'needs_review', 'evidence': evidence})
    return out

def build_enumeration_intelligence(
    services: list[dict[str, Any]],
    modern_active_validation: dict[str, Any] | None = None,
    passive_intelligence: dict[str, Any] | None = None,
    web_inventory: list[dict[str, Any]] | None = None,
    smb_summary: dict[str, Any] | None = None,
    topology_aware_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    modern_active_validation = modern_active_validation or {}
    passive_intelligence = passive_intelligence or {}
    smb_summary = smb_summary or {}
    services = services or []

    groups = build_functional_service_groups(services)
    identities = build_identity_correlation(services, modern_active_validation, smb_summary)
    relationships = build_service_relationships(services)
    roles = build_role_inferences(services)
    web_context = build_web_context(web_inventory or [], modern_active_validation)
    network_devices = build_network_device_context(services, modern_active_validation)
    confidence = build_enumeration_confidence(services, modern_active_validation, passive_intelligence)
    graph = build_knowledge_graph(services, relationships, roles)
    budget_summary = build_detection_budget_summary(modern_active_validation)
    dns_naming = build_dns_naming_intelligence(passive_intelligence, services)
    tls_trust = build_tls_trust_intelligence(modern_active_validation, passive_intelligence)
    inference_plan = build_inference_decision_plan(services, passive_intelligence, modern_active_validation)
    memory_guidance = build_enumeration_memory_guidance(services, modern_active_validation)
    # First-pass intelligence used as input to the hypothesis and negative-evidence layers.
    intelligence_seed = {
        'service_roles': roles,
        'identity_correlation': identities,
        'cross_service_relationships': relationships,
        'inference_decision_plan': inference_plan,
        'dns_naming_intelligence': dns_naming,
        'tls_trust_intelligence': tls_trust,
    }
    negative_evidence = build_negative_evidence_register(services, modern_active_validation, topology_aware_context)
    intelligence_seed['negative_evidence_register'] = negative_evidence
    hypothesis_ledger = build_hypothesis_ledger(services, intelligence_seed, topology_aware_context)
    decision_timeline = build_decision_timeline(services, intelligence_seed, modern_active_validation)
    information_yield = build_adaptive_information_yield_model(modern_active_validation, services, negative_evidence, hypothesis_ledger)
    evidence_boundary = build_evidence_boundary_summary(topology_aware_context)

    intelligence = {
        'functional_service_groups': groups,
        'identity_correlation': identities,
        'cross_service_relationships': relationships,
        'service_roles': roles,
        'web_context': web_context,
        'network_device_context': network_devices,
        'dns_naming_intelligence': dns_naming,
        'tls_trust_intelligence': tls_trust,
        'inference_decision_plan': inference_plan,
        'enumeration_memory_guidance': memory_guidance,
        'information_yield_model': information_yield,
        'evidence_boundary_summary': evidence_boundary,
        'negative_evidence_register': negative_evidence,
        'hypothesis_ledger': hypothesis_ledger,
        'decision_timeline': decision_timeline,
        'confidence': confidence,
        'knowledge_graph': graph,
        'detection_budget_summary': budget_summary,
    }
    intelligence['acceptance_matrix'] = build_recon_acceptance_matrix(intelligence, services, modern_active_validation, topology_aware_context)
    intelligence['executive_summary'] = build_executive_recon_summary(intelligence, services)
    intelligence['summary'] = [
        f"Functional service groups: {len(groups)} retained.",
        f"Identity correlation item(s): {len(identities)}.",
        f"Cross-service relationship(s): {len(relationships)}.",
        f"Service role inference item(s): {len(roles)}.",
        f"Web context item(s): {len(web_context)}.",
        f"Network device context item(s): {len(network_devices)}.",
        f"Inference decision plan item(s): {len(inference_plan)}.",
        f"Negative evidence register item(s): {len(negative_evidence)}.",
        f"Hypothesis ledger item(s): {len(hypothesis_ledger)}.",
        f"Decision timeline item(s): {len(decision_timeline)}.",
        f"Evidence boundary item(s): {len(evidence_boundary)}.",
        f"Acceptance matrix item(s): {len(intelligence.get('acceptance_matrix') or [])}.",
        f"TLS trust intelligence item(s): {len(tls_trust)}.",
        f"DNS naming intelligence item(s): {len(dns_naming)}.",
        information_yield.get('summary', ''),
    ]
    return intelligence
