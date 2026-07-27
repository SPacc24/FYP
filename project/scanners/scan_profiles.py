from __future__ import annotations
from typing import Iterable, Any, Mapping
import hashlib
import json
import re
import shutil
from pathlib import Path

from .collector_plan import (
    COLLECTION_PRESETS, COLLECTOR_GROUPS, CORE_TOOL_IDS, build_collector_catalog,
    normalise_collection_plan, normalise_host_discovery, normalise_service_identity,
    nse_script_preflight,
)

"""Recon tool, port, and runtime option normalisation.

The public scanner UI intentionally separates three concerns:
- evidence-collection tools,
- TCP/UDP port coverage,
- bounded runtime behaviour.

Policy still has final authority over explicitly disabled collectors and stop
conditions.  User-supplied port/runtimes are validated here before any target
interaction so malformed settings cannot silently fall back to a different
scan.
"""

TOOL_OPTIONS = [
    {'id':'nmap_os_identity','label':'Generic active OS fingerprint','category':'Host Identity','purpose':'Collect bounded Nmap OS match/class/CPE evidence using only operator-authorised ports already covered by discovery.','full':True},
    {'id':'windows_patch_inventory','label':'Windows authenticated patch inventory','category':'Host Identity','purpose':'Use an already-approved cached credential for read-only WMI collection of Windows build and installed KB evidence; no brute force, remote shell, service creation, or target modification.','full':False},
    {'id':'smb_host_identity','label':'SMB host/OS identity','category':'Host Identity','purpose':'Collect SMB-exposed host, domain/workgroup, OS/CPE, capability and time evidence without share/user enumeration.','full':True},
    {'id':'netbios_identity','label':'NetBIOS host identity','category':'Host Identity','purpose':'Collect NetBIOS naming identity when NetBIOS is actually observed; no RID/user enumeration.','full':True},
    {'id':'msrpc_metadata','label':'Microsoft RPC endpoint metadata','category':'Host Identity','purpose':'Collect safe RPC endpoint-mapper metadata; advertised dynamic endpoints are recorded, not silently scanned.','full':True},
    {'id':'ntlm_http_identity','label':'HTTP / WinRM NTLM host identity','category':'Host Identity','purpose':'Collect NTLM-negotiated computer/domain/product-version metadata without successful authentication.','full':True},
    {'id':'ntlm_rdp_identity','label':'RDP NTLM host identity','category':'Host Identity','purpose':'Collect RDP NTLM computer/domain/product-version metadata without successful authentication.','full':True},
    {'id':'ntlm_mssql_identity','label':'MSSQL NTLM host identity','category':'Host Identity','purpose':'Collect SQL NTLM computer/domain/product-version metadata separately from SQL Server application version.','full':True},
    {'id':'ntlm_smtp_identity','label':'SMTP NTLM host identity','category':'Host Identity','purpose':'Collect NTLM host metadata only when an applicable SMTP service exposes it.','full':False},
    {'id':'ntlm_imap_identity','label':'IMAP NTLM host identity','category':'Host Identity','purpose':'Collect NTLM host metadata only when an applicable IMAP service exposes it.','full':False},
    {'id':'ntlm_pop3_identity','label':'POP3 NTLM host identity','category':'Host Identity','purpose':'Collect NTLM host metadata only when an applicable POP3 service exposes it.','full':False},
    {'id':'ntlm_nntp_identity','label':'NNTP NTLM host identity','category':'Host Identity','purpose':'Collect NTLM host metadata only when an applicable NNTP service exposes it.','full':False},
    {'id':'ntlm_telnet_identity','label':'Telnet NTLM host identity','category':'Host Identity','purpose':'Collect NTLM host metadata only when an applicable Telnet service exposes it.','full':False},
    {'id':'passive_dns','label':'Passive DNS intelligence','category':'Passive','purpose':'Collect approved DNS record evidence including MX/TXT/SRV/NS/CNAME without authentication or exploitation.','full':True},
    {'id':'passive_tls','label':'Passive TLS certificate intelligence','category':'Passive','purpose':'Collect TLS certificate, SAN, issuer and negotiated TLS evidence from observed TLS endpoints.','full':True},
    {'id':'passive_fingerprinting','label':'Passive enterprise fingerprinting','category':'Passive','purpose':'Infer email, authentication, VPN, CDN, reverse proxy, cloud and technology hints from already collected DNS/TLS/HTTP evidence.','full':True},
    {'id':'certificate_transparency','label':'Certificate Transparency awareness','category':'Passive / Policy-gated','purpose':'Policy-controlled public certificate name discovery when external intelligence is approved.','full':True},
    {'id':'passive_packet_inventory','label':'Passive local packet inventory','category':'Passive','purpose':'Listen-only ARP/mDNS/DHCP/LLMNR inventory using tshark when an interface is approved; no target probes generated.','full':True},
    {'id':'passive_os_fingerprinting','label':'Passive OS fingerprinting','category':'Passive','purpose':'Listen-only p0f OS hints from ambient traffic when an interface is approved; no target probes generated.','full':True},

    {'id':'environment_characterisation','label':'Environment characterisation','category':'Stage 0','purpose':'Basic reachability and observed behaviour before heavier enumeration.','full':True},
    {'id':'tcp_discovery','label':'TCP port discovery','category':'Stage 1','purpose':'Discover the operator-selected TCP coverage using bounded Nmap batches.','full':True},
    {'id':'udp_discovery','label':'UDP port discovery','category':'Stage 1','purpose':'Discover the operator-selected UDP coverage using bounded Nmap batches.','full':True},
    {'id':'service_fingerprint','label':'All observed service identity','category':'Stage 1','purpose':'Banner-first product/version/CPE collection for every observed and high-value service.','full':True},
    {'id':'httpx','label':'HTTP technology hints','category':'Objective','purpose':'Low-impact HTTP status/title/technology hints where ProjectDiscovery httpx is available.','full':True},
    {'id':'http_security_context','label':'HTTP security context','category':'Information Gathering','purpose':'Collect headers, cookies, auth challenges and redirects with a single HEAD request.','full':True},
    {'id':'html_form_parser','label':'Web form/input readiness','category':'Objective','purpose':'Collect form/input/login/upload hints from a single web page without attack payloads.','full':True},
    {'id':'targeted_web_discovery','label':'Targeted web discovery','category':'Modern Active','purpose':'Policy-limited robots/sitemap/security/admin marker checks before directory brute-force escalation.','full':True},
    {'id':'api_discovery','label':'API documentation discovery','category':'Modern Active','purpose':'Detect exposed OpenAPI/Swagger/GraphQL documentation without attack payloads.','full':True},
    {'id':'nuclei_safe','label':'Nuclei safe fingerprint/misconfiguration templates','category':'Modern Active','purpose':'Run ProjectDiscovery nuclei with safe informational/low fingerprint and misconfiguration templates only.','full':True},

    {'id':'ssh_auth_methods','label':'SSH authentication-method readiness','category':'Service Validation','purpose':'Collect SSH advertised authentication methods without login attempts.','full':True},
    {'id':'ssh_audit_native','label':'Native ssh-audit enrichment','category':'Information Gathering','purpose':'Collect ssh-audit algorithm evidence when installed; no login attempts.','full':True},
    {'id':'ftp_anonymous_status','label':'FTP anonymous/system readiness','category':'Service Validation','purpose':'Collect FTP anonymous-login and system status evidence without brute force.','full':True},
    {'id':'telnet_readiness','label':'Telnet exposure readiness','category':'Legacy Service','purpose':'Collect Telnet exposure/banner evidence without authentication.','full':True},
    {'id':'dns_context','label':'DNS context gathering','category':'Information Gathering','purpose':'Collect SOA/NS/version.bind context where exposed using single DNS queries.','full':True},
    {'id':'smb_protocol_security','label':'SMB protocol/signing readiness','category':'Service Validation','purpose':'Collect SMB dialect and signing hints without share/user enumeration.','full':True},
    {'id':'ldap_rootdse','label':'LDAP RootDSE readiness','category':'Modern Active','purpose':'Collect LDAP naming-context evidence without authentication.','full':True},
    {'id':'ldapsearch_rootdse','label':'Native LDAP RootDSE parsing','category':'Information Gathering','purpose':'Extract LDAP naming contexts, capabilities and domain hints via anonymous RootDSE only.','full':True},
    {'id':'kerberos_info','label':'Kerberos realm readiness','category':'Modern Active','purpose':'Collect Kerberos realm/service evidence without credential use.','full':True},
    {'id':'winrm_wsman_probe','label':'WinRM listener readiness','category':'Service Validation','purpose':'Collect WinRM listener/header evidence without authentication attempts.','full':True},
    {'id':'rdp_negotiation','label':'RDP/NLA negotiation readiness','category':'Modern Active','purpose':'Collect RDP encryption/NLA hints without authentication.','full':True},
    {'id':'vnc_info','label':'VNC protocol readiness','category':'Legacy Service','purpose':'Collect VNC protocol/security-type hints without authentication.','full':True},
    {'id':'rpcinfo_native','label':'Native RPC program map','category':'Information Gathering','purpose':'Collect RPC program mapping using rpcinfo only; no service interaction beyond portmapper query.','full':True},
    {'id':'showmount_native','label':'Native NFS export check','category':'Information Gathering','purpose':'Collect showmount export readiness evidence only; no mounting or file access.','full':True},
    {'id':'snmp_readiness','label':'SNMP service readiness','category':'Network Service','purpose':'Collect SNMP version/basic system hints only where exposed; no broad MIB walking.','full':True},
    {'id':'snmp_targeted_oids','label':'SNMP targeted identity OIDs','category':'Information Gathering','purpose':'Collect sysDescr/sysName/sysLocation/sysContact only; no full MIB walk.','full':True},
    {'id':'postgres_readiness_native','label':'Native PostgreSQL readiness probe','category':'Information Gathering','purpose':'Collect PostgreSQL readiness evidence using pg_isready only; no authentication.','full':True},
    {'id':'mssql_info','label':'MSSQL information readiness','category':'Database','purpose':'Collect MSSQL information evidence without authentication attempts.','full':True},
    {'id':'redis_info','label':'Redis exposure readiness','category':'Database','purpose':'Collect Redis banner/info exposure evidence without writes or authentication attempts.','full':True},
    {'id':'elasticsearch_info','label':'Elasticsearch exposure readiness','category':'Database/Search','purpose':'Collect Elasticsearch root/cluster metadata exposure evidence without queries that modify state.','full':True},

    {'id':'tomcat_ajp_readiness','label':'Tomcat/AJP readiness','category':'Application Service','purpose':'Collect Tomcat/AJP header and manager marker evidence without credential attempts.','full':True},
    {'id':'tls_cipher_validation','label':'TLS cipher/protocol validation','category':'Modern Active','purpose':'Collect TLS protocol/cipher evidence from observed TLS endpoints.','full':True},
    {'id':'kubernetes_exposure','label':'Kubernetes exposure check','category':'Modern Active','purpose':'Check unauthenticated Kubernetes metadata endpoints only.','full':True},
    {'id':'container_exposure','label':'Container/registry exposure check','category':'Modern Active','purpose':'Check Docker/Podman/registry metadata endpoints only.','full':True},
    {'id':'vpn_validation','label':'VPN portal marker validation','category':'Modern Active','purpose':'Validate VPN portal markers without authentication.','full':True},
    {'id':'native_protocol_enrichment','label':'Native protocol metadata enrichment','category':'Information Gathering','purpose':'Collect one bounded product/version/capability interaction for supported observed services.','full':True},
]

VALID_TOOL_IDS = {tool['id'] for tool in TOOL_OPTIONS} | set(CORE_TOOL_IDS)
PROFILE_LABELS = {'full':'Full Recon','custom':'Operator Configured'}
PORT_MODES = {'full', 'essentials', 'custom'}
MIN_PORT = 1
MAX_PORT = 65535

# These are safety/operability bounds, not target-specific scan facts.
ADVANCED_BOUNDS = {
    'command_timeout_seconds': (30, 3600),
    'retry_count': (0, 3),
    'ports_per_batch': (1, 2048),
    'parallel_workers': (1, 8),
}


def _load_profile_policy() -> tuple[dict[str, Any], str, str]:
    candidates = [Path('project/policies/recon_policy.json'), Path('policies/recon_policy.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        return {}, 'missing', ''
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode('utf-8'))
        return data, 'loaded', hashlib.sha256(raw).hexdigest()
    except Exception:
        return {}, 'invalid', ''


def _resolve_enabled_tools(policy: dict[str, Any], requested: Iterable[str]) -> tuple[list[str], list[str]]:
    requested_set = {str(value) for value in requested if str(value) in VALID_TOOL_IDS}
    explicitly_disabled = {
        str(value)
        for value in policy.get('automatic_collectors_disabled') or []
        if str(value) in VALID_TOOL_IDS
    }
    conflicts = sorted(requested_set & explicitly_disabled)
    return sorted(requested_set - explicitly_disabled), conflicts


def parse_port_spec(spec: str | None) -> list[int]:
    """Parse comma/space separated ports and inclusive ranges.

    Examples: ``22,80,443`` and ``1-1024,8080,8443``.  Invalid tokens or
    ports outside the IANA port-number range are rejected instead of ignored.
    """
    text = (spec or '').strip()
    if not text:
        return []

    text = re.sub(r'\s*-\s*', '-', text)
    ports: set[int] = set()
    for token in [part for part in re.split(r'[,\s]+', text) if part]:
        token = token.strip()
        if '-' in token:
            if token.count('-') != 1:
                raise ValueError(f'Invalid port range: {token}')
            start_raw, end_raw = token.split('-', 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                raise ValueError(f'Invalid port range: {token}')
            start, end = int(start_raw), int(end_raw)
            if start > end:
                raise ValueError(f'Port range must be ascending: {token}')
            if start < MIN_PORT or end > MAX_PORT:
                raise ValueError(f'Port range must stay between {MIN_PORT} and {MAX_PORT}: {token}')
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f'Invalid port: {token}')
            port = int(token)
            if port < MIN_PORT or port > MAX_PORT:
                raise ValueError(f'Port must be between {MIN_PORT} and {MAX_PORT}: {token}')
            ports.add(port)
    return sorted(ports)


def _bounded_int(value: Any, key: str, default: int) -> int:
    low, high = ADVANCED_BOUNDS[key]
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(default)
    return max(low, min(high, number))


def _normalise_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on', 'enabled'}


def _normalise_port_selection(
    policy: Mapping[str, Any],
    protocol: str,
    mode: str | None,
    custom_spec: str | None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    selected_mode = str(mode or 'essentials').strip().lower()
    if selected_mode not in PORT_MODES:
        selected_mode = 'essentials'

    if selected_mode == 'full':
        return {
            'mode': 'full',
            'ports': [],
            'custom_spec': '',
            'count': MAX_PORT,
            'display': f'Full {protocol.upper()} range ({MIN_PORT}-{MAX_PORT})',
        }, errors

    if selected_mode == 'essentials':
        profile_key = f'{protocol.lower()}_essentials'
        raw_ports = ((policy.get('port_profiles') or {}).get(profile_key) or [])
        try:
            ports = parse_port_spec(','.join(str(p) for p in raw_ports))
        except ValueError as exc:
            ports = []
            errors.append(f'{protocol.upper()} essentials policy is invalid: {exc}')
        if not ports:
            errors.append(f'{protocol.upper()} essentials profile is empty in recon policy.')
        return {
            'mode': 'essentials',
            'ports': ports,
            'custom_spec': '',
            'count': len(ports),
            'display': f'Essentials ({len(ports)} ports)',
        }, errors

    try:
        ports = parse_port_spec(custom_spec)
    except ValueError as exc:
        ports = []
        errors.append(f'Invalid custom {protocol.upper()} ports: {exc}')
    if not ports:
        errors.append(f'Custom {protocol.upper()} mode requires at least one valid port.')
    return {
        'mode': 'custom',
        'ports': ports,
        'custom_spec': (custom_spec or '').strip(),
        'count': len(ports),
        'display': f'Custom ({len(ports)} ports)',
    }, errors


def profile_tool_ids(profile: str | None = None) -> list[str]:
    profile_key = (profile or 'full').lower()
    if profile_key == 'custom':
        return []
    policy, status, _policy_hash = _load_profile_policy()
    if status != 'loaded':
        return []
    configured = (
        policy.get('full_recon_enabled_tools')
        or policy.get('default_enabled_tools')
        or [tool['id'] for tool in TOOL_OPTIONS if tool.get('full')]
    )
    enabled, _conflicts = _resolve_enabled_tools(policy, configured)
    return enabled


def normalise_scan_options(
    profile: str | None = None,
    enabled_tools: Iterable[str] | None = None,
    *,
    tcp_port_mode: str | None = None,
    tcp_custom_ports: str | None = None,
    udp_port_mode: str | None = None,
    udp_custom_ports: str | None = None,
    advanced_settings: Mapping[str, Any] | None = None,
    collection_preset: str | None = None,
    collector_plan: Mapping[str, Any] | None = None,
    host_discovery_settings: Mapping[str, Any] | None = None,
    service_identity_settings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    profile_key = (profile or 'full').lower()
    if profile_key in {'adaptive', 'fast'}:
        profile_key = 'full'
    if profile_key not in PROFILE_LABELS:
        profile_key = 'full'

    policy, policy_status, policy_hash = _load_profile_policy()

    catalog = build_collector_catalog(TOOL_OPTIONS, policy)
    preset_key = str(collection_preset or ('custom' if profile_key == 'custom' and enabled_tools is not None else 'recommended')).lower()
    legacy_enabled = enabled_tools if collector_plan is None and enabled_tools is not None else None
    normalised_plan, evidence_enabled, conflicts = normalise_collection_plan(
        TOOL_OPTIONS, policy, preset_key, collector_plan, legacy_enabled
    )
    host_discovery = normalise_host_discovery(policy, host_discovery_settings)
    service_identity = normalise_service_identity(policy, service_identity_settings)

    selected = set(evidence_enabled)
    # Core discovery stages are not evidence collectors. They are controlled by
    # their own structured settings and are never shown as ordinary tool cards.
    selected.add('environment_characterisation')
    if service_identity.get('tcp_discovery_enabled'):
        selected.add('tcp_discovery')
    if service_identity.get('udp_discovery_enabled'):
        selected.add('udp_discovery')
    if service_identity.get('service_fingerprinting_enabled'):
        selected.add('service_fingerprint')
    disabled = VALID_TOOL_IDS - selected
    collector_counts = {
        'requested': sum(1 for item in normalised_plan.values() if item.get('requested')),
        'permitted': sum(1 for item in normalised_plan.values() if item.get('effective_enabled')),
        'blocked': sum(1 for item in normalised_plan.values() if item.get('requested') and item.get('policy_state') == 'blocked'),
        'catalog_total': len(normalised_plan),
    }

    tcp_selection, tcp_errors = _normalise_port_selection(
        policy, 'tcp', tcp_port_mode, tcp_custom_ports
    )
    udp_selection, udp_errors = _normalise_port_selection(
        policy, 'udp', udp_port_mode, udp_custom_ports
    )

    micro_cfg = policy.get('tcp_micro_batching') or {}
    defaults = policy.get('operator_advanced_defaults') or {}
    supplied = dict(advanced_settings or {})
    command_timeout = _bounded_int(
        supplied.get('command_timeout_seconds'),
        'command_timeout_seconds',
        int(defaults.get('command_timeout_seconds') or 600),
    )
    retry_count = _bounded_int(
        supplied.get('retry_count'),
        'retry_count',
        int(defaults.get('retry_count') or 1),
    )
    ports_per_batch = _bounded_int(
        supplied.get('ports_per_batch'),
        'ports_per_batch',
        int(defaults.get('ports_per_batch') or micro_cfg.get('batch_size_target') or 5),
    )
    parallel_workers = _bounded_int(
        supplied.get('parallel_workers'),
        'parallel_workers',
        int(defaults.get('parallel_workers') or 2),
    )
    retry_failed = _normalise_bool(
        supplied.get('retry_failed_batches'),
        bool(defaults.get('retry_failed_batches', True)),
    )
    parallel = _normalise_bool(
        supplied.get('parallel_scanning'),
        bool(defaults.get('parallel_scanning', False)),
    )
    if not parallel:
        parallel_workers = 1

    validation_errors = tcp_errors + udp_errors
    return {
        'profile': profile_key,
        'profile_label': PROFILE_LABELS[profile_key],
        'strategy': 'operator_configurable_tcp_udp_recon',
        'collection_preset': preset_key if preset_key in COLLECTION_PRESETS else 'recommended',
        'collection_preset_label': COLLECTION_PRESETS.get(preset_key, COLLECTION_PRESETS['recommended'])['label'],
        'collector_plan': normalised_plan,
        'collector_catalog': catalog,
        'collector_counts': collector_counts,
        'host_discovery': host_discovery,
        'service_identity': service_identity,
        'enabled_tools': sorted(selected),
        'enabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] in selected],
        'disabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] in disabled],
        'port_selection': {
            'tcp': tcp_selection,
            'udp': udp_selection,
        },
        'advanced_settings': {
            'command_timeout_seconds': command_timeout,
            'retry_failed_batches': retry_failed,
            'retry_count': retry_count,
            'ports_per_batch': ports_per_batch,
            'parallel_scanning': parallel,
            'parallel_workers': parallel_workers,
        },
        'validation_errors': validation_errors,
        'objective_driven': True,
        'policy_status': policy_status,
        'effective_policy_sha256': policy_hash,
        'policy_conflicts': conflicts,
        'policy_resolution': 'explicit_disabled_wins',
    }


def selected_ports(options: Mapping[str, Any] | None, protocol: str) -> range | list[int]:
    """Return the exact operator-selected port sequence for a protocol."""
    selection = ((options or {}).get('port_selection') or {}).get(protocol.lower()) or {}
    mode = str(selection.get('mode') or 'essentials').lower()
    if mode == 'full':
        return range(MIN_PORT, MAX_PORT + 1)
    return [int(p) for p in (selection.get('ports') or []) if MIN_PORT <= int(p) <= MAX_PORT]


def is_tool_enabled(options: dict[str, Any] | None, tool_id: str) -> bool:
    if not options:
        options = normalise_scan_options('full')
    return tool_id in set(options.get('enabled_tools') or [])


def collector_ui_context() -> dict[str, Any]:
    """Return policy-aware collector metadata for the starting page.

    Runtime binary availability is advisory only: a collector can remain part
    of a saved plan, while the UI tells the operator before launch that the
    current scanner host cannot execute it. The runtime still records the
    authoritative lifecycle outcome.
    """
    policy, status, policy_hash = _load_profile_policy()
    catalog = build_collector_catalog(TOOL_OPTIONS, policy)
    for item in catalog:
        binary = str(item.get('binary') or '').strip()
        binary_available = True if not binary else bool(shutil.which(binary))
        nse_state = nse_script_preflight(item.get('nse_scripts') or [])
        item['nse_preflight'] = nse_state
        item['runtime_available'] = bool(binary_available and nse_state.get('available', True))
        item['runtime_requirement'] = binary
        dependencies = [binary] if binary else []
        if item.get('nse_scripts'):
            dependencies.append('NSE: ' + ', '.join(item.get('nse_scripts') or []))
        item['runtime_dependencies'] = '; '.join(dependencies)
        if binary_available and nse_state.get('known') and nse_state.get('missing'):
            item['runtime_unavailable_reason'] = 'Missing Nmap NSE script(s): ' + ', '.join(nse_state.get('missing') or [])
        elif not binary_available and binary:
            item['runtime_unavailable_reason'] = f'Missing binary: {binary}'
        else:
            item['runtime_unavailable_reason'] = ''
    return {
        'catalog': catalog,
        'groups': list(COLLECTOR_GROUPS),
        'presets': dict(COLLECTION_PRESETS),
        'policy_status': status,
        'policy_sha256': policy_hash,
    }
