from __future__ import annotations
from typing import Iterable, Any
import json
from pathlib import Path

"""Two-mode recon profile selection.

Company-review design: only Full Recon and Custom Recon are user-facing.
Full Recon enables every evidence-only recon collector that remains inside
Matthew's reconnaissance boundary. Custom Recon respects exact user-selected
collectors. No scoring, exploitation, brute force, or teammate Caldera/AI logic
is introduced here.
"""

TOOL_OPTIONS = [
    {'id':'passive_dns','label':'Passive DNS intelligence','category':'Passive','purpose':'Collect approved DNS record evidence including MX/TXT/SRV/NS/CNAME without authentication or exploitation.','full':True},
    {'id':'passive_tls','label':'Passive TLS certificate intelligence','category':'Passive','purpose':'Collect TLS certificate, SAN, issuer and negotiated TLS evidence from observed TLS endpoints.','full':True},
    {'id':'passive_fingerprinting','label':'Passive enterprise fingerprinting','category':'Passive','purpose':'Infer email, authentication, VPN, CDN, reverse proxy, cloud and technology hints from already collected DNS/TLS/HTTP evidence.','full':True},
    {'id':'certificate_transparency','label':'Certificate Transparency awareness','category':'Passive / Policy-gated','purpose':'Policy-controlled public certificate name discovery when external intelligence is approved.','full':True},
    {'id':'passive_packet_inventory','label':'Passive local packet inventory','category':'Passive','purpose':'Listen-only ARP/mDNS/DHCP/LLMNR inventory using tshark when an interface is approved; no target probes generated.','full':True},
    {'id':'passive_os_fingerprinting','label':'Passive OS fingerprinting','category':'Passive','purpose':'Listen-only p0f OS hints from ambient traffic when an interface is approved; no target probes generated.','full':True},

    {'id':'environment_characterisation','label':'Environment characterisation','category':'Stage 0','purpose':'Basic reachability and observed behaviour before heavier enumeration.','full':True},
    {'id':'tcp_discovery','label':'Full TCP discovery strategy','category':'Stage 1','purpose':'Top-100 TCP discovery with high-value targeted expansion for enterprise and legacy services.','full':True},
    {'id':'udp_discovery','label':'Targeted UDP discovery','category':'Stage 1','purpose':'Top/service-driven UDP discovery for DNS, SNMP, NTP, NetBIOS and NFS/RPC-related surfaces.','full':True},
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
]

VALID_TOOL_IDS = {tool['id'] for tool in TOOL_OPTIONS}
PROFILE_LABELS = {'full':'Full Recon','custom':'Custom Recon'}


def _load_profile_policy() -> dict[str, Any]:
    candidates = [Path('project/policies/recon_policy.json'), Path('policies/recon_policy.json')]
    path = next((x for x in candidates if x.exists()), None)
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def profile_tool_ids(profile: str | None = None) -> list[str]:
    # Only two public modes: Full and Custom. Custom has no implicit default.
    profile_key = (profile or 'full').lower()
    if profile_key == 'custom':
        return []
    policy = _load_profile_policy()
    configured = policy.get('full_recon_enabled_tools') or []
    if configured:
        return [str(x) for x in configured if str(x) in VALID_TOOL_IDS]
    return [tool['id'] for tool in TOOL_OPTIONS if tool.get('full')]


def normalise_scan_options(profile: str | None = None, enabled_tools: Iterable[str] | None = None) -> dict[str, Any]:
    profile_key = (profile or 'full').lower()
    # Backward-compatible input mapping for old URLs/tests, but only two labels are exposed.
    if profile_key in {'adaptive', 'fast'}:
        profile_key = 'full'
    if profile_key not in PROFILE_LABELS:
        profile_key = 'full'

    if profile_key == 'custom':
        selected = {str(x) for x in (enabled_tools or []) if str(x) in VALID_TOOL_IDS}
    elif enabled_tools is not None:
        # Full can still honour posted toggles when the UI sends them; otherwise default to full policy.
        selected = {str(x) for x in enabled_tools if str(x) in VALID_TOOL_IDS}
    else:
        selected = set(profile_tool_ids('full'))

    disabled = VALID_TOOL_IDS - selected
    return {
        'profile': profile_key,
        'profile_label': PROFILE_LABELS[profile_key],
        'strategy': 'two_mode_full_or_custom_enterprise_recon',
        'enabled_tools': sorted(selected),
        'enabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] in selected],
        'disabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] in disabled],
        'objective_driven': True,
    }


def is_tool_enabled(options: dict[str, Any] | None, tool_id: str) -> bool:
    if not options:
        options = normalise_scan_options('full')
    return tool_id in set(options.get('enabled_tools') or [])
