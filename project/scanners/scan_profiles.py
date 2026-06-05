
from __future__ import annotations
from typing import Iterable, Any

TOOL_OPTIONS = [
    {
        'id': 'context_footprinting',
        'label': 'Context footprinting',
        'category': 'Pre-checks',
        'purpose': 'Reverse DNS and route-path context using dig and mtr/traceroute.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'arp_scan',
        'label': 'Local ARP discovery',
        'category': 'Pre-checks',
        'purpose': 'Local network visibility using arp-scan where available.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'tcp_discovery',
        'label': 'Full TCP port discovery',
        'category': 'Core discovery',
        'purpose': 'Nmap full TCP port discovery across the target.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'service_fingerprint',
        'label': 'Service fingerprinting',
        'category': 'Core discovery',
        'purpose': 'Nmap service, product, version and CPE evidence collection.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'udp_discovery',
        'label': 'UDP discovery',
        'category': 'Core discovery',
        'purpose': 'Nmap UDP service discovery. Fast uses top 50 ports; full uses top 200 ports.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'web_scripts',
        'label': 'HTTP evidence scripts',
        'category': 'Web',
        'purpose': 'Nmap HTTP titles, headers, server banners and known-path evidence.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'httpx',
        'label': 'HTTP technology probe',
        'category': 'Web',
        'purpose': 'ProjectDiscovery httpx technology, title, status and server hints.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'deep_web_discovery',
        'label': 'Directory discovery',
        'category': 'Web',
        'purpose': 'Gobuster directory discovery using the configured wordlist.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'smb_enum',
        'label': 'SMB enumeration',
        'category': 'File sharing',
        'purpose': 'enum4linux-ng and smbclient SMB share/domain/user/OS evidence.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'smbmap',
        'label': 'SMB permission mapping',
        'category': 'File sharing',
        'purpose': 'smbmap share visibility and permission mapping.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'ssh_audit',
        'label': 'SSH configuration review',
        'category': 'Service checks',
        'purpose': 'ssh-audit algorithm and configuration evidence.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'focused_service_checks',
        'label': 'Focused service checks',
        'category': 'Service checks',
        'purpose': 'Targeted checks for FTP, Telnet, SMTP, DNS, RPC/NFS, RMI, databases, VNC, X11, IRC, AJP/Tomcat and unknown services.',
        'fast': True,
        'full': True,
    },
    {
        'id': 'snmp',
        'label': 'SNMP walk',
        'category': 'Service checks',
        'purpose': 'SNMP public-community walk when UDP/161 is observed.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'ldap',
        'label': 'LDAP naming context check',
        'category': 'Service checks',
        'purpose': 'LDAP base naming-context collection when LDAP is observed.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'tls',
        'label': 'TLS certificate and cipher check',
        'category': 'Service checks',
        'purpose': 'sslscan certificate and cipher evidence for TLS-enabled services.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'rdp',
        'label': 'RDP security check',
        'category': 'Service checks',
        'purpose': 'RDP encryption and NTLM evidence when RDP is observed.',
        'fast': False,
        'full': True,
    },
    {
        'id': 'default_credential_checks',
        'label': 'Default credential checks',
        'category': 'Credential exposure',
        'purpose': 'Hydra checks using the configured permitted credential file.',
        'fast': False,
        'full': True,
    },
]

VALID_TOOL_IDS = {tool['id'] for tool in TOOL_OPTIONS}
PROFILE_LABELS = {
    'fast': 'Fast Recon',
    'full': 'Full Recon',
    'custom': 'Custom Recon',
}

def profile_tool_ids(profile: str) -> list[str]:
    profile = (profile or 'fast').lower()
    if profile == 'full':
        return [tool['id'] for tool in TOOL_OPTIONS if tool.get('full')]
    if profile == 'custom':
        return [tool['id'] for tool in TOOL_OPTIONS if tool.get('fast')]
    return [tool['id'] for tool in TOOL_OPTIONS if tool.get('fast')]

def normalise_scan_options(profile: str | None = None, enabled_tools: Iterable[str] | None = None) -> dict[str, Any]:
    profile = (profile or 'fast').lower()
    if profile not in PROFILE_LABELS:
        profile = 'fast'
    if enabled_tools is None:
        selected = set(profile_tool_ids(profile))
    else:
        selected = {str(x) for x in enabled_tools if str(x) in VALID_TOOL_IDS}
    return {
        'profile': profile,
        'profile_label': PROFILE_LABELS.get(profile, 'Fast Recon'),
        'enabled_tools': sorted(selected),
        'enabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] in selected],
        'disabled_tool_labels': [tool['label'] for tool in TOOL_OPTIONS if tool['id'] not in selected],
    }

def is_tool_enabled(options: dict[str, Any] | None, tool_id: str) -> bool:
    if not options:
        options = normalise_scan_options('fast')
    return tool_id in set(options.get('enabled_tools') or [])
