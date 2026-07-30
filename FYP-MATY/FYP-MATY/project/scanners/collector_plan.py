from __future__ import annotations

"""Operator-facing recon collection planning.

This module separates four concepts that used to be conflated in the UI:
operator intent, policy permission, runtime applicability, and execution outcome.
It contains no target/CVE/product facts and never builds raw shell commands.
"""

from copy import deepcopy
from typing import Any, Iterable, Mapping
from pathlib import Path
import re

CORE_TOOL_IDS = {
    "environment_characterisation",
    "tcp_discovery",
    "udp_discovery",
    "service_fingerprint",
}

COLLECTOR_GROUPS = [
    {"id": "host_identity", "label": "Host & Operating System Identity", "description": "Cross-platform OS, SMB/NTLM, NetBIOS and RPC identity evidence. Activated from observed protocol evidence, never a preselected target OS."},
    {"id": "passive", "label": "Passive & Local Observation", "description": "Listen-only or already-collected intelligence."},
    {"id": "web_http", "label": "Web & HTTP", "description": "HTTP, API, web metadata and bounded web evidence."},
    {"id": "remote_access", "label": "Remote Access", "description": "SSH, Telnet, RDP, VNC and management-listener evidence."},
    {"id": "file_directory", "label": "File Sharing & Directory Services", "description": "SMB, NFS/RPC, LDAP and Kerberos evidence."},
    {"id": "network_dns", "label": "Network & DNS", "description": "DNS, SNMP and network-service identity evidence."},
    {"id": "databases", "label": "Databases & Data Services", "description": "Database/search service readiness and identity evidence."},
    {"id": "app_platform", "label": "Application & Platform Services", "description": "AJP, containers, Kubernetes, VPN and cross-protocol metadata."},
]

def _timeout_setting(default: int, maximum: int, minimum: int = 1) -> dict[str, Any]:
    return {"type": "int", "min": minimum, "max": maximum, "default": default, "label": "Execution timeout (seconds)", "policy_max": maximum}

# Metadata is intentionally generic. Service families describe applicability,
# not fixed ports. The runtime still decides applicability from observed evidence.
COLLECTOR_METADATA: dict[str, dict[str, Any]] = {
    "nmap_os_identity": {"group": "host_identity", "scope": "host", "interaction": "active_bounded", "recommended": True, "binary": "nmap", "settings": {"timeout_seconds": _timeout_setting(240, 240, 30)}},
    "windows_patch_inventory": {"group": "host_identity", "scope": "host", "interaction": "local_operator_evidence", "recommended": False, "credential_required": False, "explicit_operator_selection": True, "settings": {"timeout_seconds": _timeout_setting(45, 120, 10)}},
    "smb_host_identity": {"group": "host_identity", "scope": "service", "families": ["smb", "netbios"], "protocols": ["tcp"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["smb-os-discovery", "smb2-capabilities", "smb2-time"], "settings": {"timeout_seconds": _timeout_setting(240, 240, 30)}},
    "netbios_identity": {"group": "host_identity", "scope": "service", "families": ["netbios"], "protocols": ["udp"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["nbstat"], "settings": {"timeout_seconds": _timeout_setting(120, 120, 15)}},
    "msrpc_metadata": {"group": "host_identity", "scope": "service", "families": ["msrpc", "epmap"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["msrpc-enum"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_http_identity": {"group": "host_identity", "scope": "service", "families": ["http", "https", "winrm", "wsman"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["http-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_rdp_identity": {"group": "host_identity", "scope": "service", "families": ["rdp"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["rdp-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_mssql_identity": {"group": "host_identity", "scope": "service", "families": ["mssql", "ms-sql"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["ms-sql-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_smtp_identity": {"group": "host_identity", "scope": "service", "families": ["smtp"], "interaction": "low_active", "recommended": False, "binary": "nmap", "nse_scripts": ["smtp-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_imap_identity": {"group": "host_identity", "scope": "service", "families": ["imap"], "interaction": "low_active", "recommended": False, "binary": "nmap", "nse_scripts": ["imap-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_pop3_identity": {"group": "host_identity", "scope": "service", "families": ["pop3"], "interaction": "low_active", "recommended": False, "binary": "nmap", "nse_scripts": ["pop3-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_nntp_identity": {"group": "host_identity", "scope": "service", "families": ["nntp"], "interaction": "low_active", "recommended": False, "binary": "nmap", "nse_scripts": ["nntp-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "ntlm_telnet_identity": {"group": "host_identity", "scope": "service", "families": ["telnet"], "interaction": "low_active", "recommended": False, "binary": "nmap", "nse_scripts": ["telnet-ntlm-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 20)}},
    "passive_dns": {"group": "passive", "scope": "host", "interaction": "passive", "recommended": True},
    "passive_tls": {"group": "passive", "scope": "service", "families": ["tls", "https"], "interaction": "low_active", "recommended": True},
    "passive_fingerprinting": {"group": "passive", "scope": "host", "interaction": "derived", "recommended": True},
    "certificate_transparency": {"group": "passive", "scope": "host", "interaction": "external_lookup", "recommended": False},
    "passive_packet_inventory": {
        "group": "passive", "scope": "host", "interaction": "passive", "recommended": True, "binary": "tshark",
        "settings": {
            "duration_seconds": {"type": "int", "min": 5, "max": 120, "default": 15, "label": "Capture duration (seconds)"},
            "interface": {"type": "text", "default": "", "max_length": 32, "pattern": r"^[A-Za-z0-9_.:-]*$", "label": "Capture interface (blank = auto)"},
        },
    },
    "passive_os_fingerprinting": {"group": "passive", "scope": "host", "interaction": "passive", "recommended": False, "binary": "p0f"},

    "httpx": {
        "group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "low_active", "recommended": True,
        "binary": "httpx-toolkit",
        "settings": {
            "timeout_seconds": {"type": "int", "min": 1, "max": 30, "default": 5, "label": "Timeout (seconds)"},
            "rate_limit_per_second": {"type": "int", "min": 1, "max": 20, "default": 1, "label": "Rate limit / second"},
            "threads": {"type": "int", "min": 1, "max": 20, "default": 1, "label": "Threads"},
        },
    },
    "http_security_context": {"group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "low_active", "recommended": True, "binary": "curl", "settings": {"request_timeout_seconds": {"type":"int","min":1,"max":5,"default":5,"label":"HTTP request timeout (seconds)","policy_max":5}}},
    "html_form_parser": {"group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "low_active", "recommended": True},
    "targeted_web_discovery": {"group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "active_bounded", "recommended": True},
    "api_discovery": {"group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "active_bounded", "recommended": True},
    "nuclei_safe": {
        "group": "web_http", "scope": "service", "families": ["http", "https"], "interaction": "active_bounded", "recommended": False, "binary": "nuclei",
        "settings": {
            "requests_per_window": {"type": "int", "min": 1, "max": 10, "default": 1, "label": "Requests per rate-limit window"},
            "window_seconds": {"type": "int", "min": 1, "max": 60, "default": 2, "label": "Rate-limit window (seconds)"},
            "retries": {"type": "int", "min": 0, "max": 2, "default": 0, "label": "Retries"},
        },
    },
    "tls_cipher_validation": {"group": "web_http", "scope": "service", "families": ["tls", "https"], "interaction": "active_bounded", "recommended": True, "binary": "nmap", "nse_scripts": ["ssl-enum-ciphers"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 30)}},

    "ssh_auth_methods": {"group": "remote_access", "scope": "service", "families": ["ssh"], "interaction": "low_active", "recommended": True, "binary": "nmap", "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "ssh_audit_native": {"group": "remote_access", "scope": "service", "families": ["ssh"], "interaction": "low_active", "recommended": False, "settings": {"timeout_seconds": _timeout_setting(4, 4, 1)}},
    "telnet_readiness": {"group": "remote_access", "scope": "service", "families": ["telnet"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["telnet-encryption"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "winrm_wsman_probe": {"group": "remote_access", "scope": "service", "families": ["winrm", "wsman"], "interaction": "low_active", "recommended": True, "binary": "curl", "settings": {"request_timeout_seconds": {"type":"int","min":1,"max":5,"default":5,"label":"HTTP request timeout (seconds)","policy_max":5}}},
    "rdp_negotiation": {"group": "remote_access", "scope": "service", "families": ["rdp"], "interaction": "active_bounded", "recommended": True, "binary": "nmap", "nse_scripts": ["rdp-enum-encryption"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 30)}},
    "vnc_info": {"group": "remote_access", "scope": "service", "families": ["vnc"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["vnc-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},

    "ftp_anonymous_status": {"group": "file_directory", "scope": "service", "families": ["ftp"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["ftp-anon", "ftp-syst"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "smb_protocol_security": {"group": "file_directory", "scope": "service", "families": ["smb", "netbios"], "protocols": ["tcp"], "component_families": ["smb"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["smb-protocols", "smb-security-mode", "smb2-security-mode"], "settings": {"timeout_seconds": _timeout_setting(240, 240, 15)}},
    "rpcinfo_native": {"group": "file_directory", "scope": "service", "families": ["rpcbind", "portmapper", "nfs", "mountd"], "protocols": ["tcp", "udp"], "interaction": "low_active", "recommended": True, "binary": "rpcinfo", "settings": {"timeout_seconds": _timeout_setting(45, 45, 5)}},
    "showmount_native": {"group": "file_directory", "scope": "service", "families": ["nfs", "mountd", "rpcbind", "portmapper"], "protocols": ["tcp", "udp"], "interaction": "low_active", "recommended": True, "binary": "showmount", "settings": {"timeout_seconds": _timeout_setting(45, 45, 5)}},
    "ldap_rootdse": {"group": "file_directory", "scope": "service", "families": ["ldap"], "interaction": "active_bounded", "recommended": True, "binary": "nmap", "nse_scripts": ["ldap-rootdse"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 30)}},
    "ldapsearch_rootdse": {"group": "file_directory", "scope": "service", "families": ["ldap"], "interaction": "low_active", "recommended": True, "binary": "ldapsearch", "settings": {"timeout_seconds": _timeout_setting(60, 60, 5)}},
    "kerberos_info": {"group": "file_directory", "scope": "service", "families": ["kerberos"], "interaction": "active_bounded", "recommended": True, "binary": "nmap", "nse_scripts": ["krb5-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 30)}},

    "dns_context": {"group": "network_dns", "scope": "service", "families": ["dns", "domain"], "interaction": "low_active", "recommended": True, "binary": "dig", "settings": {"timeout_seconds": _timeout_setting(30, 30, 5)}},
    "snmp_readiness": {"group": "network_dns", "scope": "service", "families": ["snmp"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["snmp-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "snmp_targeted_oids": {"group": "network_dns", "scope": "service", "families": ["snmp"], "interaction": "credentialed_read", "recommended": False, "binary": "snmpget", "credential_required": True, "explicit_operator_selection": True, "settings": {"timeout_seconds": _timeout_setting(45, 45, 5)}},

    "postgres_readiness_native": {"group": "databases", "scope": "service", "families": ["postgresql", "postgres"], "interaction": "low_active", "recommended": True, "binary": "pg_isready", "settings": {"timeout_seconds": _timeout_setting(30, 30, 5)}},
    "mssql_info": {"group": "databases", "scope": "service", "families": ["mssql", "ms-sql"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["ms-sql-info"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "redis_info": {"group": "databases", "scope": "service", "families": ["redis"], "interaction": "low_active", "recommended": True},
    "elasticsearch_info": {"group": "databases", "scope": "service", "families": ["elasticsearch"], "interaction": "low_active", "recommended": True},

    "tomcat_ajp_readiness": {"group": "app_platform", "scope": "service", "families": ["ajp", "tomcat", "http"], "interaction": "low_active", "recommended": True, "binary": "nmap", "nse_scripts": ["ajp-headers"], "settings": {"timeout_seconds": _timeout_setting(180, 180, 15)}},
    "kubernetes_exposure": {"group": "app_platform", "scope": "service", "families": ["http", "https", "kubernetes"], "interaction": "active_bounded", "recommended": True},
    "container_exposure": {"group": "app_platform", "scope": "service", "families": ["http", "https", "docker", "registry"], "interaction": "active_bounded", "recommended": True},
    "vpn_validation": {"group": "app_platform", "scope": "service", "families": ["http", "https", "vpn"], "interaction": "active_bounded", "recommended": True},
    "native_protocol_enrichment": {"group": "app_platform", "scope": "service", "families": ["ftp", "smtp", "mysql", "postgresql", "irc", "vnc"], "interaction": "low_active", "recommended": True},
}


# Evidence capabilities are scanner capabilities, not target facts. They state
# what a collector can directly return when it executes successfully. Adaptive
# recovery uses these facts instead of hardcoded target/CVE branches.
COLLECTOR_PRODUCES: dict[str, list[str]] = {
    "nmap_os_identity": ["host_os"],
    "smb_host_identity": ["host_identity", "host_os", "hostname", "domain_identity", "protocol_capabilities"],
    "netbios_identity": ["host_identity", "hostname", "domain_identity", "protocol_metadata"],
    "msrpc_metadata": ["protocol_metadata", "advertised_endpoints"],
    "ntlm_http_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_rdp_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_mssql_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_smtp_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_imap_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_pop3_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_nntp_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "ntlm_telnet_identity": ["host_identity", "host_build", "hostname", "domain_identity"],
    "httpx": ["service_product", "service_version", "protocol_metadata"],
    "http_security_context": ["protocol_metadata", "security_configuration"],
    "tls_cipher_validation": ["tls_configuration", "security_configuration"],
    "ssh_auth_methods": ["authentication_configuration"],
    "ssh_audit_native": ["protocol_metadata", "security_configuration"],
    "telnet_readiness": ["security_configuration"],
    "winrm_wsman_probe": ["protocol_metadata"],
    "rdp_negotiation": ["security_configuration"],
    "vnc_info": ["service_product", "service_version", "protocol_metadata"],
    "ftp_anonymous_status": ["protocol_metadata", "security_configuration"],
    "smb_protocol_security": ["protocol_component", "service_version", "protocol_security", "security_configuration"],
    "rpcinfo_native": ["service_product", "service_version", "protocol_metadata"],
    "showmount_native": ["protocol_metadata", "security_configuration"],
    "ldap_rootdse": ["protocol_metadata", "domain_identity"],
    "ldapsearch_rootdse": ["protocol_metadata", "domain_identity"],
    "kerberos_info": ["protocol_metadata", "domain_identity"],
    "dns_context": ["service_product", "service_version", "protocol_metadata"],
    "snmp_readiness": ["service_product", "service_version", "protocol_metadata"],
    "snmp_targeted_oids": ["service_product", "service_version", "protocol_metadata"],
    "postgres_readiness_native": ["protocol_metadata"],
    "mssql_info": ["service_product", "service_version", "protocol_metadata"],
    "redis_info": ["service_product", "service_version", "protocol_metadata"],
    "elasticsearch_info": ["service_product", "service_version", "protocol_metadata"],
    "tomcat_ajp_readiness": ["service_product", "service_version", "protocol_metadata"],
    "native_protocol_enrichment": ["service_product", "service_version", "protocol_metadata"],
}



NSE_SCRIPT_DIR_CANDIDATES = (
    Path('/usr/share/nmap/scripts'),
    Path('/usr/local/share/nmap/scripts'),
    Path('/opt/homebrew/share/nmap/scripts'),
)

def nse_script_preflight(scripts: Iterable[str]) -> dict[str, Any]:
    """Check local Nmap NSE payload availability without any target traffic.

    Nmap can be installed into non-standard data directories, so absence of a
    known script directory is reported as unknown rather than unavailable.
    When a standard script directory exists, missing scripts are definitive
    pre-flight failures and can be surfaced before launch.
    """
    requested = [str(x).strip() for x in scripts if str(x).strip()]
    dirs = [path for path in NSE_SCRIPT_DIR_CANDIDATES if path.is_dir()]
    if not requested:
        return {'known': True, 'available': True, 'missing': [], 'directories': [str(x) for x in dirs]}
    if not dirs:
        return {'known': False, 'available': True, 'missing': [], 'directories': []}
    missing = [
        script for script in requested
        if not any((directory / f'{script}.nse').is_file() for directory in dirs)
    ]
    return {
        'known': True,
        'available': not missing,
        'missing': missing,
        'directories': [str(x) for x in dirs],
    }

COLLECTION_PRESETS = {
    "recommended": {
        "label": "Recommended",
        "description": "Broad low-impact evidence coverage with service-conditional collectors.",
    },
    "maximum": {
        "label": "Maximum Evidence",
        "description": "Request every recon-owned collector; policy and applicability still remain authoritative.",
    },
    "minimal": {
        "label": "Minimal / Low Interaction",
        "description": "Passive intelligence plus essential low-interaction identity collection.",
    },
    "custom": {
        "label": "Custom",
        "description": "Operator-defined collector plan.",
    },
}

MINIMAL_IDS = {
    "passive_dns", "passive_tls", "passive_fingerprinting", "passive_packet_inventory",
    "http_security_context", "dns_context", "native_protocol_enrichment",
}


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(default)
    return max(low, min(high, number))


def _normalise_setting(spec: Mapping[str, Any], value: Any) -> Any:
    if spec.get("type") == "int":
        return _int(value, int(spec.get("default") or 0), int(spec.get("min") or 0), int(spec.get("max") or 2**31 - 1))
    if spec.get("type") == "bool":
        return _bool(value, bool(spec.get("default", False)))
    text = str(value if value is not None else spec.get("default") or "").strip()
    max_length = int(spec.get("max_length") or 256)
    text = text[:max_length]
    pattern = spec.get("pattern")
    if pattern and not re.fullmatch(str(pattern), text):
        return str(spec.get("default") or "")
    return text


def build_collector_catalog(base_tools: Iterable[Mapping[str, Any]], policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    disabled = {str(x) for x in policy.get("automatic_collectors_disabled") or []}
    out: list[dict[str, Any]] = []
    for base in base_tools:
        tool_id = str(base.get("id") or "")
        if not tool_id or tool_id in CORE_TOOL_IDS:
            continue
        item = deepcopy(dict(base))
        meta = deepcopy(COLLECTOR_METADATA.get(tool_id) or {})
        item.update(meta)
        item.setdefault("group", "app_platform")
        item.setdefault("scope", "service")
        item.setdefault("families", [])
        item.setdefault("protocols", [])
        item.setdefault("component_families", [])
        item["produces"] = list(COLLECTOR_PRODUCES.get(tool_id) or item.get("produces") or [])
        item.setdefault("interaction", "low_active")
        item.setdefault("recommended", bool(base.get("full", True)))
        item.setdefault("settings", {})
        # Reflect effective policy ceilings in the operator catalogue so the UI
        # never advertises values that the runtime will silently clamp.
        if tool_id == 'httpx':
            httpx_policy = dict(policy.get('httpx_options') or {})
            for setting_key, policy_key in (
                ('timeout_seconds', 'timeout_seconds'),
                ('rate_limit_per_second', 'rate_limit_per_second'),
                ('threads', 'threads'),
            ):
                spec = (item.get('settings') or {}).get(setting_key)
                if isinstance(spec, dict) and httpx_policy.get(policy_key) is not None:
                    policy_max = int(httpx_policy[policy_key])
                    spec['max'] = max(int(spec.get('min') or 1), min(int(spec.get('max') or policy_max), policy_max))
                    spec['default'] = min(int(spec.get('default') or spec['max']), spec['max'])
                    spec['policy_max'] = spec['max']
        item["minimal"] = tool_id in MINIMAL_IDS
        item["policy_blocked"] = tool_id in disabled
        item["policy_reason"] = "Disabled by effective recon policy" if item["policy_blocked"] else ""
        item["allowed_modes"] = ["auto", "disabled"] if item["scope"] == "service" else ["always", "disabled"]
        out.append(item)
    return out


def preset_ids(catalog: Iterable[Mapping[str, Any]], preset: str) -> set[str]:
    key = preset if preset in COLLECTION_PRESETS else "recommended"
    rows = [item for item in catalog if item.get("id")]
    ids = {str(item.get("id")) for item in rows}
    # Collectors marked for explicit selection are never silently enabled by a
    # preset. This includes local evidence sources whose input path must be
    # deliberately supplied by the operator.
    explicit_only = {
        str(item.get("id"))
        for item in rows
        if item.get("credential_required") or item.get("explicit_operator_selection")
    }
    if key == "maximum":
        return ids - explicit_only
    if key == "minimal":
        return (ids & MINIMAL_IDS) - explicit_only
    if key == "custom":
        return set()
    return {
        str(item.get("id"))
        for item in rows
        if item.get("recommended") and str(item.get("id")) not in explicit_only
    }


def normalise_collection_plan(
    base_tools: Iterable[Mapping[str, Any]],
    policy: Mapping[str, Any],
    preset: str | None,
    raw_plan: Mapping[str, Any] | None,
    legacy_enabled_tools: Iterable[str] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    catalog = build_collector_catalog(base_tools, policy)
    catalog_by_id = {str(item["id"]): item for item in catalog}
    selected_preset = str(preset or "recommended").lower()
    if selected_preset not in COLLECTION_PRESETS:
        selected_preset = "recommended"
    defaults = preset_ids(catalog, selected_preset)
    legacy = {str(x) for x in (legacy_enabled_tools or []) if str(x) in catalog_by_id}
    if legacy_enabled_tools is not None and raw_plan is None:
        defaults = legacy
    raw_plan = dict(raw_plan or {})
    disabled_by_policy = {str(x) for x in policy.get("automatic_collectors_disabled") or []}

    plan: dict[str, dict[str, Any]] = {}
    enabled: list[str] = []
    conflicts: list[str] = []
    for tool_id, descriptor in catalog_by_id.items():
        incoming = raw_plan.get(tool_id)
        incoming = incoming if isinstance(incoming, Mapping) else {}
        default_mode = "always" if descriptor.get("scope") == "host" else "auto"
        if tool_id not in defaults and selected_preset != "custom":
            default_mode = "disabled"
        if selected_preset == "custom" and not incoming and tool_id not in defaults:
            default_mode = "disabled"
        mode = str(incoming.get("mode") or default_mode).lower()
        allowed_modes = set(descriptor.get("allowed_modes") or ["auto", "disabled"])
        if mode not in allowed_modes:
            mode = default_mode if default_mode in allowed_modes else "disabled"
        requested = mode != "disabled"
        # Presets describe operator intent. A policy-blocked collector remains
        # requested by a preset such as Maximum Evidence, then is recorded as
        # blocked rather than silently converted into an operator-disabled item.
        if tool_id in disabled_by_policy and selected_preset != 'custom' and tool_id in defaults:
            requested = True
            mode = 'always' if descriptor.get('scope') == 'host' else 'auto'
        settings: dict[str, Any] = {}
        setting_provenance: dict[str, dict[str, Any]] = {}
        raw_settings = incoming.get("settings") if isinstance(incoming.get("settings"), Mapping) else {}
        for key, spec in (descriptor.get("settings") or {}).items():
            effective_value = _normalise_setting(spec, raw_settings.get(key))
            settings[key] = effective_value
            requested_value = raw_settings.get(key) if key in raw_settings else spec.get("default")
            setting_provenance[key] = {
                "requested": requested_value,
                "effective": effective_value,
                "policy_min": spec.get("min"),
                "policy_max": spec.get("policy_max", spec.get("max")),
                "source": "operator" if key in raw_settings else "default",
                "clamped": requested_value != effective_value,
                "reason": (
                    "normalised_to_policy_bounds_or_format"
                    if requested_value != effective_value else ""
                ),
            }
        blocked = requested and tool_id in disabled_by_policy
        if blocked:
            conflicts.append(tool_id)
        effective = requested and not blocked
        if effective:
            enabled.append(tool_id)
        plan[tool_id] = {
            "mode": mode,
            "requested": requested,
            "effective_enabled": effective,
            "policy_state": "blocked" if blocked else "permitted",
            "policy_reason": "Disabled by effective recon policy" if blocked else "",
            "scope": descriptor.get("scope"),
            "families": list(descriptor.get("families") or []),
            "protocols": list(descriptor.get("protocols") or []),
            "component_families": list(descriptor.get("component_families") or []),
            "produces": list(descriptor.get("produces") or []),
            "group": descriptor.get("group"),
            "interaction": descriptor.get("interaction"),
            "credential_required": bool(descriptor.get("credential_required")),
            "explicit_operator_selection": bool(descriptor.get("explicit_operator_selection")),
            "binary": descriptor.get("binary") or "",
            "nse_scripts": list(descriptor.get("nse_scripts") or []),
            "settings": settings,
            "setting_provenance": setting_provenance,
        }
    return plan, sorted(enabled), sorted(conflicts)


def normalise_host_discovery(policy: Mapping[str, Any], raw: Mapping[str, Any] | None = None) -> dict[str, Any]:
    cfg = dict(policy.get("host_discovery_controls") or {})
    raw = dict(raw or {})
    allowed = dict(cfg.get("allowed") or {})
    defaults = dict(cfg.get("defaults") or {})
    requested = {
        "arp_discovery": _bool(raw.get("arp_discovery"), bool(defaults.get("arp_discovery", True))),
        "icmp_echo": _bool(raw.get("icmp_echo"), bool(defaults.get("icmp_echo", True))),
        "nmap_host_discovery": _bool(raw.get("nmap_host_discovery"), bool(defaults.get("nmap_host_discovery", False))),
        "reverse_dns": _bool(raw.get("reverse_dns"), bool(defaults.get("reverse_dns", False))),
        "route_trace": _bool(raw.get("route_trace"), bool(defaults.get("route_trace", False))),
    }
    effective: dict[str, bool] = {}
    blocked: list[str] = []
    for key, value in requested.items():
        permitted = bool(allowed.get(key, True))
        effective[key] = bool(value and permitted)
        if value and not permitted:
            blocked.append(key)
    return {
        "requested": requested,
        "effective": effective,
        "policy_blocked": blocked,
        "icmp_attempts": _int(raw.get("icmp_attempts"), int(defaults.get("icmp_attempts") or 1), 1, 4),
        "icmp_timeout_seconds": _int(raw.get("icmp_timeout_seconds"), int(defaults.get("icmp_timeout_seconds") or 2), 1, 10),
        "route_max_hops": _int(raw.get("route_max_hops"), int(defaults.get("route_max_hops") or 8), 1, 30),
        "assume_single_target_live": _bool(raw.get("assume_single_target_live"), bool(defaults.get("assume_single_target_live", True))),
    }


def normalise_service_identity(policy: Mapping[str, Any], raw: Mapping[str, Any] | None = None) -> dict[str, Any]:
    raw = dict(raw or {})
    recovery = dict(policy.get("version_evidence_recovery") or {})
    defaults = dict(policy.get("service_identity_defaults") or {})
    return {
        "tcp_discovery_enabled": _bool(raw.get("tcp_discovery_enabled"), bool(defaults.get("tcp_discovery_enabled", True))),
        "udp_discovery_enabled": _bool(raw.get("udp_discovery_enabled"), bool(defaults.get("udp_discovery_enabled", True))),
        "service_fingerprinting_enabled": _bool(raw.get("service_fingerprinting_enabled"), bool(defaults.get("service_fingerprinting_enabled", True))),
        "version_intensity": _int(raw.get("version_intensity"), int(defaults.get("version_intensity") or 0), 0, 9),
        "banner_script": _bool(raw.get("banner_script"), bool(defaults.get("banner_script", True))),
        "version_recovery": _bool(raw.get("version_recovery"), bool(recovery.get("enabled", True))),
        # The existing recovery intensity is the operator/policy recovery ceiling.
        # Adaptive passes move transparently from the initial fingerprint level
        # toward this value; no additional intensity is invented.
        "recovery_intensity": _int(raw.get("recovery_intensity"), int(recovery.get("nmap_version_intensity") or 2), 0, 9),
        "recovery_max_ports": _int(raw.get("recovery_max_ports"), int(recovery.get("max_ports_per_host") or 64), 1, 256),
        "recovery_attempts": _int(raw.get("recovery_attempts"), int(defaults.get("recovery_attempts") or 1), 1, 4),
        # Version recovery applies to both selected transports. UDP recovery is
        # bounded to already-selected UDP endpoints and can never add new ports.
        "adaptive_evidence_recovery": _bool(raw.get("adaptive_evidence_recovery"), bool(recovery.get("enabled", True))),
        "udp_evidence_recovery": _bool(raw.get("udp_evidence_recovery"), bool(recovery.get("enabled", True))),
        "follow_protocol_advertised_endpoints": _bool(
            raw.get("follow_protocol_advertised_endpoints"),
            bool(defaults.get("follow_protocol_advertised_endpoints", False)),
        ),
        "advertised_endpoint_limit": _int(
            raw.get("advertised_endpoint_limit"),
            int(defaults.get("advertised_endpoint_limit") or 8),
            1, 32,
        ),
    }


def setting(plan: Mapping[str, Any] | None, collector_id: str, key: str, default: Any = None) -> Any:
    collector = (plan or {}).get(collector_id) if isinstance(plan, Mapping) else None
    if not isinstance(collector, Mapping):
        return default
    settings = collector.get("settings")
    if not isinstance(settings, Mapping):
        return default
    return settings.get(key, default)
