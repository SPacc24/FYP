# for testng , scan result
client_scan_results = [
    {"port": 22, "service": "ssh", "version": "OpenSSH 7.6"},
    {"port": 80, "service": "http", "version": "Apache 2.4.49"},
    {"port": 445, "service": "smb", "version": "Windows SMBv1"}
]

server_scan_results = [
    {"port": 22, "service": "ssh", "cve": "CVE-2018-15473", "severity": "Medium"},
    {"port": 80, "service": "http", "cve": "CVE-2021-41773", "severity": "High"},
    {"port": 445, "service": "smb", "cve": "CVE-2017-0144", "severity": "Critical"}
]

TECHNIQUE_RULES = {
    "microsoft-ds": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "risk": "High",
        "reason": "SMB is exposed, which may support remote access or lateral movement testing.",
        "remediation": "Restrict SMB access, disable SMBv1, enforce SMB signing, and apply Windows security updates."
    },

    "ms-wbt-server": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "risk": "High",
        "reason": "RDP is exposed, which may allow remote login-based attack simulation.",
        "remediation": "Restrict RDP access, use VPN/MFA, disable unused RDP, and monitor failed login attempts."
    },

    "ldap": {
        "technique_id": "T1087.002",
        "technique_name": "Account Discovery: Domain Account",
        "risk": "Medium",
        "reason": "LDAP indicates Active Directory services are available and may allow domain enumeration testing.",
        "remediation": "Limit LDAP exposure, restrict anonymous queries, and monitor directory enumeration activity."
    },

    "kerberos-sec": {
        "technique_id": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets",
        "risk": "High",
        "reason": "Kerberos is present, meaning the system is part of an Active Directory authentication environment.",
        "remediation": "Use strong passwords, monitor Kerberos ticket activity, rotate service account passwords, and enforce least privilege."
    },

    "domain": {
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "risk": "Low",
        "reason": "DNS service is exposed and can reveal domain/network structure.",
        "remediation": "Restrict DNS zone transfers and limit DNS exposure to trusted systems."
    },

    "msrpc": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "risk": "Medium",
        "reason": "MSRPC is exposed on Windows systems and may support remote management or enumeration testing.",
        "remediation": "Restrict RPC access using firewall rules and disable unnecessary remote management services."
    },

    "netbios-ssn": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "risk": "Medium",
        "reason": "NetBIOS can reveal host, workgroup, and domain information.",
        "remediation": "Disable NetBIOS if unnecessary and restrict access to trusted internal hosts."
    },

    "http": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "risk": "High",
        "reason": "HTTP service is exposed and may represent a web-based attack surface.",
        "remediation": "Patch web services, restrict admin panels, validate inputs, and monitor web access logs."
    },

    "ssl/http": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "risk": "High",
        "reason": "HTTPS/SSL web service is exposed and may represent a web-based attack surface.",
        "remediation": "Patch web services, renew expired certificates, restrict admin access, and monitor web access logs."
    },

    "ncacn_http": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "risk": "Medium",
        "reason": "RPC over HTTP is exposed and may support remote Windows communication.",
        "remediation": "Restrict RPC over HTTP access and disable it if not required."
    },

    "smb": {
    "technique_id": "T1021.002",
    "technique_name": "Remote Services: SMB/Windows Admin Shares",
    "risk": "High",
    "reason": "SMB is exposed, which may support remote access or lateral movement testing.",
    "remediation": "Restrict SMB access, disable SMBv1, enforce SMB signing, and apply Windows security updates."
    },
    
}

# RISK SORTING
RISK_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}


# attack plan 
def recommend_techniques(scan_results):
    recommendations = []

    for item in scan_results:
        service = item["service"].lower()

        if service in TECHNIQUE_RULES:
            rule = TECHNIQUE_RULES[service]

            recommendations.append({
                "target": item.get("target", "Unknown"),
                "host": item.get("host", "Unknown"),
                "port": item["port"],
                "service": service,
                "version": item.get("version", "Unknown"),
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "risk": rule["risk"],
                "reason": rule["reason"],
                "remediation": rule["remediation"]
            })

    recommendations.sort(
        key=lambda x: RISK_ORDER.get(x["risk"], 0),
        reverse=True
    )

    return recommendations

def get_all_manual_techniques():
    manual_list = []

    seen = set()

    for service, rule in TECHNIQUE_RULES.items():
        unique_key = rule["technique_id"]

        if unique_key not in seen:
            seen.add(unique_key)
            manual_list.append({
                "service": service,
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "risk": rule["risk"],
                "reason": rule["reason"],
                "remediation": rule["remediation"]
            })

    manual_list.sort(
        key=lambda x: RISK_ORDER.get(x["risk"], 0),
        reverse=True
    )

    return manual_list

# MODE
def auto_mode(scan_results):
    recommended = recommend_techniques(scan_results)

    return {
        "mode": "auto",
        "description": "Rule-based selection from detected ports and services. No user input needed.",
        "attack_plan": recommended
    }

def hybrid_mode(scan_results):
    recommended = recommend_techniques(scan_results)

    print("\nHYBRID MODE")
    print("System recommends techniques. Analyst reviews and edits before confirming.")

    if not recommended:
        return {
            "mode": "hybrid",
            "description": "No recommended techniques found.",
            "attack_plan": []
        }

    print("\nRecommended techniques:")

    for index, item in enumerate(recommended, start=1):
        print(f"{index}. {item['technique_id']} - {item['technique_name']}")
        print(f"   Port/Service: {item['port']} / {item['service']}")
        print(f"   Risk: {item['risk']}")

    choices = input("\nEnter technique numbers to KEEP, separated by commas e.g. 1,3: ")

    selected = []

    if choices.strip():
        for choice in choices.split(","):
            try:
                index = int(choice.strip()) - 1

                if 0 <= index < len(recommended):
                    selected.append(recommended[index])

            except ValueError:
                print(f"Skipping invalid choice: {choice}")

    return {
        "mode": "hybrid",
        "description": "Analyst reviewed system recommendations and selected techniques for execution.",
        "attack_plan": selected
    }

def manual_mode(scan_results):
    all_techniques = get_all_manual_techniques()

    print("\nMANUAL MODE")
    print("Expert browses all available techniques and selects manually.")

    print("\nAvailable techniques:")

    for index, item in enumerate(all_techniques, start=1):
        print(f"{index}. {item['technique_id']} - {item['technique_name']}")
        print(f"   Risk: {item['risk']}")
        print(f"   Service mapping: {item['service']}")

    choices = input("\nEnter technique numbers to SELECT, separated by commas e.g. 1,4,5: ")

    selected = []

    if choices.strip():
        for choice in choices.split(","):
            try:
                index = int(choice.strip()) - 1

                if 0 <= index < len(all_techniques):
                    rule = all_techniques[index]

                    selected.append({
                        "target": "User-selected",
                        "host": "Manual mode",
                        "port": "N/A",
                        "service": rule["service"],
                        "version": "N/A",
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "risk": rule["risk"],
                        "reason": "User manually selected this technique.",
                        "remediation": rule["remediation"]
                    })

            except ValueError:
                print(f"Skipping invalid choice: {choice}")

    return {
        "mode": "manual",
        "description": "User manually selected techniques from all available ATT&CK mappings.",
        "attack_plan": selected
    }

def select_attack_plan(mode, scan_results):
    mode = mode.lower()

    if mode == "auto":
        return auto_mode(scan_results)

    elif mode == "hybrid":
        return hybrid_mode(scan_results)

    elif mode == "manual":
        return manual_mode(scan_results)

    else:
        raise ValueError("Invalid mode. Choose auto, hybrid, or manual.")
    
# display
def print_attack_plan(result):
    print("\n==============================")
    print(f"MODE: {result['mode'].upper()}")
    print("==============================")
    print(result["description"])

    plan = result["attack_plan"]

    if not plan:
        print("\nNo techniques selected.")
        return

    print("\nFinal Attack Plan:")

    for index, item in enumerate(plan, start=1):
        print(f"\n{index}. {item['technique_id']} - {item['technique_name']}")
        print(f"   Target: {item.get('target', 'Unknown')} ({item.get('host', 'Unknown')})")
        print(f"   Port/Service: {item.get('port', 'N/A')} / {item.get('service', 'N/A')}")
        print(f"   Version: {item.get('version', 'N/A')}")
        print(f"   Risk: {item.get('risk', 'N/A')}")
        print(f"   Reason: {item.get('reason', 'N/A')}")
        print(f"   Remediation: {item.get('remediation', 'N/A')}")

# test
if __name__ == "__main__":
    print("P3 Technique Mapper Test")
    print("1. Windows 10 Client")
    print("2. Windows Server 2012 Domain Controller")

    target_choice = input("\nChoose target scan result (1/2): ")

    if target_choice == "1":
        selected_scan = client_scan_results
    elif target_choice == "2":
        selected_scan = server_scan_results
    else:
        print("Invalid target choice. Defaulting to Windows 10 Client.")
        selected_scan = client_scan_results

    print("\nChoose attack mode:")
    print("1. Auto mode - Rule-based selection. No user input needed.")
    print("2. Hybrid mode - System recommends, analyst reviews and edits.")
    print("3. Manual mode - Expert browses all techniques and selects manually.")

    mode_choice = input("\nEnter choice (1/2/3): ")

    if mode_choice == "1":
        result = select_attack_plan("auto", selected_scan)

    elif mode_choice == "2":
        result = select_attack_plan("hybrid", selected_scan)

    elif mode_choice == "3":
        result = select_attack_plan("manual", selected_scan)

    else:
        print("Invalid mode choice. Defaulting to Auto mode.")
        result = select_attack_plan("auto", selected_scan)

    print_attack_plan(result)