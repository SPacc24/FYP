"""Expand edge_to_internal_proof playbook with detectors + branches for
all new exploit classes: MS08-067, BlueKeep, SMBGhost, Zerologon,
PrintNightmare, MS14-068, plus RPC/Kerberos/WinRM surface detectors.
"""

import json
from pathlib import Path

PLAYBOOK_PATH = (
    Path(__file__).resolve().parent.parent
    / "policies" / "playbooks" / "edge_to_internal_proof.json"
)

NEW_EVIDENCE_DETECTORS = [
    # ── MS08-067 ──
    {
        "flag": "ms08_067_cve_evidence",
        "match": {"cves": ["CVE-2008-4250", "MS08-067"]},
    },
    # ── SMBGhost ──
    {
        "flag": "smbghost_cve_evidence",
        "match": {"cves": ["CVE-2020-0796"]},
    },
    # ── Zerologon ──
    {
        "flag": "zerologon_cve_evidence",
        "match": {"cves": ["CVE-2020-1472"]},
    },
    # ── PrintNightmare ──
    {
        "flag": "printnightmare_cve_evidence",
        "match": {"cves": ["CVE-2021-34527", "CVE-2021-1675"]},
    },
    # ── MS14-068 ──
    {
        "flag": "ms14_068_cve_evidence",
        "match": {"cves": ["CVE-2014-6324", "MS14-068"]},
    },
    # ── Additional surface detectors ──
    {
        "flag": "kerberos_present",
        "match": {"ports": [88], "services": ["kerberos", "kerberos-sec"]},
    },
    {
        "flag": "msrpc_present",
        "match": {"ports": [135, 593], "services": ["msrpc", "epmap", "dcerpc"]},
    },
    {
        "flag": "winrm_present",
        "match": {"ports": [5985, 5986], "services": ["winrm", "wsman"]},
    },
    {
        "flag": "mysql_present",
        "match": {"ports": [3306], "services": ["mysql"]},
    },
    {
        "flag": "telnet_present",
        "match": {"ports": [23], "services": ["telnet"]},
    },
]

NEW_BRANCHES = [
    # ── BlueKeep (RDP + CVE-2019-0708) ──
    {
        "id": "bluekeep_open",
        "when": {
            "all": [
                {"flag": "rdp_present"},
                {"any": [
                    {"flag": "bluekeep_cve_evidence"},
                    {"flag": "rdp_bluekeep_vulnerable"},
                ]},
            ]
        },
        "set_flags": ["impact_path_available", "bluekeep_path_ready", "branch_bluekeep_open"],
        "message": "RDP + BlueKeep CVE evidence present — exploit available after operator approval.",
        "priority": 18,
    },
    {
        "id": "bluekeep_patched_or_absent",
        "when": {
            "all": [
                {"flag": "rdp_present"},
                {"not": {"flag": "bluekeep_cve_evidence"}},
                {"not": {"flag": "rdp_bluekeep_vulnerable"}},
            ]
        },
        "set_flags": ["branch_bluekeep_suppressed", "bluekeep_not_exploitable"],
        "message": "RDP present but BlueKeep not evidenced — exploit suppressed.",
        "priority": 14,
    },
    # ── MS08-067 (SMB + CVE-2008-4250) ──
    {
        "id": "ms08_067_open",
        "when": {
            "all": [
                {"flag": "smb_present"},
                {"any": [
                    {"flag": "ms08_067_cve_evidence"},
                ]},
            ]
        },
        "set_flags": ["impact_path_available", "ms08_067_path_ready", "branch_ms08_067_open"],
        "message": "SMB + MS08-067 CVE evidence present — WinXP/2003 exploit available after operator approval.",
        "priority": 17,
    },
    {
        "id": "ms08_067_patched_or_absent",
        "when": {
            "all": [
                {"flag": "smb_present"},
                {"not": {"flag": "ms08_067_cve_evidence"}},
            ]
        },
        "set_flags": ["branch_ms08_067_suppressed", "ms08_067_not_exploitable"],
        "message": "MS08-067 not evidenced — exploit suppressed (modern SMB or patched).",
        "priority": 13,
    },
    # ── SMBGhost (SMB + CVE-2020-0796) ──
    {
        "id": "smbghost_open",
        "when": {
            "all": [
                {"flag": "smb_present"},
                {"flag": "smbghost_cve_evidence"},
            ]
        },
        "set_flags": ["impact_path_available", "smbghost_path_ready", "branch_smbghost_open"],
        "message": "SMB + SMBGhost CVE evidence present — Win10 v1903/1909 exploit/LPE available after operator approval.",
        "priority": 16,
    },
    {
        "id": "smbghost_patched_or_absent",
        "when": {
            "all": [
                {"flag": "smb_present"},
                {"not": {"flag": "smbghost_cve_evidence"}},
            ]
        },
        "set_flags": ["branch_smbghost_suppressed", "smbghost_not_exploitable"],
        "message": "SMB Ghost not evidenced — SMBv3 compression exploit suppressed.",
        "priority": 12,
    },
    # ── Zerologon (RPC + CVE-2020-1472) ──
    {
        "id": "zerologon_open",
        "when": {
            "all": [
                {"any": [
                    {"flag": "smb_present"},
                    {"flag": "msrpc_present"},
                ]},
                {"flag": "zerologon_cve_evidence"},
            ]
        },
        "set_flags": ["impact_path_available", "zerologon_path_ready", "branch_zerologon_open"],
        "message": "RPC/SMB + Zerologon CVE evidence present — DC takeover exploit available after EXTREME CAUTION approval.",
        "priority": 24,
    },
    {
        "id": "zerologon_patched_or_absent",
        "when": {
            "all": [
                {"any": [
                    {"flag": "smb_present"},
                    {"flag": "msrpc_present"},
                ]},
                {"not": {"flag": "zerologon_cve_evidence"}},
            ]
        },
        "set_flags": ["branch_zerologon_suppressed", "zerologon_not_exploitable"],
        "message": "Zerologon not evidenced — DC takeover suppressed.",
        "priority": 11,
    },
    # ── PrintNightmare (SMB + CVE-2021-34527) ──
    {
        "id": "printnightmare_open",
        "when": {
            "all": [
                {"any": [
                    {"flag": "smb_present"},
                    {"flag": "msrpc_present"},
                ]},
                {"flag": "printnightmare_cve_evidence"},
            ]
        },
        "set_flags": ["impact_path_available", "printnightmare_path_ready", "branch_printnightmare_open"],
        "message": "SMB/RPC + PrintNightmare CVE evidence present — Print Spooler RCE available after operator approval.",
        "priority": 19,
    },
    {
        "id": "printnightmare_patched_or_absent",
        "when": {
            "all": [
                {"any": [
                    {"flag": "smb_present"},
                    {"flag": "msrpc_present"},
                ]},
                {"not": {"flag": "printnightmare_cve_evidence"}},
            ]
        },
        "set_flags": ["branch_printnightmare_suppressed", "printnightmare_not_exploitable"],
        "message": "PrintNightmare not evidenced — Print Spooler RCE suppressed.",
        "priority": 9,
    },
    # ── MS14-068 (Kerberos + CVE-2014-6324) ──
    {
        "id": "ms14_068_open",
        "when": {
            "all": [
                {"flag": "kerberos_present"},
                {"flag": "ms14_068_cve_evidence"},
            ]
        },
        "set_flags": ["impact_path_available", "ms14_068_path_ready", "branch_ms14_068_open"],
        "message": "Kerberos + MS14-068 CVE evidence present — domain PAC forgery exploit available.",
        "priority": 22,
    },
    {
        "id": "ms14_068_patched_or_absent",
        "when": {
            "all": [
                {"flag": "kerberos_present"},
                {"not": {"flag": "ms14_068_cve_evidence"}},
            ]
        },
        "set_flags": ["branch_ms14_068_suppressed", "ms14_068_not_exploitable"],
        "message": "MS14-068 not evidenced — Kerberos PAC forgery suppressed.",
        "priority": 8,
    },
    # ── Web SQL injection / file upload paths ──
    {
        "id": "web_critical_unlocked",
        "when": {
            "any": [
                {"flag": "web_profile_matched"},
                {"flag": "sql_injection_surface"},
                {"flag": "file_upload_surface"},
            ]
        },
        "set_flags": ["impact_path_available", "web_critical_path_ready"],
        "message": "Web critical attack surface detected — SQLi / file upload / cmd injection paths available after operator approval.",
        "priority": 21,
    },
]


def expand():
    raw = PLAYBOOK_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)

    # Back up
    PLAYBOOK_PATH.with_suffix(".json.bak2").write_text(raw, encoding="utf-8")

    # Append evidence detectors (deduplicate by flag)
    existing_flags = {d["flag"] for d in data.get("evidence_detectors", [])}
    for det in NEW_EVIDENCE_DETECTORS:
        if det["flag"] not in existing_flags:
            data.setdefault("evidence_detectors", []).append(det)
            existing_flags.add(det["flag"])

    # Append branches (deduplicate by id)
    existing_branch_ids = {b["id"] for b in data.get("branches", [])}
    for br in NEW_BRANCHES:
        if br["id"] not in existing_branch_ids:
            data.setdefault("branches", []).append(br)
            existing_branch_ids.add(br["id"])

    PLAYBOOK_PATH.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    detectors = len(data.get("evidence_detectors", []))
    branches = len(data.get("branches", []))
    print(f"Playbook expanded: {detectors} evidence detectors, {branches} branch rules")


if __name__ == "__main__":
    expand()
