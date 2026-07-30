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
from core.helpers import (
    _active_scan_record,
    _active_validation_results,
    _save_active_scan_fields,
)
from pivot.pivot_engine import PivotEngine
import ipaddress
from datetime import datetime, timezone

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

@pivot_bp.route("/scan", methods=["POST"])
def pivot_scan():
    """
    Scan an internal network range through the pivot.
    Common targets: 10.10.10.0/24 (ADMIN), 10.10.20.0/24 (USERS).
    """
    data = request.get_json(silent=True) or {}
    target_range = data.get("range", "10.10.20.0/24")
    ports = data.get("ports", "21,22,80,445,3389,5985,5986")
    timeout = int(data.get("timeout", 60))

    engine = get_pivot_engine()

    if not engine.is_running:
        return jsonify({
            "ok": False,
            "error": "Pivot is not active. Run /pivot/setup first.",
        }), 400

    results = engine.scan_network(target_range, ports=ports, timeout=timeout)

    # Identify interesting targets
    targets = []
    for host in results:
        service_names = [p["service"] for p in host.get("open_ports", [])]
        target_type = "unknown"
        if any(s in service_names for s in ["microsoft-ds", "smb"]):
            target_type = "windows_smb"
        elif "ssh" in service_names:
            target_type = "linux_ssh"
        elif "rdp" in service_names or "ms-wbt-server" in service_names:
            target_type = "windows_rdp"

        targets.append({
            "ip": host["ip"],
            "os": host.get("os", ""),
            "open_ports": host["open_ports"],
            "type": target_type,
        })

    pivot_scan_results = {
        "ok": True,
        "phase": "internal_scan",
        "target_range": target_range,
        "hosts_found": len(results),
        "targets": targets,
        "recommendations": _generate_recommendations(targets),
    }

    internal_targets = []

    for target in targets:
        try:
            address = ipaddress.ip_address(target.get("ip", ""))
        except ValueError:
            continue

        if (
            address.version != 4
            or not address.is_private
            or address.is_loopback
        ):
            continue

        internal_targets.append({
            **target,
            "ip": str(address),
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "source": "pivot_scan",
        })

    pivot_scan_results["targets"] = internal_targets
    pivot_scan_results["hosts_found"] = len(internal_targets)

    flask_session["internal_targets"] = internal_targets
    flask_session["pivot_scan_results"] = pivot_scan_results

    _save_active_scan_fields(
        internal_targets=internal_targets,
        pivot_scan_results=pivot_scan_results,
    )

    return jsonify(pivot_scan_results)


@pivot_bp.route("/target/select", methods=["POST"])
def pivot_target_select():
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or set(data) != {"target_ip"}:
        return jsonify({
            "ok": False,
            "error": "Only target_ip is accepted.",
        }), 400

    try:
        address = ipaddress.ip_address(
            str(data.get("target_ip") or "").strip()
        )
    except ValueError:
        return jsonify({
            "ok": False,
            "error": "target_ip must be a valid IPv4 address.",
        }), 400

    if (
        address.version != 4
        or not address.is_private
        or address.is_loopback
    ):
        return jsonify({
            "ok": False,
            "error": "target_ip must be a private non-loopback IPv4 address.",
        }), 400

    active_scan = _active_scan_record()
    internal_targets = (
        active_scan.get("internal_targets")
        or flask_session.get("internal_targets")
        or []
    )

    selected = next(
        (
            target
            for target in internal_targets
            if isinstance(target, dict)
            and target.get("ip") == str(address)
        ),
        None,
    )

    if selected is None:
        return jsonify({
            "ok": False,
            "error": "The target was not discovered by the current pivot scan.",
        }), 400

    external_target = (
        active_scan.get("external_target")
        or active_scan.get("target")
        or flask_session.get("external_target_ip")
        or flask_session.get("target_ip")
    )

    selected_internal_target = {
        **selected,
        "selected_at": datetime.now(timezone.utc).isoformat(),
    }

    flask_session["external_target_ip"] = external_target
    flask_session["selected_internal_target"] = selected_internal_target
    flask_session.pop("selected_agent_paw", None)

    _save_active_scan_fields(
        external_target=external_target,
        selected_internal_target=selected_internal_target,
        selected_agent_paw=None,
    )

    return jsonify({
        "ok": True,
        "selected_internal_target": selected_internal_target,
        "external_target": external_target,
        "selected_agent_paw": None,
    })

def _generate_recommendations(targets):
    """Generate recommendations from the evidence-driven lateral technique catalog."""
    try:
        from exploitation.module_catalog import get_module_catalog
        catalog = get_module_catalog()
    except Exception:
        catalog = None

    recs = []
    seen = set()

    for target in targets or []:
        target_type = str(target.get("type") or "").strip().lower()
        service = str(target.get("service") or "").strip().lower()
        try:
            port = int(target.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        cves = target.get("cves") or []

        if catalog is not None:
            matches = catalog.matching_lateral(
                target_type=target_type,
                service=service,
                port=port,
                cves=cves,
            )
            for tech in matches:
                note = tech.recommendation or tech.title
                if note and note not in seen:
                    seen.add(note)
                    recs.append(note)
        else:
            # Minimal fallback if catalog cannot load.
            if target_type == "windows_smb" and "smb" not in seen:
                seen.add("smb")
                recs.append("Windows SMB hosts detected — review catalog lateral techniques")
            elif target_type == "windows_rdp" and "rdp" not in seen:
                seen.add("rdp")
                recs.append("RDP accessible — review catalog RDP techniques")
            elif target_type == "linux_ssh" and "ssh" not in seen:
                seen.add("ssh")
                recs.append("Linux SSH hosts detected — review catalog SSH techniques")

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

    username = data.get("username") or "Administrator"
    password = data.get("password") or "P@ssw0rd"

    try:
        from exploitation.module_catalog import get_module_catalog
        catalog = get_module_catalog()
        tech = catalog.lateral_by_key(str(technique))
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Catalog unavailable: {exc}"}), 500

    if not tech:
        available = [item.key for item in catalog.lateral_techniques]
        return jsonify({
            "ok": False,
            "error": f"Unknown technique: {technique}",
            "available_techniques": available,
        }), 400

    cmd = tech.command_template.format(
        target_ip=target_ip,
        username=username,
        password=password,
    )

    return jsonify({
        "ok": True,
        "phase": "lateral_movement",
        "target": target_ip,
        "technique": technique,
        "title": tech.title,
        "command": cmd,
        "proxychains": True,
        "catalog_driven": True,
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
