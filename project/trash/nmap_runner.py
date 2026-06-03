"""
P2/P3 Scanner Module - Nmap Runner
Builds and executes controlled Nmap scans for authorised lab testing.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

try:
    from typing import Literal
except ImportError:  # Python 3.7 compatibility
    from typing_extensions import Literal

SCAN_OUTPUT_DIR = Path("storage/scans")
DEFAULT_PORTS = "1-1000"
DEFAULT_INTENSITY = 3
SCAN_TIMEOUT_SECONDS = 600

ScanProfile = Literal["quick", "standard", "deep"]


class NmapScanError(Exception):
    """Raised when scan validation or Nmap execution fails."""


@dataclass
class ScanRequest:
    target: str
    ports: str = DEFAULT_PORTS
    intensity: int = DEFAULT_INTENSITY
    profile: ScanProfile = "standard"


@dataclass
class ScanResult:
    success: bool
    target: str
    ports: str
    intensity: int
    profile: str
    output_file: str
    command: str
    started_at: str
    completed_at: str
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_nmap_path() -> str:
    """
    Resolve Nmap without hardcoding one machine's path.
    Priority:
      1. NMAP_PATH environment variable
      2. System PATH
      3. Common Windows install locations
    """
    env_path = os.getenv("NMAP_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    path_nmap = shutil.which("nmap")
    if path_nmap:
        return path_nmap

    common_windows_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]

    for path in common_windows_paths:
        if Path(path).exists():
            return path

    raise NmapScanError("Nmap was not found. Install Nmap, add it to PATH, or set NMAP_PATH.")


def _project_path(path: Path) -> Path:
    return Path.cwd() / path


def validate_target(target: str) -> str:
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")

    target = target.strip()

    if len(target) > 255:
        raise ValueError("Target is too long.")

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    hostname_pattern = r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$"
    if not re.fullmatch(hostname_pattern, target):
        raise ValueError("Invalid target format. Use an IP address, CIDR range, or hostname.")

    return target


def validate_ports(ports: str | None) -> str:
    if ports is None or str(ports).strip() == "":
        return DEFAULT_PORTS

    ports = str(ports).strip().replace(" ", "")

    if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", ports):
        raise ValueError("Invalid port format. Use formats like 80, 22,80,443, or 1-1000.")

    for part in ports.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Port ranges must be between 1 and 65535.")
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Ports must be between 1 and 65535.")

    return ports


def validate_intensity(intensity: int | str | None) -> int:
    if intensity is None or str(intensity).strip() == "":
        return DEFAULT_INTENSITY

    try:
        intensity_value = int(intensity)
    except (TypeError, ValueError):
        raise ValueError("Scan intensity must be a number from 0 to 5.")

    if not 0 <= intensity_value <= 5:
        raise ValueError("Scan intensity must be between 0 and 5.")

    return intensity_value


def validate_profile(profile: str | None) -> ScanProfile:
    if profile is None or profile.strip() == "":
        return "standard"

    profile = profile.lower().strip()

    if profile not in {"quick", "standard", "deep"}:
        raise ValueError("Scan profile must be quick, standard, or deep.")

    return profile  # type: ignore[return-value]


def generate_output_file(target: str) -> Path:
    output_dir = _project_path(SCAN_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]

    return output_dir / f"scan_{safe_target}_{timestamp}_{unique_id}.xml"


def build_nmap_command(request: ScanRequest, output_file: Path) -> list[str]:
    command = [
        resolve_nmap_path(),
        "-Pn",  # Treat host as online. Better for firewalled Windows targets.
        "-T",
        str(request.intensity),
        "-p",
        request.ports,
        "-oX",
        str(output_file),
    ]

    if request.profile == "quick":
        command.extend(["-sV", "--version-light"])
    elif request.profile == "standard":
        command.extend(["-sV", "-sC"])
    elif request.profile == "deep":
        command.extend(["-sV", "-sC", "-O", "--version-all"])

    command.append(request.target)
    return command


def run_nmap_scan(
    target: str,
    ports: str | None = None,
    intensity: int | str | None = None,
    profile: str | None = None,
) -> dict:
    request = ScanRequest(
        target=validate_target(target),
        ports=validate_ports(ports),
        intensity=validate_intensity(intensity),
        profile=validate_profile(profile),
    )

    output_file = generate_output_file(request.target)
    command = build_nmap_command(request, output_file)
    started_at = datetime.now().isoformat(timespec="seconds")

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapScanError(f"Nmap scan timed out after {SCAN_TIMEOUT_SECONDS} seconds.") from exc
    except OSError as exc:
        raise NmapScanError(f"Failed to execute Nmap: {exc}") from exc

    completed_at = datetime.now().isoformat(timespec="seconds")

    if completed.returncode != 0:
        raise NmapScanError(completed.stderr.strip() or "Nmap scan failed.")

    if not output_file.exists():
        raise NmapScanError("Nmap completed but XML output file was not created.")

    return ScanResult(
        success=True,
        target=request.target,
        ports=request.ports,
        intensity=request.intensity,
        profile=request.profile,
        output_file=str(output_file),
        command=" ".join(command),
        started_at=started_at,
        completed_at=completed_at,
        stdout=completed.stdout,
        stderr=completed.stderr,
    ).to_dict()