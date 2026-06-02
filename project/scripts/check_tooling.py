from __future__ import annotations
import platform
import shutil
from pathlib import Path

TOOLS = [
    ("nmap", "Required for live host/service discovery and most CVE-supporting evidence"),
    ("git", "Required to sync/rebuild the official CVE List index"),
    ("gobuster", "Optional deep web path discovery"),
    ("hydra", "Optional default credential checks in authorised lab scope"),
    ("ssh-audit", "Optional SSH configuration evidence"),
    ("smbclient", "Optional SMB share listing evidence"),
    ("enum4linux-ng", "Optional SMB/NetBIOS enumeration evidence"),
    ("smbmap", "Optional SMB permission mapping evidence"),
    ("httpx-toolkit", "Optional ProjectDiscovery HTTP technology probe"),
]

WINDOWS_NOTES = {
    "nmap": "Install Nmap for Windows and ensure nmap.exe is in PATH.",
    "git": "Install Git for Windows and ensure git.exe is in PATH.",
    "gobuster": "Install a Windows gobuster build or use WSL/Docker for this optional tool.",
    "hydra": "Hydra is usually easier through WSL/Docker; Windows native support varies.",
    "smbclient": "Samba client tools are usually easier through WSL/Docker; Windows native support varies.",
    "enum4linux-ng": "Install Python/perl dependencies manually or use WSL/Docker for this optional tool.",
    "smbmap": "Install with pip if supported in your environment, or use WSL/Docker.",
    "httpx-toolkit": "Install ProjectDiscovery httpx and expose it as httpx-toolkit/httpx in PATH.",
}


def main() -> int:
    print(f"Platform: {platform.system()} {platform.release()}")
    print("\nExternal tool availability:")
    missing_required = False
    for tool, purpose in TOOLS:
        found = shutil.which(tool) or (shutil.which("httpx") if tool == "httpx-toolkit" else None)
        status = "FOUND" if found else "MISSING"
        print(f"- {tool:15} {status:8} {found or ''}")
        print(f"  Purpose: {purpose}")
        if not found and platform.system().lower().startswith("win"):
            print(f"  Windows note: {WINDOWS_NOTES.get(tool, 'Install and ensure it is in PATH.')}")
        if tool in {"nmap", "git"} and not found:
            missing_required = True
    if missing_required:
        print("\nApp/UI can still run in VS Code, but live scan quality will be limited until required tools are installed.")
        return 2
    print("\nCore external tooling is available.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
