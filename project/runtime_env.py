from __future__ import annotations

import argparse
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PROJECT_DIR = Path(__file__).resolve().parent
ENV_PATH = PROJECT_DIR / ".env"

# Values that indicate a secret has not been configured yet.
SECRET_PLACEHOLDERS = {
    "",
    "change-me",
    "replace-me",
    "replace-with-at-least-32-random-characters",
    "replace-with-a-random-password",
    "<generated-secret-key>",
    "<generated-operator-token>",
    "<generated-rpc-password>",
    "<generated-proof-secret>",
    "<password>",
}

SECRET_FACTORIES: tuple[tuple[str, Callable[[], str]], ...] = (
    ("SECRET_KEY", lambda: secrets.token_urlsafe(32)),
    ("OPERATOR_TOKEN", lambda: secrets.token_urlsafe(32)),
    ("PROOF_OF_ACCESS_SECRET", lambda: secrets.token_urlsafe(48)),
    ("METASPLOIT_RPC_PASS", lambda: secrets.token_hex(24)),
)

# This is the canonical runtime configuration list. Every variable supported by
# config.py is represented here so a new checkout gets a complete .env file.
DEFAULT_VALUES: tuple[tuple[str, str], ...] = (
    # Application
    ("DEBUG", "false"),
    ("APP_HOST", "127.0.0.1"),
    ("PORT", "5000"),
    ("ALLOW_INSECURE_OPERATOR_ACCESS", "0"),

    # AI / Ollama
    ("OLLAMA_URL", "http://localhost:11434/api/generate"),
    ("OLLAMA_MODEL", "llama3.2:1b"),
    ("OLLAMA_TIMEOUT", "180"),

    # CVE / NVD
    ("NVD_ENRICHMENT_ENABLED", "1"),
    ("NVD_CPE_RESOLUTION_ENABLED", "0"),
    ("NVD_API_KEY", ""),
    ("NVD_REQUEST_DELAY_SECONDS", "6.5"),
    ("NVD_REQUEST_TIMEOUT_SECONDS", "20"),
    ("NVD_CACHE_TTL_SECONDS", "604800"),
    ("MITRE_CVE_REPO", "https://github.com/CVEProject/cvelistV5.git"),

    # Windows / MSRC
    ("WINDOWS_INVENTORY_DIR", ""),
    ("MSRC_REQUEST_TIMEOUT_SECONDS", "45"),
    ("MSRC_HISTORY_YEARS", "15"),

    # Database
    ("MYSQL_HOST", "127.0.0.1"),
    ("MYSQL_USER", "autopentest"),
    ("MYSQL_PASS", ""),
    ("MYSQL_DB", "autopentest"),

    # CALDERA
    ("CALDERA_URL", "http://127.0.0.1:8888"),
    ("CALDERA_API_KEY", ""),
    ("ENABLE_CALDERA_EXECUTION", "0"),
    ("MAX_EXPANDED_TARGETS", "256"),
    ("AGENT_GROUP", "red"),
    ("KALI_IP", "127.0.0.1"),
    ("OPERATION_TIMEOUT", "180"),

    # Metasploit
    ("ENABLE_METASPLOIT", "0"),
    ("ENABLE_METASPLOIT_EXPLOITS", "0"),
    ("METASPLOIT_RPC_URL", "https://127.0.0.1:55552"),
    ("METASPLOIT_RPC_USER", "msf"),
    ("METASPLOIT_RPC_VERIFY_SSL", "0"),
    ("METASPLOIT_RPC_TIMEOUT", "20"),
    ("METASPLOIT_RESULT_TIMEOUT", "90"),
    ("METASPLOIT_POLL_INTERVAL", "1"),
    ("METASPLOIT_LPORT", "4445"),
    ("METASPLOIT_SESSION_TIMEOUT", "45"),
    ("METASPLOIT_SESSION_POLL_INTERVAL", "2"),

    # Web callback
    ("WEB_CALLBACK_BIND_HOST", "0.0.0.0"),
    ("WEB_CALLBACK_ADVERTISE_HOST", ""),
    ("WEB_CALLBACK_PORT", "4444"),
    ("WEB_CALLBACK_TIMEOUT", "15"),
    ("WEB_CALLBACK_MAX_BYTES", "8192"),

    # Proof of access
    ("PROOF_OF_ACCESS_ENABLED", "false"),
    ("PROOF_OF_ACCESS_TTL", "300"),

    # Recon / enumeration
    ("ENABLE_CONTEXT_FOOTPRINTING", "0"),
    ("ENABLE_ARP_SCAN", "0"),
    ("ENABLE_HTTPX", "0"),
    ("ENABLE_DEEP_WEB_DISCOVERY", "0"),
    ("ENABLE_SMBMAP", "0"),
    ("ENABLE_HYDRA", "0"),
    ("GOBUSTER_WORDLIST", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    ("HYDRA_CREDENTIAL_FILE", ""),

    # Nmap
    ("NMAP_DEFAULT_PORTS", "1-1024"),
    ("NMAP_DEFAULT_INTENSITY", "3"),
    ("NMAP_DEFAULT_PROFILE", "basic"),

    # Web validation
    ("ENABLE_WEB_VALIDATION", "0"),
    ("WEB_VALIDATION_TIMEOUT", "5"),
    ("WEB_VALIDATION_MAX_RESPONSE_BYTES", "65536"),
    ("WEB_VALIDATION_MAX_REDIRECTS", "2"),
    ("LAB_WEB_OS", "windows"),
    ("LAB_WEB_EXPECTED_TITLE", "AutoPentest Lab Diagnostics"),
    ("LAB_WEB_SCHEME", "http"),
    ("LAB_WEB_PORT", "80"),

    # Web exploitation
    ("ENABLE_WEB_EXPLOITATION", "0"),
    ("LAB_WEB_EXPLOIT_ENDPOINT", ""),
    ("LAB_WEB_EXPLOIT_PARAMETER", "host"),
    ("LAB_WEB_EXPLOIT_METHOD", "POST"),
    ("LAB_WEB_EXPLOIT_PLATFORM", "linux"),

    # SMB exploitation
    ("ENABLE_SMB_EXPLOITATION", "0"),
    ("SMB_DEFAULT_USERNAME", "smbtest"),
    ("SMB_DEFAULT_SHARE", "PrivEscLab"),
    ("SMB_HYDRA_TIMEOUT", "90"),

    # Controlled lab credential audit
    ("ENABLE_LAB_CREDENTIAL_AUDIT", "0"),
    ("LAB_CREDENTIAL_AUDIT_FILE", ""),
    ("LAB_CREDENTIAL_AUDIT_MAX_ATTEMPTS", "8"),
    ("LAB_CREDENTIAL_AUDIT_DELAY_SECONDS", "1.5"),

    # Infrastructure topology
    ("INFRA_TOPOLOGY_PROFILES_JSON", "{}"),
)


@dataclass(frozen=True)
class EnvBootstrapResult:
    env_path: Path
    created_file: bool
    changed: bool
    generated: dict[str, str]
    defaulted: dict[str, str]


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        return None

    key, value = line.split("=", 1)
    key = key.strip()
    if key.startswith("export "):
        key = key[len("export "):].strip()
    if not key:
        return None
    return key, _strip_quotes(value.strip())


def read_env_values(env_path: Path | None = None) -> dict[str, str]:
    path = env_path or ENV_PATH
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed:
            key, value = parsed
            values[key] = value
    return values


def _needs_secret(value: str | None) -> bool:
    return value is None or _strip_quotes(value) in SECRET_PLACEHOLDERS


def _line_for(key: str, value: str) -> str:
    return f"{key}={value}\n"


def _restrict_env_file(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_env_file(env_path: Path | None = None) -> EnvBootstrapResult:
    path = env_path or ENV_PATH
    created_file = not path.exists()
    lines = (
        path.read_text(encoding="utf-8").splitlines(keepends=True)
        if path.exists()
        else []
    )

    if not lines:
        lines = [
            "# Auto-generated local configuration for AutoPenTest.\n",
            "# Non-secret values use the project defaults; existing values are preserved.\n",
            "\n",
        ]

    values: dict[str, str] = {}
    indexes: dict[str, int] = {}
    for index, line in enumerate(lines):
        parsed = _parse_env_line(line)
        if parsed:
            key, value = parsed
            values[key] = value
            indexes[key] = index

    generated: dict[str, str] = {}
    defaulted: dict[str, str] = {}
    updates: dict[str, str] = {}

    # Generate only secrets that are missing or still placeholders.
    for key, factory in SECRET_FACTORIES:
        if _needs_secret(values.get(key)):
            value = factory()
            generated[key] = value
            updates[key] = value

    # Add every supported configuration key. Existing values, including valid
    # blank optional values, are preserved.
    for key, default in DEFAULT_VALUES:
        if key not in values:
            defaulted[key] = default
            updates[key] = default

    if updates:
        if lines and lines[-1].strip():
            lines.append("\n")

        missing_keys = [key for key in updates if key not in indexes]
        if missing_keys:
            lines.append("# Auto-generated runtime defaults\n")

        for key, value in updates.items():
            new_line = _line_for(key, value)
            if key in indexes:
                lines[indexes[key]] = new_line
            else:
                lines.append(new_line)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(lines), encoding="utf-8")
        _restrict_env_file(path)

    return EnvBootstrapResult(
        env_path=path,
        created_file=created_file,
        changed=bool(updates),
        generated=generated,
        defaulted=defaulted,
    )


def startup_messages(result: EnvBootstrapResult) -> list[str]:
    if not result.changed:
        return []

    action = "Created" if result.created_file else "Updated"
    lines = [f"[*] {action} {result.env_path} with complete local runtime configuration."]

    if result.generated:
        lines.append("[*] Generated secrets: " + ", ".join(result.generated))
        if "OPERATOR_TOKEN" in result.generated:
            lines.append(f"[*] Operator unlock token: {result.generated['OPERATOR_TOKEN']}")
        if "METASPLOIT_RPC_PASS" in result.generated:
            lines.append(f"[*] Metasploit RPC password: {result.generated['METASPLOIT_RPC_PASS']}")

    if result.defaulted:
        lines.append("[*] Added configuration values: " + ", ".join(result.defaulted))

    lines.append("[*] Existing non-placeholder values were preserved.")
    lines.append("[*] The local .env file is excluded from Git and restricted to the current user on Unix-like systems.")
    return lines


def _print_secret_values(env_path: Path) -> None:
    values = read_env_values(env_path)
    for key in ("SECRET_KEY", "OPERATOR_TOKEN", "METASPLOIT_RPC_PASS", "PROOF_OF_ACCESS_SECRET"):
        value = values.get(key)
        if value:
            print(f"{key}={value}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or refresh project/.env with the complete AutoPenTest configuration."
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Print generated/current local secrets. Use only in a trusted terminal.",
    )
    args = parser.parse_args(argv)

    result = ensure_env_file()
    for line in startup_messages(result):
        print(line)
    if not result.changed:
        print(f"[*] {result.env_path} already contains the complete runtime configuration.")

    if args.show_secrets:
        print("\n[!] Current local secrets:")
        _print_secret_values(result.env_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
