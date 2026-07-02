from __future__ import annotations

import argparse
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PROJECT_DIR = Path(__file__).resolve().parent
ENV_PATH = PROJECT_DIR / ".env"

PLACEHOLDER_VALUES = {
    "",
    "change-me",
    "replace-me",
    "replace-with-at-least-32-random-characters",
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

DEFAULT_VALUES: tuple[tuple[str, str], ...] = (
    ("DEBUG", "false"),
    ("APP_HOST", "127.0.0.1"),
    ("OLLAMA_URL", "http://localhost:11434/api/generate"),
    ("OLLAMA_MODEL", "llama3.2:1b"),
    ("OLLAMA_TIMEOUT", "180"),
    ("ENABLE_CALDERA_EXECUTION", "0"),
    ("CALDERA_URL", "http://127.0.0.1:8888"),
    ("AGENT_GROUP", "red"),
    ("KALI_IP", "127.0.0.1"),
    ("OPERATION_TIMEOUT", "180"),
    ("ENABLE_METASPLOIT", "0"),
    ("ENABLE_METASPLOIT_EXPLOITS", "0"),
    ("METASPLOIT_RPC_URL", "https://127.0.0.1:55552"),
    ("METASPLOIT_RPC_USER", "msf"),
    ("METASPLOIT_RPC_VERIFY_SSL", "0"),
    ("METASPLOIT_RPC_TIMEOUT", "20"),
    ("PROOF_OF_ACCESS_ENABLED", "false"),
    ("PROOF_OF_ACCESS_TTL", "300"),
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


def _needs_value(value: str | None) -> bool:
    if value is None:
        return True
    return _strip_quotes(value) in PLACEHOLDER_VALUES


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
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []

    if not lines:
        lines = [
            "# Auto-generated local configuration for AutoPenTest.\n",
            "# Existing non-placeholder values are preserved when this file is refreshed.\n",
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

    for key, factory in SECRET_FACTORIES:
        if _needs_value(values.get(key)):
            value = factory()
            generated[key] = value
            updates[key] = value

    for key, value in DEFAULT_VALUES:
        if _needs_value(values.get(key)):
            defaulted[key] = value
            updates[key] = value

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
    lines = [f"[*] {action} {result.env_path} with local runtime defaults."]

    if result.generated:
        lines.append("[*] Generated secrets: " + ", ".join(result.generated))
        if "OPERATOR_TOKEN" in result.generated:
            lines.append(f"[*] Operator unlock token: {result.generated['OPERATOR_TOKEN']}")
        if "METASPLOIT_RPC_PASS" in result.generated:
            lines.append(f"[*] Metasploit RPC password: {result.generated['METASPLOIT_RPC_PASS']}")

    if result.defaulted:
        lines.append("[*] Added defaults: " + ", ".join(result.defaulted))

    lines.append("[*] These values were written to project/.env and will be reused.")
    return lines


def _print_secret_values(env_path: Path) -> None:
    values = read_env_values(env_path)
    for key in ("SECRET_KEY", "OPERATOR_TOKEN", "METASPLOIT_RPC_PASS", "PROOF_OF_ACCESS_SECRET"):
        value = values.get(key)
        if value:
            print(f"{key}={value}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or refresh project/.env for AutoPenTest.")
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
        print(f"[*] {result.env_path} already contains the required local runtime values.")

    if args.show_secrets:
        print("\n[!] Current local secrets:")
        _print_secret_values(result.env_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
