from __future__ import annotations

import os
import re
import socket
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


_SSH_MSG_DISCONNECT = 1
_SSH_MSG_KEXINIT = 20
_MAX_IDENTIFICATION_BYTES = 8192
_MAX_PACKET_BYTES = 1_048_576
_MAX_ALGORITHMS_PER_LIST = 512


@dataclass(frozen=True)
class SSHCryptoProfile:
    """Cryptographic profile advertised by an SSH server."""

    target: str
    port: int
    protocol_version: str
    server_software: str
    key_exchange_algorithms: list[str]
    server_host_key_algorithms: list[str]
    encryption_ciphers_cs: list[str]
    encryption_ciphers_sc: list[str]
    mac_algorithms_cs: list[str]
    mac_algorithms_sc: list[str]
    compression_algorithms: list[str]
    inferred_os: str | None
    inferred_patch_level: str | None
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SSHProtocolError(ValueError):
    """Raised internally when an SSH handshake is malformed or oversized."""


def _name_list(values: list[str]) -> bytes:
    encoded = ",".join(values).encode("ascii")
    return struct.pack(">I", len(encoded)) + encoded


def _client_kex_packet() -> bytes:
    payload = bytearray([_SSH_MSG_KEXINIT])
    payload.extend(os.urandom(16))
    payload.extend(
        _name_list(
            [
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "diffie-hellman-group14-sha256",
            ]
        )
    )
    payload.extend(_name_list(["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]))
    ciphers = [
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes128-ctr",
    ]
    payload.extend(_name_list(ciphers))
    payload.extend(_name_list(ciphers))
    macs = [
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256",
    ]
    payload.extend(_name_list(macs))
    payload.extend(_name_list(macs))
    payload.extend(_name_list(["none"]))
    payload.extend(_name_list(["none"]))
    payload.extend(_name_list([]))
    payload.extend(_name_list([]))
    payload.extend(b"\x00")  # first_kex_packet_follows
    payload.extend(struct.pack(">I", 0))

    block_size = 8
    padding_length = block_size - ((len(payload) + 5) % block_size)
    if padding_length < 4:
        padding_length += block_size
    packet_length = len(payload) + padding_length + 1
    return (
        struct.pack(">I", packet_length)
        + bytes([padding_length])
        + bytes(payload)
        + os.urandom(padding_length)
    )


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0 or size > _MAX_PACKET_BYTES:
        raise SSHProtocolError("SSH packet length is outside the accepted bound")
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise SSHProtocolError("SSH server closed the connection during negotiation")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_server_identification(sock: socket.socket) -> str:
    total = 0
    for _ in range(50):
        line = bytearray()
        while len(line) <= 1024:
            char = _recv_exact(sock, 1)
            line.extend(char)
            total += 1
            if total > _MAX_IDENTIFICATION_BYTES:
                raise SSHProtocolError("SSH identification exceeded the accepted bound")
            if char == b"\n":
                break
        value = bytes(line).rstrip(b"\r\n").decode("utf-8", errors="replace")
        if value.startswith("SSH-"):
            if not re.fullmatch(r"SSH-[0-9.]+-[\x20-\x7e]+", value):
                raise SSHProtocolError("SSH identification contains invalid characters")
            return value
    raise SSHProtocolError("SSH server identification was not received")


def _read_packet(sock: socket.socket) -> bytes:
    packet_length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if packet_length < 6 or packet_length > _MAX_PACKET_BYTES:
        raise SSHProtocolError("SSH packet length is outside the accepted bound")
    packet = _recv_exact(sock, packet_length)
    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1
    if padding_length < 4 or payload_length < 1:
        raise SSHProtocolError("SSH packet padding is invalid")
    return packet[1 : 1 + payload_length]


def _read_name_list(payload: bytes, offset: int) -> tuple[list[str], int]:
    if offset + 4 > len(payload):
        raise SSHProtocolError("SSH KEXINIT name-list length is truncated")
    length = struct.unpack(">I", payload[offset : offset + 4])[0]
    offset += 4
    if length > _MAX_PACKET_BYTES or offset + length > len(payload):
        raise SSHProtocolError("SSH KEXINIT name-list is truncated or oversized")
    value = payload[offset : offset + length].decode("ascii", errors="replace")
    offset += length
    algorithms = [item for item in value.split(",") if item]
    if len(algorithms) > _MAX_ALGORITHMS_PER_LIST:
        raise SSHProtocolError("SSH KEXINIT advertised too many algorithms")
    return algorithms, offset


def _parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """Parse an unencrypted SSH_MSG_KEXINIT payload.

    This helper is intentionally separated so a captured packet can be tested
    without making a network connection.
    """
    if len(payload) < 17 or payload[0] != _SSH_MSG_KEXINIT:
        raise SSHProtocolError("SSH packet is not a KEXINIT message")
    offset = 17
    names = (
        "key_exchange_algorithms",
        "server_host_key_algorithms",
        "encryption_ciphers_cs",
        "encryption_ciphers_sc",
        "mac_algorithms_cs",
        "mac_algorithms_sc",
        "compression_algorithms_cs",
        "compression_algorithms_sc",
        "languages_cs",
        "languages_sc",
    )
    parsed: dict[str, list[str]] = {}
    for name in names:
        parsed[name], offset = _read_name_list(payload, offset)
    if offset + 5 > len(payload):
        raise SSHProtocolError("SSH KEXINIT trailer is truncated")
    return parsed


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def infer_ssh_os_from_algorithms(
    algorithms: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Infer OS/package details only when the banner provides explicit evidence.

    Algorithm lists alone are shared across operating systems and are not used
    to claim an exact distribution or patch level. They remain available in the
    returned profile for security-posture analysis.

    >>> infer_ssh_os_from_algorithms({"server_software": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"})
    ('Ubuntu Linux', 'Ubuntu-3ubuntu0.10')
    >>> infer_ssh_os_from_algorithms({"key_exchange_algorithms": ["diffie-hellman-group1-sha1"]})
    (None, None)
    """
    software = str(
        algorithms.get("server_software")
        or algorithms.get("banner")
        or ""
    )
    operating_system: str | None = None
    package_level: str | None = None
    os_patterns: tuple[tuple[str, str], ...] = (
        (r"\bUbuntu\b", "Ubuntu Linux"),
        (r"\bDebian\b", "Debian Linux"),
        (r"\bRaspbian\b", "Raspbian Linux"),
        (r"\bRed\s*Hat\b|\bRHEL\b", "Red Hat Enterprise Linux"),
        (r"\bCentOS\b", "CentOS Linux"),
        (r"\bFedora\b", "Fedora Linux"),
        (r"\bOpenBSD\b", "OpenBSD"),
        (r"\bFreeBSD\b", "FreeBSD"),
        (r"\bNetBSD\b", "NetBSD"),
        (r"\bWin32-OpenSSH\b|\bMicrosoft\b|\bWindows\b", "Windows"),
    )
    for pattern, label in os_patterns:
        if re.search(pattern, software, re.I):
            operating_system = label
            break

    package_match = re.search(
        r"\b(Ubuntu[-_][^\s]+|Debian[-_][^\s]+|Raspbian[-_][^\s]+|FreeBSD[-_][^\s]+)",
        software,
        re.I,
    )
    if package_match:
        package_level = package_match.group(1)
    return operating_system, package_level


def collect_ssh_cryptography(
    target: str,
    port: int = 22,
    timeout: int = 10,
) -> SSHCryptoProfile | None:
    """Collect one SSH cryptographic negotiation without authentication.

    The collector opens one TCP connection, exchanges protocol identification,
    sends one KEXINIT packet, records the server's advertised algorithms, and
    closes before key exchange or user authentication.

    Network failures, timeouts, refusals, and malformed responses return
    ``None`` so the scan pipeline can retain an empty/partial coverage state.
    """
    clean_target = str(target or "").strip()
    if not clean_target:
        raise ValueError("target cannot be empty")
    try:
        clean_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer from 1 to 65535") from exc
    if not 1 <= clean_port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    try:
        clean_timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout must be between 0.1 and 60 seconds") from exc
    if not 0.1 <= clean_timeout <= 60:
        raise ValueError("timeout must be between 0.1 and 60 seconds")

    try:
        with socket.create_connection((clean_target, clean_port), timeout=clean_timeout) as sock:
            sock.settimeout(clean_timeout)
            sock.sendall(b"SSH-2.0-APTScanner_1.0\r\n")
            banner = _read_server_identification(sock)
            sock.sendall(_client_kex_packet())
            parsed: dict[str, list[str]] | None = None
            for _ in range(4):
                payload = _read_packet(sock)
                if payload[0] == _SSH_MSG_KEXINIT:
                    parsed = _parse_kexinit(payload)
                    break
                if payload[0] == _SSH_MSG_DISCONNECT:
                    return None
            if parsed is None:
                return None
    except (OSError, socket.timeout, SSHProtocolError, struct.error, UnicodeError):
        return None

    banner_match = re.match(r"SSH-([0-9.]+)-(.+)", banner)
    if not banner_match:
        return None
    protocol_version = banner_match.group(1)
    server_software = banner_match.group(2).strip()
    inference_input: dict[str, Any] = dict(parsed)
    inference_input["server_software"] = server_software
    inferred_os, inferred_patch = infer_ssh_os_from_algorithms(inference_input)
    compression = _unique(
        parsed["compression_algorithms_cs"] + parsed["compression_algorithms_sc"]
    )
    return SSHCryptoProfile(
        target=clean_target,
        port=clean_port,
        protocol_version=protocol_version,
        server_software=server_software,
        key_exchange_algorithms=parsed["key_exchange_algorithms"],
        server_host_key_algorithms=parsed["server_host_key_algorithms"],
        encryption_ciphers_cs=parsed["encryption_ciphers_cs"],
        encryption_ciphers_sc=parsed["encryption_ciphers_sc"],
        mac_algorithms_cs=parsed["mac_algorithms_cs"],
        mac_algorithms_sc=parsed["mac_algorithms_sc"],
        compression_algorithms=compression,
        inferred_os=inferred_os,
        inferred_patch_level=inferred_patch,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


__all__ = [
    "SSHCryptoProfile",
    "collect_ssh_cryptography",
    "infer_ssh_os_from_algorithms",
]
