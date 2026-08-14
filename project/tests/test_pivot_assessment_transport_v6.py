from __future__ import annotations

from unittest.mock import patch

import pivot.runtime as pivot_runtime
import scanners.enumerator as enumerator


class _ReadyPivot:
    proxychains_config_path = "/tmp/test-proxychains.conf"

    def is_socks_ready(self) -> bool:
        return True


def _which(name: str):
    if name == "proxychains4":
        return "/usr/bin/proxychains4"
    return None


def test_pivot_target_nmap_is_forced_to_tcp_connect_and_pn():
    scan_id = "pivot-v6-nmap"
    enumerator._register_pivot_targets(scan_id, ["10.20.30.25"])
    try:
        with patch.object(enumerator, "which", _which), patch.object(
            pivot_runtime, "get_pivot_engine", lambda: _ReadyPivot()
        ):
            adapted, reason = enumerator._pivot_wrap_command(
                scan_id,
                ["/usr/bin/nmap", "-sS", "-sV", "-p", "443", "10.20.30.25"],
            )
        assert reason == ""
        assert adapted[:4] == [
            "/usr/bin/proxychains4",
            "-q",
            "-f",
            "/tmp/test-proxychains.conf",
        ]
        assert "-sT" in adapted
        assert "-Pn" in adapted
        assert "-sS" not in adapted
        assert adapted[-1] == "10.20.30.25"
    finally:
        enumerator._clear_pivot_targets(scan_id)


def test_pivot_target_udp_is_explicitly_not_applicable():
    scan_id = "pivot-v6-udp"
    enumerator._register_pivot_targets(scan_id, ["10.20.30.25"])
    try:
        with patch.object(enumerator, "which", _which), patch.object(
            pivot_runtime, "get_pivot_engine", lambda: _ReadyPivot()
        ):
            adapted, reason = enumerator._pivot_wrap_command(
                scan_id,
                ["/usr/bin/nmap", "-sU", "-p", "53", "10.20.30.25"],
            )
        assert adapted is None
        assert reason == "udp_scanning_not_supported_through_socks_pivot"
    finally:
        enumerator._clear_pivot_targets(scan_id)


def test_non_pivot_target_command_is_not_changed():
    scan_id = "pivot-v6-direct"
    enumerator._register_pivot_targets(scan_id, ["10.20.30.25"])
    original = ["/usr/bin/nmap", "-sS", "-p", "443", "10.20.30.26"]
    try:
        adapted, reason = enumerator._pivot_wrap_command(scan_id, original)
        assert adapted == original
        assert reason == ""
    finally:
        enumerator._clear_pivot_targets(scan_id)


def test_pivot_target_nmap_raw_os_fingerprint_is_not_applicable():
    scan_id = "pivot-v6-os"
    enumerator._register_pivot_targets(scan_id, ["10.20.30.25"])
    try:
        with patch.object(enumerator, "which", _which), patch.object(
            pivot_runtime, "get_pivot_engine", lambda: _ReadyPivot()
        ):
            adapted, reason = enumerator._pivot_wrap_command(
                scan_id,
                ["/usr/bin/nmap", "-O", "-p", "22", "10.20.30.25"],
            )
        assert adapted is None
        assert reason == "active_os_fingerprinting_not_supported_through_socks_pivot"
    finally:
        enumerator._clear_pivot_targets(scan_id)
