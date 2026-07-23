from __future__ import annotations

import json
import importlib
import io
import re
import socket
import struct
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
import urllib.error

from scanners import mitre_cve
from scanners.active_validation import _fetch, _interesting_response
from scanners.acl_mapper import detect_firewall_acl
from scanners.fingerprint_validator import validate_service_fingerprint
from scanners.parsers import (
    detect_tool_error,
    parse_gobuster,
    parse_httpx_jsonl,
    parse_nmap_xml,
)
from scanners.scan_profiles import normalise_scan_options
from scanners.ssh_crypto_intel import _name_list, collect_ssh_cryptography


def _nmap_xml(port_body: str) -> str:
    return (
        "<?xml version='1.0'?><nmaprun scanner='nmap'>"
        "<host><status state='up'/><address addr='192.0.2.10' addrtype='ipv4'/>"
        f"<ports>{port_body}</ports></host></nmaprun>"
    )


def _synthetic_cve(year: int, sequence: int) -> str:
    """Build an isolated test identifier without embedding a fixed CVE."""
    return f"CVE-{year:04d}-{sequence:05d}"


def _server_kex_packet() -> bytes:
    payload = bytearray([20]) + bytearray(16)
    lists = [
        ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        ["ssh-ed25519", "rsa-sha2-512"],
        ["aes256-ctr"],
        ["aes256-ctr"],
        ["hmac-sha2-256"],
        ["hmac-sha2-256"],
        ["none"],
        ["none"],
        [],
        [],
    ]
    for values in lists:
        payload.extend(_name_list(values))
    payload.extend(b"\x00" + struct.pack(">I", 0))
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    packet_length = len(payload) + padding + 1
    return struct.pack(">I", packet_length) + bytes([padding]) + bytes(payload) + bytes(padding)


class _FakeSocket:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        return None

    def sendall(self, value: bytes):
        self.sent.append(value)

    def recv(self, size: int) -> bytes:
        if not self.data:
            return b""
        value = bytes(self.data[:size])
        del self.data[:size]
        return value


class ScannerHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_nmap_parser_preserves_all_states_and_open_services(self):
        xml = self.root / "scan.xml"
        xml.write_text(
            _nmap_xml(
                "<port protocol='tcp' portid='22'><state state='open' reason='syn-ack'/>"
                "<service name='ssh' product='OpenSSH' version='8.9'/></port>"
                "<port protocol='tcp' portid='23'><state state='filtered' reason='no-response'/></port>"
            ),
            encoding="utf-8",
        )
        data, warnings = parse_nmap_xml(xml)
        self.assertEqual(warnings, [])
        self.assertEqual([item["state"] for item in data["ports"]], ["open", "filtered"])
        self.assertEqual(
            [(item["port"], item["product"]) for item in data["services"]],
            [(22, "OpenSSH")],
        )
        self.assertEqual(data["parser_status"], "success")

    def test_nmap_parser_recovers_truncated_port(self):
        xml = self.root / "truncated.xml"
        xml.write_text(
            "<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.11' addrtype='ipv4'/>"
            "<ports><port protocol='tcp' portid='22'><state state='open' reason='syn-ack'",
            encoding="utf-8",
        )
        data, warnings = parse_nmap_xml(xml)
        self.assertTrue(data["partial"])
        self.assertEqual(data["ports"][0]["port"], 22)
        self.assertEqual(data["ports"][0]["state"], "open")
        self.assertTrue(any("missing closing </nmaprun>" in warning for warning in warnings))
        self.assertTrue(any("missing closing tags for 1 ports" in warning for warning in warnings))

    def test_nmap_parser_strict_mode_rejects_truncation(self):
        xml = self.root / "strict.xml"
        xml.write_text("<nmaprun><host>", encoding="utf-8")
        with self.assertRaises(ET.ParseError):
            parse_nmap_xml(xml, strict=True)

    def test_nmap_parser_replaces_invalid_utf8_and_reports_offset(self):
        xml = self.root / "latin.xml"
        xml.write_bytes(
            b"<nmaprun><host><address addr='192.0.2.12'/><ports>"
            b"<port protocol='tcp' portid='80'><state state='open'/>"
            b"<service name='http' product='nginx\xff' version='1.20'/></port>"
            b"</ports></host></nmaprun>"
        )
        data, warnings = parse_nmap_xml(xml)
        self.assertEqual(data["services"][0]["port"], 80)
        self.assertTrue(any("Encoding error at byte" in warning for warning in warnings))

    def test_empty_and_malformed_secondary_parsers_return_warnings(self):
        empty = self.root / "empty.jsonl"
        empty.write_bytes(b"")
        rows, warnings = parse_httpx_jsonl(empty)
        self.assertEqual(rows, [])
        self.assertIn("Empty output file: scan may have failed", warnings)

        malformed = self.root / "httpx.jsonl"
        malformed.write_text('{"url":"http://x","webserver":"nginx"}\nnot-json\n', encoding="utf-8")
        rows, warnings = parse_httpx_jsonl(malformed)
        self.assertEqual(len(rows), 1)
        self.assertTrue(any("line 2" in warning for warning in warnings))

        gobuster = self.root / "gobuster.txt"
        gobuster.write_text("admin (Status: 302) [Size: 0]\n[TIMEOUT]\n", encoding="utf-8")
        paths, warnings = parse_gobuster(gobuster, "192.0.2.10", 80)
        self.assertEqual(paths[0]["path"], "/admin")
        self.assertTrue(any("partial results" in warning for warning in warnings))

    def test_tool_error_signatures(self):
        cases = [
            ("nmap", "permission denied", "Nmap requires elevated privileges"),
            ("gobuster", "connection refused", "HTTP service not responding"),
            ("httpx", "unknown flag -json", "does not support"),
            ("ssh-audit", "timed out", "SSH cryptographic probe timed out"),
        ]
        for tool, stderr, expected in cases:
            with self.subTest(tool=tool):
                self.assertIn(expected, str(detect_tool_error(stderr, "", tool)))

    def test_fingerprint_contradiction_blocks_cve_and_serialises(self):
        fingerprint = validate_service_fingerprint(
            "192.0.2.10",
            80,
            {"product": "Apache httpd", "version": "2.4.41"},
            http_response="HTTP/1.1 200 OK\r\nServer: nginx/1.20\r\n",
        )
        self.assertEqual(fingerprint.confidence_score, 0.3)
        self.assertFalse(fingerprint.recommended_for_cve)
        self.assertTrue(fingerprint.contradictions)
        json.dumps(fingerprint.to_dict())

    def test_fingerprint_consensus_and_single_source_rules(self):
        agreed = validate_service_fingerprint(
            "192.0.2.10",
            443,
            {"product": "nginx", "version": "1.20"},
            http_response="Server: nginx/1.20",
        )
        self.assertGreaterEqual(agreed.confidence_score, 0.9)
        self.assertTrue(agreed.recommended_for_cve)

        nmap_only = validate_service_fingerprint(
            "192.0.2.10", 443, {"product": "nginx", "version": "1.20"}
        )
        self.assertEqual(nmap_only.confidence_score, 0.6)
        self.assertFalse(nmap_only.recommended_for_cve)

        tls_http = validate_service_fingerprint(
            "192.0.2.10",
            443,
            {},
            http_response="Server: nginx/1.20",
            tls_cert={"product": "nginx", "version": "1.20"},
        )
        self.assertEqual(tls_http.confidence_score, 0.8)
        self.assertTrue(tls_http.recommended_for_cve)

    def test_acl_patterns_use_port_state_evidence(self):
        udp = detect_firewall_acl(
            {
                "ports": [{"protocol": "tcp", "port": 22, "state": "open"}],
                "extraports": [{"protocol": "udp", "state": "filtered", "count": 12}],
            },
            "192.0.2.20",
        )
        self.assertIsNotNone(udp)
        self.assertEqual(udp.pattern_type, "stateless_udp_block")

        stateful = detect_firewall_acl(
            {
                "ports": [
                    {"protocol": "tcp", "port": 80, "state": "closed"},
                    {"protocol": "tcp", "port": 22, "state": "open"},
                ],
                "extraports": [{"protocol": "tcp", "state": "filtered", "count": 18}],
            },
            "192.0.2.21",
        )
        self.assertIsNotNone(stateful)
        self.assertEqual(stateful.pattern_type, "stateful_tcp_inspection")

        rate = detect_firewall_acl(
            {
                "rate_observations": [
                    {"rate": 2, "probes": 20, "resets": 1, "timeouts": 1},
                    {"rate": 20, "probes": 20, "resets": 5, "timeouts": 8},
                ]
            },
            "192.0.2.22",
        )
        self.assertIsNotNone(rate)
        self.assertEqual(rate.pattern_type, "rate_limit_active")

    def test_ssh_crypto_collector_parses_one_kexinit(self):
        fake = _FakeSocket(
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n" + _server_kex_packet()
        )
        with patch("socket.create_connection", return_value=fake):
            profile = collect_ssh_cryptography("192.0.2.30", 22, 2)
        self.assertIsNotNone(profile)
        self.assertTrue(profile.server_software.startswith("OpenSSH_8.9p1"))
        self.assertEqual(profile.key_exchange_algorithms[0], "curve25519-sha256")
        self.assertEqual(profile.inferred_os, "Ubuntu Linux")
        self.assertEqual(profile.inferred_patch_level, "Ubuntu-3ubuntu0.10")
        self.assertEqual(len(fake.sent), 2)
        json.dumps(profile.to_dict())

    def test_ssh_crypto_collector_handles_network_timeout(self):
        with patch("socket.create_connection", side_effect=socket.timeout("timeout")):
            self.assertIsNone(collect_ssh_cryptography("192.0.2.31", 22, 1))

    def test_mitre_search_stops_before_index_lookup_on_low_confidence(self):
        with patch.object(
            mitre_cve,
            "_search_cached",
            side_effect=AssertionError("index lookup must not run"),
        ):
            confirmed, held = mitre_cve.search_with_held(
                "Apache httpd",
                "2.4.41",
                "http",
                confidence_score=0.6,
                recommended_for_cve=False,
            )
        self.assertEqual(confirmed, ())
        self.assertEqual(held[0]["reason"], "fingerprint_confidence_below_cve_threshold")

    def test_enumerator_applies_consensus_and_dashboard_badge(self):
        dotenv_stub = types.ModuleType("dotenv")
        dotenv_stub.load_dotenv = lambda *_args, **_kwargs: None
        with patch.dict(sys.modules, {"dotenv": dotenv_stub}):
            enumerator = importlib.import_module("scanners.enumerator")
        services = [
            {
                "host": "192.0.2.10",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.41",
                "cpe": [],
                "evidence_sources": ["nmap"],
            }
        ]
        web = [
            {
                "host": "192.0.2.10",
                "port": 80,
                "webserver": "nginx/1.20",
                "url": "http://192.0.2.10",
            }
        ]
        rows, fingerprints = enumerator._apply_service_fingerprints(
            services, web, [], [], [], []
        )
        self.assertEqual(rows[0]["confidence_score"], 0.3)
        self.assertFalse(rows[0]["recommended_for_cve"])
        self.assertEqual(len(fingerprints), 1)
        summary = enumerator._build_service_summary(rows, [], [])
        self.assertEqual(summary[0]["confidence_badge"], "Low (0.30)")

    def test_ssh_crypto_collection_requires_existing_profile_selection(self):
        full = normalise_scan_options("full")
        self.assertNotIn("ssh_audit_native", full["enabled_tools"])
        custom = normalise_scan_options("custom", ["ssh_audit_native"])
        self.assertEqual(custom["enabled_tools"], [])
        self.assertIn("ssh_audit_native", custom["policy_conflicts"])
        self.assertEqual(custom["policy_resolution"], "explicit_disabled_wins")
        self.assertRegex(custom["effective_policy_sha256"], r"^[0-9a-f]{64}$")

    def test_http_error_response_is_not_success_or_retained_evidence(self):
        error = urllib.error.HTTPError(
            "http://example.invalid/missing",
            404,
            "Not Found",
            {},
            io.BytesIO(b"missing marker echoed by fallback page"),
        )
        with patch("urllib.request.urlopen", side_effect=error):
            row = _fetch("http://example.invalid/missing")
        self.assertTrue(row["transport_success"])
        self.assertFalse(row["success"])
        self.assertFalse(row["evidence_observed"])
        self.assertFalse(_interesting_response(row, ["marker"]))

    def test_native_evidence_can_corroborate_nmap_identity(self):
        fingerprint = validate_service_fingerprint(
            "192.0.2.40",
            22,
            {"product": "OpenSSH", "version": "9.2"},
            additional_evidence=[{
                "tool": "native_protocol",
                "product": "OpenSSH",
                "version": "9.2",
                "raw_evidence": "captured protocol identification",
            }],
        )
        self.assertGreaterEqual(fingerprint.confidence_score, 0.9)
        self.assertTrue(fingerprint.recommended_for_cve)

    def test_dynamic_product_cpe_match_uses_only_index_record(self):
        index = self.root / "official-index.jsonl"
        record = {
            "cve_id": _synthetic_cve(2099, 12345),
            "description": "RangeWidget Server issue",
            "affected_entries": [{
                "vendor": "ExampleVendor",
                "product": "RangeWidget Server",
                "versions": [{"version": "7.4.2", "status": "affected"}],
                "cpes": ["cpe:2.3:a:examplevendor:rangewidget_server:7.4.2:*:*:*:*:*:*:*"],
            }],
            "references": ["https://example.invalid/advisory"],
            "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        }
        index.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with patch.object(mitre_cve, "INDEX", index), patch.object(
            mitre_cve, "query_vulnerable_cpe", return_value=([], {"status": "available", "reason": "test_cache", "record_count": 0})
        ):
            mitre_cve._search_cached.cache_clear()
            confirmed, held = mitre_cve.search_with_held(
                "RangeWidget Server",
                "7.4.2",
                "custom-service",
                "cpe:/a:examplevendor:rangewidget_server:7.4.2",
                confidence_score=0.95,
                recommended_for_cve=True,
            )
        mitre_cve._search_cached.cache_clear()
        self.assertEqual([row["cve_id"] for row in confirmed], [record["cve_id"]])
        self.assertEqual(held[0]["reason"], "test_cache")

    def test_downstream_mapping_cves_are_replaced_by_canonical_contract(self):
        dotenv_stub = types.ModuleType("dotenv")
        dotenv_stub.load_dotenv = lambda *_args, **_kwargs: None
        with patch.dict(sys.modules, {"dotenv": dotenv_stub}):
            enumerator = importlib.import_module("scanners.enumerator")
        legacy_id = _synthetic_cve(2098, 11111)
        canonical_id = _synthetic_cve(2099, 22222)
        mapping = {"vulnerabilities": [{
            "host": "192.0.2.50", "port": "443", "title": f"Legacy ({legacy_id})",
            "severity": "Critical", "priority_score": 99,
            "cve_ids": [legacy_id], "cve_matches": [{"cve_id": legacy_id}],
        }], "top_risks": [], "recommended_techniques": []}
        result = enumerator._canonicalise_downstream_mapping(mapping, [{
            "host": "192.0.2.50", "port": 443, "cve_id": canonical_id,
            "cvss_severity": "High", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        }], [])
        finding = result["vulnerabilities"][0]
        self.assertEqual(finding["cve_ids"], [canonical_id])
        self.assertNotIn(legacy_id, json.dumps(result))
        self.assertEqual(result["cve_source_of_truth"], "scanner_official_index")

    def test_scanner_runtime_has_no_fixed_cve_or_private_target_literals(self):
        scanner_root = Path(__file__).resolve().parents[1]
        fixed_cve = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
        private_target = re.compile(r"(?:192\.168\.|10\.(?:[0-9]{1,3}\.)|172\.(?:1[6-9]|2[0-9]|3[01])\.)")
        violations = []
        for path in scanner_root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            text = path.read_text(encoding="utf-8-sig")
            if fixed_cve.search(text) or private_target.search(text):
                violations.append(path.name)
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
