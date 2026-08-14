from __future__ import annotations

import json
import tempfile
import types
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scanners import mitre_cve
from scanners.collector_plan import COLLECTOR_GROUPS
from scanners.parsers import parse_nmap_xml
from scanners.platform_identity import (
    extract_host_identities_from_nmap,
    host_identity_gaps,
    host_identity_inventory,
    merge_host_identity_map,
    platform_component_inventory,
    normalise_host_identity,
)
from scanners.scan_profiles import normalise_scan_options


def _cve(num: int) -> str:
    return f"CVE-2099-{num:05d}"


class CrossPlatformIdentityTests(TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        mitre_cve._search_cached.cache_clear()
        self.temp.cleanup()

    def _write_xml(self, text: str) -> Path:
        path = self.root / "scan.xml"
        path.write_text(text, encoding="utf-8")
        return path

    def _write_index(self, records: list[dict]) -> Path:
        path = self.root / "index.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        return path

    def test_primary_parser_preserves_os_cpe_and_host_os_evidence(self):
        path = self._write_xml('''<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.20" addrtype="ipv4"/>
<hostnames><hostname name="workstation.example"/></hostnames>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds" product="Example Service" ostype="Windows" hostname="CLIENT01">
<cpe>cpe:2.3:o:examplevendor:example_os:10.2:*:*:*:*:*:*:*</cpe>
</service></port></ports>
<os><osmatch name="Example OS 10" accuracy="98"><osclass vendor="ExampleVendor" osfamily="ExampleOS" osgen="10" type="general purpose" accuracy="98"><cpe>cpe:2.3:o:examplevendor:example_os:10.2:*:*:*:*:*:*:*</cpe></osclass></osmatch></os>
<hostscript><script id="smb-os-discovery" output="OS: Example OS 10"><elem key="os">Example OS 10</elem><elem key="computer_name">CLIENT01</elem></script></hostscript>
</host></nmaprun>''')
        parsed, warnings = parse_nmap_xml(path)
        self.assertEqual(warnings, [])
        service = parsed["services"][0]
        self.assertEqual(service["cpe"], [])
        self.assertEqual(service["os_cpe"], ["cpe:2.3:o:examplevendor:example_os:10.2:*:*:*:*:*:*:*"])
        host = parsed["hosts"][0]
        self.assertTrue(host["os_identities"])
        self.assertEqual(host["scripts"][0]["fields"]["os"], "Example OS 10")

        identities = extract_host_identities_from_nmap(parsed, evidence_reference=str(path))
        self.assertTrue(any(i.get("product") == "Example OS 10" for i in identities))
        self.assertTrue(any("example_os" in " ".join(i.get("cpe") or []) for i in identities))

    def test_windows_range_stays_ambiguous_and_is_not_converted_to_numeric_release(self):
        parsed = {
            "hosts": [{
                "address": "192.0.2.21", "hostnames": [], "scripts": [],
                "os_identities": [],
                "ports": [{
                    "port": 445, "protocol": "tcp", "service": "microsoft-ds",
                    "service_attributes": {"ostype": "Windows", "hostname": "CLIENT01"},
                    "os_cpe": [], "scripts": [],
                }],
            }]
        }
        identities = extract_host_identities_from_nmap(parsed)
        # A per-service ostype/CPE is endpoint context, not host OS identity.
        self.assertEqual(identities, [])

        # A broad service product string stays on the service evidence and is
        # never converted into a host identity or exact Windows release.
        parsed["hosts"][0]["ports"][0]["service_attributes"]["ostype"] = "Microsoft Windows 7 - 10"
        identities = extract_host_identities_from_nmap(parsed)
        self.assertEqual(identities, [])

    def test_ntlm_product_version_is_build_evidence_not_windows_marketing_edition(self):
        parsed = {
            "hosts": [{
                "address": "192.0.2.22", "hostnames": [], "os_identities": [],
                "scripts": [],
                "ports": [{
                    "port": 3389, "protocol": "tcp", "service_attributes": {}, "os_cpe": [],
                    "scripts": [{
                        "id": "rdp-ntlm-info",
                        "output": "Product_Version: 10.0.19045\nNetBIOS_Computer_Name: CLIENT01",
                        "fields": {"Product_Version": "10.0.19045", "NetBIOS_Computer_Name": "CLIENT01"},
                    }],
                }],
            }]
        }
        identities = extract_host_identities_from_nmap(parsed)
        row = next(i for i in identities if i.get("build") == "10.0.19045")
        self.assertEqual(row["product"], "Microsoft Windows")
        self.assertEqual(row["family"], "Windows")
        self.assertNotIn("Windows 10", row["product"])
        self.assertEqual(
            row["quality"],
            "Build observed; exact Windows release unresolved",
        )

    def test_conflicting_host_identity_observations_are_preserved(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [
            {"host": "192.0.2.23", "product": "Example OS Family", "family": "ExampleOS", "source": "nmap"},
            {"host": "192.0.2.23", "product": "Example OS Family", "family": "ExampleOS", "build": "42.7", "source": "ntlm"},
        ])
        self.assertEqual(len(identity_map["192.0.2.23"]), 2)
        gaps = host_identity_gaps(identity_map, ["192.0.2.23"])
        self.assertEqual(gaps, [])


    def test_direct_protocol_identity_excludes_conflicting_probabilistic_os_fingerprints_from_cve_scope(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [
            {
                "host": "192.0.2.230", "product": "Example OS Alpha or Example OS Beta",
                "family": "ExampleOS", "generation": "Beta", "accuracy": "98",
                "cpe": ["cpe:2.3:o:example:example_os_beta:2:*:*:*:*:*:*:*"],
                "evidence_kind": "probabilistic_fingerprint", "source": "os_fingerprint",
            },
            {
                "host": "192.0.2.230", "product": "Example OS Gamma",
                "family": "ExampleOS", "generation": "Gamma", "accuracy": "97",
                "cpe": ["cpe:2.3:o:example:example_os_gamma:3:*:*:*:*:*:*:*"],
                "evidence_kind": "probabilistic_fingerprint", "source": "os_fingerprint",
            },
            {
                "host": "192.0.2.230", "product": "Example OS Delta Enterprise",
                "family": "ExampleOS", "version": "4.2.100", "build": "4.2.100",
                "evidence_kind": "protocol_assertion", "source": "protocol_identity",
            },
        ])
        inventory = host_identity_inventory(identity_map)[0]
        self.assertEqual(len(inventory["identities"]), 3)
        self.assertEqual(len(inventory["cve_identities"]), 1)
        self.assertEqual(inventory["cve_identities"][0]["product"], "Example OS Delta Enterprise")
        fingerprint_rows = [row for row in inventory["identities"] if row.get("evidence_kind") == "probabilistic_fingerprint"]
        self.assertTrue(fingerprint_rows)
        self.assertTrue(all(row.get("cve_eligible") is False for row in fingerprint_rows))
        self.assertTrue(all(row.get("quality") == "Probabilistic OS fingerprint" for row in fingerprint_rows))

    def test_authenticated_inventory_outranks_protocol_identity_without_product_version_mapping(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [
            {
                "host": "192.0.2.231", "product": "Example OS", "family": "ExampleOS",
                "build": "5.0.10", "version": "5.0.10",
                "evidence_kind": "protocol_assertion", "source": "protocol_identity",
            },
            {
                "host": "192.0.2.231", "product": "Example OS Professional", "family": "ExampleOS",
                "build": "5.0.10", "version": "5.0.10",
                "evidence_kind": "authenticated_inventory", "source": "authenticated_inventory",
            },
        ])
        inventory = host_identity_inventory(identity_map)[0]
        self.assertEqual(len(inventory["cve_identities"]), 1)
        self.assertEqual(inventory["cve_identities"][0]["product"], "Example OS Professional")
        self.assertEqual(inventory["best"]["evidence_kind"], "authenticated_inventory")

    def test_ambiguous_probabilistic_fingerprint_alone_is_not_promoted_to_cve_identity(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [{
            "host": "192.0.2.232", "product": "Example OS One or Example OS Two",
            "family": "ExampleOS", "generation": "Two", "accuracy": "99",
            "cpe": ["cpe:2.3:o:example:example_os_two:2:*:*:*:*:*:*:*"],
            "evidence_kind": "probabilistic_fingerprint", "source": "os_fingerprint",
        }])
        inventory = host_identity_inventory(identity_map)[0]
        self.assertEqual(inventory["cve_identities"], [])
        self.assertEqual(inventory["identities"][0]["reconciliation_status"], "supporting_only")

    def test_single_highest_accuracy_probabilistic_fingerprint_remains_unresolved_candidate_input(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [
            {
                "host": "192.0.2.233", "product": "Example OS Three", "family": "ExampleOS",
                "generation": "3", "accuracy": "97",
                "cpe": ["cpe:2.3:o:example:example_os_three:3:*:*:*:*:*:*:*"],
                "evidence_kind": "probabilistic_fingerprint", "source": "os_fingerprint",
            },
            {
                "host": "192.0.2.233", "product": "Example OS Four", "family": "ExampleOS",
                "generation": "4", "accuracy": "95",
                "cpe": ["cpe:2.3:o:example:example_os_four:4:*:*:*:*:*:*:*"],
                "evidence_kind": "probabilistic_fingerprint", "source": "os_fingerprint",
            },
        ])
        inventory = host_identity_inventory(identity_map)[0]
        self.assertEqual(inventory["cve_identities"], [])
        self.assertEqual(inventory["best"], {})
        self.assertEqual(inventory["identity_state"], "unresolved_probabilistic")
        self.assertTrue(any(row.get("product") == "Example OS Three" for row in inventory["candidate_identities"]))
        self.assertTrue(all(row.get("reconciliation_status") == "candidate_fingerprint" for row in inventory["candidate_identities"]))

    def test_component_inventory_only_uses_direct_component_observations(self):
        services = [{
            "host": "192.0.2.24", "port": 8180, "protocol": "tcp", "service": "http",
            "product": "Example Web App", "version": "5.5",
            "observed_identities": [
                {"kind": "connector", "service": "http", "product": "Example Connector", "version": "1.1", "sources": ["nmap"]},
                {"kind": "web_application", "service": "http", "product": "Example Web App", "version": "5.5", "sources": ["httpx"]},
            ],
        }]
        rows = platform_component_inventory(services)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["product"], "Example Connector")
        self.assertEqual(rows[0]["scope"], "platform_component")

    def test_scope_aware_cve_engine_separates_os_and_application_cpes(self):
        os_id, app_id = _cve(10001), _cve(10002)
        index = self._write_index([
            {
                "cve_id": os_id, "description": "Synthetic OS issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "affected_entries": [{
                    "vendor": "ExampleVendor", "product": "Example OS",
                    "versions": [{"version": "10.2", "status": "affected"}],
                    "cpes": ["cpe:2.3:o:examplevendor:example_os:10.2:*:*:*:*:*:*:*"],
                }],
            },
            {
                "cve_id": app_id, "description": "Synthetic application issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "affected_entries": [{
                    "vendor": "ExampleVendor", "product": "Example Service",
                    "versions": [{"version": "3.4", "status": "affected"}],
                    "cpes": ["cpe:2.3:a:examplevendor:example_service:3.4:*:*:*:*:*:*:*"],
                }],
            },
        ])
        with patch.object(mitre_cve, "INDEX", index):
            mitre_cve._search_cached.cache_clear()
            os_rows, _ = mitre_cve.search_with_held(
                "Example OS", "10.2", "host operating system",
                "cpe:2.3:o:examplevendor:example_os:10.2:*:*:*:*:*:*:*",
                scope="host_os", recommended_for_cve=True,
            )
            app_rows, _ = mitre_cve.search_with_held(
                "Example Service", "3.4", "custom",
                "cpe:2.3:a:examplevendor:example_service:3.4:*:*:*:*:*:*:*",
                scope="application_service", recommended_for_cve=True,
            )
        self.assertEqual([r["cve_id"] for r in os_rows], [os_id])
        self.assertEqual([r["cve_id"] for r in app_rows], [app_id])

    def test_platform_component_uses_same_engine_but_keeps_component_scope(self):
        component_id = _cve(10003)
        index = self._write_index([{
            "cve_id": component_id, "description": "Synthetic component issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
            "affected_entries": [{
                "vendor": "ExampleVendor", "product": "Example Connector",
                "versions": [{"version": "1.1", "status": "affected"}],
                "cpes": ["cpe:2.3:a:examplevendor:example_connector:1.1:*:*:*:*:*:*:*"],
            }],
        }])
        with patch.object(mitre_cve, "INDEX", index):
            mitre_cve._search_cached.cache_clear()
            rows, _ = mitre_cve.search_with_held(
                "Example Connector", "1.1", "http",
                "cpe:2.3:a:examplevendor:example_connector:1.1:*:*:*:*:*:*:*",
                scope="platform_component", recommended_for_cve=True,
            )
        self.assertEqual([r["cve_id"] for r in rows], [component_id])
        self.assertEqual(rows[0]["identity_scope"], "platform_component")
        self.assertIn("exact_component_cpe", rows[0]["match_basis"])

    def test_generic_os_family_does_not_expand_to_unobserved_specific_release(self):
        windows_id, mac_id = _cve(10009), _cve(10010)
        index = self._write_index([
            {
                "cve_id": windows_id, "description": "Synthetic specific Windows release issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "affected_entries": [{
                    "vendor": "Microsoft", "product": "Windows 10", "defaultStatus": "affected",
                    "versions": [], "cpes": [],
                }],
            },
            {
                "cve_id": mac_id, "description": "Synthetic named macOS release issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "affected_entries": [{
                    "vendor": "Apple", "product": "macOS Sonoma", "defaultStatus": "affected",
                    "versions": [], "cpes": [],
                }],
            },
        ])
        with patch.object(mitre_cve, "INDEX", index):
            mitre_cve._search_cached.cache_clear()
            windows_rows, _ = mitre_cve.search_with_held("Microsoft Windows", "", "host operating system", "", scope="host_os", recommended_for_cve=True)
            mitre_cve._search_cached.cache_clear()
            mac_rows, _ = mitre_cve.search_with_held("Apple macOS", "", "host operating system", "", scope="host_os", recommended_for_cve=True)
        self.assertEqual(tuple(windows_rows), ())
        self.assertEqual(tuple(mac_rows), ())

    def test_macos_host_identity_uses_same_os_scope_without_apple_scan_mode(self):
        cve_id = _cve(10004)
        index = self._write_index([{
            "cve_id": cve_id, "description": "Synthetic operating system issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
            "affected_entries": [{
                "vendor": "Apple", "product": "macOS",
                "versions": [{"version": "14.2", "status": "affected"}],
                "cpes": ["cpe:2.3:o:apple:macos:14.2:*:*:*:*:*:*:*"],
            }],
        }])
        with patch.object(mitre_cve, "INDEX", index):
            mitre_cve._search_cached.cache_clear()
            rows, _ = mitre_cve.search_with_held(
                "Apple macOS", "14.2", "host operating system",
                "cpe:2.3:o:apple:macos:14.2:*:*:*:*:*:*:*",
                scope="host_os", recommended_for_cve=True,
            )
        self.assertEqual([r["cve_id"] for r in rows], [cve_id])

    def test_enumerator_emits_host_component_and_service_scopes(self):
        dotenv_stub = types.ModuleType("dotenv")
        dotenv_stub.load_dotenv = lambda *_args, **_kwargs: None
        with patch.dict(sys.modules, {"dotenv": dotenv_stub}):
            from scanners import enumerator

        host_id = _cve(10005)
        app_id = _cve(10006)
        component_id = _cve(10007)
        def fake_search(product, version, service, cpe, **kwargs):
            scope = kwargs.get("scope")
            ids = {"host_os": host_id, "application_service": app_id, "platform_component": component_id}
            cid = ids[scope]
            return (({
                "cve_id": cid, "description": "Synthetic issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "matched_product_tokens": [product], "matched_version_tokens": [version],
                "match_basis": "structured_exact_version", "affected_entries": [], "references": [],
            },), ())

        services = [{
            "host": "192.0.2.25", "port": 12345, "protocol": "tcp", "service": "custom",
            "product": "Example Service", "version": "3.4", "cpe": [], "evidence_sources": ["nmap"],
            "observed_identities": [{"kind": "connector", "service": "custom", "product": "Example Connector", "version": "1.1", "cpe": [], "sources": ["nmap"]}],
        }]
        host_ids = [{"scope": "host_os", "host": "192.0.2.25", "product": "Example OS", "version": "10.2", "quality": "Version evidence observed", "sources": ["nmap"], "cpe": []}]
        with patch.object(enumerator, "mitre_search_with_held", side_effect=fake_search):
            rows, held = enumerator._match_cves(services, [], host_ids)
        self.assertEqual(held, [])
        by_id = {r["cve_id"]: r for r in rows}
        self.assertEqual(by_id[app_id]["match_scope"], "application_service")
        self.assertEqual(by_id[component_id]["match_scope"], "platform_component")
        self.assertEqual(by_id[host_id]["match_scope"], "host_os")
        self.assertEqual(by_id[host_id]["port"], "host")

    def test_collector_plan_exposes_host_identity_group_and_target_agnostic_collectors(self):
        group_ids = {g["id"] for g in COLLECTOR_GROUPS}
        self.assertIn("host_identity", group_ids)
        options = normalise_scan_options("full")
        for collector in (
            "nmap_os_identity", "smb_host_identity", "netbios_identity", "msrpc_metadata",
            "ntlm_http_identity", "ntlm_rdp_identity", "ntlm_mssql_identity",
        ):
            self.assertIn(collector, options["enabled_tools"])

    def _load_enumerator(self):
        dotenv_stub = types.ModuleType("dotenv")
        dotenv_stub.load_dotenv = lambda *_args, **_kwargs: None
        with patch.dict(sys.modules, {"dotenv": dotenv_stub}):
            from scanners import enumerator
        return enumerator

    def test_ttl_is_retained_as_fact_and_never_assigns_windows_linux_or_device_role(self):
        enumerator = self._load_enumerator()
        for ttl in (64, 128, 255):
            self.assertEqual(enumerator._environment_role_hint(ttl), "ttl_observed")
            layer = enumerator._classify_network_layer(
                "192.0.2.30", [{"host": "192.0.2.30", "ttl": ttl}], [22, 80, 443]
            )
            self.assertEqual(layer["scan_posture"], "default")
            self.assertNotIn("windows", json.dumps(layer).lower())
            self.assertNotIn("linux", json.dumps(layer).lower())
            self.assertNotIn("infrastructure_candidate", json.dumps(layer).lower())

    def test_http_layers_keep_tomcat_application_separate_from_coyote_connector(self):
        enumerator = self._load_enumerator()
        services = [{
            "host": "192.0.2.31", "port": 8180, "protocol": "tcp", "service": "http",
            "product": "Apache Tomcat/Coyote JSP engine", "version": "1.1", "cpe": [],
            "evidence_sources": ["nmap"],
        }]
        web = [{
            "tool": "httpx", "host": "192.0.2.31", "port": 8180,
            "title": "Apache Tomcat/5.5", "webserver": "Apache-Coyote/1.1",
            "tech": ["Apache Tomcat", "Java"], "cpe": [],
        }]
        rows, _ = enumerator._apply_service_fingerprints(services, web, [], [], [], [])
        identities = rows[0].get("observed_identities") or []
        self.assertTrue(any(i.get("product") == "Apache Tomcat" and i.get("version") == "5.5" for i in identities))
        self.assertTrue(any(i.get("product") == "Apache-Coyote" and i.get("version") == "1.1" for i in identities))
        self.assertFalse(any(i.get("product") == "Apache Tomcat" and i.get("version") == "1.1" for i in identities))

    def test_equivalent_service_aliases_do_not_duplicate_same_cve_row(self):
        enumerator = self._load_enumerator()
        cve_id = _cve(10008)
        def fake_search(product, version, service, cpe, **kwargs):
            return (({
                "cve_id": cve_id, "description": "Synthetic issue", "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "matched_product_tokens": ["Canonical Example Service"], "matched_version_tokens": [version],
                "match_basis": "structured_exact_version", "affected_entries": [], "references": [],
            },), ())
        services = [{
            "host": "192.0.2.32", "port": 8080, "protocol": "tcp", "service": "http",
            "product": "Example Service Daemon", "version": "3.4", "cpe": [], "evidence_sources": ["nmap"],
            "observed_identities": [{
                "kind": "web_application", "service": "http", "product": "Example Service",
                "version": "3.4", "cpe": [], "sources": ["httpx"],
            }],
        }]
        with patch.object(enumerator, "mitre_search_with_held", side_effect=fake_search):
            rows, _ = enumerator._match_cves(services, [], [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id"], cve_id)

    def test_security_observation_summary_deduplicates_equivalent_evidence(self):
        enumerator = self._load_enumerator()
        checks = [
            {
                "tool": "ssh_auth_methods", "host": "192.0.2.33", "port": 22,
                "parsed": {"evidence_state": "observed", "fields": {"authentication_methods": "publickey password publickey password"}},
            },
            {
                "tool": "ssh_auth_methods", "host": "192.0.2.33", "port": 22,
                "parsed": {"evidence_state": "observed", "fields": {"authentication_methods": "publickey password"}},
            },
        ]
        rows = enumerator._build_observed_security_evidence(checks, {})
        auth_rows = [r for r in rows if r.get("source") == "ssh_auth_methods" and "authentication" in str(r.get("check") or "").lower()]
        self.assertEqual(len(auth_rows), 1)

    def test_protocol_advertised_endpoint_parser_only_uses_explicit_tcp_port_fields(self):
        enumerator = self._load_enumerator()
        values = [
            "uuid: abc\ntcp_port: 49153\nannotation: Example",
            "product mentions 445 but no endpoint field",
            "tcp_port: 65536\ntcp_port: 12345",
        ]
        self.assertEqual(enumerator._extract_protocol_advertised_tcp_ports(values), [12345, 49153])

    def test_protocol_advertised_endpoint_followup_is_explicit_and_off_by_default(self):
        options = normalise_scan_options("full")
        identity = options["service_identity"]
        self.assertFalse(identity["follow_protocol_advertised_endpoints"])
        self.assertEqual(identity["advertised_endpoint_limit"], 8)

    def test_missing_collector_lifecycle_is_explicit_assurance_failure_not_ambiguous_applicable_state(self):
        enumerator = self._load_enumerator()
        scan_options = normalise_scan_options("full")
        service = {"host": "192.0.2.34", "port": 80, "protocol": "tcp", "service": "http", "product": "Example", "version": "1.0"}
        matrix = enumerator._build_collector_coverage_matrix([service], scan_options, [], [])
        outcomes = [str(row.get("outcome") or "") for row in matrix["endpoint_rows"]]
        self.assertFalse(any("Applicable - no execution record" in value for value in outcomes))
        self.assertTrue(any(row.get("lifecycle_state") == "assurance_failure" for row in matrix["endpoint_rows"]))

    def test_complementary_direct_os_product_cpe_and_build_are_correlated(self):
        smb_path = self._write_xml('''<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.36" addrtype="ipv4"/>
<hostscript><script id="smb-os-discovery" output="OS: Windows Example Enterprise&#xa;OS CPE: cpe:/o:microsoft:windows_example::-&#xa;Computer name: CLIENT01">
<elem key="os">Windows Example Enterprise</elem><elem key="cpe">cpe:/o:microsoft:windows_example::-</elem><elem key="computer_name">CLIENT01</elem>
</script></hostscript></host></nmaprun>''')
        smb_parsed, _ = parse_nmap_xml(smb_path)
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(
            identity_map,
            extract_host_identities_from_nmap(smb_parsed, source="smb_host_identity", evidence_reference=str(smb_path)),
        )

        rdp_path = self.root / "rdp.xml"
        rdp_path.write_text('''<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.36" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/>
<script id="rdp-ntlm-info" output="Product_Version: 10.0.42424&#xa;NetBIOS_Computer_Name: CLIENT01">
<elem key="Product_Version">10.0.42424</elem><elem key="NetBIOS_Computer_Name">CLIENT01</elem>
</script></port></ports></host></nmaprun>''', encoding="utf-8")
        rdp_parsed, _ = parse_nmap_xml(rdp_path)
        merge_host_identity_map(
            identity_map,
            extract_host_identities_from_nmap(rdp_parsed, source="ntlm_rdp_identity", evidence_reference=str(rdp_path)),
        )
        merge_host_identity_map(identity_map, [{
            "host": "192.0.2.36",
            "vendor": "Linux",
            "family": "Linux",
            "product": "Linux Example",
            "version": "4.2",
            "cpe": ["cpe:/o:linux:linux_kernel:4.2"],
            "accuracy": "99",
            "evidence_kind": "probabilistic_fingerprint",
            "source": "nmap_os_identity",
        }])

        inventory = host_identity_inventory(identity_map)[0]
        correlated = [
            row for row in inventory["cve_identities"]
            if row.get("evidence_kind") == "protocol_correlation"
        ]
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["build"], "10.0.42424")
        self.assertEqual(correlated[0]["version"], "10.0.42424")
        self.assertEqual(correlated[0]["cpe"], ["cpe:/o:microsoft:windows_example::-"])
        self.assertIn("smb_host_identity", correlated[0]["sources"])
        self.assertIn("ntlm_rdp_identity", correlated[0]["sources"])
        linux_rows = [row for row in inventory["identities"] if row.get("family") == "Linux"]
        self.assertTrue(linux_rows)
        self.assertTrue(all(row.get("cve_eligible") is False for row in linux_rows))
        self.assertEqual(host_identity_gaps(identity_map, ["192.0.2.36"]), [])

    def test_product_only_cpe22_os_identity_is_preserved(self):
        identity = normalise_host_identity({
            "host": "192.0.2.35", "product": "Windows", "family": "Windows",
            "cpe": ["cpe:/o:microsoft:windows"], "source": "nmap",
        })
        self.assertEqual(identity["cpe"], ["cpe:/o:microsoft:windows"])
        self.assertEqual(identity["quality"], "OS CPE observed")
        self.assertEqual(mitre_cve._cpe_values("cpe:/o:microsoft:windows", "host_os"), ["cpe:/o:microsoft:windows"])

    def test_production_scanner_has_no_special_case_eternalblue_or_real_cve_literals(self):
        root = Path(__file__).resolve().parents[1]
        production = "\n".join(
            p.read_text(encoding="utf-8", errors="ignore")
            for p in root.glob("*.py")
            if p.name != Path(__file__).name
        )
        self.assertNotIn("EternalBlue", production)
        import re
        self.assertIsNone(re.search(r"CVE-20\d{2}-\d{4,}", production))


if __name__ == "__main__":
    import unittest
    unittest.main()
