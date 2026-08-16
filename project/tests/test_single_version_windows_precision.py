import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1] / "project"
import sys

sys.path.insert(0, str(PROJECT))

from scanners.cpe_utils import evaluate_configurations
from scanners import mitre_cve
from scanners.platform_identity import identity_quality, reconcile_host_identities
from scanners.windows_patch_inventory import collect_windows_patch_inventory


class WindowsIdentityPrecisionTests(unittest.TestCase):
    def test_ambiguous_windows_range_and_generic_build_are_not_cve_eligible(self):
        rows = reconcile_host_identities([
            {
                "host": "192.0.2.10",
                "family": "Windows",
                "vendor": "Microsoft",
                "product": "Microsoft Windows 7 - 10 microsoft-ds",
                "evidence_kind": "protocol_assertion",
                "source": "smb-os-discovery",
            },
            {
                "host": "192.0.2.10",
                "family": "Windows",
                "vendor": "Microsoft",
                "product": "Microsoft Windows",
                "version": "10.0.10240",
                "build": "10.0.10240",
                "evidence_kind": "protocol_assertion",
                "source": "rdp-ntlm-info",
            },
        ])
        self.assertTrue(rows)
        self.assertFalse(any(row.get("cve_eligible") for row in rows))
        self.assertTrue(all(row.get("reconciliation_status") == "identity_evidence_gap" for row in rows))
        build_row = next(row for row in rows if row.get("build"))
        self.assertEqual(
            build_row.get("quality"),
            "Build observed; exact Windows release unresolved",
        )

    def test_exact_observed_windows_product_and_build_remain_eligible(self):
        rows = reconcile_host_identities([{
            "host": "192.0.2.20",
            "family": "Windows",
            "vendor": "Microsoft",
            "product": "Microsoft Windows 10",
            "version": "10.0.19045",
            "build": "10.0.19045",
            "evidence_kind": "operator_inventory",
            "source": "windows_patch_inventory",
        }])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].get("cve_eligible"))
        self.assertEqual(identity_quality(rows[0]), "Exact build observed")


class ScopeSeparatedCveMatchingTests(unittest.TestCase):
    def setUp(self):
        mitre_cve._search_cached.cache_clear()

    def tearDown(self):
        mitre_cve._search_cached.cache_clear()

    @staticmethod
    def _write_index(directory: str, records: list[dict]) -> Path:
        path = Path(directory) / "official-index.jsonl"
        path.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    def test_windows_os_alias_cannot_activate_in_service_scope(self):
        identity, specification = mitre_cve._identity(
            "Microsoft Windows RPC",
            "msrpc",
            "",
            "application_service",
        )
        self.assertEqual(identity, "microsoft windows rpc")
        self.assertTrue(specification.get("dynamic_exact_identity"))
        self.assertEqual(
            specification.get("affected_products"),
            {"microsoft windows rpc"},
        )

    def test_reported_unversioned_rpc_pattern_produces_no_cves(self):
        synthetic_id = f"CVE-{2099}-{64001}"
        with tempfile.TemporaryDirectory() as directory:
            index = self._write_index(directory, [{
                "cve_id": synthetic_id,
                "description": "Synthetic operating-system issue",
                "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "record_state": "PUBLISHED",
                "affected_entries": [{
                    "vendor": "Microsoft",
                    "product": "Windows 10",
                    "defaultStatus": "affected",
                    "versions": [{"version": "10.0.0", "status": "affected"}],
                    "cpes": [],
                }],
            }])
            with patch.object(mitre_cve, "INDEX", index):
                matches, diagnostics = mitre_cve.search_with_held(
                    "Microsoft Windows RPC",
                    "",
                    "msrpc",
                    "",
                    scope="application_service",
                    recommended_for_cve=True,
                )

        self.assertEqual(matches, ())
        self.assertTrue(diagnostics)
        self.assertEqual(diagnostics[-1].get("reason"), "observed_version_missing")
        self.assertEqual(
            diagnostics[-1].get("identity_scope"),
            "application_service",
        )

    def test_unversioned_terminal_service_is_held_before_index_matching(self):
        synthetic_id = f"CVE-{2099}-{64002}"
        with tempfile.TemporaryDirectory() as directory:
            index = self._write_index(directory, [{
                "cve_id": synthetic_id,
                "description": "Synthetic service issue",
                "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "record_state": "PUBLISHED",
                "affected_entries": [{
                    "vendor": "Example",
                    "product": "Microsoft Terminal Services",
                    "defaultStatus": "affected",
                    "versions": [],
                    "cpes": [],
                }],
            }])
            with patch.object(mitre_cve, "INDEX", index):
                matches, diagnostics = mitre_cve.search_with_held(
                    "Microsoft Terminal Services",
                    "",
                    "ms-wbt-server",
                    "",
                    scope="application_service",
                    recommended_for_cve=True,
                )

        self.assertEqual(matches, ())
        self.assertEqual(diagnostics[-1].get("reason"), "observed_version_missing")

    def test_reported_rpc_and_rdp_service_rows_emit_zero_cve_findings(self):
        from scanners.enumerator import _match_cves

        synthetic_id = f"CVE-{2099}-{64005}"
        with tempfile.TemporaryDirectory() as directory:
            index = self._write_index(directory, [{
                "cve_id": synthetic_id,
                "description": "Synthetic operating-system issue",
                "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "record_state": "PUBLISHED",
                "affected_entries": [{
                    "vendor": "Microsoft",
                    "product": "Windows 10",
                    "defaultStatus": "affected",
                    "versions": [{"version": "10.0.0", "status": "affected"}],
                    "cpes": [],
                }],
            }])
            diagnostics: list[dict] = []
            services = [
                {
                    "host": "192.0.2.40",
                    "port": 135,
                    "protocol": "tcp",
                    "service": "msrpc",
                    "product": "Microsoft Windows RPC",
                    "version": "",
                    "cpe": [],
                    "confidence_score": 1.0,
                    "recommended_for_cve": True,
                },
                {
                    "host": "192.0.2.40",
                    "port": 3389,
                    "protocol": "tcp",
                    "service": "ms-wbt-server",
                    "product": "Microsoft Terminal Services",
                    "version": "",
                    "cpe": [],
                    "confidence_score": 1.0,
                    "recommended_for_cve": True,
                },
            ]
            with patch.object(mitre_cve, "INDEX", index):
                cve_matches, legacy_rows = _match_cves(
                    services,
                    diagnostics=diagnostics,
                    host_identities=[],
                )

        self.assertEqual(cve_matches, [])
        self.assertEqual(legacy_rows, [])
        self.assertEqual(
            [row.get("reason") for row in diagnostics],
            ["observed_version_missing", "observed_version_missing"],
        )

    def test_exact_versioned_application_matching_still_works(self):
        synthetic_id = f"CVE-{2099}-{64003}"
        with tempfile.TemporaryDirectory() as directory:
            index = self._write_index(directory, [{
                "cve_id": synthetic_id,
                "description": "Synthetic application issue",
                "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "record_state": "PUBLISHED",
                "affected_entries": [{
                    "vendor": "Example",
                    "product": "Example Service",
                    "defaultStatus": "unknown",
                    "versions": [{"version": "2.4.1", "status": "affected"}],
                    "cpes": [],
                }],
            }])
            with patch.object(mitre_cve, "INDEX", index):
                matches, diagnostics = mitre_cve.search_with_held(
                    "Example Service",
                    "2.4.1",
                    "example",
                    "",
                    scope="application_service",
                    recommended_for_cve=True,
                )

        self.assertEqual([row.get("cve_id") for row in matches], [synthetic_id])
        self.assertEqual(diagnostics, ())

    def test_exact_windows_release_remains_host_os_eligible(self):
        synthetic_id = f"CVE-{2099}-{64004}"
        with tempfile.TemporaryDirectory() as directory:
            index = self._write_index(directory, [{
                "cve_id": synthetic_id,
                "description": "Synthetic operating-system issue",
                "source": mitre_cve.OFFICIAL_CVE_SOURCE,
                "record_state": "PUBLISHED",
                "affected_entries": [{
                    "vendor": "Microsoft",
                    "product": "Windows 10",
                    "defaultStatus": "affected",
                    "versions": [{"version": "10.0.0", "status": "affected"}],
                    "cpes": [],
                }],
            }])
            with patch.object(mitre_cve, "INDEX", index):
                matches, diagnostics = mitre_cve.search_with_held(
                    "Microsoft Windows 10",
                    "10.0.19045",
                    "host operating system",
                    "",
                    scope="host_os",
                    recommended_for_cve=True,
                )

        self.assertEqual([row.get("cve_id") for row in matches], [synthetic_id])
        self.assertEqual(diagnostics, ())


class NvdConfigurationTests(unittest.TestCase):
    def test_non_vulnerable_context_cannot_create_a_finding(self):
        cve = {
            "configurations": [{
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:service:2.0:*:*:*:*:*:*:*",
                        }],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                        }],
                    },
                ],
            }],
        }
        matched, _basis = evaluate_configurations(
            cve,
            ["cpe:2.3:o:microsoft:windows_10:10.0:*:*:*:*:*:*:*"],
        )
        self.assertFalse(matched)


class LocalInventorySafetyTests(unittest.TestCase):
    def test_local_inventory_retains_no_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps({
                "host": "192.0.2.30",
                "ProductName": "Microsoft Windows 11 Pro",
                "CurrentBuildNumber": "22631",
                "UBR": "5000",
                "HotFixIDs": ["KB5060000"],
                "username": "must-not-be-retained",
                "password": "must-not-be-retained",
            }), encoding="utf-8")
            with patch.dict(os.environ, {"WINDOWS_INVENTORY_DIR": directory}):
                result = collect_windows_patch_inventory("192.0.2.30")
        self.assertTrue(result.get("ok"))
        encoded = json.dumps(result).lower()
        self.assertNotIn("must-not-be-retained", encoded)
        self.assertEqual(result.get("credential_source"), "none")
        self.assertFalse(result.get("remote_session_opened"))


if __name__ == "__main__":
    unittest.main()
