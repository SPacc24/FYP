from __future__ import annotations

import json
from unittest import TestCase

from scanners.windows_patch_inventory import collect_windows_patch_inventory, inventory_host_identity, windows_target_applicability


class WindowsPatchInventoryTests(TestCase):
    def test_no_cached_credential_is_deferred(self):
        result = collect_windows_patch_inventory("10.10.10.20", credential_loader=lambda _host: None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["lifecycle_state"], "deferred")


    def test_explicit_non_windows_host_identity_is_not_applicable(self):
        state, reason = windows_target_applicability([{
            "host": "10.10.10.24", "vendor": "Canonical", "family": "Linux", "product": "Ubuntu Linux"
        }])
        self.assertEqual(state, "not_applicable")
        self.assertIn("non-Windows", reason)

    def test_public_target_is_scope_blocked_before_credentials(self):
        called = []
        result = collect_windows_patch_inventory("8.8.8.8", credential_loader=lambda host: called.append(host))
        self.assertFalse(result["ok"])
        self.assertEqual(result["lifecycle_state"], "scope_blocked")
        self.assertEqual(called, [])

    def test_read_only_inventory_preserves_build_ubr_and_kbs_without_credentials(self):
        secret = "NeverStoreThisPassword!"

        def wmi_reader(target, username, password, domain, timeout):
            self.assertEqual(target, "10.10.10.21")
            self.assertEqual(username, "analyst")
            self.assertEqual(password, secret)
            self.assertEqual(domain, "LAB")
            return {
                "operating_system": [{
                    "Caption": "Microsoft Windows 11 Pro",
                    "Version": "10.0.22631",
                    "BuildNumber": "22631",
                    "OSArchitecture": "64-bit",
                    "CSName": "CLIENT01",
                }],
                "computer_system": [{"Name": "CLIENT01", "Domain": "LAB", "Manufacturer": "Example", "Model": "VM"}],
                "quick_fix_engineering": [
                    {"HotFixID": "KB9999991", "Description": "Security Update", "InstalledOn": "7/1/2026"},
                    {"HotFixID": "kb9999992", "Description": "Update", "InstalledOn": "7/8/2026"},
                    {"HotFixID": "KB9999991", "Description": "duplicate", "InstalledOn": "7/1/2026"},
                ],
            }

        def registry_reader(target, username, password, domain, timeout):
            self.assertEqual(password, secret)
            return {
                "ProductName": "Microsoft Windows 11 Pro",
                "EditionID": "Professional",
                "DisplayVersion": "23H2",
                "CurrentBuildNumber": "22631",
                "UBR": 4000,
            }

        result = collect_windows_patch_inventory(
            "10.10.10.21",
            credential_loader=lambda _host: (r"LAB\analyst", secret),
            wmi_reader=wmi_reader,
            registry_reader=registry_reader,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["lifecycle_state"], "executed_evidence")
        self.assertEqual(result["product"], "Microsoft Windows 11 Pro")
        self.assertEqual(result["edition"], "Professional")
        self.assertEqual(result["release"], "23H2")
        self.assertEqual(result["build"], "22631")
        self.assertEqual(result["ubr"], "4000")
        self.assertEqual(result["installed_kbs"], ["KB9999991", "KB9999992"])
        self.assertEqual(result["registry_evidence_status"], "collected")
        serialised = json.dumps(result)
        self.assertNotIn(secret, serialised)
        self.assertNotIn("LAB\\analyst", serialised)
        self.assertNotIn('"username"', serialised.lower())
        self.assertNotIn('"password"', serialised.lower())

        identity = inventory_host_identity(result, "scan-evidence.json")
        self.assertIsNotNone(identity)
        self.assertEqual(identity["family"], "Windows")
        self.assertEqual(identity["build"], "22631")
        self.assertEqual(identity["release"], "23H2")

    def test_registry_unavailable_does_not_destroy_successful_wmi_evidence(self):
        result = collect_windows_patch_inventory(
            "10.10.10.22",
            credential_loader=lambda _host: ("Administrator", "placeholder-secret"),
            wmi_reader=lambda *_args: {
                "operating_system": [{"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348", "BuildNumber": "20348"}],
                "computer_system": [],
                "quick_fix_engineering": [],
            },
            registry_reader=lambda *_args: (_ for _ in ()).throw(ConnectionError("service unavailable")),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["registry_evidence_status"], "unavailable")
        self.assertEqual(result["ubr"], "")

    def test_failure_does_not_echo_transport_exception_or_secret(self):
        secret = "top-secret-value"

        def failing_reader(*_args):
            raise RuntimeError(f"authentication failed with {secret}")

        result = collect_windows_patch_inventory(
            "10.10.10.23",
            credential_loader=lambda _host: ("Administrator", secret),
            wmi_reader=failing_reader,
        )
        text = json.dumps(result)
        self.assertFalse(result["ok"])
        self.assertEqual(result["lifecycle_state"], "executed_failed")
        self.assertNotIn(secret, text)
