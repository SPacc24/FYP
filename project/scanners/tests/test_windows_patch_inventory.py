from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scanners.windows_patch_inventory import (
    collect_windows_patch_inventory,
    inventory_host_identity,
    windows_target_applicability,
)


class WindowsPatchInventoryTests(TestCase):
    def test_missing_local_inventory_is_deferred_without_remote_session(self):
        with patch.dict(os.environ, {"WINDOWS_INVENTORY_DIR": ""}, clear=False):
            result = collect_windows_patch_inventory("192.0.2.20")
        self.assertFalse(result["ok"])
        self.assertEqual(result["lifecycle_state"], "deferred")
        self.assertFalse(result["remote_session_opened"])
        self.assertEqual(result["credential_source"], "none")

    def test_explicit_non_windows_host_identity_is_not_applicable(self):
        state, reason = windows_target_applicability([{
            "host": "192.0.2.24",
            "vendor": "Canonical",
            "family": "Linux",
            "product": "Ubuntu Linux",
        }])
        self.assertEqual(state, "not_applicable")
        self.assertIn("non-Windows", reason)

    def test_local_inventory_preserves_only_whitelisted_fields(self):
        secret = "must-not-be-retained"
        with tempfile.TemporaryDirectory() as directory:
            payload = {
                "host": "192.0.2.21",
                "ProductName": "Microsoft Windows 11 Pro",
                "EditionID": "Professional",
                "DisplayVersion": "23H2",
                "CurrentBuildNumber": "22631",
                "UBR": 4000,
                "OSArchitecture": "64-bit",
                "HotFixIDs": ["KB9999991", "kb9999992", "not-a-kb"],
                "username": "analyst",
                "password": secret,
            }
            Path(directory, "inventory.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"WINDOWS_INVENTORY_DIR": directory},
                clear=False,
            ):
                result = collect_windows_patch_inventory(
                    "192.0.2.21",
                    username="ignored",
                    password=secret,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(result["product"], "Microsoft Windows 11 Pro")
        self.assertEqual(result["release"], "23H2")
        self.assertEqual(result["build"], "22631.4000")
        self.assertEqual(result["installed_kbs"], ["KB9999991", "KB9999992"])
        self.assertFalse(result["remote_session_opened"])
        serialised = json.dumps(result)
        self.assertNotIn(secret, serialised)
        self.assertNotIn("analyst", serialised)
        self.assertNotIn('"password"', serialised.lower())

        identity = inventory_host_identity(result, "inventory.json")
        self.assertIsNotNone(identity)
        self.assertEqual(identity["family"], "Windows")
        self.assertEqual(identity["build"], "22631.4000")
        self.assertEqual(identity["evidence_kind"], "operator_inventory")
