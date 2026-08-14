from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanners import windows_advisory
from scanners.platform_identity import host_identity_inventory, merge_host_identity_map


class WindowsBuildResolutionTests(unittest.TestCase):
    def test_resolver_uses_only_msrc_products_on_the_observed_build_line(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "official_msrc_windows_index.jsonl"
            rows = [
                {
                    "cve_id": "CVE-2099-10001",
                    "product_id": "p1",
                    "product": "Windows 10 Version 1507 for x64-based Systems",
                    "product_normalised": "windows 10 version 1507 for x64 based systems",
                    "document_id": "2099-Jan",
                    "fixed_builds": ["10.0.10240.20000"],
                },
                {
                    "cve_id": "CVE-2099-10002",
                    "product_id": "p2",
                    "product": "Windows 10 Version 22H2 for x64-based Systems",
                    "product_normalised": "windows 10 version 22h2 for x64 based systems",
                    "document_id": "2099-Jan",
                    "fixed_builds": ["10.0.19045.5000"],
                },
            ]
            index.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            with patch.object(windows_advisory, "INDEX", index):
                candidates, diagnostics = windows_advisory.resolve_products_for_build(
                    "10.0.10240"
                )

        self.assertEqual(
            [row["product"] for row in candidates],
            ["Windows 10 Version 1507 for x64-based Systems"],
        )
        self.assertEqual(diagnostics[0]["candidate_product_count"], 1)

    def test_msrc_derived_product_is_context_only_and_never_cve_eligible(self):
        identity_map: dict[str, list[dict]] = {}
        merge_host_identity_map(identity_map, [{
            "host": "192.0.2.1",
            "vendor": "Microsoft",
            "family": "Windows",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "version": "10.0.10240",
            "build": "10.0.10240",
            "evidence_kind": "official_product_resolution",
            "sources": [
                "ntlm_rdp_identity",
                "Microsoft Security Response Center CVRF",
            ],
            "resolution_candidate": True,
            "resolution_basis": "msrc_shared_windows_build_line",
        }])

        inventory = host_identity_inventory(identity_map)[0]
        self.assertEqual(inventory["cve_identities"], [])
        identity = inventory["identities"][0]
        self.assertTrue(identity["resolution_candidate"])
        self.assertFalse(identity["cve_eligible"])
        self.assertEqual(identity["reconciliation_status"], "advisory_context_only")


if __name__ == "__main__":
    unittest.main()
