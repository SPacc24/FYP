from __future__ import annotations

import json
from unittest import TestCase

from scanners.msrc_client import _release_ids_from_updates, parse_cvrf_document


CVE = "CVE-2099-99999"


class MsrcClientParserTests(TestCase):
    def test_json_cvrf_remediation_parses_product_kb_fixed_build_and_supercedence(self):
        payload = {
            "ProductTree": {
                "Branch": [{
                    "Items": [{"ProductID": "p1", "Value": "Microsoft Windows 11 Version 23H2 for x64-based Systems"}]
                }]
            },
            "Vulnerability": [{
                "CVE": CVE,
                "Title": {"Value": "Fixture vulnerability"},
                "Remediations": [{
                    "ProductID": ["p1"],
                    "Description": {"Value": "Security Update KB9999999"},
                    "URL": "https://example.invalid/KB9999999",
                    "FixedBuild": "10.0.22631.3155",
                    "Supercedence": "KB9999998",
                    "SubType": "Security Update",
                }],
            }],
        }
        rows = parse_cvrf_document(json.dumps(payload).encode(), CVE, "2099-Jul")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["product_id"], "p1")
        self.assertIn("Windows 11", rows[0]["product"])
        self.assertEqual(rows[0]["kb"], "KB9999999")
        self.assertEqual(rows[0]["fixed_build"], "10.0.22631.3155")
        self.assertEqual(rows[0]["superceded_kbs"], ["KB9999998"])

    def test_xml_cvrf_remediation_parses_same_evidence(self):
        payload = f'''<?xml version="1.0" encoding="utf-8"?>
        <cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1">
          <ProductTree><FullProductName ProductID="p1">Microsoft Windows Server 2022 Standard</FullProductName></ProductTree>
          <Vulnerability>
            <Title>Fixture vulnerability</Title><CVE>{CVE}</CVE>
            <Remediations><Remediation>
              <Description>Security Update KB9999999</Description>
              <URL>https://example.invalid/KB9999999</URL>
              <ProductID>p1</ProductID>
              <FixedBuild>10.0.20348.9999</FixedBuild>
              <Supercedence>KB9999998</Supercedence>
              <SubType>Security Update</SubType>
            </Remediation></Remediations>
          </Vulnerability>
        </cvrfdoc>'''.encode()
        rows = parse_cvrf_document(payload, CVE, "2099-Jul")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kb"], "KB9999999")
        self.assertEqual(rows[0]["fixed_build"], "10.0.20348.9999")
        self.assertEqual(rows[0]["superceded_kbs"], ["KB9999998"])

    def test_updates_lookup_extracts_month_release_ids(self):
        payload = json.dumps({"value": [{"ID": "2026-Jul"}, {"Alias": "2026-Jun"}, {"ID": "not-a-month"}]}).encode()
        self.assertEqual(_release_ids_from_updates(payload), ["2026-Jul", "2026-Jun"])
