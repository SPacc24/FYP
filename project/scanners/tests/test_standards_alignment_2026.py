from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase, mock


PROJECT = Path(__file__).resolve().parents[2]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scanners import mitre_cve, nvd_repository  # noqa: E402
from scanners.scoring_policy import (  # noqa: E402
    ScoringPolicyError,
    cvss_selection,
    validate_published_metric,
)


def _application(version: str = "7.4.2") -> str:
    return f"cpe:2.3:a:example:range_widget:{version}:*:*:*:*:*:*:*"


def _record(cve_id: str = "CVE-2099-60001") -> dict:
    return {
        "cve_id": cve_id,
        "description": "Synthetic applicability test record.",
        "metrics": {},
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "negate": False,
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:example:range_widget:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "7.0",
                    "versionEndExcluding": "8.0",
                }],
            }],
        }],
        "references": [],
        "last_modified": "2099-01-01T00:00:00Z",
    }


class StandardsAlignmentTests(TestCase):
    def test_latest_first_cvss_is_default_and_legacy_31_remains_selectable(self):
        self.assertEqual(cvss_selection(None)["version"], "4.0")
        self.assertEqual(cvss_selection("3.1")["version"], "3.1")

    def test_cvss_base_metric_values_are_validated_against_first_schema(self):
        with self.assertRaises(ScoringPolicyError):
            validate_published_metric(
                "4.0",
                9.3,
                "CRITICAL",
                "CVSS:4.0/AV:INVALID/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            )

    def test_concrete_cpe_conversion_preserves_nmap_uri_identity(self):
        self.assertEqual(
            nvd_repository.concrete_cpe23("cpe:/a:example:range_widget:7.4.2"),
            _application(),
        )
        self.assertEqual(
            nvd_repository.concrete_cpe23("cpe:2.3:a:example:range_widget:*:*:*:*:*:*:*:*"),
            "",
        )

    def test_private_confidence_gate_and_cve_list_fallback_cannot_emit_candidates(self):
        with mock.patch.object(
            mitre_cve,
            "_search_cached",
            side_effect=AssertionError("legacy CVE List candidate matcher must not run"),
            create=True,
        ), mock.patch.object(mitre_cve, "query_vulnerable_cpe") as nvd_query:
            rows, diagnostics = mitre_cve.search_with_held(
                "Range Widget",
                "7.4.2",
                "custom-service",
                "",
                cvss_version="4.0",
                confidence_score=0.99,
                recommended_for_cve=True,
            )
        self.assertEqual(rows, ())
        self.assertEqual(diagnostics[0]["reason"], "concrete_cpe_required")
        nvd_query.assert_not_called()

    def test_nvd_cpe_query_is_the_only_runtime_candidate_source(self):
        query_status = {
            "status": "available",
            "reason": "nvd_cpe_query_applied",
            "record_count": 1,
            "authoritative_query_verified": True,
        }
        with mock.patch.object(
            mitre_cve, "query_vulnerable_cpe", return_value=([_record()], query_status)
        ), mock.patch.object(
            mitre_cve,
            "_search_cached",
            side_effect=AssertionError("legacy matcher must not run"),
            create=True,
        ):
            rows, _diagnostics = mitre_cve.search_with_held(
                "ignored product text",
                "ignored version text",
                "ignored service text",
                _application(),
                cvss_version="4.0",
                confidence_score=0.01,
                recommended_for_cve=False,
                observed_environment_cpes=(_application(),),
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["applicability_decision"], "potentially_affected")
        self.assertTrue(rows[0]["applicability_only"])

    def test_same_product_different_concrete_version_is_not_promoted(self):
        configurations = [{
            "nodes": [{
                "operator": "AND",
                "cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": _application("7.4.2"),
                    },
                    {
                        "vulnerable": True,
                        "criteria": _application("7.5.0"),
                    },
                ],
            }],
        }]
        result = nvd_repository.evaluate_configurations(
            configurations,
            _application("7.4.2"),
            [_application("7.4.2")],
            primary_query_verified=True,
        )
        self.assertEqual(result["decision"], "rejected")


if __name__ == "__main__":
    import unittest

    unittest.main()
