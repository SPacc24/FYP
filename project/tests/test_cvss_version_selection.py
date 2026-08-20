import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1] / "project"
sys.path.insert(0, str(PROJECT_DIR))

from scanners import mitre_cve
from scanners.scoring_policy import ScoringPolicyError, cvss_selection, load_scoring_policy, normalise_cvss_version, scoring_choices, validate_published_metric


def test_external_policy_defaults_to_cvss_31_and_offers_both_versions():
    assert load_scoring_policy()["default_version"] == "3.1"
    assert [choice["id"] for choice in scoring_choices()] == ["3.1", "4.0"]
    assert cvss_selection(None)["version"] == "3.1"
    assert cvss_selection("4.0")["version"] == "4.0"


def test_invalid_cvss_version_is_rejected():
    with pytest.raises(ScoringPolicyError):
        normalise_cvss_version("unsupported")


def test_metric_extraction_preserves_versions_without_conversion():
    record = {"containers": {"cna": {
        "providerMetadata": {"orgId": "example-cna"},
        "metrics": [{
            "cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
            "cvssV4_0": {"baseScore": 8.7, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"},
        }],
    }}}
    metrics = mitre_cve._extract_metrics(record)
    assert metrics["3.1"]["cvss_score"] == 7.5
    assert metrics["4.0"]["cvss_score"] == 8.7
    assert metrics["3.1"]["cvss_provider_role"] == "CNA"


def test_selected_metric_does_not_fall_back_to_another_version():
    record = {"cvss_metrics": {"4.0": {"cvss_score": 8.7, "cvss_version": "4.0"}}}
    assert mitre_cve._metric_for_version(record, "3.1") == {}
    assert mitre_cve._metric_for_version(record, "4.0")["cvss_score"] == 8.7


@pytest.mark.parametrize("version,score,severity,vector", [
    ("3.1", 9.8, "CRITICAL", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("3.1", 9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L"),
    ("3.1", 9.8, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
])
def test_published_metric_integrity_rejects_cross_version_incomplete_or_inconsistent_data(version, score, severity, vector):
    with pytest.raises(ScoringPolicyError):
        validate_published_metric(version, score, severity, vector)


def test_published_metric_integrity_preserves_exact_source_values():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    metric = validate_published_metric("3.1", 9.8, "CRITICAL", vector)
    assert metric == {
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "cvss_vector": vector,
        "cvss_version": "3.1",
        "cvss_metric_integrity": "published_source_exact",
    }


def test_index_status_counts_each_published_version():
    with TemporaryDirectory() as tmp:
        index_path = Path(tmp) / "index.jsonl"
        index_path.write_text(json.dumps({"source": mitre_cve.OFFICIAL_CVE_SOURCE, "cvss_metrics": {
            "3.1": {"cvss_score": 6.5}, "4.0": {"cvss_score": 7.1}
        }}) + "\n", encoding="utf-8")
        with mock.patch.object(mitre_cve, "INDEX", index_path):
            result = mitre_cve.status()
    assert result["records_with_cvss_metadata_by_version"] == {"3.1": 1, "4.0": 1}
