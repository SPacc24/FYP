import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


PROJECT_DIR = Path(__file__).resolve().parents[1] / "project"
sys.path.insert(0, str(PROJECT_DIR))

from scanners import nvd_repository
from scanners.enumerator import _canonicalise_downstream_mapping


def _application(version="7.4.2"):
    return f"cpe:2.3:a:example:range_widget:{version}:*:*:*:*:*:*:*"


def _platform(version="12"):
    return f"cpe:2.3:o:example:platform:{version}:*:*:*:*:*:*:*"


def _configuration(operator="OR", include_platform=False):
    matches = [{
        "vulnerable": True,
        "criteria": "cpe:2.3:a:example:range_widget:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "7.0",
        "versionEndExcluding": "8.0",
    }]
    if include_platform:
        matches.append({"vulnerable": False, "criteria": _platform()})
    return [{"nodes": [{"operator": operator, "negate": False, "cpeMatch": matches}]}]


def test_nvd_primary_cpe_query_result_uses_nvd_range_decision():
    result = nvd_repository.evaluate_configurations(_configuration(), _application(), [_application()])
    assert result["decision"] == "confirmed_affected"
    assert result["configuration_truth"] == "true"


def test_nvd_and_dependency_requires_observed_environment_cpe():
    result = nvd_repository.evaluate_configurations(_configuration("AND", True), _application(), [_application()])
    assert result["decision"] == "analyst_review"
    assert _platform() in result["required_conditions"]


def test_nvd_and_dependency_can_be_satisfied_or_rejected_by_evidence():
    satisfied = nvd_repository.evaluate_configurations(
        _configuration("AND", True), _application(), [_application(), _platform()]
    )
    contradicted = nvd_repository.evaluate_configurations(
        _configuration("AND", True), _application(), [_application(), _platform("11")]
    )
    assert satisfied["decision"] == "confirmed_affected"
    assert contradicted["decision"] == "rejected"


def test_nvd_cpe_query_is_persistently_cached_without_static_cve_rules():
    cve_id = "CVE-2099-51001"
    payload = {
        "totalResults": 1,
        "resultsPerPage": 1,
        "vulnerabilities": [{"cve": {
            "id": cve_id,
            "sourceIdentifier": "security@example.invalid",
            "vulnStatus": "Analyzed",
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Synthetic official test record."}],
            "metrics": {},
            "configurations": _configuration(),
            "references": [],
        }}],
    }
    with TemporaryDirectory() as tmp, mock.patch.object(
        nvd_repository, "REPOSITORY", Path(tmp) / "nvd.sqlite3"
    ), mock.patch.object(nvd_repository, "_request", return_value=payload) as request:
        first, first_status = nvd_repository.query_vulnerable_cpe(_application())
        second, second_status = nvd_repository.query_vulnerable_cpe(_application())
    assert [row["cve_id"] for row in first] == [cve_id]
    assert [row["cve_id"] for row in second] == [cve_id]
    assert first_status["reason"] == "nvd_cpe_query_applied"
    assert second_status["reason"] == "nvd_cpe_query_cache"
    request.assert_called_once()


def test_full_nvd_sync_uses_all_pages_and_marks_completeness_only_at_end():
    def payload(cve_id):
        return {"cve": {
            "id": cve_id,
            "sourceIdentifier": "security@example.invalid",
            "vulnStatus": "Analyzed",
            "published": "2099-01-01T00:00:00.000Z",
            "lastModified": "2099-01-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "Synthetic official sync record."}],
            "metrics": {}, "configurations": [], "references": [],
        }}

    def request(params):
        start = int(dict(params).get("startIndex", 0))
        return {
            "totalResults": 2,
            "resultsPerPage": 1,
            "vulnerabilities": [payload(f"CVE-2099-{52001 + start}")],
        }

    with TemporaryDirectory() as tmp, mock.patch.object(
        nvd_repository, "REPOSITORY", Path(tmp) / "nvd.sqlite3"
    ), mock.patch.object(nvd_repository, "_request", side_effect=request) as nvd_request, mock.patch.object(
        nvd_repository, "_delay", return_value=0
    ):
        result = nvd_repository.sync(full=True)
    assert result["complete"] is True
    assert result["records"] == 2
    assert result["source_total_results"] == 2
    assert nvd_request.call_count == 2


def test_analyst_review_never_enters_downstream_cve_contract():
    mapping = {"vulnerabilities": [{"host": "192.0.2.10", "port": "443"}]}
    analyst = [{"host": "192.0.2.10", "port": 443, "cve_id": "CVE-2099-51002"}]
    result = _canonicalise_downstream_mapping(mapping, [], analyst)
    assert result["vulnerabilities"][0]["cve_ids"] == []
    assert result["vulnerabilities"][0]["candidate_cve_ids"] == []
    assert result["vulnerabilities"][0]["cve_matches"] == []
    assert result["cve_contract_version"] == "scanner-canonical-v4"


def test_runtime_has_no_description_applicability_parser():
    text = (PROJECT_DIR / "scanners" / "mitre_cve.py").read_text(encoding="utf-8")
    assert "legacy_description" not in text
    assert "_text_version_match" not in text
