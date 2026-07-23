from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from scanners import cve_v5_matcher, mitre_cve


def _test_id(sequence: int) -> str:
    return "-".join(("CVE", str(2099), f"{sequence:04d}"))


def _record(
    sequence: int,
    *,
    product: str = "Example Server",
    vendor: str = "Example Vendor",
    versions: list[dict] | None = None,
    default_status: str = "unaffected",
    cpes: list[str] | None = None,
    platforms: list[str] | None = None,
    modules: list[str] | None = None,
    package_name: str = "",
    metrics: dict | None = None,
) -> dict:
    entry = {
        "container_role": "CNA",
        "provider_org_id": "test-provider",
        "vendor": vendor,
        "product": product,
        "versions": versions or [],
        "defaultStatus": default_status,
        "cpes": cpes or [],
        "platforms": platforms or [],
        "modules": modules or [],
        "packageName": package_name,
        "programFiles": [],
        "programRoutines": [],
    }
    return {
        "index_schema_version": 4,
        "cve_id": _test_id(sequence),
        "state": "PUBLISHED",
        "description": "Official fixture description.",
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "affected_entries": [entry],
        "cvss_metrics": metrics or {},
        "references": [],
    }


def _write_index(tmp_path: Path, records: list[dict]) -> tuple[Path, Path]:
    index = tmp_path / "official.jsonl"
    index.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    database_path = tmp_path / "official.sqlite3"
    database = sqlite3.connect(database_path)
    database.execute("CREATE TABLE affected_identities (cve_id TEXT, identity_key TEXT, record_json TEXT)")
    for record in records:
        encoded = json.dumps(record)
        for entry in record.get("affected_entries") or []:
            for key in cve_v5_matcher.affected_identity_keys(entry):
                database.execute("INSERT INTO affected_identities VALUES (?, ?, ?)", (record["cve_id"], key, encoded))
    database.commit()
    database.close()
    return index, database_path


def _activate(monkeypatch, index: Path, database: Path) -> None:
    monkeypatch.setattr(cve_v5_matcher, "SQLITE_INDEX", database)


def test_structured_semver_range_creates_only_candidate(monkeypatch, tmp_path):
    record = _record(
        1,
        versions=[{
            "version": "1.0.0",
            "lessThan": "2.0.0",
            "status": "affected",
            "versionType": "semver",
            "changes": [],
        }],
        metrics={"3.1": {
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }},
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, diagnostics = cve_v5_matcher.search("Example Server", "1.5.0", selected_cvss="3.1")
    assert diagnostics == []
    assert len(rows) == 1
    assert rows[0]["classification"] == "Candidate"
    assert rows[0]["status"] == "Candidate"
    assert rows[0]["cvss_score"] == 9.8


def test_published_unaffected_version_produces_no_finding(monkeypatch, tmp_path):
    record = _record(
        2,
        default_status="affected",
        versions=[{"version": "3.0", "status": "unaffected", "versionType": "custom", "changes": []}],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, diagnostics = cve_v5_matcher.search("Example Server", "3.0", selected_cvss="4.0")
    assert rows == []
    assert diagnostics == []


def test_missing_selected_cvss_does_not_fallback(monkeypatch, tmp_path):
    record = _record(
        3,
        versions=[{"version": "1.0", "status": "affected", "versionType": "custom", "changes": []}],
        metrics={"3.1": {"cvss_score": 7.5}},
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="4.0")
    assert rows[0]["cvss_status"] == "not_provided_for_selected_version"
    assert rows[0]["cvss_score"] is None


def test_cvss_selection_never_changes_applicability(monkeypatch, tmp_path):
    record = _record(
        31,
        versions=[{"version": "1.0", "status": "affected", "changes": []}],
        metrics={
            "3.1": {"cvss_score": 5.0},
            "4.0": {"cvss_score": 8.0},
        },
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows_31, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="3.1")
    rows_40, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="4.0")
    assert [row["cve_id"] for row in rows_31] == [row["cve_id"] for row in rows_40]
    assert rows_31[0]["classification"] == rows_40[0]["classification"] == "Candidate"
    assert rows_31[0]["cvss_score"] == 5.0
    assert rows_40[0]["cvss_score"] == 8.0


def test_technical_severity_sort_is_descending_with_unavailable_last():
    rows = [
        {"cve_id": _test_id(34), "cvss_score": None},
        {"cve_id": _test_id(32), "cvss_score": 5.0},
        {"cve_id": _test_id(33), "cvss_score": 9.0},
    ]
    ordered = sorted(rows, key=mitre_cve._sort_key)
    assert [row["cvss_score"] for row in ordered] == [9.0, 5.0, None]


def test_description_text_never_creates_candidate(monkeypatch, tmp_path):
    record = _record(4, product="n/a", vendor="n/a", versions=[])
    record["description"] = "Example Server 1.0 is mentioned in prose."
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="3.1")
    assert rows == []


def test_custom_range_is_not_compared_by_an_internal_algorithm(monkeypatch, tmp_path):
    record = _record(
        5,
        versions=[{
            "version": "4.0",
            "lessThan": "5.0",
            "status": "affected",
            "versionType": "custom",
            "changes": [],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "4.7", selected_cvss="3.1")
    assert rows == []


def test_exact_custom_version_uses_published_equality(monkeypatch, tmp_path):
    record = _record(
        6,
        versions=[{"version": "4.7", "status": "affected", "versionType": "custom", "changes": []}],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "4.7", selected_cvss="3.1")
    assert [row["cve_id"] for row in rows] == [record["cve_id"]]


def test_semver_change_applies_published_status_transition(monkeypatch, tmp_path):
    record = _record(
        7,
        versions=[{
            "version": "1.0.0",
            "lessThan": "3.0.0",
            "status": "affected",
            "versionType": "semver",
            "changes": [{"at": "2.0.0", "status": "unaffected"}],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    before, _ = cve_v5_matcher.search("Example Server", "1.9.0", selected_cvss="3.1")
    after, _ = cve_v5_matcher.search("Example Server", "2.1.0", selected_cvss="3.1")
    assert len(before) == 1
    assert after == []


def test_semver_is_not_extended_with_a_leading_v(monkeypatch, tmp_path):
    record = _record(
        71,
        versions=[{
            "version": "1.0.0",
            "lessThan": "2.0.0",
            "status": "affected",
            "versionType": "semver",
            "changes": [],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "v1.5.0", selected_cvss="3.1")
    assert rows == []


def test_semver_rejects_numeric_prerelease_leading_zeroes(monkeypatch, tmp_path):
    record = _record(
        74,
        versions=[{
            "version": "1.0.0-alpha",
            "lessThan": "1.0.0",
            "status": "affected",
            "versionType": "semver",
            "changes": [],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "1.0.0-01", selected_cvss="3.1")
    assert rows == []


def test_exact_versions_follow_direct_string_equality(monkeypatch, tmp_path):
    record = _record(
        72,
        versions=[{"version": "Release-A", "status": "affected", "changes": []}],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    exact, _ = cve_v5_matcher.search("Example Server", "Release-A", selected_cvss="3.1")
    different_case, _ = cve_v5_matcher.search("Example Server", "release-a", selected_cvss="3.1")
    assert len(exact) == 1
    assert different_case == []


def test_cve_list_semver_zero_and_branch_limit_conventions(monkeypatch, tmp_path):
    record = _record(
        73,
        versions=[{
            "version": "0",
            "lessThan": "2.*",
            "status": "affected",
            "versionType": "semver",
            "changes": [],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    in_branch, _ = cve_v5_matcher.search("Example Server", "2.9.9", selected_cvss="3.1")
    outside_branch, _ = cve_v5_matcher.search("Example Server", "3.0.0", selected_cvss="3.1")
    assert len(in_branch) == 1
    assert outside_branch == []


def test_version_changes_are_applied_by_version_order_not_source_order(monkeypatch, tmp_path):
    record = _record(
        75,
        versions=[{
            "version": "1.0.0",
            "lessThan": "4.0.0",
            "status": "affected",
            "versionType": "semver",
            "changes": [
                {"at": "3.0.0", "status": "affected"},
                {"at": "2.0.0", "status": "unaffected"},
            ],
        }],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "3.5.0", selected_cvss="3.1")
    assert len(rows) == 1


def test_each_published_affected_entry_is_evaluated_independently(monkeypatch, tmp_path):
    record = _record(
        76,
        versions=[{"version": "1.0", "status": "affected", "changes": []}],
    )
    record["affected_entries"].append({
        **record["affected_entries"][0],
        "container_role": "ADP",
        "provider_org_id": "second-provider",
        "versions": [{"version": "1.0", "status": "unaffected", "changes": []}],
    })
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="3.1")
    assert len(rows) == 1
    assert rows[0]["classification"] == "Candidate"


def test_platform_and_module_constraints_require_observed_evidence(monkeypatch, tmp_path):
    record = _record(
        8,
        versions=[{"version": "1.0", "status": "affected", "versionType": "custom", "changes": []}],
        platforms=["Example OS"],
        modules=["Example Module"],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    absent, _ = cve_v5_matcher.search("Example Server", "1.0", selected_cvss="3.1")
    present, _ = cve_v5_matcher.search(
        "Example Server",
        "1.0",
        selected_cvss="3.1",
        observed_platforms=("Example OS",),
        observed_modules=("Example Module",),
    )
    assert absent == []
    assert len(present) == 1


def test_cpe_identity_uses_exact_standard_components(monkeypatch, tmp_path):
    published_cpe = "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"
    record = _record(
        9,
        product="Server",
        vendor="Example",
        versions=[{"version": "1.0", "status": "affected", "versionType": "custom", "changes": []}],
        cpes=[published_cpe],
    )
    index, database = _write_index(tmp_path, [record])
    _activate(monkeypatch, index, database)
    rows, _ = cve_v5_matcher.search(
        "Unrelated banner label",
        "1.0",
        selected_cvss="3.1",
        service_cpes=(published_cpe,),
    )
    assert len(rows) == 1


def test_schema_v4_importer_and_matcher_end_to_end(monkeypatch, tmp_path):
    repository = tmp_path / "cvelistV5"
    record_dir = repository / "cves" / "2099"
    record_dir.mkdir(parents=True)
    cve_id = _test_id(10)
    source_record = {
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "dateUpdated": "2099-01-01T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": "test-provider", "shortName": "TEST"},
                "descriptions": [{"lang": "en", "value": "Official fixture description."}],
                "affected": [{
                    "vendor": "Example Vendor",
                    "product": "Example Server",
                    "defaultStatus": "unaffected",
                    "versions": [{
                        "version": "1.0.0",
                        "lessThan": "2.0.0",
                        "versionType": "semver",
                        "status": "affected",
                        "changes": [],
                    }],
                }],
                "references": [{"url": "https://example.invalid/advisory"}],
            }
        },
    }
    (record_dir / f"{cve_id}.json").write_text(json.dumps(source_record), encoding="utf-8")
    base = tmp_path / "storage"
    index = base / "official.jsonl"
    database = base / "official.sqlite3"
    monkeypatch.setattr(mitre_cve, "BASE", base)
    monkeypatch.setattr(mitre_cve, "REPO_DIR", repository)
    monkeypatch.setattr(mitre_cve, "INDEX", index)
    monkeypatch.setattr(mitre_cve, "SQLITE_INDEX", database)
    monkeypatch.setattr(cve_v5_matcher, "SQLITE_INDEX", database)
    monkeypatch.setattr(mitre_cve.subprocess, "run", lambda *_args, **_kwargs: None)
    result = mitre_cve.build_index()
    assert result["records_indexed"] == 1
    indexed = json.loads(index.read_text(encoding="utf-8").strip())
    assert indexed["index_schema_version"] == 4
    connection = sqlite3.connect(database)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    connection.close()
    assert "affected_identities" in tables
    rows, diagnostics = cve_v5_matcher.search("Example Server", "1.5.0", selected_cvss="3.1")
    assert diagnostics == []
    assert [row["cve_id"] for row in rows] == [cve_id]


def test_runtime_contract_has_exactly_two_values_and_no_fixed_cve():
    from scanners.enumerator import ALLOWED_CVE_STATUSES

    assert ALLOWED_CVE_STATUSES == frozenset({"Candidate", "Confirmed"})
    scanner_dir = Path(__file__).resolve().parents[1]
    fixed_cve = __import__("re").compile(r"CVE-[0-9]{4}-[0-9]{4,}")
    for name in ("enumerator.py", "mitre_cve.py", "cve_v5_matcher.py", "pdf_export.py"):
        text = (scanner_dir / name).read_text(encoding="utf-8").casefold()
        assert fixed_cve.search(text) is None


def test_runtime_modules_do_not_import_nvd():
    scanner_dir = Path(__file__).resolve().parents[1]
    for name in ("enumerator.py", "mitre_cve.py", "cve_v5_matcher.py"):
        text = (scanner_dir / name).read_text(encoding="utf-8")
        assert "from .nvd" not in text
        assert "import nvd" not in text
