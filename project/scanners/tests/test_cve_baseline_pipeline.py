from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from scanners import mitre_cve
from scanners.enumerator import _match_cves
from scanners.enumerator import _classify_cve_match
from scanners.platform_identity import reconcile_host_identities


def _record(
    cve_id: str,
    *,
    vendor: str,
    product: str,
    versions: list[dict] | None = None,
    cpes: list[str] | None = None,
    default_status: str = "unknown",
) -> dict:
    return {
        "cve_id": cve_id,
        "description": "Synthetic official-record fixture",
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "record_state": "PUBLISHED",
        "affected_vendors": [vendor],
        "affected_products": [product],
        "affected_versions": [
            str(rule.get("version") or "")
            for rule in versions or []
            if rule.get("version")
        ],
        "affected_entries": [{
            "vendor": vendor,
            "product": product,
            "defaultStatus": default_status,
            "versions": versions or [],
            "cpes": cpes or [],
            "modules": [],
            "platforms": [],
            "packageName": "",
        }],
        "cpes": cpes or [],
        "cvss_metrics": {},
    }


def _service(product: str, version: str, *, port: int = 12345, cpe: list[str] | None = None) -> dict:
    return {
        "host": "192.0.2.25",
        "port": port,
        "protocol": "tcp",
        "service": "observed-service",
        "product": product,
        "version": version,
        "cpe": cpe or [],
        "confidence_score": 0.61,
        "recommended_for_cve": False,
        "evidence_sources": ["test-fixture"],
    }


def _search(index: Path, services: list[dict]):
    with patch.object(mitre_cve, "INDEX", index):
        mitre_cve._search_cached.cache_clear()
        diagnostics: list[dict] = []
        rows, legacy = _match_cves(services, diagnostics)
    mitre_cve._search_cached.cache_clear()
    return rows, diagnostics, legacy


def test_arbitrary_exact_product_version_becomes_baseline_reference(tmp_path: Path):
    cve_id = "CVE-2099-70001"
    record = _record(
        cve_id,
        vendor="Example Vendor",
        product="Example Widget Service",
        versions=[{
            "version": "7.4.2",
            "status": "affected",
            "lessThan": "",
            "lessThanOrEqual": "",
            "versionType": "custom",
            "changes": [],
        }],
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    rows, diagnostics, legacy = _search(
        index,
        [_service("Example Widget Service", "7.4.2")],
    )

    assert legacy == []
    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0]["reference_type"] == "Baseline CVE Reference"
    assert "classification" not in rows[0]
    assert "cve_status" not in rows[0]
    assert any(item["reason"] == "fingerprint_confidence_advisory" for item in diagnostics)
    assert mitre_cve._lookup_is_current(index, mitre_cve._lookup_path(index))


def test_exact_full_cpe_attributes_match_without_cross_platform_contamination(tmp_path: Path):
    cve_id = "CVE-2099-70002"
    affected_cpe = "cpe:2.3:a:example:widget:4.2.1:*:*:*:*:linux:x86_64:*"
    record = _record(
        cve_id,
        vendor="Example",
        product="Widget",
        cpes=[affected_cpe],
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    matching, _, _ = _search(
        index,
        [_service("Widget", "4.2.1", cpe=[affected_cpe])],
    )
    wrong_platform, _, _ = _search(
        index,
        [_service(
            "Widget",
            "4.2.1",
            cpe=["cpe:2.3:a:example:widget:4.2.1:*:*:*:*:windows:x86_64:*"],
        )],
    )

    assert [row["cve_id"] for row in matching] == [cve_id]
    assert wrong_platform == []


def test_custom_range_is_reported_as_evidence_gap_not_silently_dropped(tmp_path: Path):
    cve_id = "CVE-2099-70003"
    record = _record(
        cve_id,
        vendor="Example",
        product="Example Range Product",
        default_status="unaffected",
        versions=[{
            "version": "2.2.0",
            "status": "affected",
            "lessThan": "2.2.21",
            "lessThanOrEqual": "",
            "versionType": "custom",
            "changes": [],
        }],
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    rows, diagnostics, _ = _search(
        index,
        [_service("Example Range Product", "2.2.8")],
    )

    assert not rows
    assert any(
        item.get("cve_id") == cve_id
        and item.get("reason") == "published_version_rule_not_comparable"
        for item in diagnostics
    )



def test_complementary_direct_host_identity_reaches_official_matcher(tmp_path: Path):
    cve_id = "CVE-2099-70005"
    record = _record(
        cve_id,
        vendor="Microsoft",
        product="Windows Example Enterprise",
        versions=[{
            "version": "10.0.42424",
            "status": "affected",
            "lessThan": "",
            "lessThanOrEqual": "",
            "versionType": "custom",
            "changes": [],
        }],
        cpes=["cpe:/o:microsoft:windows_example::-"],
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    identities = reconcile_host_identities([
        {
            "host": "192.0.2.36",
            "vendor": "Microsoft",
            "family": "Windows",
            "product": "Windows Example Enterprise",
            "cpe": ["cpe:/o:microsoft:windows_example::-"],
            "evidence_kind": "protocol_assertion",
            "source": "protocol_product_identity",
        },
        {
            "host": "192.0.2.36",
            "vendor": "Microsoft",
            "family": "Windows",
            "product": "Microsoft Windows",
            "version": "10.0.42424",
            "build": "10.0.42424",
            "evidence_kind": "protocol_assertion",
            "source": "protocol_build_identity",
        },
    ])
    eligible = [row for row in identities if row.get("cve_eligible")]

    assert len(eligible) == 1
    assert eligible[0]["evidence_kind"] == "protocol_correlation"
    assert eligible[0]["version"] == "10.0.42424"
    assert eligible[0]["cpe"] == ["cpe:/o:microsoft:windows_example::-"]

    diagnostics: list[dict] = []
    with patch.object(mitre_cve, "INDEX", index):
        mitre_cve._search_cached.cache_clear()
        rows, legacy = _match_cves([], diagnostics, host_identities=eligible)
    mitre_cve._search_cached.cache_clear()

    assert legacy == []
    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0]["match_scope"] == "host_os"
    assert "classification" not in rows[0]
    assert "cve_status" not in rows[0]
    assert not any(item.get("reason") == "observed_version_missing" for item in diagnostics)

def test_official_record_without_retained_product_version_basis_is_not_a_baseline_reference():
    reference_type, reason = _classify_cve_match(
        {},
        {
            "source": mitre_cve.OFFICIAL_CVE_SOURCE,
            "match_basis": "structured_exact_version",
        },
    )

    assert reference_type == "Excluded - Incomplete Baseline Evidence"
    assert "concrete matched version" in reason


def test_unversioned_host_identity_is_held_not_emitted(tmp_path: Path):
    record = _record(
        "CVE-2099-70004",
        vendor="Example",
        product="Example Operating System",
        default_status="affected",
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with patch.object(mitre_cve, "INDEX", index):
        mitre_cve._search_cached.cache_clear()
        rows, diagnostics = mitre_cve.search_with_held(
            "Example Operating System",
            "",
            "host operating system",
            "",
            scope="host_os",
        )
    mitre_cve._search_cached.cache_clear()

    assert not rows
    assert any(item.get("reason") == "observed_version_missing" for item in diagnostics)
