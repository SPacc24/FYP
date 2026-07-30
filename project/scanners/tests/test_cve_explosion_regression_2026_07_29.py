from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch

from scanners import mitre_cve, windows_advisory
from scanners.enumerator import _match_cves, _resolve_windows_build_product_candidates
from scanners.platform_identity import host_identity_inventory, merge_host_identity_map, reconcile_host_identities


def _official_record(cve_id: str, product: str, version: str) -> dict:
    return {
        "cve_id": cve_id,
        "description": "Synthetic structured fixture",
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "record_state": "PUBLISHED",
        "affected_vendors": ["Example Vendor"],
        "affected_products": [product],
        "affected_versions": [version],
        "affected_entries": [{
            "vendor": "Example Vendor",
            "product": product,
            "defaultStatus": "unknown",
            "versions": [{
                "version": version,
                "status": "affected",
                "lessThan": "",
                "lessThanOrEqual": "",
                "versionType": "custom",
                "changes": [],
            }],
            "cpes": [],
            "modules": [],
            "platforms": [],
            "packageName": "",
        }],
        "cpes": [],
        "cvss_metrics": {},
    }


def test_build_line_diagnostics_do_not_mutate_observed_identity_map():
    identity_map = {
        "192.0.2.10": [{
            "scope": "host_os",
            "host": "192.0.2.10",
            "vendor": "Microsoft",
            "family": "Windows",
            "product": "Microsoft Windows",
            "version": "10.0.42424",
            "build": "10.0.42424",
            "evidence_kind": "protocol_assertion",
            "sources": ["synthetic-protocol-evidence"],
        }]
    }
    before = copy.deepcopy(identity_map)

    diagnostics = _resolve_windows_build_product_candidates(identity_map)

    assert identity_map == before
    assert diagnostics
    assert diagnostics[0]["reason"] == "msrc_build_line_not_promoted_to_identity"
    assert diagnostics[0]["matcher_status"] == "held"


def test_resolution_candidate_is_never_cve_eligible_even_when_alone():
    identity_map: dict[str, list[dict]] = {}
    merge_host_identity_map(identity_map, [{
        "scope": "host_os",
        "host": "192.0.2.11",
        "vendor": "Microsoft",
        "family": "Windows",
        "product": "Example Advisory Product 42424",
        "version": "10.0.42424",
        "build": "10.0.42424",
        "evidence_kind": "official_product_resolution",
        "resolution_candidate": True,
        "resolution_basis": "shared_build_line",
        "sources": ["Example Vendor Advisory"],
    }])

    inventory = host_identity_inventory(identity_map)[0]
    assert inventory["cve_identities"] == []
    assert inventory["identities"][0]["reconciliation_status"] == "advisory_context_only"


def test_stale_advisory_identity_cannot_match_canonical_cve(tmp_path: Path):
    product = "Example Advisory Product 42424"
    version = "10.0.42424"
    index = tmp_path / "official.jsonl"
    index.write_text(
        json.dumps(_official_record("CVE-2099-91001", product, version)) + "\n",
        encoding="utf-8",
    )
    stale_identity = {
        "scope": "host_os",
        "host": "192.0.2.12",
        "vendor": "Microsoft",
        "family": "Windows",
        "product": product,
        "version": version,
        "build": version,
        "evidence_kind": "official_product_resolution",
        "resolution_candidate": True,
    }

    diagnostics: list[dict] = []
    with patch.object(mitre_cve, "INDEX", index):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves([], diagnostics, host_identities=[stale_identity])
    mitre_cve._search_cached.cache_clear()

    assert rows == []
    assert any(item.get("reason") == "advisory_identity_not_observed" for item in diagnostics)


def test_msrc_search_cannot_create_a_cve_reference(tmp_path: Path):
    # The canonical CVE Program index is empty for this observed product.  Even
    # if the MSRC remediation search would return a record, matching must remain
    # empty because MSRC is post-match remediation intelligence only.
    index = tmp_path / "official.jsonl"
    index.write_text("", encoding="utf-8")
    identity = {
        "scope": "host_os",
        "host": "192.0.2.13",
        "vendor": "Microsoft",
        "family": "Windows",
        "product": "Windows Example 42424",
        "version": "10.0.42424",
        "build": "10.0.42424",
        "evidence_kind": "protocol_assertion",
        "cve_eligible": True,
    }
    fake_advisory = ({
        "cve_id": "CVE-2099-91002",
        "product": "Windows Example 42424",
        "fixed_builds": ["10.0.42424.999"],
    },)

    with (
        patch.object(mitre_cve, "INDEX", index),
        patch.object(windows_advisory, "search", return_value=(fake_advisory, ())) as advisory_search,
    ):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves([], [], host_identities=[identity])
    mitre_cve._search_cached.cache_clear()

    assert rows == []
    advisory_search.assert_not_called()


def test_probabilistic_cross_family_guesses_remain_supporting_when_direct_identity_exists():
    rows = reconcile_host_identities([
        {
            "host": "192.0.2.14",
            "vendor": "Microsoft",
            "family": "Windows",
            "product": "Windows Example 42424",
            "version": "10.0.42424",
            "evidence_kind": "protocol_assertion",
            "source": "direct-protocol",
        },
        {
            "host": "192.0.2.14",
            "vendor": "Linux",
            "family": "Linux",
            "product": "Linux 4.4",
            "version": "4.4",
            "accuracy": "96",
            "evidence_kind": "probabilistic_fingerprint",
            "source": "nmap-os-guess",
        },
    ])

    direct = [row for row in rows if row.get("evidence_kind") == "protocol_assertion"]
    guesses = [row for row in rows if row.get("evidence_kind") == "probabilistic_fingerprint"]
    assert direct and direct[0]["cve_eligible"] is True
    assert guesses and all(row["cve_eligible"] is False for row in guesses)
