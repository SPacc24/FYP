from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from scanners import mitre_cve, windows_advisory
from scanners.enumerator import (
    _build_cve_review_summary,
    _match_cves,
    _run_cmd_with_retry,
)
from scanners.scoring_policy import load_scoring_policy
from scanners.phase_discovery import _local_connected_scope_for_entry, _segment_from_entry
from scanners.pdf_export import _canonical_report_candidate_rows


def _write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def _cve_record(cve_id: str, *, vendor: str, product: str, versions: list[dict], default_status: str = "unknown") -> dict:
    return {
        "cve_id": cve_id,
        "description": "Synthetic regression fixture",
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "record_state": "PUBLISHED",
        "affected_vendors": [vendor],
        "affected_products": [product],
        "affected_versions": [str(row.get("version") or "") for row in versions],
        "affected_entries": [{
            "vendor": vendor,
            "product": product,
            "defaultStatus": default_status,
            "versions": versions,
            "cpes": [],
            "modules": [],
            "platforms": [],
            "packageName": "",
        }],
        "cpes": [],
        "cvss_metrics": {},
    }


def _direct_windows_identity(host: str = "192.0.2.50") -> dict:
    return {
        "host": host,
        "scope": "host_os",
        "vendor": "Microsoft",
        "family": "Windows",
        "product": "Windows 10 Enterprise 10240",
        "version": "10.0.10240",
        "build": "10.0.10240",
        "cpe": ["cpe:/o:microsoft:windows_10::-"],
        "evidence_kind": "protocol_correlation",
        "authority_tier": 1,
        "candidate_eligible": True,
        "cve_eligible": True,
        "sources": ["smb_host_identity", "ntlm_rdp_identity"],
    }


def test_cvss_policy_supports_only_31_and_40():
    status = load_scoring_policy()
    assert status["supported_versions"] == ["3.1", "4.0"]
    assert status["retainable_versions"] == ["3.1", "4.0"]


def test_configuration_findings_layer_removed_from_user_outputs():
    root = Path(__file__).resolve().parents[2]
    assert not (root / "policies" / "configuration_findings.json").exists()
    for relative in (
        "templates/scan_vul.html",
        "templates/pdf_report.html",
        "templates/scan_summary_sidebar.html",
        "scanners/pdf_export.py",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        assert "Configuration / Security Findings" not in text
        assert "Configuration Findings" not in text
        assert "configuration_findings" not in text


def test_microsoft_custom_version_hold_is_not_promoted_by_msrc_product_context(tmp_path: Path):
    cve_id = "CVE-2099-81001"
    cve_index = _write_jsonl(tmp_path / "cve.jsonl", [
        _cve_record(
            cve_id,
            vendor="Microsoft",
            product="Windows 10",
            versions=[{
                "version": "1507",
                "status": "affected",
                "lessThan": "1607",
                "lessThanOrEqual": "",
                "versionType": "custom",
                "changes": [],
            }],
        )
    ])
    msrc_index = _write_jsonl(tmp_path / "msrc.jsonl", [
        {
            "cve_id": "CVE-2099-89990",
            "product_id": "map1",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "document_id": "2099-Jan",
            "fixed_builds": ["10.0.10240.19999"],
            "kb_ids": [],
        },
        {
            "cve_id": cve_id,
            "product_id": "p1",
            "product": "Windows 10 for x64-based Systems",
            "document_id": "2099-Jan",
            "fixed_builds": [],
            "kb_ids": [],
        },
    ])
    diagnostics: list[dict] = []
    with (
        patch.object(mitre_cve, "INDEX", cve_index),
        patch.object(windows_advisory, "INDEX", msrc_index),
        patch(
            "scanners.enumerator.windows_advisory_corroborate_cves_for_observed_windows_context",
            wraps=windows_advisory.corroborate_cves_for_observed_windows_context,
        ) as advisory_lookup,
    ):
        mitre_cve._search_cached.cache_clear()
        rows, _review = _match_cves([], diagnostics, [_direct_windows_identity()], return_review_candidates=True)
    mitre_cve._search_cached.cache_clear()

    assert rows == []
    assert advisory_lookup.call_count == 0
    assert any(
        item.get("reason") == "published_version_rule_not_comparable"
        and item.get("cve_id") == cve_id
        for item in diagnostics
    )


def test_microsoft_custom_version_context_cannot_introduce_unseen_cve(tmp_path: Path):
    held_id = "CVE-2099-81002"
    unrelated_id = "CVE-2099-81003"
    cve_index = _write_jsonl(tmp_path / "cve.jsonl", [
        _cve_record(
            held_id,
            vendor="Microsoft",
            product="Windows 10",
            versions=[{
                "version": "1507", "status": "affected", "lessThan": "1607",
                "lessThanOrEqual": "", "versionType": "custom", "changes": [],
            }],
        )
    ])
    with patch.object(mitre_cve, "INDEX", cve_index):
        mitre_cve._search_cached.cache_clear()
        resolved, _diag = mitre_cve.resolve_held_version_candidates_by_ids(
            "Windows 10 Enterprise 10240", "10.0.10240", "host operating system", "",
            [unrelated_id], scope="host_os",
        )
    mitre_cve._search_cached.cache_clear()
    assert resolved == ()


def test_msrc_corroboration_cannot_introduce_unrequested_cve(tmp_path: Path):
    requested = "CVE-2099-81020"
    unrelated = "CVE-2099-81021"
    msrc_index = _write_jsonl(tmp_path / "msrc_isolation.jsonl", [
        {
            "cve_id": unrelated, "product_id": "map1",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": ["10.0.10240.9999"], "kb_ids": [],
        },
        {
            "cve_id": unrelated, "product_id": "u1",
            "product": "Windows 10 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": [], "kb_ids": [],
        },
    ])
    with patch.object(windows_advisory, "INDEX", msrc_index):
        contexts, _diagnostics = windows_advisory.corroborate_cves_for_observed_windows_context(
            "Windows 10 Enterprise", "10.0.10240", [requested]
        )
    assert [row["cve_id"] for row in contexts] == [requested]
    assert contexts[0]["context_state"] == "uncorroborated"
    assert unrelated not in {row["cve_id"] for row in contexts}


def test_narrative_component_candidate_is_not_suppressed_when_candidate_cve_has_no_fixed_build(tmp_path: Path):
    cve_id = "CVE-2099-81004"
    narrative = "The SMBv1 server in Microsoft Windows 10 Gold, 1511, and 1607"
    cve_index = _write_jsonl(tmp_path / "cve.jsonl", [
        _cve_record(
            cve_id,
            vendor="Microsoft Corporation",
            product="Windows SMB",
            versions=[{
                "version": narrative,
                "status": "affected",
                "lessThan": "",
                "lessThanOrEqual": "",
                "versionType": "custom",
                "changes": [],
            }],
        )
    ])
    observation = [{
        "host": "192.0.2.50", "port": 445, "protocol": "tcp",
        "service": "microsoft-ds", "component": "smb", "version": "1",
        "evidence_sources": ["smb_protocol_security"],
    }]
    msrc_index = _write_jsonl(tmp_path / "msrc.jsonl", [
        {
            "cve_id": "CVE-2099-89991", "product_id": "map1",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": ["10.0.10240.9999"], "kb_ids": [],
        },
        {
            "cve_id": cve_id, "product_id": "p2",
            "product": "Windows 10 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": [], "kb_ids": [],
        },
    ])
    with patch.object(mitre_cve, "INDEX", cve_index), patch.object(windows_advisory, "INDEX", msrc_index):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves([], [], [_direct_windows_identity()], component_observations=observation, return_review_candidates=True)
    mitre_cve._search_cached.cache_clear()
    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0]["match_basis"] == "prose_component_version_with_windows_product_context"
    assert rows[0]["windows_advisory_context"]["context_state"] == "corroborated"


def test_narrative_component_msrc_contradiction_is_diagnostic_only(tmp_path: Path):
    cve_id = "CVE-2099-81014"
    narrative = "SMBv1 server on Microsoft Windows 10"
    cve_index = _write_jsonl(tmp_path / "cve.jsonl", [
        _cve_record(
            cve_id,
            vendor="Microsoft Corporation",
            product="Windows SMB",
            versions=[{
                "version": narrative, "status": "affected", "lessThan": "",
                "lessThanOrEqual": "", "versionType": "custom", "changes": [],
            }],
        )
    ])
    observation = [{
        "host": "192.0.2.50", "port": 445, "protocol": "tcp",
        "service": "microsoft-ds", "component": "smb", "version": "1",
        "evidence_sources": ["smb_protocol_security"],
    }]
    msrc_index = _write_jsonl(tmp_path / "msrc_wrong_release.jsonl", [
        {
            "cve_id": "CVE-2099-89992", "product_id": "map1",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": ["10.0.10240.9999"], "kb_ids": [],
        },
        {
            "cve_id": cve_id, "product_id": "wrong",
            "product": "Windows 10 Version 22H2 for x64-based Systems",
            "document_id": "2099-Jan", "fixed_builds": [], "kb_ids": [],
        },
    ])
    diagnostics: list[dict] = []
    with patch.object(mitre_cve, "INDEX", cve_index), patch.object(windows_advisory, "INDEX", msrc_index):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves([], diagnostics, [_direct_windows_identity()], component_observations=observation, return_review_candidates=True)
    mitre_cve._search_cached.cache_clear()
    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0].get("windows_advisory_context_state") == "contradicted"
    assert any(item.get("reason") == "windows_release_context_contradicted" for item in diagnostics)


def test_narrative_component_missing_msrc_context_does_not_suppress_candidate(tmp_path: Path):
    cve_id = "CVE-2099-81015"
    cve_index = _write_jsonl(tmp_path / "cve.jsonl", [
        _cve_record(
            cve_id,
            vendor="Microsoft Corporation",
            product="Windows SMB",
            versions=[{
                "version": "SMBv1 server in Microsoft Windows 10", "status": "affected",
                "lessThan": "", "lessThanOrEqual": "", "versionType": "custom", "changes": [],
            }],
        )
    ])
    observation = [{
        "host": "192.0.2.50", "port": 445, "protocol": "tcp",
        "service": "microsoft-ds", "component": "smb", "version": "1",
        "evidence_sources": ["smb_protocol_security"],
    }]
    missing_index = tmp_path / "missing-msrc.jsonl"
    with patch.object(mitre_cve, "INDEX", cve_index), patch.object(windows_advisory, "INDEX", missing_index):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves([], [], [_direct_windows_identity()], component_observations=observation, return_review_candidates=True)
    mitre_cve._search_cached.cache_clear()
    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0]["match_basis"] == "prose_affected_component_version_scrape"

def test_default_status_affected_semantics_are_preserved():
    entry = {
        "product": "Windows 10",
        "defaultStatus": "affected",
        "versions": [{"version": "10.0.0", "status": "unaffected"}],
    }
    matched, token, basis = mitre_cve._entry_version_match(entry, "10.0.10240")
    assert matched is True
    assert token == "10.0.10240"
    assert basis == "structured_default_status_affected"


def test_review_summary_counts_actual_candidate_identities():
    rows = [
        {"cve_id": "CVE-2099-82001", "host": "192.0.2.50", "product": "Windows 10", "version": "10.0.10240", "match_scope": "host_os", "candidate_basis": "Direct host operating-system identity"},
        {"cve_id": "CVE-2099-82002", "host": "192.0.2.50", "product": "smb", "version": "1", "match_scope": "platform_component", "candidate_basis": "Observed platform/protocol component version"},
    ]
    summary = _build_cve_review_summary(rows, rows, [])
    assert summary["identities_reviewed"] == 2
    assert summary["unique_candidate_ids"] == 2
    assert summary["target_candidate_records"] == 2
    assert summary["identity_correlations_retained"] == 2



def test_narrative_microsoft_component_build_lookup_is_batched_per_observation(tmp_path: Path):
    cve_ids = [f"CVE-2099-{value}" for value in range(81005, 81011)]
    narrative = "The SMBv1 server in Microsoft Windows 10 Gold, 1511, and 1607"
    cve_index = _write_jsonl(tmp_path / "cve_batch.jsonl", [
        _cve_record(
            cve_id,
            vendor="Microsoft Corporation",
            product="Windows SMB",
            versions=[{
                "version": narrative,
                "status": "affected",
                "lessThan": "",
                "lessThanOrEqual": "",
                "versionType": "custom",
                "changes": [],
            }],
        )
        for cve_id in cve_ids
    ])
    msrc_index = _write_jsonl(tmp_path / "msrc_batch.jsonl", [
        {
            "cve_id": "CVE-2099-89993",
            "product_id": "map1",
            "product": "Windows 10 Version 1507 for x64-based Systems",
            "document_id": "2099-Jan",
            "fixed_builds": ["10.0.10240.9999"],
            "kb_ids": [],
        },
        *[
            {
                "cve_id": cve_id,
                "product_id": f"p{idx}",
                "product": "Windows 10 for x64-based Systems",
                "document_id": "2099-Jan",
                "fixed_builds": [],
                "kb_ids": [],
            }
            for idx, cve_id in enumerate(cve_ids, 1)
        ],
    ])
    observation = [{
        "host": "192.0.2.50", "port": 445, "protocol": "tcp",
        "service": "microsoft-ds", "component": "smb", "version": "1",
        "evidence_sources": ["smb_protocol_security"],
    }]

    with (
        patch.object(mitre_cve, "INDEX", cve_index),
        patch.object(windows_advisory, "INDEX", msrc_index),
        patch(
            "scanners.enumerator.windows_advisory_corroborate_cves_for_observed_windows_context",
            wraps=windows_advisory.corroborate_cves_for_observed_windows_context,
        ) as build_lookup,
    ):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves(
            [], [], [_direct_windows_identity()],
            component_observations=observation,
            return_review_candidates=True,
        )
    mitre_cve._search_cached.cache_clear()

    assert {row["cve_id"] for row in rows} == set(cve_ids)
    assert build_lookup.call_count == 1
    requested_ids = set(build_lookup.call_args.args[2])
    assert requested_ids == set(cve_ids)


def test_local_connected_entry_scope_preserves_interface_and_source():
    snapshot = {
        "interfaces": [
            {
                "ifname": "ethA",
                "addr_info": [{"local": "198.51.100.10", "prefixlen": 24}],
            },
            {
                "ifname": "ethB",
                "addr_info": [{"local": "198.51.100.18", "prefixlen": 28}],
            },
        ]
    }
    with patch("scanners.phase_discovery._discovery_network_scope_state", return_value=(True, "test_allow")):
        scope = _local_connected_scope_for_entry(snapshot, "198.51.100.17")

    assert scope is not None
    assert scope["network"] == "198.51.100.16/28"
    assert scope["interface"] == "ethB"
    assert scope["scanner_ip"] == "198.51.100.18"
    assert scope["scope_allowed"] is True

    context = {
        "entry_target": "198.51.100.17",
        "interface": scope["interface"],
        "scanner_ip": scope["scanner_ip"],
        "gateway": "",
        "route_table": "",
        "route_type": "local_interface",
        "access_mode": "directly_connected",
        "route": {},
        "matched_route": {},
    }
    segment = _segment_from_entry(context, {"reachable": True, "evidence": []})
    assert segment["interface"] == "ethB"
    assert segment["source_address"] == "198.51.100.18"
    assert segment["access_mode"] == "directly_connected"



def test_pdf_candidate_rows_use_same_target_cve_granularity():
    results = {
        "cve_review_candidates": [
            {
                "host": "192.0.2.50", "cve_id": "CVE-2099-83001",
                "product": "Windows 10", "version": "10.0.1", "port": "host",
                "protocol": "host", "match_scope": "host_os",
                "candidate_basis": "Direct host operating-system identity",
                "evidence_sources": ["host_identity"],
            },
            {
                "host": "192.0.2.50", "cve_id": "CVE-2099-83001",
                "product": "smb", "version": "1", "port": 445,
                "protocol": "tcp", "match_scope": "platform_component",
                "candidate_basis": "Observed platform/protocol component version",
                "evidence_sources": ["component_identity"],
            },
            {
                "host": "192.0.2.51", "cve_id": "CVE-2099-83001",
                "product": "Windows 10", "version": "10.0.1", "port": "host",
                "protocol": "host", "match_scope": "host_os",
            },
        ]
    }
    rows = _canonical_report_candidate_rows(results)
    assert len(rows) == 2
    first = next(row for row in rows if row["host"] == "192.0.2.50")
    assert len(first["_correlation_identities"]) == 2
    assert set(first["evidence_sources"]) == {"host_identity", "component_identity"}



def test_timed_out_batch_is_not_retried(tmp_path: Path):
    timed_out = {"success": False, "timed_out": True, "error": "timeout"}
    with patch("scanners.enumerator.run_cmd", return_value=timed_out) as mocked:
        result = _run_cmd_with_retry(
            "scan-test", ["nmap", "-p", "22", "192.0.2.50"],
            tmp_path / "out.xml", 5, True, 3,
        )
    assert result["timed_out"] is True
    assert result["attempts"] == 1
    assert mocked.call_count == 1


def test_recovery_policy_is_bounded_and_silent_udp_is_not_default():
    policy = json.loads((Path(__file__).resolve().parents[2] / "policies" / "recon_policy.json").read_text())
    recovery = policy["version_evidence_recovery"]
    assert recovery["include_uncertain_udp"] is False
    assert 0 <= int(recovery["uncertain_udp_max_ports"]) <= 4
    assert 1 <= int(recovery["udp_command_timeout_seconds"]) <= 60
    assert 1 <= int(recovery["recovery_budget_seconds"]) <= 180
    timing = policy["tcp_micro_batching"]["nmap_options"]
    rate_index = timing.index("--max-rate")
    assert int(timing[rate_index + 1]) >= 20



def test_service_level_candidate_generation_does_not_require_host_os(tmp_path: Path):
    cve_id = "CVE-2099-84001"
    cve_index = _write_jsonl(tmp_path / "service_only_cve.jsonl", [
        _cve_record(
            cve_id,
            vendor="Example Vendor",
            product="Example SSH Service",
            versions=[{
                "version": "8.0",
                "status": "affected",
                "lessThan": "",
                "lessThanOrEqual": "",
                "versionType": "semver",
                "changes": [],
            }],
        )
    ])
    service = [{
        "host": "192.0.2.70",
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "Example SSH Service",
        "version": "8.0",
        "evidence_sources": ["service_fingerprint"],
    }]
    with patch.object(mitre_cve, "INDEX", cve_index):
        mitre_cve._search_cached.cache_clear()
        rows, _ = _match_cves(service, [], [], return_review_candidates=True)
    mitre_cve._search_cached.cache_clear()

    assert [row["cve_id"] for row in rows] == [cve_id]
    assert rows[0]["match_scope"] == "application_service"
    assert rows[0]["validation_state"] == "not_performed"
