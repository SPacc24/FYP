from __future__ import annotations

from pathlib import Path

from scanners.command_builders import nmap_host_discovery, nmap_internal_host_discovery
from scanners.enumerator import _build_cve_review_summary


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_candidate_summary_has_no_tiers_and_preserves_cvss_31_and_40_coverage():
    rows = [
        {
            "cve_id": "CVE-2099-10001",
            "candidate_basis": "Observed software identity",
            "effective_cvss_metrics": {
                "3.1": {"cvss_score": 8.8, "cvss_severity": "HIGH"},
                "4.0": {"cvss_score": 8.2, "cvss_severity": "HIGH"},
            },
        },
        {
            "cve_id": "CVE-2099-10002",
            "candidate_basis": "Observed software identity",
            "effective_cvss_metrics": {
                "3.1": {"cvss_score": 5.3, "cvss_severity": "MEDIUM"},
            },
        },
    ]
    summary = _build_cve_review_summary(rows, rows, [])

    assert summary["candidate_cves_retained"] == 2
    assert "evidence_strength" not in summary
    assert summary["cvss"]["3.1"] == {"published_candidates": 2, "missing_candidates": 0}
    assert summary["cvss"]["4.0"] == {"published_candidates": 1, "missing_candidates": 1}
    assert "confidence" in summary["cvss"]["role"].lower()


def test_candidate_source_unavailable_is_not_reported_as_successful_zero_match():
    summary = _build_cve_review_summary(
        [],
        [],
        [{"reason": "cve_program_index_unavailable", "matcher_status": "degraded"}],
    )
    assert summary["candidate_generation_state"] == "unavailable"
    assert summary["candidate_cves_retained"] == 0


def test_phase2_host_discovery_is_numeric_and_not_reverse_dns_dependent(tmp_path: Path):
    out = tmp_path / "hosts.xml"
    command = nmap_internal_host_discovery("/usr/bin/nmap", "192.0.2.0/24", out, interface="eth9")
    assert command[:3] == ["/usr/bin/nmap", "-sn", "-n"]
    assert command[-3:] == ["-e", "eth9", "192.0.2.0/24"]

    general = nmap_host_discovery("/usr/bin/nmap", ["192.0.2.0/24"], out, interface="eth9")
    assert "-n" in general


def test_operator_asset_identity_input_and_candidate_tier_ui_are_removed():
    assessment = (PROJECT_ROOT / "templates" / "assessment_config.html").read_text(encoding="utf-8")
    scan_route = (PROJECT_ROOT / "routes" / "scan_routes.py").read_text(encoding="utf-8")
    results = (PROJECT_ROOT / "templates" / "scan_vul.html").read_text(encoding="utf-8")

    combined = "\n".join((assessment, scan_route, results))
    assert "operator_asset_identity" not in combined
    assert "candidate_evidence_strength" not in combined
    assert "High Evidence" not in results
    assert "Medium Evidence" not in results
    assert "Low Evidence" not in results
    assert "Candidate CVSS 3.1" in results
    assert "Candidate CVSS 4.0" in results


def test_requested_frontend_cleanup_is_present():
    scanning = (PROJECT_ROOT / "templates" / "scanning.html").read_text(encoding="utf-8")
    appendix = (PROJECT_ROOT / "templates" / "technical_appendix.html").read_text(encoding="utf-8")

    assert "Last updated" in scanning
    assert "Last activity" in scanning
    forbidden = (
        "Last visible change",
        "Last backend event",
        "The browser heartbeat remains active even while an existing scanner command is still running.",
        "Only findings already published by the existing Phase 3 pipeline are shown here.",
        "The assessment is running against the operator-selected retained targets.",
        "Every completed tool command can be copied exactly.",
        "Exact recorded commands can be copied for independent operator use.",
    )
    for phrase in forbidden:
        assert phrase not in scanning
        assert phrase not in appendix
