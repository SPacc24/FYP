from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from scanners import mitre_cve, scoring_policy
from scanners.result_contracts import (
    analyse_nmap_port_batch,
    build_endpoint_coverage,
    build_selected_plan_readiness,
    derive_result_state,
    execution_lifecycle,
)
from scanners.scan_profiles import normalise_scan_options
from scanners.tooling import run_cmd


def test_timeout_is_a_distinct_execution_state_and_retains_partial_output(tmp_path: Path):
    output = tmp_path / "partial.txt"
    expired = subprocess.TimeoutExpired(
        cmd=["example-tool"],
        timeout=1,
        output=b"partial evidence",
        stderr=b"still running",
    )
    with patch("scanners.tooling.subprocess.run", side_effect=expired):
        result = run_cmd(["example-tool"], output_file=output, timeout=1)

    assert result["completion_reason"] == "timeout"
    assert result["lifecycle_state"] == "executed_timeout"
    assert result["timed_out"] is True
    assert result["partial_output_retained"] is True
    assert "partial evidence" in output.read_text(encoding="utf-8")
    assert execution_lifecycle(result, produced=True) == "executed_timeout"


def test_partial_timeout_coverage_marks_only_parseable_ports_as_scanned():
    batch = analyse_nmap_port_batch(
        host="192.0.2.10",
        protocol="tcp",
        requested_ports=[22, 80, 443],
        result={
            "success": False,
            "error": "timeout",
            "completion_reason": "timeout",
            "timed_out": True,
        },
        parsed={
            "ports": [
                {"protocol": "tcp", "port": 22, "state": "open"},
            ],
            "extraports": [],
        },
    )
    coverage = build_endpoint_coverage(
        live_hosts=["192.0.2.10"],
        scan_options={
            "port_selection": {
                "tcp": {"mode": "custom", "ports": [22, 80, 443]},
                "udp": {"mode": "custom", "ports": []},
            }
        },
        batches=[batch],
    )
    row = coverage["tcp"]["hosts"]["192.0.2.10"]

    assert batch["lifecycle_state"] == "executed_timeout"
    assert row["scanned_port_count"] == 1
    assert row["untested_port_count"] == 2
    assert row["failed_port_count"] == 2
    assert row["states"]["open"]["count"] == 1
    assert row["untested_by_cause"]["timeout"]["count"] == 2
    assert row["invariant"]["configured_equals_scanned_plus_untested"] is True


def test_extraports_evidence_completes_the_exact_state_partition():
    batch = analyse_nmap_port_batch(
        host="192.0.2.20",
        protocol="tcp",
        requested_ports=[21, 22, 23],
        result={"success": True, "completion_reason": "completed"},
        parsed={
            "ports": [{"protocol": "tcp", "port": 22, "state": "open"}],
            "extraports": [{"protocol": "tcp", "state": "closed", "count": 2}],
        },
    )
    coverage = build_endpoint_coverage(
        live_hosts=["192.0.2.20"],
        scan_options={
            "port_selection": {
                "tcp": {"mode": "custom", "ports": [21, 22, 23]},
                "udp": {"mode": "custom", "ports": []},
            }
        },
        batches=[batch],
    )
    row = coverage["tcp"]["hosts"]["192.0.2.20"]

    assert row["scanned_port_count"] == 3
    assert row["untested_port_count"] == 0
    assert row["states"]["open"]["count"] == 1
    assert row["states"]["closed"]["count"] == 2
    assert coverage["tcp"]["invariant"]["all_hosts_reconcile"] is True


def test_readiness_checks_only_requested_collectors_and_blocks_only_core_failures():
    options = {
        "enabled_tools": ["tcp_discovery", "http_security_context"],
        "service_identity": {
            "tcp_discovery_enabled": True,
            "udp_discovery_enabled": False,
            "service_fingerprinting_enabled": False,
        },
        "collector_plan": {
            "http_security_context": {
                "requested": True,
                "policy_state": "permitted",
                "binary": "curl",
                "nse_scripts": [],
            },
            "ssh_audit_native": {
                "requested": False,
                "policy_state": "permitted",
                "binary": "ssh-audit",
                "nse_scripts": [],
            },
        },
    }
    resolver = lambda name: "/usr/bin/nmap" if name == "nmap" else None
    readiness = build_selected_plan_readiness(
        scan_options=options,
        cve_source_status={"available": True, "records_indexed": 123},
        cvss_verifiers={"3.1": {"available": True, "method": "internal"}},
        binary_resolver=resolver,
    )

    components = {row["component"] for row in readiness["rows"]}
    assert readiness["status"] == "degraded"
    assert readiness["launch_blocked"] is False
    assert "http_security_context" in readiness["degraded_components"]
    assert "ssh_audit_native" not in components

    blocked = build_selected_plan_readiness(
        scan_options=options,
        cve_source_status={"available": True, "records_indexed": 123},
        cvss_verifiers={"3.1": {"available": True, "method": "internal"}},
        binary_resolver=lambda _name: None,
    )
    assert blocked["status"] == "blocked"
    assert blocked["launch_blocked"] is True
    assert "nmap" in blocked["blocking_components"]


def test_cvss4_verifier_unavailable_is_not_source_inconsistency():
    metric_data = {
        "baseScore": 9.3,
        "baseSeverity": "CRITICAL",
        "vectorString": (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
            "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        ),
    }
    with patch.object(scoring_policy, "CVSS4", None):
        metric = mitre_cve._validated_metric("4.0", metric_data, "publisher", "CNA")

    assert metric["cvss_verified"] is False
    assert metric["cvss_metric_integrity"] == "verifier_unavailable"
    assert metric["cvss_verification_status"] == "verifier_unavailable"
    assert metric["cvss_verification_method"] == "python_cvss4_library"


def test_invalid_vector_and_score_mismatch_have_distinct_cvss_statuses():
    invalid = mitre_cve._validated_metric(
        "3.1",
        {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"},
        "publisher",
        "CNA",
    )
    mismatch = mitre_cve._validated_metric(
        "3.1",
        {
            "baseScore": 1.0,
            "baseSeverity": "LOW",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "publisher",
        "CNA",
    )

    assert invalid["cvss_verification_status"] == "invalid_vector"
    assert invalid["cvss_metric_integrity"] == "invalid_vector"
    assert mismatch["cvss_verification_status"] == "source_inconsistent"
    assert mismatch["cvss_metric_integrity"] == "published_source_inconsistent"


def test_advanced_settings_preserve_requested_policy_and_effective_values():
    policy = {
        "port_profiles": {"tcp_essentials": [22], "udp_essentials": [53]},
        "operator_advanced_defaults": {
            "command_timeout_seconds": 600,
            "retry_count": 1,
            "ports_per_batch": 5,
            "parallel_workers": 2,
            "retry_failed_batches": True,
            "parallel_scanning": False,
        },
        "tcp_micro_batching": {"batch_size_target": 5},
    }
    with patch(
        "scanners.scan_profiles._load_profile_policy",
        return_value=(policy, "loaded", "policy-sha"),
    ):
        options = normalise_scan_options(
            "custom",
            collection_preset="custom",
            collector_plan={},
            tcp_port_mode="custom",
            tcp_custom_ports="22",
            udp_port_mode="custom",
            udp_custom_ports="53",
            advanced_settings={
                "command_timeout_seconds": 10,
                "parallel_scanning": False,
                "parallel_workers": 8,
            },
        )

    provenance = options["advanced_settings_provenance"]
    assert provenance["command_timeout_seconds"]["requested"] == 10
    assert provenance["command_timeout_seconds"]["policy_min"] == 30
    assert provenance["command_timeout_seconds"]["effective"] == 30
    assert provenance["command_timeout_seconds"]["clamped"] is True
    assert provenance["parallel_workers"]["requested"] == 8
    assert provenance["parallel_workers"]["effective"] == 1
    assert provenance["parallel_workers"]["reason"] == "forced_to_one_when_parallel_scanning_is_disabled"


def test_result_states_remain_neutral_and_downstream_classification_free():
    assert derive_result_state(
        readiness={"launch_blocked": False},
        services=[{"port": 80}],
        baseline_cves=[],
        held_diagnostics=[{"reason": "observed_version_missing"}],
        cve_source_available=True,
    ) == "all_matches_held"
    assert derive_result_state(
        readiness={"launch_blocked": False},
        services=[{"port": 80}],
        baseline_cves=[{"cve_id": "CVE-2099-0001"}],
        held_diagnostics=[],
        cve_source_available=True,
    ) == "completed_with_baseline_matches"
