from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from unittest.mock import patch

from scanners import collector_plan, command_builders, match_basis, mitre_cve, scoring_policy, version_compare
from scanners.enumerator import _match_cves
from scanners.result_contracts import build_selected_plan_readiness


def _record(
    cve_id: str,
    *,
    vendor: str,
    product: str,
    version: str = "",
    cpe: str = "",
) -> dict:
    versions = []
    if version:
        versions.append(
            {
                "version": version,
                "status": "affected",
                "lessThan": "",
                "lessThanOrEqual": "",
                "versionType": "custom",
                "changes": [],
            }
        )
    cpes = [cpe] if cpe else []
    return {
        "cve_id": cve_id,
        "description": "Synthetic official-record fixture",
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "record_state": "PUBLISHED",
        "affected_vendors": [vendor],
        "affected_products": [product],
        "affected_versions": [version] if version else [],
        "affected_entries": [
            {
                "vendor": vendor,
                "product": product,
                "defaultStatus": "unknown",
                "versions": versions,
                "cpes": cpes,
                "modules": [],
                "platforms": [],
                "packageName": "",
            }
        ],
        "cpes": cpes,
        "cvss_metrics": {},
    }


def _service(product: str, version: str, *, cpe: list[str] | None = None) -> dict:
    return {
        "host": "192.0.2.70",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "product": product,
        "version": version,
        "cpe": cpe or [],
        "confidence_score": 1.0,
        "recommended_for_cve": True,
        "evidence_sources": ["synthetic-test"],
    }


def _search(index: Path, services: list[dict]) -> tuple[list[dict], list[dict]]:
    diagnostics: list[dict] = []
    with patch.object(mitre_cve, "INDEX", index):
        mitre_cve._search_cached.cache_clear()
        rows, _legacy = _match_cves(services, diagnostics)
    mitre_cve._search_cached.cache_clear()
    return rows, diagnostics


def test_matcher_has_no_alias_registry_or_description_version_matcher():
    source = inspect.getsource(mitre_cve)
    assert not hasattr(mitre_cve, "PRODUCTS")
    assert not hasattr(mitre_cve, "_text_version_match")
    assert "product_alias_registry" not in source
    assert "exact_observed_version_in_record_text" not in source
    assert "explicit_same_product_text_range" not in source
    assert "named_branch_before" not in source


def test_service_name_alone_cannot_manufacture_product_identity():
    identity, spec = mitre_cve._identity("", "http", "", "application_service")
    assert identity is None
    assert spec == {}

    identity, spec = mitre_cve._identity("OpenSSH", "ssh", "", "application_service")
    assert identity == "openssh"
    assert "openssh" in spec["affected_products"]


def test_version_extraction_prefers_specific_build_and_refuses_ambiguous_years():
    assert mitre_cve._first_version("Windows Server 2019 build 10.0.17763") == "10.0.17763"
    assert mitre_cve._first_version("Example product 2019 2022") == ""
    assert mitre_cve._first_version("OpenSSH 9.7p1") == "9.7p1"


def test_application_alias_does_not_create_cve_match(tmp_path: Path):
    record = _record(
        "CVE-2099-71001",
        vendor="Apache Software Foundation",
        product="Apache HTTP Server",
        version="2.4.58",
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    rows, _diagnostics = _search(index, [_service("Apache httpd", "2.4.58")])
    assert rows == []


def test_exact_application_cpe_can_supply_structured_identity(tmp_path: Path):
    cpe = "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    record = _record(
        "CVE-2099-71002",
        vendor="apache",
        product="http_server",
        version="2.4.58",
        cpe=cpe,
    )
    index = tmp_path / "official.jsonl"
    index.write_text(json.dumps(record) + "\n", encoding="utf-8")

    rows, _diagnostics = _search(index, [_service("", "2.4.58", cpe=[cpe])])
    assert [row["cve_id"] for row in rows] == ["CVE-2099-71002"]


def test_debian_comparator_is_supported_but_unverified_maven_and_rpm_are_held():
    assert version_compare.supports_version_type("deb") is True
    assert version_compare.supports_version_type("dpkg") is True
    assert version_compare.supports_version_type("maven") is False
    assert version_compare.supports_version_type("rpm") is False

    assert version_compare.deb_vercmp("1:1.2.3-1", "1:1.2.3-2") == -1
    assert version_compare.deb_vercmp("1.2.3~rc1-1", "1.2.3-1") == -1
    assert version_compare.deb_vercmp("1.2.3-1", "1.2.3-1") == 0
    # Different package-revision precision is intentionally held rather than guessed.
    assert version_compare.deb_vercmp("1.2.3", "1.2.3-1") is None


def test_command_builders_receive_scan_policy_timing_instead_of_inventing_it():
    command = command_builders.nmap_udp_discovery(
        "nmap",
        "192.0.2.80",
        [53, 137],
        ["-T1", "--scan-delay", "250ms", "--max-rate", "20"],
        "/tmp/test.xml",
    )
    assert "-T1" in command
    assert "--scan-delay" in command
    assert "250ms" in command
    assert "-T2" not in command
    assert command[-1] == "192.0.2.80"


def test_enumerator_has_no_inline_external_command_list_construction():
    from scanners import enumerator

    tree = ast.parse(inspect.getsource(enumerator))
    command_names = {"cmd", "command", "fingerprint_cmd", "httpx_cmd"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and target.id in command_names:
                    assert not isinstance(value, ast.List), f"inline command list assigned to {target.id}"
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in {"run_cmd", "_run_cmd"} and node.args:
                assert not isinstance(node.args[0], ast.List), "run_cmd called with inline argv list"


def test_snmp_targeted_oid_collector_requires_explicit_credentials_and_has_no_default():
    metadata = collector_plan.COLLECTOR_METADATA["snmp_targeted_oids"]
    assert metadata["credential_required"] is True
    assert metadata["recommended"] is False
    assert metadata["explicit_operator_selection"] is True

    from scanners import enumerator

    source = inspect.getsource(enumerator)
    assert "['snmpget', '-v2c', '-c', 'public'" not in source
    assert '["snmpget", "-v2c", "-c", "public"' not in source


def test_readiness_accounts_for_host_discovery_binaries_and_credential_deferment():
    options = {
        "enabled_tools": [],
        "service_identity": {
            "tcp_discovery_enabled": False,
            "udp_discovery_enabled": False,
            "service_fingerprinting_enabled": False,
        },
        "host_discovery": {
            "effective": {
                "icmp_echo": True,
                "reverse_dns": True,
                "arp_discovery": True,
                "nmap_host_discovery": False,
                "route_trace": True,
            }
        },
        "collector_plan": {
            "snmp_targeted_oids": {
                "requested": True,
                "policy_state": "permitted",
                "binary": "snmpget",
                "nse_scripts": [],
                "credential_required": True,
            }
        },
    }
    available = {
        "ping": "/usr/bin/ping",
        "dig": "/usr/bin/dig",
        "arp-scan": "/usr/bin/arp-scan",
        "tracepath": "/usr/bin/tracepath",
        "snmpget": "/usr/bin/snmpget",
    }
    readiness = build_selected_plan_readiness(
        scan_options=options,
        cve_source_status={"available": True, "records_indexed": 1},
        cvss_verifiers={"3.1": {"available": True, "method": "internal"}},
        binary_resolver=lambda name: available.get(name),
    )

    rows = {row["component"]: row for row in readiness["rows"]}
    assert rows["host_discovery:icmp_echo"]["status"] == "ready"
    assert rows["host_discovery:reverse_dns"]["status"] == "ready"
    assert rows["host_discovery:arp_discovery"]["status"] == "ready"
    assert rows["host_discovery:route_trace"]["resolved_binary"] == "tracepath"
    assert rows["snmp_targeted_oids"]["status"] == "deferred_credentials"
    assert readiness["status"] == "degraded"
    assert readiness["launch_blocked"] is False


def test_existing_cvss_exception_and_verification_contract_is_preserved():
    assert issubclass(scoring_policy.CvssVerifierUnavailableError, scoring_policy.ScoringPolicyError)
    assert issubclass(scoring_policy.InvalidCvssVectorError, scoring_policy.ScoringPolicyError)
    assert issubclass(scoring_policy.PublishedMetricInconsistencyError, scoring_policy.ScoringPolicyError)

    metric = mitre_cve._validated_metric(
        "3.1",
        {
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "publisher",
        "CNA",
    )
    assert "cvss_verification_status" in metric
    assert "cvss_metric_integrity" in metric
    assert "cvss_verification_method" in metric


def test_match_basis_registry_contains_no_description_or_alias_bases():
    keys = set(match_basis.DISPLAY_LABELS)
    assert "exact_observed_version_in_record_text" not in keys
    assert "explicit_same_product_text_range" not in keys
    assert "named_branch_before" not in keys
    assert all("description" not in key for key in keys)


def test_scanner_contract_does_not_reintroduce_candidate_confirmed_model():
    from scanners import enumerator

    source = inspect.getsource(enumerator)
    assert "Candidate/Confirmed classification is owned" not in source
    assert "promotion gate" not in source.lower()


def test_external_process_argv_construction_is_centralised_in_command_builders():
    scanners_dir = Path(__file__).resolve().parents[1]
    excluded = {"command_builders.py", "tooling.py"}
    for path in scanners_dir.glob("*.py"):
        if path.name in excluded:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id in {"cmd", "command", "args"}
                        and isinstance(node.value, ast.List)
                    ):
                        raise AssertionError(f"inline argv construction in {path.name}:{node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen", "check_output", "check_call"}
                    and node.args
                    and isinstance(node.args[0], ast.List)
                ):
                    raise AssertionError(f"inline subprocess argv in {path.name}:{node.lineno}")


def test_native_ssh_crypto_collector_does_not_require_unrelated_ssh_audit_binary():
    metadata = collector_plan.COLLECTOR_METADATA["ssh_audit_native"]
    assert not metadata.get("binary")


def test_legacy_nmap_runner_preserves_command_shape_through_central_builder():
    from scanners import nmap_runner

    request = nmap_runner.ScanRequest(
        target="192.0.2.90",
        ports="22,80",
        intensity=3,
        profile="standard",
    )
    with patch.object(nmap_runner, "resolve_nmap_path", return_value="/usr/bin/nmap"):
        command = nmap_runner.build_nmap_command(request, Path("/tmp/scan.xml"))
    assert command == [
        "/usr/bin/nmap", "-Pn", "-T", "3", "-p", "22,80", "-oX", "/tmp/scan.xml",
        "-sV", "-sC", "192.0.2.90",
    ]


def test_nvd_cannot_fallback_into_cve_applicability_when_official_index_is_missing(tmp_path: Path):
    missing_index = tmp_path / "missing-official-index.jsonl"
    fake_nvd_row = {
        "cve_id": "CVE-2099-71999",
        "source": "NVD CVE API 2.0",
        "matched_version_tokens": ["1.0"],
    }
    with (
        patch.object(mitre_cve, "INDEX", missing_index),
        patch.object(mitre_cve.nvd_client, "search", return_value=((fake_nvd_row,), tuple())) as nvd_search,
    ):
        rows, diagnostics = mitre_cve.search_with_held("Example Product", "1.0", "http")

    assert rows == tuple()
    assert any(item.get("reason") == "cve_index_unavailable" for item in diagnostics)
    nvd_search.assert_not_called()


def test_mitre_status_availability_is_canonical_index_only(tmp_path: Path):
    missing_index = tmp_path / "missing-official-index.jsonl"
    with (
        patch.object(mitre_cve, "INDEX", missing_index),
        patch.object(mitre_cve, "REPO_DIR", tmp_path / "missing-repo"),
        patch.object(mitre_cve.nvd_client, "status", return_value={"enabled": True, "attribution": "NVD optional enrichment"}),
    ):
        status = mitre_cve.status()
    assert status["available"] is False
    assert status["source_mode"] == "unavailable"
    assert status["matcher_status"] == "unavailable"
    assert status["nvd_enrichment"]["enabled"] is True
