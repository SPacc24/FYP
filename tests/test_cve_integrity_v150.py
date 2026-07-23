import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest


PROJECT_DIR = Path(__file__).resolve().parents[1] / "project"
sys.path.insert(0, str(PROJECT_DIR))

from mapping.technique_mapper import map_vulnerabilities
from scanners import mitre_cve, nvd_enrichment
from scanners import enumerator
from storage.db import Database


def _synthetic_cve(year: int, sequence: int) -> str:
    return f"CVE-{year}-{sequence}"


def test_nvd_metric_parser_keeps_versions_and_provider_separate():
    cve = {
        "metrics": {
            "cvssMetricV31": [{
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            }],
            "cvssMetricV40": [{
                "source": "security@example.invalid",
                "type": "Secondary",
                "cvssData": {
                    "version": "4.0",
                    "baseScore": 8.7,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
                },
            }],
        }
    }
    metrics = nvd_enrichment._extract_nvd_metrics(cve)
    assert metrics["3.1"]["cvss_score"] == 9.8
    assert metrics["3.1"]["cvss_source"] == "nvd@nist.gov"
    assert metrics["4.0"]["cvss_score"] == 8.7


def test_nvd_enrichment_fills_only_missing_selected_version():
    cve_id = _synthetic_cve(2099, 41001)
    matches = [{
        "cve_id": cve_id,
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "cvss_score": None,
        "cvss_version": "3.1",
        "cvss_status": "not_provided_for_selected_version",
    }]
    fetched = {
        cve_id: {
            "3.1": {
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_source": "nvd@nist.gov",
                "cvss_version": "3.1",
                "cvss_provider_role": "NVD Primary",
                "cvss_enrichment_source": nvd_enrichment.NVD_SOURCE,
            }
        }
    }
    with TemporaryDirectory() as tmp, \
            mock.patch.object(nvd_enrichment, "CACHE_DIR", Path(tmp)), \
            mock.patch.object(nvd_enrichment, "_fetch_metrics", return_value=fetched):
        enriched, diagnostics = nvd_enrichment.enrich_matches(matches, "3.1")
    assert len(enriched) == len(matches)
    assert enriched[0]["cve_id"] == cve_id
    assert enriched[0]["cvss_score"] == 9.8
    assert enriched[0]["cvss_version"] == "3.1"
    assert any(row["reason"] == "nvd_cvss_enrichment_applied" for row in diagnostics)


def test_nvd_enrichment_never_falls_back_between_versions():
    cve_id = _synthetic_cve(2099, 41002)
    matches = [{
        "cve_id": cve_id,
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "cvss_score": None,
        "cvss_version": "4.0",
    }]
    fetched = {cve_id: {"3.1": {"cvss_score": 9.8, "cvss_version": "3.1"}}}
    with TemporaryDirectory() as tmp, \
            mock.patch.object(nvd_enrichment, "CACHE_DIR", Path(tmp)), \
            mock.patch.object(nvd_enrichment, "_fetch_metrics", return_value=fetched):
        enriched, _diagnostics = nvd_enrichment.enrich_matches(matches, "4.0")
    assert enriched[0].get("cvss_score") is None
    assert enriched[0]["cvss_version"] == "4.0"


def test_description_only_version_statement_is_not_a_candidate():
    cve_id = _synthetic_cve(2099, 41003)
    record = {
        "index_schema_version": 2,
        "cve_id": cve_id,
        "description": "Apache HTTP Server 2.2.8 and earlier can be affected by a crafted range header denial of service.",
        "affected_entries": [{
            "vendor": "n/a",
            "product": "n/a",
            "versions": [],
            "cpes": [],
        }],
        "references": [],
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "cvss_metrics": {},
    }
    service = {
        "host": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.2.8",
        "cpe": [],
        "confidence_score": 0.95,
        "recommended_for_cve": True,
    }
    with TemporaryDirectory() as tmp:
        index = Path(tmp) / "index.jsonl"
        index.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with mock.patch.object(mitre_cve, "INDEX", index), \
                mock.patch.object(enumerator, "enrich_matches_from_nvd", side_effect=lambda rows, _version: (rows, [])):
            mitre_cve._search_cached.cache_clear()
            confirmed, candidates = enumerator._match_cves([service], [], "3.1")
    mitre_cve._search_cached.cache_clear()
    assert confirmed == []
    assert candidates == []


def test_package_provenance_condition_is_conditional():
    cve_id = _synthetic_cve(2099, 41004)
    service = {"product": "Example FTP", "service": "ftp"}
    match = {
        "cve_id": cve_id,
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "match_basis": "exact_structured_version",
        "description": "Example FTP 1.2.3 downloaded between two publication dates contains a backdoor.",
        "applicability_decision": "analyst_review",
        "required_conditions": ["Package provenance was not established by authoritative applicability data."],
    }
    classification, reason = enumerator._classify_cve_match(service, match)
    assert classification == "Analyst Review — Required Conditions Unresolved"
    assert "provenance" in reason.lower()


def test_reported_provenance_candidate_keeps_official_nvd_cvss():
    cve_id = _synthetic_cve(2099, 41007)
    record = {
        "index_schema_version": 2,
        "cve_id": cve_id,
        "description": "vsftpd 2.3.4 downloaded between two publication dates contains a backdoor.",
        "affected_entries": [{
            "vendor": "vsftpd",
            "product": "vsftpd",
            "versions": [{"version": "2.3.4", "status": "affected"}],
            "cpes": [],
        }],
        "references": [],
        "source": mitre_cve.OFFICIAL_CVE_SOURCE,
        "cvss_metrics": {},
    }
    service = {
        "host": "192.0.2.30",
        "port": 21,
        "protocol": "tcp",
        "service": "ftp",
        "product": "vsftpd",
        "version": "2.3.4",
        "cpe": [],
        "confidence_score": 0.98,
        "recommended_for_cve": True,
    }

    def enrich(rows, selected_version):
        assert selected_version == "3.1"
        enriched = []
        for row in rows:
            enriched.append({
                **row,
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_source": "nvd@nist.gov",
                "cvss_version": "3.1",
                "cvss_status": "published",
            })
        return enriched, [{"reason": "nvd_cvss_enrichment_applied", "record_count": len(enriched)}]

    with TemporaryDirectory() as tmp:
        index = Path(tmp) / "index.jsonl"
        index.write_text(json.dumps(record) + "\n", encoding="utf-8")
        diagnostics = []
        with mock.patch.object(mitre_cve, "INDEX", index), \
                mock.patch.object(enumerator, "enrich_matches_from_nvd", side_effect=enrich):
            mitre_cve._search_cached.cache_clear()
            confirmed, candidates = enumerator._match_cves([service], diagnostics, "3.1")
    mitre_cve._search_cached.cache_clear()
    assert confirmed == []
    assert candidates[0]["classification"] == "Analyst Review — Required Conditions Unresolved"
    assert candidates[0]["source_cvss_score"] == 9.8
    assert candidates[0]["source_cvss_source"] == "nvd@nist.gov"
    assert any(row["reason"] == "nvd_cvss_enrichment_applied" for row in diagnostics)


def test_mapping_runtime_contains_no_static_cve_identifiers():
    fixed_cve = __import__("re").compile(r"CVE-[0-9]{4}-[0-9]{4,}")
    mapping_root = PROJECT_DIR / "mapping"
    violations = []
    for path in mapping_root.glob("*.py"):
        if fixed_cve.search(path.read_text(encoding="utf-8")):
            violations.append(path.name)
    assert violations == []


def test_mapping_output_keeps_exposure_priority_separate_from_canonical_cvss():
    cve_id = _synthetic_cve(2099, 41005)
    parsed = {
        "hosts": [{
            "address": {"primary": "192.0.2.20"},
            "os": {"name": "Linux"},
            "port_findings": [{
                "port": 21,
                "protocol": "tcp",
                "state": "open",
                "service": "ftp",
                "product": "Example FTP",
                "version": "1.2.3",
                "cpe": [],
            }],
        }],
    }
    mapping = map_vulnerabilities(parsed)
    baseline = mapping["vulnerabilities"][0]
    baseline_severity = baseline["severity"]
    baseline_priority = baseline["priority_score"]
    canonical = [{
        "host": "192.0.2.20",
        "port": 21,
        "protocol": "tcp",
        "observed_ports": ["21/tcp"],
        "cve_id": cve_id,
        "source_cvss_severity": "CRITICAL",
        "source_cvss_score": 9.8,
        "source_cvss_version": "3.1",
        "source_cvss_source": "nvd@nist.gov",
        "match_source": mitre_cve.OFFICIAL_CVE_SOURCE,
    }]
    result = enumerator._canonicalise_downstream_mapping(mapping, canonical, [])
    finding = result["vulnerabilities"][0]
    assert finding["cve_ids"] == [cve_id]
    assert finding["severity"] == baseline_severity
    assert finding["priority_score"] == baseline_priority
    assert finding["cve_matches"][0]["severity"] == "CRITICAL"
    assert result["cve_contract_version"] == "scanner-canonical-v4"


def test_direct_database_vulnerability_write_is_disabled():
    database = object.__new__(Database)
    with pytest.raises(RuntimeError):
        database.save_vulnerabilities(1, [{"cve_id": _synthetic_cve(2099, 41006)}])
