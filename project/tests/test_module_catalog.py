"""Tests for the evidence-driven exploit module catalog."""

import json
import os
import tempfile

import pytest

from exploitation.module_catalog import (
    MatchRule,
    ModuleCatalog,
    PortEvidence,
    get_module_catalog,
    normalise_service,
    reload_module_catalog,
)


@pytest.fixture(autouse=True)
def _clear_catalog_cache():
    """Make sure every test reloads the live catalog."""
    reload_module_catalog()
    yield
    reload_module_catalog()


def _minimal_catalog_path(tmp_path, extra_modules=None, extra_lateral=None):
    data = {
        "version": 1,
        "metasploit_modules": extra_modules or [],
        "web_profiles": [
            {
                "key": "test_web",
                "title": "Test web profile",
                "endpoint": "/diagnostics.php",
                "parameter": "cmd",
                "method": "GET",
                "ports": [80, 8080],
                "platforms": ["linux"],
                "requires_approval": True,
                "risk": "high",
                "match": {"services": ["http"], "ports": [80]},
            }
        ],
        "lateral_techniques": extra_lateral or [],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_catalog_loads_default_json():
    catalog = get_module_catalog()
    assert catalog.metasploit_modules
    assert catalog.web_profiles
    assert catalog.lateral_techniques

    # EternalBlue entries expected for the lab chain.
    keys = {m.key for m in catalog.metasploit_modules}
    assert "msf_smb_ms17_010_check" in keys
    assert "msf_smb_ms17_010_exploit" in keys
    assert "msf_smb_version" in keys

    lateral_keys = {t.key for t in catalog.lateral_techniques}
    assert "ms17_010" in lateral_keys


def test_ms17_010_exploit_matches_smb_445_with_cve():
    catalog = get_module_catalog()
    evidence = PortEvidence(
        target="10.10.20.50",
        port=445,
        service="microsoft-ds",
        product="Windows 10",
        version="",
        cves={"CVE-2017-0144"},
        paths=set(),
        target_type="windows_smb",
    )

    hits = catalog.matching_msf_modules(evidence)
    keys = {m.key for m in hits}
    assert "msf_smb_ms17_010_exploit" in keys
    assert "msf_smb_ms17_010_check" in keys


def test_ms17_010_exploit_does_not_match_without_cve():
    catalog = get_module_catalog()
    evidence = PortEvidence(
        target="10.10.20.50",
        port=445,
        service="microsoft-ds",
        product="Windows 10",
        version="",
        cves=set(),
        paths=set(),
        target_type="windows_smb",
    )

    hits = catalog.matching_msf_modules(evidence)
    keys = {m.key for m in hits}
    assert "msf_smb_ms17_010_exploit" not in keys
    assert "msf_smb_version" in keys


def test_lateral_eternalblue_matches_windows_smb_445():
    catalog = get_module_catalog()
    matches = catalog.matching_lateral(
        target_type="windows_smb",
        service="smb",
        port=445,
        cves=["CVE-2017-0144"],
    )
    keys = {t.key for t in matches}
    assert "ms17_010" in keys


def test_lateral_psexec_matches_windows_smb_without_cve():
    catalog = get_module_catalog()
    matches = catalog.matching_lateral(
        target_type="windows_smb",
        service="microsoft-ds",
        port=445,
        cves=[],
    )
    keys = {t.key for t in matches}
    assert "psexec" in keys
    assert "ms17_010" in keys  # target_type + port/service still matches


def test_web_profile_matches_http_on_80():
    catalog = get_module_catalog()
    evidence = PortEvidence(
        target="172.16.0.10",
        port=80,
        service="http",
        product="",
        version="",
        cves=set(),
        paths={"/diagnostics.php"},
        target_type="http",
    )
    profiles = catalog.matching_web_profiles(evidence)
    assert any(p.key == "cmdi_diagnostics_php" for p in profiles)


def test_catalog_ignores_unknown_top_level_keys(tmp_path):
    """Adding extra keys to the JSON must not break parsing."""
    data = {
        "version": 1,
        "unknown_future_key": [1, 2, 3],
        "metasploit_modules": [
            {
                "key": "test_module",
                "title": "Test module",
                "module_type": "auxiliary",
                "module_name": "scanner/test/test",
                "validation_keys": ["tcp_reachability_check"],
                "match": {"services": ["ssh"], "ports": [22]},
            }
        ],
        "web_profiles": [],
        "lateral_techniques": [],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data))

    catalog = ModuleCatalog(str(path))
    assert catalog.metasploit_modules[0].key == "test_module"


def test_custom_catalog_path_used(tmp_path):
    path = _minimal_catalog_path(
        tmp_path,
        extra_modules=[
            {
                "key": "custom_smb",
                "title": "Custom SMB scanner",
                "module_type": "auxiliary",
                "module_name": "scanner/smb/custom",
                "validation_keys": ["tcp_reachability_check"],
                "match": {"services": ["smb"], "ports": [445]},
            }
        ],
    )
    catalog = ModuleCatalog(path)
    assert [m.key for m in catalog.metasploit_modules] == ["custom_smb"]


def test_env_token_resolved_in_web_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("LAB_WEB_EXPLOIT_ENDPOINT", "/custom.php")
    monkeypatch.setenv("LAB_WEB_EXPLOIT_PARAMETER", "run")
    monkeypatch.setenv("LAB_WEB_EXPLOIT_METHOD", "POST")

    data = {
        "version": 1,
        "metasploit_modules": [],
        "web_profiles": [
            {
                "key": "env_profile",
                "title": "Env profile",
                "endpoint": "${LAB_WEB_EXPLOIT_ENDPOINT}",
                "parameter": "${LAB_WEB_EXPLOIT_PARAMETER}",
                "method": "${LAB_WEB_EXPLOIT_METHOD}",
                "ports": [80],
                "platforms": ["linux"],
                "requires_approval": True,
                "risk": "high",
                "match": {
                    "services": ["http"],
                    "ports": [80],
                    "require_env_endpoint": True,
                },
            }
        ],
        "lateral_techniques": [],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data))

    catalog = ModuleCatalog(str(path))
    profile = catalog.web_profile_by_key("env_profile")
    assert profile.endpoint == "/custom.php"
    assert profile.parameter == "run"
    assert profile.method == "POST"


def test_match_rule_service_and_cve_or_port_mode():
    rule = MatchRule.from_dict(
        {
            "services": ["smb"],
            "ports": [445],
            "cves": ["CVE-2017-0144"],
            "match_mode": "service_and_cve_or_port",
        }
    )
    # Service + port match.
    assert rule.services == {"smb"}
    assert rule.ports == {445}
    # CVE match alone should not count without service/port.
    no_service = PortEvidence(
        target="t", port=80, service="http", cves={"CVE-2017-0144"}
    )
    assert not ModuleCatalog("")._matches(rule, no_service)


def test_normalise_service_aliases():
    assert normalise_service("microsoft-ds") == "smb"
    assert normalise_service("ms-wbt-server") == "rdp"
    assert normalise_service("HTTP-ALT") == "http"
