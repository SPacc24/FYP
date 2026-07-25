import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "project"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scanners.enumerator import (  # noqa: E402
    _coverage_display_status,
    _classify_cve_match,
    STRICT_CVE_MATCH,
    RELEVANT_VERSION_INFORMATION,
    EVIDENCE_INCOMPLETE,
    NOT_APPLICABLE_TO_CONTEXT,
)
from storage import scan_store  # noqa: E402
from scanners.mitre_cve import OFFICIAL_CVE_SOURCE  # noqa: E402


def test_httpx_incompatible_is_not_successful_empty():
    result = {
        "success": True,
        "stdout": "ProjectDiscovery httpx not available or incompatible; nmap HTTP scripts used as fallback",
        "command": "/usr/bin/httpx-toolkit -h",
    }
    status = _coverage_display_status("httpx", scan_store.STATUS_EMPTY, "ProjectDiscovery httpx not available or incompatible; nmap HTTP scripts used as fallback", result)
    assert status == "Tool Unavailable - Fallback Used"


def test_hydra_missing_wordlist_is_input_missing():
    status = _coverage_display_status("hydra", scan_store.STATUS_EMPTY, "Credential wordlist missing for 192.168.1.10:21/ftp", {})
    assert status == "Input Missing"


def test_timeout_is_evidence_incomplete():
    result = {"success": False, "stderr": "timeout", "returncode": -1}
    status = _coverage_display_status("smbmap", scan_store.STATUS_FAILED, "SMB share permission map", result)
    assert status == "Timed Out - Incomplete"


def test_exact_vsftpd_cve_is_strict():
    service = {"product": "vsftpd", "version": "2.3.4", "service": "ftp"}
    match = {
        "source": OFFICIAL_CVE_SOURCE,
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.",
        "match_basis": "exact_structured_version",
    }
    classification, reason = _classify_cve_match(service, match)
    assert classification == STRICT_CVE_MATCH
    assert "match" in reason.lower()


def test_range_only_cve_moves_to_relevant_information():
    service = {"product": "ISC BIND", "version": "9.4.2", "service": "domain"}
    match = {
        "source": OFFICIAL_CVE_SOURCE,
        "cve_id": "CVE-2021-25215",
        "description": "BIND 9.0.0 -> 9.11.29 can terminate due to an assertion check.",
        "match_basis": "explicit_same_product_text_range:9.0.0..9.11.29",
    }
    classification, _ = _classify_cve_match(service, match)
    assert classification == RELEVANT_VERSION_INFORMATION


def test_module_dependent_cve_moves_to_evidence_incomplete():
    service = {"product": "Apache httpd", "version": "2.2.8", "service": "http"}
    match = {
        "source": OFFICIAL_CVE_SOURCE,
        "cve_id": "CVE-2008-2364",
        "description": "The mod_proxy module in the Apache HTTP Server 2.2.8 does not limit interim responses.",
        "match_basis": "exact_observed_version_in_record_text",
    }
    classification, _ = _classify_cve_match(service, match)
    assert classification == EVIDENCE_INCOMPLETE


def test_wrong_platform_context_is_not_rendered_as_relevant_evidence():
    service = {"product": "Apache httpd", "version": "2.2.8", "service": "http"}
    match = {
        "source": OFFICIAL_CVE_SOURCE,
        "cve_id": "CVE-2010-0425",
        "description": "modules/arch/win32/mod_isapi.c in Apache HTTP Server allows remote attackers to execute arbitrary code.",
        "match_basis": "exact_observed_version_in_record_text",
    }
    classification, _ = _classify_cve_match(service, match)
    assert classification == NOT_APPLICABLE_TO_CONTEXT


def test_service_level_nmap_script_descriptions_are_specific():
    from scanners.enumerator import _describe_command

    assert _describe_command(['/usr/bin/nmap', '-sV', '--script', 'dns-recursion,dns-zone-transfer,dns-nsid', '-p', '53', '192.168.1.10']) == 'Checked DNS recursion, NSID, and zone-transfer evidence.'
    assert _describe_command(['/usr/bin/nmap', '-sV', '--script', 'ftp-anon,ftp-syst', '-p', '21,2121', '192.168.1.10']) == 'Checked FTP banner, anonymous-login, and system evidence.'
    assert _describe_command(['/usr/sbin/arp-scan', '192.168.1.10']) == 'Checked local ARP visibility for the target address or local range.'


def test_ssh_audit_nonzero_recommendation_text_is_evidence():
    from scanners.enumerator import _text_has_ssh_audit_evidence

    text = '.se -- enc algorithm to remove (rec) -ssh-dss -- key algorithm to remove (rec) -ssh-rsa'
    assert _text_has_ssh_audit_evidence(text) is True


def test_successful_command_output_with_timeout_word_is_not_marked_timeout():
    result = {"success": True, "stdout": "script output mentioned timeout threshold", "returncode": 0}
    status = _coverage_display_status("nmap_ftp_checks", scan_store.STATUS_SUCCESS, "192.0.2.10:21/tcp", result)
    assert status == "Completed"


def test_postgresql_check_does_not_use_missing_pgsql_info_script():
    text = (PROJECT / "scanners" / "enumerator.py").read_text(encoding="utf-8")
    assert "pgsql-info" not in text
    assert "pgsql-empty-password" in text
