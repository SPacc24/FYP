import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "project"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scanners.enumerator import (  # noqa: E402
    _coverage_display_status,
    _classify_cve_match,
    ALLOWED_CVE_STATUSES,
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


def test_cve_contract_accepts_only_candidate_and_confirmed():
    for status in ALLOWED_CVE_STATUSES:
        result = _classify_cve_match({
            "source": OFFICIAL_CVE_SOURCE,
            "classification": status,
            "classification_reason": "Published applicability evidence.",
        })
        assert result == (status, "Published applicability evidence.")


def test_cve_contract_rejects_every_other_value():
    assert _classify_cve_match({
        "source": OFFICIAL_CVE_SOURCE,
        "classification": "Different value",
    }) is None


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
