"""Cross-family host-identity exclusivity.

Reproduces the identity contradiction observed in scan 57ae6b437f61, where a
directly observed Windows host identity coexisted with probabilistic Linux
fingerprints and the Linux hypotheses were still emitted as Candidate CVE
inputs. Per-family arbitration cannot see that contradiction; the cross-family
pass must.
"""

from scanners.platform_identity import reconcile_host_identities


def _smb_windows_identity() -> dict:
    return {
        "vendor": "Microsoft",
        "family": "Windows",
        "product": "Windows 10 Enterprise 10240",
        "cpe": ["cpe:/o:microsoft:windows_10::-"],
        "evidence_kind": "protocol_assertion",
        "sources": ["smb_host_identity"],
    }


def _nmap_linux_fingerprint(product: str, version: str, cpe: str, accuracy: str) -> dict:
    return {
        "vendor": "Linux",
        "family": "Linux",
        "product": product,
        "version": version,
        "cpe": [cpe],
        "accuracy": accuracy,
        "evidence_kind": "probabilistic_fingerprint",
        "sources": ["nmap_os_identity"],
    }


def _linux_rows() -> list[dict]:
    return [
        _nmap_linux_fingerprint("Linux 4.4", "4.4", "cpe:/o:linux:linux_kernel:4.4", "92"),
        _nmap_linux_fingerprint("Linux 3.2", "3.2", "cpe:/o:linux:linux_kernel:3.2", "92"),
        _nmap_linux_fingerprint(
            "DD-WRT v24-sp2 (Linux 2.4.37)", "2.4.37",
            "cpe:/o:linux:linux_kernel:2.4.37", "92",
        ),
    ]


def test_direct_windows_identity_suppresses_linux_fingerprint_candidates():
    rows = reconcile_host_identities([_smb_windows_identity(), *_linux_rows()])

    linux = [row for row in rows if row.get("family") == "Linux"]
    assert linux, "Linux fingerprint evidence must still be retained"
    for row in linux:
        assert row["candidate_eligible"] is False
        assert row["cve_eligible"] is False
        assert row["reconciliation_status"] == "contradicted_by_direct_identity"
        assert "contradicted by a directly observed host identity" in row["reconciliation_reason"]


def test_direct_identity_itself_is_unaffected():
    rows = reconcile_host_identities([_smb_windows_identity(), *_linux_rows()])

    windows = [row for row in rows if row.get("family") == "Windows"]
    assert len(windows) == 1
    assert windows[0]["reconciliation_status"] == "authoritative"
    assert windows[0]["cve_eligible"] is True


def test_fingerprints_are_unaffected_when_no_direct_identity_exists():
    rows = reconcile_host_identities(_linux_rows())

    assert rows, "fingerprint-only input must still reconcile"
    assert any(row.get("candidate_eligible") for row in rows), (
        "with no contradicting direct observation, precise fingerprints remain "
        "eligible Candidate CVE inputs"
    )
    assert all(
        row.get("reconciliation_status") != "contradicted_by_direct_identity"
        for row in rows
    )


def test_two_direct_families_are_flagged_not_silently_resolved():
    linux_direct = {
        "vendor": "Linux",
        "family": "Linux",
        "product": "Ubuntu 22.04",
        "version": "22.04",
        "cpe": ["cpe:/o:canonical:ubuntu_linux:22.04"],
        "evidence_kind": "protocol_assertion",
        "sources": ["ssh_auth_methods"],
    }
    rows = reconcile_host_identities([_smb_windows_identity(), linux_direct])

    conflicted = [row for row in rows if row.get("direct_identity_family_conflict")]
    assert len(conflicted) == 2, "a genuine two-family conflict must be surfaced"
    for row in conflicted:
        assert row["reconciliation_status"] != "contradicted_by_direct_identity"


def test_evidence_is_never_discarded():
    rows = reconcile_host_identities([_smb_windows_identity(), *_linux_rows()])
    assert len(rows) == 4, "suppression withdraws eligibility, it never deletes evidence"
