from __future__ import annotations

import pytest

from scanners.cve_confirmation import (
    ConfirmationEvidence,
    CveConfirmationError,
    GENERIC_EVIDENCE_CATEGORIES,
    confirm_candidate,
    is_valid_confirmation,
)


def _candidate(**overrides) -> dict:
    base = {
        "cve_id": "CVE-2099-0001",
        "host": "10.0.0.5",
        "port": 443,
        "classification": "Candidate",
        "status": "Candidate",
    }
    base.update(overrides)
    return base


def _evidence(**overrides) -> ConfirmationEvidence:
    fields = {
        "cve_id": "CVE-2099-0001",
        "host": "10.0.0.5",
        "port": 443,
        "validation_method": "purpose_built_safe_poc_check",
        "result": True,
        "evidence_reference": "storage/scans/example/validation_cve-2099-0001.json",
        "validator_source": "exploitation.validator.example_check",
    }
    fields.update(overrides)
    return ConfirmationEvidence(**fields)


def test_well_formed_cve_specific_evidence_promotes_to_confirmed():
    row = confirm_candidate(_candidate(), _evidence())
    assert row["classification"] == "Confirmed"
    assert row["status"] == "Confirmed"
    assert row["applicability_status"] == "Confirmed"
    assert row["confirmation_evidence"]["cve_id"] == "CVE-2099-0001"
    assert is_valid_confirmation(row) is True


@pytest.mark.parametrize("category", sorted(GENERIC_EVIDENCE_CATEGORIES))
def test_generic_evidence_categories_are_rejected(category):
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(validation_method=category))


def test_generic_evidence_category_rejected_case_insensitively():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(validation_method="CVSS_Score"))


def test_mismatched_cve_id_is_rejected():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(cve_id="CVE-2099-9999"))


def test_mismatched_host_is_rejected():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(host="10.0.0.6"))


def test_mismatched_port_is_rejected():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(port=8443))


def test_negative_result_does_not_promote():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(result=False))


def test_missing_evidence_reference_is_rejected():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(evidence_reference=""))


def test_missing_validator_source_is_rejected():
    with pytest.raises(CveConfirmationError):
        confirm_candidate(_candidate(), _evidence(validator_source=""))


def test_only_a_candidate_may_be_promoted():
    already_confirmed = _candidate(classification="Confirmed", status="Confirmed")
    with pytest.raises(CveConfirmationError):
        confirm_candidate(already_confirmed, _evidence())


def test_confirm_candidate_does_not_mutate_input():
    candidate = _candidate()
    confirm_candidate(candidate, _evidence())
    assert candidate["classification"] == "Candidate"


def test_is_valid_confirmation_rejects_bare_classification_string():
    """A row hand-set to Confirmed without going through confirm_candidate must not be trusted."""
    row = _candidate(classification="Confirmed", status="Confirmed")
    assert is_valid_confirmation(row) is False


def test_is_valid_confirmation_rejects_generic_evidence_attached_directly():
    row = _candidate(classification="Confirmed", status="Confirmed")
    row["confirmation_evidence"] = {
        "cve_id": "CVE-2099-0001",
        "host": "10.0.0.5",
        "port": 443,
        "validation_method": "banner_match",
        "result": True,
        "evidence_reference": "some evidence",
        "validator_source": "someone",
    }
    assert is_valid_confirmation(row) is False


def test_is_valid_confirmation_rejects_identity_mismatch():
    row = _candidate(classification="Confirmed", status="Confirmed")
    row["confirmation_evidence"] = _evidence(host="10.0.0.9").to_dict()
    assert is_valid_confirmation(row) is False


def test_is_valid_confirmation_accepts_output_of_confirm_candidate():
    row = confirm_candidate(_candidate(), _evidence())
    assert is_valid_confirmation(row) is True
