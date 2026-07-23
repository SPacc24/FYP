"""The single gate for promoting a CVE finding from Candidate to Confirmed.

``cve_v5_matcher`` only ever produces ``Candidate`` findings: a structured,
machine-readable match against official CVE List V5 affected data. That is a
statement about applicability, not about verified exploitability.

``Confirmed`` means separate, target-specific validation evidence exists that
verifies the vulnerable condition described by that exact CVE record on that
exact target. No generic scanner signal -- a service banner, a TLS
handshake, a version string, a protocol probe, a CVSS score, or a
cross-tool fingerprint confidence score -- proves that on its own, because
none of them test the specific vulnerable behaviour a CVE describes. This
module refuses to let any of them satisfy the gate, even indirectly.

No conclusive per-CVE validator exists anywhere in this project yet. That is
intentional: inventing generic "is this CVE probably exploitable" heuristics
would not be backed by CVE List V5, CVSS, or NIST SP 800-115, and this
project's owner explicitly does not want invented decision logic. This
module is the tested contract a future validator (a specific per-CVE safe
check, or a human review record) must satisfy to promote a finding -- not a
mechanism that produces confirmations itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class CveConfirmationError(ValueError):
    """Raised when a Confirmed promotion attempt does not meet the gate's requirements."""


# Evidence categories already collected elsewhere in this project that can
# never, by themselves, satisfy this gate. They corroborate a service's
# general identity; they do not test any specific CVE's vulnerable
# condition. Listed explicitly (rather than merely "not on an allow-list")
# so a future validator cannot casually relabel one of these as a bespoke
# method name to slip past the gate.
GENERIC_EVIDENCE_CATEGORIES = frozenset({
    "banner_match",
    "tls_evidence",
    "version_string",
    "protocol_probe",
    "cvss_score",
    "fingerprint_confidence",
    "service_identity",
})

_REQUIRED_STRING_FIELDS = (
    "cve_id",
    "host",
    "validation_method",
    "evidence_reference",
    "validator_source",
)


@dataclass(frozen=True)
class ConfirmationEvidence:
    """A single, explicit, CVE-specific, target-specific validation record.

    This dataclass does not perform validation itself. It is the durable,
    auditable record a validator must produce after actually verifying a
    CVE's vulnerable condition against one exact target/service -- who
    performed the check (``validator_source``), what kind of check it was
    (``validation_method``), what was found (``result``), and where the
    supporting evidence lives (``evidence_reference``).
    """

    cve_id: str
    host: str
    port: int
    validation_method: str
    result: bool
    evidence_reference: str
    validator_source: str
    validated_at: str = ""

    def __post_init__(self) -> None:
        if not self.validated_at:
            object.__setattr__(
                self, "validated_at", datetime.now(timezone.utc).isoformat(timespec="seconds")
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "host": self.host,
            "port": self.port,
            "validation_method": self.validation_method,
            "result": self.result,
            "evidence_reference": self.evidence_reference,
            "validator_source": self.validator_source,
            "validated_at": self.validated_at,
        }


def confirm_candidate(candidate: dict[str, Any], evidence: ConfirmationEvidence) -> dict[str, Any]:
    """Promote a Candidate CVE finding to Confirmed.

    Fails closed: raises :class:`CveConfirmationError` unless ``evidence`` is
    a complete, CVE-specific, and target-specific validation record that
    exactly matches ``candidate``, and records a positive result through a
    non-generic validation method. Never mutates ``candidate``; returns a new
    dict.
    """
    if not isinstance(candidate, dict):
        raise CveConfirmationError("candidate must be a dict.")
    if str(candidate.get("classification") or candidate.get("status") or "") != "Candidate":
        raise CveConfirmationError("Only a Candidate finding may be promoted to Confirmed.")
    if not isinstance(evidence, ConfirmationEvidence):
        raise CveConfirmationError("evidence must be a ConfirmationEvidence record.")

    for field in _REQUIRED_STRING_FIELDS:
        if not str(getattr(evidence, field) or "").strip():
            raise CveConfirmationError(f"Confirmation evidence is missing required field: {field}.")

    method = str(evidence.validation_method).strip().lower()
    if method in GENERIC_EVIDENCE_CATEGORIES:
        raise CveConfirmationError(
            f"validation_method {evidence.validation_method!r} is a generic scanner-evidence "
            "category and can never, by itself, confirm a specific CVE's vulnerable condition."
        )

    candidate_cve = str(candidate.get("cve_id") or "").strip()
    if not candidate_cve or candidate_cve != str(evidence.cve_id).strip():
        raise CveConfirmationError("Confirmation evidence CVE ID does not match the candidate.")

    candidate_host = str(candidate.get("host") or "").strip()
    if not candidate_host or candidate_host != str(evidence.host).strip():
        raise CveConfirmationError("Confirmation evidence host does not match the candidate.")

    try:
        candidate_port = int(candidate.get("port") or 0)
        evidence_port = int(evidence.port)
    except (TypeError, ValueError) as exc:
        raise CveConfirmationError("Candidate or evidence port is not a valid integer.") from exc
    if not candidate_port or candidate_port != evidence_port:
        raise CveConfirmationError("Confirmation evidence port does not match the candidate.")

    if evidence.result is not True:
        raise CveConfirmationError(
            "Confirmation evidence must record a positive (vulnerable-condition-confirmed) "
            "result; a negative or inconclusive result must not promote a finding."
        )

    return {
        **candidate,
        "classification": "Confirmed",
        "status": "Confirmed",
        "applicability_status": "Confirmed",
        "confirmation_evidence": evidence.to_dict(),
        "classification_reason": (
            f"Confirmed by {evidence.validator_source} via {evidence.validation_method}: "
            f"see {evidence.evidence_reference}."
        ),
    }


def is_valid_confirmation(row: dict[str, Any]) -> bool:
    """Defense-in-depth re-check before trusting a row already marked Confirmed.

    A ``classification`` string of ``"Confirmed"`` is never sufficient on its
    own. This verifies the attached ``confirmation_evidence`` block is
    complete, matches the row's own CVE/host/port identity, records a
    positive result, and was not built from a generic evidence category --
    i.e. that it could only have come from :func:`confirm_candidate`.
    """
    if str(row.get("classification") or row.get("status") or "") != "Confirmed":
        return False
    evidence = row.get("confirmation_evidence")
    if not isinstance(evidence, dict):
        return False
    for field in _REQUIRED_STRING_FIELDS:
        if not str(evidence.get(field) or "").strip():
            return False
    if str(evidence.get("validation_method")).strip().lower() in GENERIC_EVIDENCE_CATEGORIES:
        return False
    if evidence.get("result") is not True:
        return False
    if str(evidence.get("cve_id")).strip() != str(row.get("cve_id") or "").strip():
        return False
    if str(evidence.get("host")).strip() != str(row.get("host") or "").strip():
        return False
    try:
        if int(evidence.get("port") or 0) != int(row.get("port") or 0) or not evidence.get("port"):
            return False
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "ConfirmationEvidence",
    "CveConfirmationError",
    "GENERIC_EVIDENCE_CATEGORIES",
    "confirm_candidate",
    "is_valid_confirmation",
]
