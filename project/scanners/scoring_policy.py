from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

POLICY_CANDIDATES = (
    Path("project/policies/vulnerability_scoring.json"),
    Path("policies/vulnerability_scoring.json"),
    Path(__file__).resolve().parents[1] / "policies" / "vulnerability_scoring.json",
)


class ScoringPolicyError(ValueError):
    """Raised when the external scoring policy is missing or invalid."""


_REQUIRED_BASE_METRICS = {
    "3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
    "4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
}

_BASE_METRIC_VALUES = {
    "3.1": {
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "R"},
        "S": {"U", "C"},
        "C": {"N", "L", "H"},
        "I": {"N", "L", "H"},
        "A": {"N", "L", "H"},
    },
    "4.0": {
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "AT": {"N", "P"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "P", "A"},
        "VC": {"N", "L", "H"},
        "VI": {"N", "L", "H"},
        "VA": {"N", "L", "H"},
        "SC": {"N", "L", "H"},
        "SI": {"N", "L", "H"},
        "SA": {"N", "L", "H"},
    },
}

_ALLOWED_OPTIONAL_METRICS = {
    "3.1": {
        "E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR",
        "MUI", "MS", "MC", "MI", "MA",
    },
    "4.0": {
        "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
        "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R",
        "V", "RE", "U",
    },
}

def _severity_for_score(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def validate_published_metric(
    version: str,
    score: Any,
    severity: Any,
    vector: Any,
) -> dict[str, Any]:
    """Validate a source-published metric without generating or converting it.

    The score and vector remain the provider's values. This guard only rejects
    malformed, cross-version, incomplete, or internally inconsistent source
    data before it can be labelled as the operator-selected CVSS version.
    """
    selected = normalise_cvss_version(version)
    try:
        numeric_score = float(score)
    except (TypeError, ValueError) as exc:
        raise ScoringPolicyError("Published CVSS score is not numeric.") from exc
    if not 0.0 <= numeric_score <= 10.0:
        raise ScoringPolicyError("Published CVSS score is outside the permitted range.")

    vector_text = str(vector or "").strip()
    prefix = f"CVSS:{selected}/"
    if not vector_text.startswith(prefix):
        raise ScoringPolicyError(
            f"Published vector does not match selected CVSS v{selected}."
        )

    seen: set[str] = set()
    metric_values: dict[str, str] = {}
    for component in vector_text.split("/")[1:]:
        if ":" not in component:
            raise ScoringPolicyError("Published CVSS vector contains a malformed metric.")
        metric_name, metric_value = component.split(":", 1)
        if not metric_name or not metric_value or metric_name in seen:
            raise ScoringPolicyError("Published CVSS vector contains an empty or duplicate metric.")
        seen.add(metric_name)
        metric_values[metric_name] = metric_value
    missing = _REQUIRED_BASE_METRICS[selected] - seen
    if missing:
        raise ScoringPolicyError(
            "Published CVSS vector is missing required Base metrics: "
            + ", ".join(sorted(missing))
        )
    allowed_names = set(_BASE_METRIC_VALUES[selected]) | _ALLOWED_OPTIONAL_METRICS[selected]
    unknown = seen - allowed_names
    if unknown:
        raise ScoringPolicyError(
            "Published CVSS vector contains metrics not defined by the selected FIRST specification: "
            + ", ".join(sorted(unknown))
        )
    invalid_base = [
        f"{name}:{metric_values[name]}"
        for name, allowed in _BASE_METRIC_VALUES[selected].items()
        if metric_values.get(name) not in allowed
    ]
    if invalid_base:
        raise ScoringPolicyError(
            "Published CVSS vector contains invalid Base metric values: "
            + ", ".join(invalid_base)
        )

    severity_text = str(severity or "").strip().upper()
    expected_severity = _severity_for_score(numeric_score)
    if severity_text != expected_severity:
        raise ScoringPolicyError(
            f"Published severity {severity_text or 'missing'} does not match "
            f"the FIRST rating band for score {numeric_score:g}."
        )
    return {
        "cvss_score": numeric_score,
        "cvss_severity": severity_text,
        "cvss_vector": vector_text,
        "cvss_version": selected,
        "cvss_metric_integrity": "published_source_exact",
    }


@lru_cache(maxsize=1)
def load_scoring_policy() -> dict[str, Any]:
    path = next((candidate for candidate in POLICY_CANDIDATES if candidate.exists()), None)
    if path is None:
        raise ScoringPolicyError("Vulnerability scoring policy is missing.")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScoringPolicyError(f"Vulnerability scoring policy is invalid: {exc}") from exc

    versions = policy.get("supported_versions")
    if not isinstance(versions, list) or not versions:
        raise ScoringPolicyError("supported_versions must be a non-empty list.")
    seen: set[str] = set()
    for entry in versions:
        if not isinstance(entry, dict):
            raise ScoringPolicyError("Each supported CVSS version must be an object.")
        version_id = str(entry.get("id") or "").strip()
        metric_key = str(entry.get("metric_key") or "").strip()
        if not version_id or not metric_key or version_id in seen:
            raise ScoringPolicyError("CVSS version IDs and metric keys must be present and unique.")
        seen.add(version_id)

    default = str(policy.get("default_version") or "").strip()
    if default not in seen:
        raise ScoringPolicyError("default_version must name a supported CVSS version.")
    if policy.get("fallback_between_versions") is not False:
        raise ScoringPolicyError("fallback_between_versions must remain false.")
    if policy.get("convert_between_versions") is not False:
        raise ScoringPolicyError("convert_between_versions must remain false.")
    return {
        **policy,
        "configured_default_version": default,
        "default_version": default,
        "default_selection_basis": "external_policy",
        "policy_file": str(path),
    }


def scoring_choices() -> list[dict[str, str]]:
    return [
        {
            "id": str(entry["id"]),
            "label": str(entry.get("label") or entry["id"]),
            "specification_url": str(entry.get("specification_url") or ""),
        }
        for entry in load_scoring_policy()["supported_versions"]
    ]


def normalise_cvss_version(value: str | None) -> str:
    policy = load_scoring_policy()
    supported = {str(entry["id"]) for entry in policy["supported_versions"]}
    selected = str(value or policy["default_version"]).strip()
    if selected not in supported:
        raise ScoringPolicyError(
            f"Unsupported CVSS version {selected!r}; supported versions: {', '.join(sorted(supported))}."
        )
    return selected


def cvss_selection(value: str | None) -> dict[str, Any]:
    policy = load_scoring_policy()
    selected = normalise_cvss_version(value)
    entry = next(item for item in policy["supported_versions"] if str(item["id"]) == selected)
    return {
        "framework": policy["framework"],
        "framework_owner": policy["framework_owner"],
        "version": selected,
        "label": str(entry.get("label") or selected),
        "metric_key": str(entry["metric_key"]),
        "specification_url": str(entry.get("specification_url") or ""),
        "is_default": selected == normalise_cvss_version(None),
        "default_selection_basis": "external_policy",
        "fallback_between_versions": False,
        "convert_between_versions": False,
        "missing_score_behavior": str(policy.get("missing_selected_version") or "report_unavailable"),
        "severity_semantics": str(policy.get("severity_semantics") or ""),
    }


def metric_keys_by_version() -> dict[str, str]:
    return {
        str(entry["id"]): str(entry["metric_key"])
        for entry in load_scoring_policy()["supported_versions"]
    }
