from __future__ import annotations

from typing import Any
import math

try:
    from cvss import CVSS3, CVSS4
except ImportError:  # pragma: no cover - install.sh installs project requirements
    CVSS3 = CVSS4 = None


class ScoringPolicyError(ValueError):
    """Raised when published CVSS metadata is malformed or internally inconsistent."""


_SUPPORTED = ("3.1", "4.0")
_POLICY = {
    "default_version": "3.1",
    "supported_versions": list(_SUPPORTED),
    "allow_conversion": False,
    "missing_metric_label": "Not published",
}


def load_scoring_policy() -> dict[str, Any]:
    return dict(_POLICY)


def scoring_choices() -> list[dict[str, str]]:
    return [
        {"id": "3.1", "label": "CVSS 3.1"},
        {"id": "4.0", "label": "CVSS 4.0"},
    ]


def normalise_cvss_version(value: str | None) -> str:
    version = str(value or _POLICY["default_version"]).strip()
    if version not in _SUPPORTED:
        raise ScoringPolicyError(f"Unsupported CVSS version: {version}")
    return version


def cvss_selection(value: str | None) -> dict[str, str]:
    version = normalise_cvss_version(value)
    return {"version": version, "label": f"CVSS {version}"}


def _severity_from_score(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _parse_vector(vector: str, expected_version: str) -> dict[str, str]:
    prefix = f"CVSS:{expected_version}/"
    if not vector.startswith(prefix):
        raise ScoringPolicyError(f"CVSS {expected_version} metric must contain a {prefix[:-1]} vector")
    values: dict[str, str] = {}
    for token in vector[len(prefix):].split('/'):
        if ':' not in token:
            raise ScoringPolicyError(f"Invalid CVSS {expected_version} vector token")
        key, value = token.split(':', 1)
        if key in values:
            raise ScoringPolicyError(f"Duplicate CVSS metric: {key}")
        values[key] = value
    return values


def _roundup_1(value: float) -> float:
    return math.ceil((value * 10.0) - 1e-10) / 10.0


def _cvss31_base_score(vector: str) -> float:
    values = _parse_vector(vector, "3.1")
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(values):
        raise ScoringPolicyError("Invalid or incomplete CVSS 3.1 vector")

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    impact_metric = {"N": 0.0, "L": 0.22, "H": 0.56}
    scope = values["S"]
    pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if scope == "U"
          else {"N": 0.85, "L": 0.68, "H": 0.50} if scope == "C" else None)
    if pr is None:
        raise ScoringPolicyError("Invalid CVSS 3.1 Scope metric")
    try:
        iss = 1.0 - ((1.0 - impact_metric[values["C"]]) * (1.0 - impact_metric[values["I"]]) * (1.0 - impact_metric[values["A"]]))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = 8.22 * av[values["AV"]] * ac[values["AC"]] * pr[values["PR"]] * ui[values["UI"]]
    except KeyError as exc:
        raise ScoringPolicyError(f"Invalid CVSS 3.1 metric value for {exc.args[0]}") from exc

    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup_1(min(impact + exploitability, 10.0))
    return _roundup_1(min(1.08 * (impact + exploitability), 10.0))


def _calculated_base_score(version: str, vector: str) -> float:
    if version == "3.1":
        return _cvss31_base_score(vector)
    if version == "4.0":
        _parse_vector(vector, "4.0")
        if CVSS4 is None:
            raise ScoringPolicyError("CVSS 4.0 verification library is unavailable")
        try:
            return float(CVSS4(vector).scores()[0])
        except Exception as exc:
            raise ScoringPolicyError("Invalid or incomplete CVSS 4.0 vector") from exc
    raise ScoringPolicyError(f"Unsupported CVSS version: {version}")


def validate_published_metric(version: str, score: Any, severity: Any, vector: Any) -> dict[str, Any]:
    """Recompute a published CVSS vector and verify its score/severity.

    No cross-version conversion is attempted. The source score/vector are
    preserved only when the vector independently recomputes to the same base
    score and qualitative severity.
    """
    version = normalise_cvss_version(version)
    vector_text = str(vector or "").strip()
    if not vector_text:
        raise ScoringPolicyError("Published CVSS metric has no vector string")
    try:
        source_score = float(score)
    except (TypeError, ValueError) as exc:
        raise ScoringPolicyError("Published CVSS metric has an invalid score") from exc
    if source_score < 0.0 or source_score > 10.0:
        raise ScoringPolicyError("Published CVSS score must be between 0.0 and 10.0")

    calculated_score = _calculated_base_score(version, vector_text)

    if round(calculated_score, 1) != round(source_score, 1):
        raise ScoringPolicyError(
            f"Published CVSS {version} score {source_score:.1f} does not match vector score {calculated_score:.1f}"
        )

    calculated_severity = _severity_from_score(calculated_score)
    source_severity = str(severity or calculated_severity).strip().upper()
    if source_severity != calculated_severity:
        raise ScoringPolicyError(
            f"Published CVSS {version} severity {source_severity} does not match score severity {calculated_severity}"
        )

    return {
        "cvss_score": source_score,
        "cvss_severity": source_severity,
        "cvss_vector": vector_text,
        "cvss_version": version,
        "cvss_metric_integrity": "published_source_exact",
    }
