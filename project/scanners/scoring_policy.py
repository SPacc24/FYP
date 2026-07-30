from __future__ import annotations

from typing import Any
import math

try:
    from cvss import CVSS3, CVSS4
except ImportError:  # pragma: no cover - install.sh installs project requirements
    CVSS3 = CVSS4 = None


class ScoringPolicyError(ValueError):
    """Raised when published CVSS metadata is malformed or internally inconsistent."""


class CvssVerifierUnavailableError(ScoringPolicyError):
    """Raised when an independent verifier required by a CVSS version is absent."""


class InvalidCvssVectorError(ScoringPolicyError):
    """Raised when a published CVSS vector cannot be parsed or calculated."""


class PublishedMetricInconsistencyError(ScoringPolicyError):
    """Raised when a valid vector disagrees with its published score or severity."""


_SUPPORTED = ("3.1", "4.0")
_POLICY = {
    "default_version": "3.1",
    "supported_versions": list(_SUPPORTED),
    "allow_conversion": False,
    "missing_metric_label": "Not present in CVE Program record",
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
        raise InvalidCvssVectorError(f"CVSS {expected_version} metric must contain a {prefix[:-1]} vector")
    values: dict[str, str] = {}
    for token in vector[len(prefix):].split('/'):
        if ':' not in token:
            raise InvalidCvssVectorError(f"Invalid CVSS {expected_version} vector token")
        key, value = token.split(':', 1)
        if key in values:
            raise InvalidCvssVectorError(f"Duplicate CVSS metric: {key}")
        values[key] = value
    return values


def _roundup_1(value: float) -> float:
    return math.ceil((value * 10.0) - 1e-10) / 10.0


def _cvss31_base_score(vector: str) -> float:
    values = _parse_vector(vector, "3.1")
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(values):
        raise InvalidCvssVectorError("Invalid or incomplete CVSS 3.1 vector")

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    impact_metric = {"N": 0.0, "L": 0.22, "H": 0.56}
    scope = values["S"]
    pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if scope == "U"
          else {"N": 0.85, "L": 0.68, "H": 0.50} if scope == "C" else None)
    if pr is None:
        raise InvalidCvssVectorError("Invalid CVSS 3.1 Scope metric")
    try:
        iss = 1.0 - ((1.0 - impact_metric[values["C"]]) * (1.0 - impact_metric[values["I"]]) * (1.0 - impact_metric[values["A"]]))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = 8.22 * av[values["AV"]] * ac[values["AC"]] * pr[values["PR"]] * ui[values["UI"]]
    except KeyError as exc:
        raise InvalidCvssVectorError(f"Invalid CVSS 3.1 metric value for {exc.args[0]}") from exc

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
            raise CvssVerifierUnavailableError("CVSS 4.0 verification library is unavailable")
        try:
            return float(CVSS4(vector).scores()[0])
        except Exception as exc:
            raise InvalidCvssVectorError("Invalid or incomplete CVSS 4.0 vector") from exc
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
        raise PublishedMetricInconsistencyError(
            f"Published CVSS {version} score {source_score:.1f} does not match vector score {calculated_score:.1f}"
        )

    calculated_severity = _severity_from_score(calculated_score)
    source_severity = str(severity or calculated_severity).strip().upper()
    if source_severity != calculated_severity:
        raise PublishedMetricInconsistencyError(
            f"Published CVSS {version} severity {source_severity} does not match score severity {calculated_severity}"
        )

    return {
        "cvss_score": source_score,
        "cvss_severity": source_severity,
        "cvss_vector": vector_text,
        "cvss_version": version,
        "cvss_metric_integrity": "published_source_exact",
        "cvss_verified": True,
        "cvss_verification_status": "verified",
        "cvss_verification_method": (
            "internal_cvss31_formula" if version == "3.1" else "python_cvss4_library"
        ),
    }


def cvss_verifier_status() -> dict[str, dict[str, Any]]:
    """Return independent verifier readiness without validating a CVE record."""
    return {
        "3.1": {
            "available": True,
            "method": "internal_cvss31_formula",
        },
        "4.0": {
            "available": CVSS4 is not None,
            "method": "python_cvss4_library",
        },
    }


def metric_for_version(row: dict[str, Any], version: str) -> dict[str, Any]:
    """Return exactly one requested CVSS version without cross-version fallback."""
    selected = normalise_cvss_version(version)
    for field in ("effective_cvss_metrics", "source_cvss_metrics", "cvss_metrics"):
        metrics = row.get(field)
        if not isinstance(metrics, dict):
            continue
        metric = metrics.get(selected)
        if isinstance(metric, dict):
            return dict(metric)
    return {}


def cvss_sort_key(row: dict[str, Any], version: str) -> tuple[int, float, str]:
    """Sort by one selected standard only; never compare 3.1 against 4.0."""
    metric = metric_for_version(row, version)
    try:
        score = float(metric.get("cvss_score"))
    except (TypeError, ValueError):
        score = None
    cve_id = str(row.get("cve_id") or "")
    return (0 if score is not None else 1, -score if score is not None else 0.0, cve_id)


def apply_cvss_selection(rows: list[dict[str, Any]], version: str) -> list[dict[str, Any]]:
    """Attach the selected metric view and return deterministically ordered rows."""
    selected = normalise_cvss_version(version)
    for row in rows or []:
        metric = metric_for_version(row, selected)
        row["selected_cvss_version"] = selected
        row["selected_cvss_metric"] = metric
        row["selected_cvss_score"] = metric.get("cvss_score") if metric else None
        row["selected_cvss_severity"] = metric.get("cvss_severity") if metric else ""
        row["selected_cvss_vector"] = metric.get("cvss_vector") if metric else ""
        row["selected_cvss_source"] = metric.get("cvss_source") if metric else ""
        row["selected_cvss_status"] = "published" if metric else "not_published"
        # Backward-compatible single-metric fields are pinned to the selected
        # standard. Missing 3.1 never falls back to 4.0, and vice versa.
        row["cvss_score"] = metric.get("cvss_score") if metric else None
        row["cvss_severity"] = metric.get("cvss_severity") if metric else ""
        row["cvss_vector"] = metric.get("cvss_vector") if metric else ""
        row["cvss_source"] = metric.get("cvss_source") if metric else ""
        row["cvss_version"] = selected
        if "source_cvss_metrics" in row:
            row["source_cvss_score"] = metric.get("cvss_score") if metric else None
            row["source_cvss_severity"] = metric.get("cvss_severity") if metric else ""
            row["source_cvss_vector"] = metric.get("cvss_vector") if metric else ""
            row["source_cvss_source"] = metric.get("cvss_source") if metric else ""
            row["source_cvss_version"] = selected
    rows.sort(key=lambda item: cvss_sort_key(item, selected))
    return rows
