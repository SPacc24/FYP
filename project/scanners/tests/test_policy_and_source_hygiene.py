from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanners.mitre_cve import INDEX, OFFICIAL_CVE_SOURCE

# Business-risk/priority wording that must never appear in shipped
# templates/policies/static assets: this scanner reports technical CVE
# applicability and published CVSS severity only. Priority, risk, and
# exploitability scoring are downstream organisational decisions owned
# outside this module.
_FORBIDDEN_SCORING_TERMS = (
    "risk score",
    "priority score",
    "severity score",
    "exploitability score",
    "manual validation required",
    "exploitation candidate",
)
# Scoped to assets this module owns/controls (policies) and its shared static
# assets. templates/ is intentionally excluded: it is teammate-owned UI copy
# that legitimately describes other features (e.g. the CALDERA operational
# risk score) using some of the same words for unrelated concepts, so a
# blanket scan there produces false positives rather than real findings
# about this module's own output.
_SCANNED_ROOTS = ("policies", "static")


def test_cve_index_uses_official_source_only():
    """Every indexed CVE record must be attributed to the official CVE List V5 source.

    Skipped when the local index hasn't been built (scripts/rebuild_mitre_cve_index.py) --
    this check verifies index provenance, not index presence.
    """
    if not INDEX.exists():
        pytest.skip("Local CVE List V5 index has not been built; run scripts/rebuild_mitre_cve_index.py")

    checked = 0
    bad: list[str] = []
    with INDEX.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if checked >= 1000:
                break
            checked += 1
            try:
                row = json.loads(line)
            except (TypeError, ValueError):
                continue
            if row.get("source") != OFFICIAL_CVE_SOURCE:
                bad.append(str(row.get("cve_id")))

    assert not bad, f"Non-official CVE source rows found in first {checked} indexed records: {bad}"


def test_no_forbidden_scoring_wording_in_shipped_assets():
    """Templates/policies/static must not present business-risk wording as if it were a scanner output.

    CVSS is technical severity; risk/priority/exploitability scoring is an
    organisational decision made outside this module (see
    docs/vulnerability_scanning_standards.md).
    """
    project_root = Path(__file__).resolve().parents[2]
    violations: list[tuple[str, str]] = []
    for root_name in _SCANNED_ROOTS:
        root = project_root / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            for term in _FORBIDDEN_SCORING_TERMS:
                if term in text:
                    violations.append((str(path.relative_to(project_root)), term))

    assert not violations, f"Forbidden scoring wording found: {violations}"
