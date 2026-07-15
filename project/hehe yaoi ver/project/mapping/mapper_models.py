from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CVEMatch:
    cve_id: str
    title: str
    severity: str
    reason: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class VulnerabilityFinding:
    host: str
    port: str
    protocol: str
    service: str
    product: str
    version: str
    state: str
    title: str
    severity: str
    priority_score: int
    cve_ids: list[str]
    cve_matches: list[dict[str, str]]
    cve_hint: str
    evidence: str
    recommendation: str
    attack_techniques: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)