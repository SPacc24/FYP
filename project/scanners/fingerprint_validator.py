from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal


EvidenceConfidence = Literal["exact", "partial", "hint"]


@dataclass(frozen=True)
class ServiceEvidence:
    """Evidence from a single tool about a service."""

    tool: str
    product: str
    version: str
    confidence: Literal["exact", "partial", "hint"]
    raw_evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ServiceFingerprint:
    """Consensus fingerprint across tools."""

    target: str
    port: int
    primary_product: str
    primary_version: str
    confidence_score: float
    evidence_sources: list[ServiceEvidence]
    contradictions: list[str]
    recommended_for_cve: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "primary_product": self.primary_product,
            "primary_version": self.primary_version,
            "confidence_score": self.confidence_score,
            "evidence_sources": [item.to_dict() for item in self.evidence_sources],
            "contradictions": list(self.contradictions),
            "recommended_for_cve": self.recommended_for_cve,
        }


_PRODUCT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Apache Tomcat", re.compile(r"\b(?:Apache\s+)?Tomcat(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Apache HTTP Server", re.compile(r"\bApache(?:\s+HTTP\s+Server|\s+httpd)?(?:[/\s_-]+v?([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("nginx", re.compile(r"\bnginx(?:[/\s_-]+v?([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("OpenSSH", re.compile(r"\bOpenSSH[_/\s-]*([0-9][A-Za-z0-9._+~-]*)?", re.I)),
    ("Microsoft IIS", re.compile(r"\b(?:Microsoft[- ]?)?IIS(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Samba", re.compile(r"\bSamba(?:\s+smbd)?(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Windows Server", re.compile(r"\bWindows\s+Server(?:[/\s_-]+([0-9]{4}|[0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("vsftpd", re.compile(r"\bvsftpd(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("ProFTPD", re.compile(r"\bProFTPD(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("PostgreSQL", re.compile(r"\bPostgreSQL(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("MySQL", re.compile(r"\bMySQL(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Microsoft SQL Server", re.compile(r"\b(?:Microsoft\s+)?SQL\s+Server(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Redis", re.compile(r"\bRedis(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("Elasticsearch", re.compile(r"\bElasticsearch(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("BIND", re.compile(r"\bBIND(?:[/\s_-]+([0-9][A-Za-z0-9._+~-]*))?", re.I)),
    ("UnrealIRCd", re.compile(r"\bUnreal(?:IRCd)?[/\s_-]*([0-9][A-Za-z0-9._+~-]*)?", re.I)),
)

_ALIASES = {
    "apache": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "nginx": "nginx",
    "openssh": "OpenSSH",
    "microsoft iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "samba": "Samba",
    "samba smbd": "Samba",
    "windows server": "Windows Server",
    "microsoft windows server": "Windows Server",
    "apache tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "microsoft sql server": "Microsoft SQL Server",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "bind": "BIND",
    "unrealircd": "UnrealIRCd",
}

_TOOL_LABELS = {
    "nmap": "Nmap",
    "http_headers": "HTTP headers",
    "native_protocol": "Native protocol probe",
    "ssh_banner": "SSH banner",
    "smb_enum": "SMB enumeration",
    "tls_cert": "TLS certificate",
}

_CONFIDENCE_WEIGHT: dict[EvidenceConfidence, float] = {
    "exact": 1.0,
    "partial": 0.7,
    "hint": 0.4,
}


def _clean_version(value: Any) -> str:
    text = str(value or "").strip().strip("()[]{};,.")
    return text if re.search(r"\d", text) else ""


def _canonical_product(value: Any) -> str:
    text = re.sub(r"[_-]+", " ", str(value or "")).strip()
    key = re.sub(r"\s+", " ", text).lower()
    if key in _ALIASES:
        return _ALIASES[key]
    for alias, canonical in _ALIASES.items():
        if re.fullmatch(rf"{re.escape(alias)}(?:\s+(?:server|daemon|service|smbd))?", key):
            return canonical
    for canonical, pattern in _PRODUCT_PATTERNS:
        if pattern.search(text):
            return canonical
    return text


def _extract_known_product(text: str) -> tuple[str, str]:
    for product, pattern in _PRODUCT_PATTERNS:
        match = pattern.search(text or "")
        if match:
            version = _clean_version(match.group(1) if match.lastindex else "")
            return product, version
    return "", ""


def _json_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _nmap_service_evidence(value: dict[str, Any]) -> ServiceEvidence | None:
    if not isinstance(value, dict):
        return None
    product = _canonical_product(value.get("product"))
    version = _clean_version(value.get("version"))
    raw = str(value.get("raw_evidence") or _json_text(value))
    if not product:
        product, extracted_version = _extract_known_product(
            " ".join(
                [
                    str(value.get("service") or ""),
                    str(value.get("extra") or value.get("extrainfo") or ""),
                    _json_text(value.get("scripts") or []),
                ]
            )
        )
        version = version or extracted_version
    if not product:
        return None
    return ServiceEvidence(
        tool="nmap",
        product=product,
        version=version,
        confidence="exact" if version else "partial",
        raw_evidence=raw,
    )


def _http_service_evidence(response: str) -> ServiceEvidence | None:
    raw = str(response or "")
    if not raw.strip():
        return None
    server_values = re.findall(r"(?im)^\s*server\s*:\s*([^\r\n]+)", raw)
    # Titles and technology detections can be more specific than a generic
    # connector/server header. Search all captured HTTP evidence while keeping
    # the raw server values available for audit.
    search_text = "\n".join([raw.strip(), *server_values])
    product, version = _extract_known_product(search_text)
    if not product:
        return None
    return ServiceEvidence(
        tool="http_headers",
        product=product,
        version=version,
        confidence="exact" if version else "partial",
        raw_evidence=raw,
    )


def _additional_service_evidence(value: Any) -> list[ServiceEvidence]:
    """Convert captured, caller-supplied protocol evidence into typed facts.

    No product, version, target, or vulnerability data is invented here. Each
    item must carry a captured product or raw response from which a known
    product can be parsed.
    """
    output: list[ServiceEvidence] = []
    if not isinstance(value, list):
        return output
    for item in value:
        if not isinstance(item, dict) or item.get("error"):
            continue
        raw = str(item.get("raw_evidence") or item.get("raw") or _json_text(item))
        product = _canonical_product(item.get("product"))
        version = _clean_version(item.get("version"))
        if not product:
            product, parsed_version = _extract_known_product(raw)
            version = version or parsed_version
        if not product:
            continue
        confidence = str(item.get("confidence") or "").lower()
        if confidence not in _CONFIDENCE_WEIGHT:
            confidence = "exact" if version else "partial"
        output.append(
            ServiceEvidence(
                tool=str(item.get("tool") or "native_protocol"),
                product=product,
                version=version,
                confidence=confidence,  # type: ignore[arg-type]
                raw_evidence=raw,
            )
        )
    return output


def _ssh_service_evidence(banner: str) -> ServiceEvidence | None:
    raw = str(banner or "").strip()
    if not raw:
        return None
    product, version = _extract_known_product(raw)
    if not product:
        match = re.search(r"SSH-[0-9.]+-([^\s_-]+)[_-]?([^\s]*)", raw, re.I)
        if match:
            product = _canonical_product(match.group(1))
            version = _clean_version(match.group(2))
    if not product:
        return None
    return ServiceEvidence(
        tool="ssh_banner",
        product=product,
        version=version,
        confidence="exact" if version else "partial",
        raw_evidence=raw,
    )


def _smb_service_evidence(version_text: str) -> ServiceEvidence | None:
    raw = str(version_text or "").strip()
    if not raw:
        return None
    product, version = _extract_known_product(raw)
    if not product:
        return None
    return ServiceEvidence(
        tool="smb_enum",
        product=product,
        version=version,
        confidence="exact" if version else "hint",
        raw_evidence=raw,
    )


def _tls_service_evidence(certificate: dict[str, Any]) -> ServiceEvidence | None:
    if not isinstance(certificate, dict) or not certificate:
        return None
    # Certificate subject/issuer names do not prove the serving software. Only
    # explicit software fields supplied by the TLS collector are eligible.
    explicit = " ".join(
        str(certificate.get(key) or "")
        for key in ("product", "server", "server_software", "software")
    ).strip()
    product, version = _extract_known_product(explicit)
    if not product:
        product = _canonical_product(certificate.get("product"))
        version = _clean_version(certificate.get("version"))
    if not product:
        return None
    return ServiceEvidence(
        tool="tls_cert",
        product=product,
        version=version,
        confidence="hint",
        raw_evidence=_json_text(certificate),
    )


def _product_key(product: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _canonical_product(product).lower())


def _version_parts(version: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[0-9]+|[a-z]+", str(version or "").lower()))


def _versions_compatible(left: str, right: str) -> bool:
    if not left or not right:
        return True
    lparts = _version_parts(left)
    rparts = _version_parts(right)
    if not lparts or not rparts:
        return left.lower() == right.lower()
    shorter = min(len(lparts), len(rparts))
    return lparts[:shorter] == rparts[:shorter]


def _label(evidence: ServiceEvidence) -> str:
    return _TOOL_LABELS.get(evidence.tool, evidence.tool)


def _display(evidence: ServiceEvidence) -> str:
    return " ".join(part for part in (evidence.product, evidence.version) if part).strip()


def _contradictions(evidence: list[ServiceEvidence]) -> list[str]:
    findings: list[str] = []
    for index, left in enumerate(evidence):
        for right in evidence[index + 1 :]:
            if _product_key(left.product) != _product_key(right.product):
                findings.append(
                    f"{_label(left)} says {_display(left)}, {_label(right)} says {_display(right)}"
                )
            elif left.version and right.version and not _versions_compatible(left.version, right.version):
                findings.append(
                    f"{_label(left)} reports {left.product} {left.version}, "
                    f"{_label(right)} reports {right.product} {right.version}"
                )
    return list(dict.fromkeys(findings))


def _primary_identity(evidence: list[ServiceEvidence]) -> tuple[str, str]:
    if not evidence:
        return "", ""
    groups: dict[str, list[ServiceEvidence]] = {}
    for item in evidence:
        groups.setdefault(_product_key(item.product), []).append(item)
    tool_bonus = {
        "ssh_banner": 0.15,
        "http_headers": 0.12,
        "smb_enum": 0.1,
        "native_protocol": 0.1,
        "nmap": 0.08,
        "tls_cert": 0.0,
    }
    selected = max(
        groups.values(),
        key=lambda items: (
            sum(_CONFIDENCE_WEIGHT[item.confidence] + tool_bonus.get(item.tool, 0.0) for item in items),
            len(items),
        ),
    )
    product = max(
        selected,
        key=lambda item: (_CONFIDENCE_WEIGHT[item.confidence], tool_bonus.get(item.tool, 0.0)),
    ).product
    version_items = [item for item in selected if item.version]
    if not version_items:
        return product, ""
    version = max(
        version_items,
        key=lambda item: (
            sum(1 for peer in version_items if _versions_compatible(item.version, peer.version)),
            _CONFIDENCE_WEIGHT[item.confidence],
            len(item.version),
        ),
    ).version
    return product, version


def _score_consensus(
    evidence: list[ServiceEvidence],
    contradictions: list[str],
) -> float:
    if not evidence:
        return 0.0
    product_groups = {_product_key(item.product) for item in evidence}
    if contradictions:
        return 0.3 if len(product_groups) > 1 else 0.4

    tools = {item.tool for item in evidence}
    if len(evidence) == 1:
        item = evidence[0]
        if item.tool == "nmap":
            return 0.6
        if item.tool == "tls_cert":
            return 0.4
        return 0.7 if item.version and item.confidence == "exact" else 0.5

    versioned = [item for item in evidence if item.version]
    exact_version_consensus = any(
        left.version
        and right.version
        and _versions_compatible(left.version, right.version)
        for index, left in enumerate(versioned)
        for right in versioned[index + 1 :]
    )
    if {"http_headers", "tls_cert"}.issubset(tools) and "nmap" not in tools:
        return 0.8
    if {"nmap", "http_headers"}.issubset(tools):
        return 0.92 if exact_version_consensus else 0.85
    if exact_version_consensus:
        return 0.92
    return 0.8


def validate_service_fingerprint(
    target: str,
    port: int,
    nmap_evidence: dict[str, Any],
    http_response: str | None = None,
    ssh_banner: str | None = None,
    smb_version: str | None = None,
    tls_cert: dict[str, Any] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
) -> ServiceFingerprint:
    """Cross-validate a service identity using only captured tool evidence.

    A CVE lookup is recommended only when the score reaches 0.70 and no
    contradiction remains.

    Runtime identity values are supplied by the current scan. Examples and
    fixed targets intentionally live only in the isolated test suite.
    """
    clean_target = str(target or "").strip()
    if not clean_target:
        raise ValueError("target cannot be empty")
    try:
        clean_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer from 1 to 65535") from exc
    if not 1 <= clean_port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")

    collected: list[ServiceEvidence] = []
    candidates = (
        _nmap_service_evidence(nmap_evidence),
        _http_service_evidence(http_response or ""),
        _ssh_service_evidence(ssh_banner or ""),
        _smb_service_evidence(smb_version or ""),
        _tls_service_evidence(tls_cert or {}),
    )
    for candidate in candidates:
        if candidate is not None:
            collected.append(candidate)
    collected.extend(_additional_service_evidence(additional_evidence or []))

    contradictions = _contradictions(collected)
    product, version = _primary_identity(collected)
    score = round(_score_consensus(collected, contradictions), 2)
    recommended = score >= 0.7 and not contradictions
    return ServiceFingerprint(
        target=clean_target,
        port=clean_port,
        primary_product=product,
        primary_version=version,
        confidence_score=score,
        evidence_sources=collected,
        contradictions=contradictions,
        recommended_for_cve=recommended,
    )


__all__ = [
    "ServiceEvidence",
    "ServiceFingerprint",
    "validate_service_fingerprint",
]
