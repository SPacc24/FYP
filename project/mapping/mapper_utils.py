from __future__ import annotations

from typing import Any
import json
import logging

from mapping.mapper_models import CVEMatch
from mapping.mapper_knowledge import (
    KNOWN_CVE_SIGNATURES,
    MITRE_ENTERPRISE_ATTACK_FILE,
    PORT_FALLBACKS,
    SEVERITY_ORDER,
    SEVERITY_SCORE,
)


log = logging.getLogger(__name__)

_TACTIC_LOOKUP_CACHE: dict[str, list[str]] | None = None


def normalise_technique_id(technique_id: Any) -> str:
    technique_id = str(technique_id or "").strip()

    if not technique_id:
        return ""

    if not technique_id.startswith("T"):
        technique_id = f"T{technique_id}"

    return technique_id


def load_mitre_tactic_lookup() -> dict[str, list[str]]:
    if not MITRE_ENTERPRISE_ATTACK_FILE.exists():
        log.warning(
            "MITRE ATT&CK tactic file not found at %s. "
            "Technique tactics will show as 'No tactic mapped'.",
            MITRE_ENTERPRISE_ATTACK_FILE,
        )
        return {}

    try:
        with open(MITRE_ENTERPRISE_ATTACK_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as exc:
        log.warning("Could not read MITRE ATT&CK tactic file: %s", exc)
        return {}

    tactic_shortname_to_display: dict[str, str] = {}

    for obj in data.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue

        shortname = obj.get("x_mitre_shortname")
        display_name = obj.get("name")

        if shortname and display_name:
            tactic_shortname_to_display[shortname] = display_name

    technique_to_tactics: dict[str, list[str]] = {}

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = ""

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        tactics: list[str] = []

        for phase in obj.get("kill_chain_phases", []):
            shortname = phase.get("phase_name")
            tactic_name = tactic_shortname_to_display.get(shortname)

            if tactic_name and tactic_name not in tactics:
                tactics.append(tactic_name)

        technique_to_tactics[technique_id] = tactics

    return technique_to_tactics


def get_mitre_tactic_lookup() -> dict[str, list[str]]:
    global _TACTIC_LOOKUP_CACHE

    if _TACTIC_LOOKUP_CACHE is None:
        _TACTIC_LOOKUP_CACHE = load_mitre_tactic_lookup()

    return _TACTIC_LOOKUP_CACHE


def attach_tactics(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lookup = get_mitre_tactic_lookup()
    fixed: list[dict[str, Any]] = []

    for technique in techniques or []:
        enriched = dict(technique)

        technique_id = normalise_technique_id(
            enriched.get("id") or enriched.get("technique_id")
        )

        enriched["id"] = technique_id

        tactics = lookup.get(technique_id, [])

        enriched["tactics"] = tactics
        enriched["tactic"] = ", ".join(tactics) if tactics else "No tactic mapped"

        fixed.append(enriched)

    return fixed


def normalise(value: Any) -> str:
    return str(value or "").lower().strip()


def normalise_service(item: dict[str, Any]) -> str:
    service = normalise(item.get("service"))

    if service in {"", "unknown"}:
        service = PORT_FALLBACKS.get(str(item.get("port", "")), "unknown")

    return service


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def build_evidence(host: str, item: dict[str, Any]) -> str:
    product = item.get("product") or "unknown product"
    version = item.get("version") or "unknown version"
    cpes = ", ".join(item.get("cpe", [])) or "no CPE reported"

    return (
        f"{host}:{item.get('port')}/{item.get('protocol')} "
        f"state={item.get('state')} service={item.get('service')} "
        f"product={product} version={version} cpe={cpes}"
    )


def match_known_cves(item: dict[str, Any], service: str) -> list[CVEMatch]:
    product = normalise(item.get("product"))
    version = normalise(item.get("version"))
    cpes = [normalise(cpe) for cpe in item.get("cpe", [])]

    matches: list[CVEMatch] = []

    for sig in KNOWN_CVE_SIGNATURES:
        matched = False

        if sig["match_type"] == "cpe_contains":
            for pattern in sig.get("patterns", []):
                if any(normalise(pattern) in cpe for cpe in cpes):
                    matched = True
                    break

        elif sig["match_type"] == "product_version_contains":
            product_pattern = normalise(sig.get("product"))
            version_patterns = [normalise(p) for p in sig.get("version_patterns", [])]

            if product_pattern in product and any(p in version for p in version_patterns):
                matched = True

            if service in {"microsoft-ds", "netbios-ssn"} and "samba" in product:
                if any(p in version for p in version_patterns):
                    matched = True

        if matched:
            matches.append(
                CVEMatch(
                    cve_id=sig["cve_id"],
                    title=sig["title"],
                    severity=sig["severity"],
                    reason=sig["reason"],
                    remediation=sig["remediation"],
                )
            )

    return matches


def priority_score(severity: str, service: str, cve_matches: list[CVEMatch]) -> int:
    score = SEVERITY_SCORE.get(severity, 0)

    if cve_matches:
        score += 2

    if service in {
        "telnet",
        "ftp",
        "microsoft-ds",
        "netbios-ssn",
        "exec",
        "login",
        "mysql",
        "ms-wbt-server",
    }:
        score += 1

    return min(score, 10)


def build_title(base_title: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_title

    return f"{base_title} ({', '.join(c.cve_id for c in cves)})"


def build_cve_hint(base_hint: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_hint

    cve_lines = [f"{c.cve_id}: {c.title} — {c.reason}" for c in cves]
    return "Known match: " + " | ".join(cve_lines)


def build_recommendation(base_recommendation: str, cves: list[CVEMatch]) -> str:
    if not cves:
        return base_recommendation

    specific = " ".join(c.remediation for c in cves)
    return f"{specific} General hardening: {base_recommendation}"


def host_os_text(host: dict[str, Any], parsed_results: dict[str, Any]) -> str:
    host_os = host.get("os", {})

    if isinstance(host_os, dict):
        os_name = host_os.get("name", "")
    else:
        os_name = str(host_os or "")

    return " ".join([os_name, str(parsed_results.get("os", ""))]).lower()


def is_windows_os(os_text: str) -> bool:
    return "windows" in os_text or "microsoft" in os_text


def is_legacy_windows_10(os_text: str) -> bool:
    legacy_tokens = [
        "1507",
        "1511",
        "1607",
        "build 10240",
        "build 10586",
        "build 14393",
    ]

    return "windows 10" in os_text and any(token in os_text for token in legacy_tokens)


def service_fingerprint_text(item: dict[str, Any], os_text: str) -> str:
    return " ".join([
        os_text,
        str(item.get("service", "")),
        str(item.get("product", "")),
        str(item.get("version", "")),
        str(item.get("extrainfo", "")),
        str(item.get("cpe", "")),
    ]).lower()


def is_legacy_windows_smb_candidate(
    item: dict[str, Any],
    service: str,
    os_text: str,
) -> bool:
    text = service_fingerprint_text(item, os_text)

    is_smb = (
        service in {"microsoft-ds", "netbios-ssn"}
        or "smb" in text
        or "microsoft-ds" in text
    )

    legacy_windows_tokens = [
        "windows 10 enterprise 10240",
        "windows 10 10240",
        "build 10240",
        "windows 10 1507",
        "windows 10 enterprise",
    ]

    return is_smb and any(token in text for token in legacy_windows_tokens)


def technique_reason(
    technique: dict[str, Any],
    service: str,
    item: dict[str, Any],
    os_text: str,
) -> str:
    technique_id = technique.get("id")
    port = item.get("port")

    if technique_id == "T1210":
        if is_legacy_windows_10(os_text):
            return (
                "SMB/NetBIOS exposure on a legacy Windows 10 build should be validated in the lab "
                "with safe exploitability checks, not destructive payloads."
            )

        return (
            "SMB/remote-service exposure is a candidate for controlled exploitability validation "
            "inside the authorised cyber range."
        )

    if technique_id == "T1021.002":
        return "SMB/admin-share behaviour can emulate post-access lateral movement once authorised access is present."

    if technique_id == "T1135":
        return "Open SMB/NetBIOS services support safe network share discovery validation."

    if technique_id == "T1046":
        return f"Port {port}/{service} exposure supports service discovery validation before deeper emulation."

    return "Recommended by mapped service exposure, vulnerability context, and lab-safe ATT&CK planning."


def apply_attack_path_context(
    techniques: list[dict[str, str]],
    service: str,
    item: dict[str, Any],
    os_text: str,
) -> list[dict[str, str]]:
    staged: list[dict[str, str]] = []
    seen: set[str] = set()

    for technique in techniques:
        technique_id = technique.get("id")

        if not technique_id or technique_id in seen:
            continue

        enriched = dict(technique)
        enriched.setdefault("attack_path_stage", "Validation / Discovery")
        enriched["reason"] = technique_reason(enriched, service, item, os_text)

        staged.append(enriched)
        seen.add(technique_id)

    if service in {"microsoft-ds", "netbios-ssn"} and is_windows_os(os_text) and "T1059" not in seen:
        staged.append({
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "attack_path_stage": "Optional Post-access Emulation",
            "reason": (
                "Windows SMB exposure may support optional PowerShell or command-shell emulation "
                "after access is explicitly authorised and established."
            ),
        })

    return attach_tactics(staged)