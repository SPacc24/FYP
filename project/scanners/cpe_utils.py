from __future__ import annotations

import re
from typing import Any, Iterable


CPE23_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


def _split_escaped(value: str, separator: str = ":") -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == separator:
            fields.append("".join(current))
            current = []
            continue
        current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _component(value: Any, default: str = "*") -> str:
    text = str(value if value is not None else default).strip().lower()
    return text if text else default


def parse_cpe(value: str) -> dict[str, str] | None:
    """Parse CPE 2.3 formatted strings and legacy CPE URI bindings.

    The parser retains all CPE 2.3 components needed to avoid treating
    different Windows editions, target platforms, or architectures as equal.
    """
    raw = str(value or "").strip()
    if raw.lower().startswith("cpe:2.3:"):
        fields = _split_escaped(raw)[2:]
        if len(fields) < 4:
            return None
        fields.extend(["*"] * (len(CPE23_FIELDS) - len(fields)))
        return {
            name: _component(fields[index])
            for index, name in enumerate(CPE23_FIELDS)
        }
    if raw.lower().startswith("cpe:/"):
        fields = _split_escaped(raw[5:])
        if len(fields) < 3:
            return None
        fields.extend(["*"] * (7 - len(fields)))
        part, vendor, product, version, update, edition, language = fields[:7]
        return {
            "part": _component(part),
            "vendor": _component(vendor),
            "product": _component(product),
            "version": _component(version),
            "update": _component(update),
            "edition": _component(edition),
            "language": _component(language),
            "sw_edition": "*",
            "target_sw": "*",
            "target_hw": "*",
            "other": "*",
        }
    return None


def format_cpe23(components: dict[str, str]) -> str:
    def escape(value: str) -> str:
        return str(value or "*").replace("\\", "\\\\").replace(":", "\\:")

    return "cpe:2.3:" + ":".join(
        escape(components.get(name, "*"))
        for name in CPE23_FIELDS
    )


def extract_cpes(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        candidates = re.findall(r"cpe:(?:2\.3:|/)[^\s,]+", value, re.I)
    else:
        candidates = [str(item or "").strip() for item in value]
    return list(dict.fromkeys(item for item in candidates if parse_cpe(item)))


def concrete(value: str) -> bool:
    return _component(value) not in {"*", "-", ""}


def normalise_product(value: str) -> str:
    return " ".join(
        token
        for token in re.split(r"[^a-z0-9]+", str(value or "").lower())
        if token
    )


def _attribute_matches(criteria: str, observed: str) -> bool:
    required = _component(criteria)
    actual = _component(observed)
    if required == "*":
        return True
    if required == "-":
        return actual == "-"
    if actual in {"*", "-", ""}:
        return False
    return required == actual


def identity_matches(
    criteria: dict[str, str],
    observed: dict[str, str],
    *,
    ignore_version: bool = True,
) -> bool:
    fields = [name for name in CPE23_FIELDS if not (ignore_version and name == "version")]
    return all(_attribute_matches(criteria.get(name, "*"), observed.get(name, "*")) for name in fields)


def _version_tokens(value: str) -> tuple[tuple[int, int | str], ...]:
    tokens: list[tuple[int, int | str]] = []
    for token in re.findall(r"\d+|[a-z]+", str(value or "").lower()):
        tokens.append((0, int(token)) if token.isdigit() else (1, token))
    return tuple(tokens)


def compare_versions(left: str, right: str) -> int | None:
    a = _version_tokens(left)
    b = _version_tokens(right)
    if not a or not b:
        return None
    length = max(len(a), len(b))
    pad = (0, 0)
    aa = a + (pad,) * (length - len(a))
    bb = b + (pad,) * (length - len(b))
    return (aa > bb) - (aa < bb)


def _range_matches(match: dict[str, Any], observed_version: str) -> tuple[bool, str]:
    bounds = (
        ("versionStartIncluding", 1, "start_including"),
        ("versionStartExcluding", 1, "start_excluding"),
        ("versionEndIncluding", -1, "end_including"),
        ("versionEndExcluding", -1, "end_excluding"),
    )
    applied: list[str] = []
    for field, direction, label in bounds:
        bound = str(match.get(field) or "").strip()
        if not bound:
            continue
        comparison = compare_versions(observed_version, bound)
        if comparison is None:
            return False, ""
        if field == "versionStartIncluding" and comparison < 0:
            return False, ""
        if field == "versionStartExcluding" and comparison <= 0:
            return False, ""
        if field == "versionEndIncluding" and comparison > 0:
            return False, ""
        if field == "versionEndExcluding" and comparison >= 0:
            return False, ""
        applied.append(f"{label}:{bound}")
    return (bool(applied), ",".join(applied))


def cpe_match_entry(
    match: dict[str, Any],
    observed: dict[str, str],
) -> tuple[bool, str]:
    criteria_raw = str(match.get("criteria") or match.get("cpe23Uri") or "")
    criteria = parse_cpe(criteria_raw)
    if not criteria or not identity_matches(criteria, observed, ignore_version=True):
        return False, ""

    observed_version = observed.get("version", "*")
    if not concrete(observed_version):
        return False, ""

    required_version = criteria.get("version", "*")
    if concrete(required_version):
        if _component(required_version) != _component(observed_version):
            return False, ""
        return True, f"exact_cpe_version:{criteria_raw}"

    in_range, range_basis = _range_matches(match, observed_version)
    has_range = any(
        str(match.get(field) or "").strip()
        for field in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    if has_range:
        return (in_range, f"cpe_version_range:{range_basis}" if in_range else "")
    return True, f"cpe_all_versions:{criteria_raw}"


def _observed_records(cpes: Iterable[str], observed_version: str = "") -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for raw in extract_cpes(cpes):
        parsed = parse_cpe(raw)
        if not parsed:
            continue
        if not concrete(parsed.get("version", "")) and concrete(observed_version):
            parsed = dict(parsed)
            parsed["version"] = _component(observed_version)
        records.append(parsed)
    return records


def evaluate_configurations(
    cve: dict[str, Any],
    primary_cpes: Iterable[str],
    *,
    context_cpes: Iterable[str] = (),
    observed_version: str = "",
) -> tuple[bool, str]:
    """Evaluate NVD configuration logic without flattening its tree.

    A vulnerable CPE must match the primary asset. Non-vulnerable CPE entries
    may be satisfied by primary or contextual platform evidence.
    """
    primary = _observed_records(primary_cpes, observed_version)
    context = primary + _observed_records(context_cpes)
    if not primary:
        return False, ""

    def evaluate_match(match: dict[str, Any]) -> tuple[bool, bool, str]:
        vulnerable = bool(match.get("vulnerable", False))
        evidence_pool = primary if vulnerable else context
        for observed in evidence_pool:
            matched, basis = cpe_match_entry(match, observed)
            if matched:
                return True, vulnerable, basis
        return False, False, ""

    def evaluate_node(node: dict[str, Any]) -> tuple[bool, bool, list[str]]:
        operands: list[tuple[bool, bool, list[str]]] = []
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict):
                continue
            satisfied, vulnerable, basis = evaluate_match(match)
            operands.append((satisfied, vulnerable, [basis] if basis else []))
        for child in node.get("nodes") or []:
            if isinstance(child, dict):
                operands.append(evaluate_node(child))
        if not operands:
            return False, False, []

        operator = str(node.get("operator") or "OR").upper()
        if operator == "AND":
            satisfied = all(item[0] for item in operands)
            selected = operands if satisfied else []
        else:
            satisfied = any(item[0] for item in operands)
            selected = [item for item in operands if item[0]]

        vulnerable = satisfied and any(item[1] for item in selected)
        bases = [basis for item in selected for basis in item[2]]
        if bool(node.get("negate", False)):
            return not satisfied, False, []
        return satisfied, vulnerable, bases

    configurations = cve.get("configurations") or []
    if isinstance(configurations, dict):
        configurations = [configurations]
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        satisfied, vulnerable, bases = evaluate_node(configuration)
        if satisfied and vulnerable:
            return True, "nvd_configuration:" + "|".join(dict.fromkeys(bases))
    return False, ""
