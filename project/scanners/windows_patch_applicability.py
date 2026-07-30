from __future__ import annotations

"""Conservative Windows patch/remediation evidence correlation.

No CVE identifiers, products, KBs, or target builds are hardcoded.  Missing KBs
alone never prove vulnerability because modern Windows updates are cumulative.
"""

import re
from typing import Any, Callable, Iterable


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _build_tuple(value: Any) -> tuple[int, ...]:
    text = str(value or "").strip()
    if not text:
        return tuple()
    numbers = re.findall(r"\d+", text)
    return tuple(int(x) for x in numbers[:4])


def _observed_build(inventory: dict[str, Any]) -> tuple[int, ...]:
    version = _build_tuple(inventory.get("version"))
    build = _build_tuple(inventory.get("build"))
    ubr = _build_tuple(inventory.get("ubr"))
    if len(version) >= 4:
        return version
    # Win32_OperatingSystem normally reports major.minor.build while the UBR
    # revision is a separate registry value.  Combine only directly observed
    # components; never infer a revision from a KB identifier.
    if len(version) == 3 and ubr:
        return version + (ubr[0],)
    if version:
        return version
    if build:
        # A build-only observation can be compared only with remediation data
        # at the same precision.  Preserve UBR when directly observed, but do
        # not fabricate major/minor values.
        if len(build) == 1 and ubr:
            return (build[0], ubr[0])
        return build
    return ()


def _fixed_build(value: Any) -> tuple[int, ...]:
    return _build_tuple(value)


def _generation_tokens(text: str) -> set[str]:
    normal = _norm(text)
    tokens: set[str] = set()
    for match in re.finditer(r"\bwindows\s+(10|11)\b", normal):
        tokens.add(f"windows {match.group(1)}")
    for match in re.finditer(r"\bserver\s+(20\d{2})\b", normal):
        tokens.add(f"server {match.group(1)}")
    return tokens


def microsoft_product_matches(observed_product: str, vendor_product: str) -> bool:
    observed = _norm(observed_product)
    vendor = _norm(vendor_product)
    if not observed or not vendor or "windows" not in observed or "windows" not in vendor:
        return False
    observed_generations = _generation_tokens(observed)
    vendor_generations = _generation_tokens(vendor)
    if observed_generations and vendor_generations and observed_generations.isdisjoint(vendor_generations):
        return False
    # Require at least a shared explicit generation when either side supplies
    # one; this avoids treating every Microsoft Windows SKU as equivalent.
    if observed_generations or vendor_generations:
        return bool(observed_generations & vendor_generations)
    observed_tokens = {x for x in observed.split() if x not in {"microsoft", "standard", "datacenter", "enterprise", "professional", "pro", "edition"}}
    vendor_tokens = {x for x in vendor.split() if x not in {"microsoft", "standard", "datacenter", "enterprise", "professional", "pro", "edition"}}
    common = observed_tokens & vendor_tokens
    return "windows" in common and len(common) >= 2


def _compare_builds(observed: tuple[int, ...], fixed: tuple[int, ...]) -> int | None:
    """Return -1/0/1 only when the comparison has enough precision."""
    if not observed or not fixed:
        return None
    # A one-component observed build can be compared to a one-component fixed
    # build, but not to a fixed build carrying a revision/UBR.
    if len(observed) < len(fixed):
        return None
    width = min(len(observed), len(fixed))
    left, right = observed[:width], fixed[:width]
    if left < right:
        return -1
    if left > right:
        return 1
    return 0 if len(observed) >= len(fixed) else None


def assess_windows_cve_patch(
    cve_row: dict[str, Any],
    inventory: dict[str, Any],
    remediations: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    cve_id = str(cve_row.get("cve_id") or "").upper()
    host = str(cve_row.get("host") or inventory.get("host") or "")
    observed_product = str(inventory.get("product") or cve_row.get("product") or "")
    installed = {str(x).upper() for x in inventory.get("installed_kbs") or [] if str(x).strip()}
    observed_build = _observed_build(inventory)

    applicable = [dict(row) for row in remediations if microsoft_product_matches(observed_product, str(row.get("product") or ""))]
    vendor_kbs = sorted({str(kb).upper() for row in applicable for kb in (row.get("kb_candidates") or ([row.get("kb")] if row.get("kb") else [])) if str(kb).strip()})
    fixed_builds = sorted({str(row.get("fixed_build") or "").strip() for row in applicable if str(row.get("fixed_build") or "").strip()})

    result = {
        "host": host,
        "cve_id": cve_id,
        "observed_product": observed_product,
        "observed_version": str(inventory.get("version") or ""),
        "observed_build": str(inventory.get("build") or ""),
        "observed_ubr": str(inventory.get("ubr") or ""),
        "installed_kbs": sorted(installed),
        "vendor_kbs": vendor_kbs,
        "vendor_fixed_builds": fixed_builds,
        "matching_msrc_products": sorted({str(row.get("product") or "") for row in applicable if str(row.get("product") or "")}),
        "msrc_remediations": applicable,
        "source": "Microsoft Security Response Center Security Update Guide / CVRF API",
        "match_scope": "host_os",
    }

    if not inventory.get("ok"):
        return {**result, "patch_state": "Insufficient patch evidence", "patch_basis": "Operator-exported Windows patch inventory was not available."}
    if not applicable:
        return {**result, "patch_state": "Insufficient patch evidence", "patch_basis": "No Microsoft remediation record matched the observed Windows product identity."}

    direct = sorted(installed & set(vendor_kbs))
    if direct:
        return {**result, "patch_state": "Remediation observed", "patch_basis": "A Microsoft remediation KB for this CVE is present in authenticated patch inventory.", "observed_remediation_kbs": direct}

    comparisons: list[tuple[str, int]] = []
    for fixed_text in fixed_builds:
        comparison = _compare_builds(observed_build, _fixed_build(fixed_text))
        if comparison is not None:
            comparisons.append((fixed_text, comparison))
    if comparisons and any(value >= 0 for _fixed, value in comparisons):
        satisfied = [fixed for fixed, value in comparisons if value >= 0]
        return {**result, "patch_state": "Remediation observed", "patch_basis": "The directly observed Windows build/revision is at or newer than a Microsoft fixed build for the matched product.", "satisfied_fixed_builds": satisfied}
    if comparisons and all(value < 0 for _fixed, value in comparisons):
        return {**result, "patch_state": "Applicable update not observed", "patch_basis": "The directly observed Windows build/revision predates all comparable Microsoft fixed builds for the matched product; no matching remediation KB was observed."}

    return {
        **result,
        "patch_state": "Insufficient patch evidence",
        "patch_basis": "No matching remediation KB was observed, but build/revision precision is insufficient to treat a missing KB as proof that the CVE remains unremediated.",
    }


def enrich_windows_patch_states(
    cve_rows: list[dict[str, Any]],
    inventories: Iterable[dict[str, Any]],
    lookup: Callable[[str], tuple[list[dict[str, Any]], dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    inventory_by_host = {str(row.get("host") or ""): row for row in inventories if str(row.get("host") or "")}
    assessments: list[dict[str, Any]] = []
    lookup_cache: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {}
    for row in cve_rows:
        if str(row.get("match_scope") or "") != "host_os":
            continue
        vendor = _norm(row.get("os_vendor") or row.get("product"))
        family = _norm(row.get("os_family") or row.get("product"))
        if "microsoft" not in vendor and "windows" not in family:
            continue
        host = str(row.get("host") or "")
        inventory = inventory_by_host.get(host)
        if not inventory:
            row["patch_state"] = "Insufficient patch evidence"
            row["patch_evidence"] = {"patch_basis": "No operator-exported Windows patch inventory was available for this host."}
            continue
        cve_id = str(row.get("cve_id") or "").upper()
        if cve_id not in lookup_cache:
            lookup_cache[cve_id] = lookup(cve_id)
        remediations, diagnostic = lookup_cache[cve_id]
        assessment = assess_windows_cve_patch(row, inventory, remediations)
        assessment["msrc_lookup_diagnostic"] = diagnostic
        assessments.append(assessment)
        row["patch_state"] = assessment.get("patch_state")
        row["patch_evidence"] = assessment
        row["patch_source"] = assessment.get("source")
    return assessments, [diag for _rows, diag in lookup_cache.values()]
