import json
from typing import Optional

from ai.technique_intel import (
    build_mitre_url,
    extract_cves_from_mapping,
    get_cves_for_technique,
    get_mitre_technique_info,
)

from ai.technique_helpers import (
    ATTACK_PATH_PRIORITY,
    severity_rank,
    shorten_text,
)


DEFAULT_AI_NEXT_STEPS = [
    "Review the mapped MITRE ATT&CK techniques and linked CVEs.",
    "Check CALDERA ability coverage for each selected technique.",
    "Run only supported techniques within the authorised lab environment.",
    "Flag unsupported techniques as manual validation or reporting items.",
]


def extract_allowed_techniques(mapping_result: dict) -> list[dict]:
    allowed = []
    cve_context = extract_cves_from_mapping(mapping_result)

    for tech in mapping_result.get("recommended_techniques", []):
        technique_id = tech.get("id") or tech.get("technique_id")

        if not technique_id:
            continue

        technique_id = str(technique_id).strip()
        mitre_info = get_mitre_technique_info(technique_id)

        linked_cve_ids = get_cves_for_technique(
            technique_id,
            mapping_result,
        )

        linked_cves = []

        for cve_id in linked_cve_ids:
            if cve_id in cve_context:
                linked_cves.append(cve_context[cve_id])

        max_severity = tech.get("max_severity", "Info")

        allowed.append({
            "id": technique_id,
            "name": (
                tech.get("name")
                or tech.get("technique_name")
                or mitre_info.get("name")
                or "MITRE ATT&CK Technique"
            ),
            "count": tech.get("count", 0),
            "max_severity": max_severity,
            "severity_rank": severity_rank(max_severity),
            "mitre_url": mitre_info.get(
                "mitre_url",
                build_mitre_url(technique_id),
            ),
            "mitre_description": mitre_info.get("description", ""),
            "mitre_tactics": mitre_info.get("tactics", []),
            "mitre_platforms": mitre_info.get("platforms", []),
            "mitre_data_sources": mitre_info.get(
                "data_sources",
                [],
            )[:8],
            "mitre_detection": mitre_info.get(
                "detection",
                "",
            ),
            "linked_cves": linked_cves,
            "linked_cve_ids": linked_cve_ids,
            "cve_ids": linked_cve_ids,
            "attack_path_stage": tech.get(
                "attack_path_stage",
                "Validation / Discovery",
            ),
            "supporting_services": tech.get(
                "supporting_services",
                [],
            ),
            "mapper_reason": tech.get(
                "reason",
                " ".join(tech.get("reasons", [])[:2])
                or (
                    f"This technique appeared in "
                    f"{tech.get('count', 0)} mapped finding(s), "
                    f"with maximum severity {max_severity}."
                ),
            ),
        })

    allowed.sort(
        key=lambda item: (
            ATTACK_PATH_PRIORITY.get(
                item.get("id"),
                999,
            ),
            -item.get("severity_rank", 0),
            -len(item.get("linked_cves", [])),
            -item.get("count", 0),
        ),
    )

    return allowed


def safe_json_loads(value) -> dict:
    if isinstance(value, dict):
        return value

    if not isinstance(value, str):
        return {
            "selected_technique_ids": [],
            "reasoning": (
                "The LLM response could not be parsed because "
                "it had an unexpected JSON shape."
            ),
            "technique_explanations": [],
            "next_steps": DEFAULT_AI_NEXT_STEPS,
        }

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {
            "selected_technique_ids": [],
            "reasoning": (
                "The LLM response could not be parsed "
                "as valid JSON."
            ),
            "technique_explanations": [],
            "next_steps": DEFAULT_AI_NEXT_STEPS,
        }

    if isinstance(parsed, dict):
        return parsed

    return {
        "selected_technique_ids": [],
        "reasoning": (
            "The LLM response could not be parsed because "
            "it had an unexpected JSON shape."
        ),
        "technique_explanations": [],
        "next_steps": DEFAULT_AI_NEXT_STEPS,
    }


def normalise_technique_explanations(
    plan: dict,
    selected_ids: list[str],
    allowed_techniques: list[dict],
) -> list[dict]:

    explanations = plan.get(
        "technique_explanations",
        [],
    )

    if not isinstance(explanations, list):
        explanations = []

    allowed_lookup = {
        tech["id"]: tech
        for tech in allowed_techniques
        if tech.get("id")
    }

    explanation_lookup = {}

    for item in explanations:
        if not isinstance(item, dict):
            continue

        technique_id = item.get("technique_id")

        if technique_id:
            explanation_lookup[technique_id] = item

    final_explanations = []

    for technique_id in selected_ids:
        allowed = allowed_lookup.get(
            technique_id,
            {},
        )

        existing = explanation_lookup.get(
            technique_id,
            {},
        )

        linked_cves = allowed.get(
            "linked_cves",
            [],
        )

        linked_cve_ids = [
            cve.get("id")
            for cve in linked_cves
            if cve.get("id")
        ]

        mitre_description = allowed.get(
            "mitre_description",
            "This technique was mapped from the detected attack surface.",
        )

        final_explanations.append({
            "technique_id": technique_id,

            "technique_name": existing.get(
                "technique_name",
                allowed.get(
                    "name",
                    "MITRE ATT&CK Technique",
                ),
            ),

            "mitre_url": allowed.get(
                "mitre_url",
                build_mitre_url(technique_id),
            ),

            "mitre_tactics": allowed.get(
                "mitre_tactics",
                [],
            ),

            "attack_path_stage": allowed.get(
                "attack_path_stage",
                "Validation / Discovery",
            ),

            "linked_cves": linked_cves,

            "linked_cve_ids": linked_cve_ids,

            "cve_ids": linked_cve_ids,

            "mitre_summary": shorten_text(
                mitre_description,
                180,
            ),

            "mitre_full_description": mitre_description,

            "why_recommended": shorten_text(
                existing.get("why_recommended")
                or allowed.get(
                    "mapper_reason",
                    (
                        "Recommended because it matches "
                        "the detected services, vulnerabilities, "
                        "or attack surface."
                    ),
                ),
                120,
            ),

            "caldera_validation": shorten_text(
                existing.get("caldera_validation")
                or (
                    "Check whether CALDERA has a matching "
                    "ability for this technique and use it "
                    "only for safe authorised emulation."
                ),
                180,
            ),
        })

    return final_explanations


def enrich_explanations_with_coverage(
    technique_explanations: list[dict],
    coverage_info: Optional[dict] = None,
) -> list[dict]:

    if not coverage_info:
        for explanation in technique_explanations:
            explanation["caldera_coverage"] = {
                "supported": None,
                "ability_count": None,
                "abilities": [],
                "note": (
                    "Coverage status could not be determined. "
                    "Check CALDERA manually."
                ),
            }

        return technique_explanations

    techniques_coverage = coverage_info.get(
        "techniques",
        {},
    )

    for explanation in technique_explanations:
        technique_id = explanation.get(
            "technique_id",
            "",
        ).upper()

        coverage_data = techniques_coverage.get(
            technique_id,
            {},
        )

        explanation["caldera_coverage"] = {
            "supported": coverage_data.get(
                "supported",
                False,
            ),
            "ability_count": coverage_data.get(
                "ability_count",
                0,
            ),
            "abilities": coverage_data.get(
                "abilities",
                [],
            ),
            "note": (
                f"CALDERA has "
                f"{coverage_data.get('ability_count', 0)} "
                f"ability/ies for this technique."
                if coverage_data.get("supported")
                else (
                    "This technique has no matching abilities "
                    "in CALDERA. Consider manual validation."
                )
            ),
        }

    return technique_explanations