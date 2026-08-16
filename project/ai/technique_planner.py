import json
import logging
from typing import Optional

from ai.llm_client import ask_llm_json
from ai.technique_intel import (
    build_mitre_url,
    extract_cves_from_mapping,
    get_cves_for_technique,
    get_mitre_technique_info,
)
from ai.technique_helpers import (
    ATTACK_PATH_PRIORITY,
    MAX_SELECTED_TECHNIQUES,
    severity_rank,
    shorten_text,
    clean_text_list,
    choose_fallback_selected_ids,
    expand_attack_path_selection,
)


ALLOWED_MODES = {"auto", "hybrid", "manual"}

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


def generate_ai_technique_plan(
    mapping_result: dict,
    preferred_mode: str = "hybrid",
    caldera_client=None,
) -> dict:

    preferred_mode = str(
        preferred_mode
    ).lower()

    if preferred_mode not in ALLOWED_MODES:
        preferred_mode = "hybrid"

    allowed_techniques = extract_allowed_techniques(
        mapping_result
    )

    llm_techniques = []

    for tech in allowed_techniques[:8]:
        llm_techniques.append({
            "id": tech.get("id"),
            "name": tech.get("name"),
            "max_severity": tech.get("max_severity"),
            "count": tech.get("count"),
            "mitre_tactics": tech.get(
                "mitre_tactics",
                [],
            ),
            "linked_cve_ids": tech.get(
                "linked_cve_ids",
                [],
            ),
            "supporting_services": tech.get(
                "supporting_services",
                [],
            ),
            "attack_path_stage": tech.get(
                "attack_path_stage"
            ),
            "mapper_reason": shorten_text(
                tech.get(
                    "mapper_reason",
                    "",
                ),
                250,
            ),
            "mitre_description": shorten_text(
                tech.get(
                    "mitre_description",
                    "",
                ),
                300,
            ),
        })

    safe_input = {
        "selected_mode_by_user": preferred_mode,
        "top_risks": mapping_result.get(
            "top_risks",
            [],
        )[:5],
        "severity_counts": mapping_result.get(
            "severity_counts",
            {},
        ),
        "attack_chain": mapping_result.get(
            "attack_chain",
            [],
        )[:5],
        "allowed_techniques": llm_techniques,
    }

    prompt = f"""
You are an AI MITRE ATT&CK technique planner for an authorised cybersecurity lab.

Task:
Select the best mapped MITRE ATT&CK techniques for safe CALDERA validation or manual security review.

Mode:
{preferred_mode}

Rules:
- Choose ONLY IDs from allowed_techniques.
- Do not frame the answer as mitigation. Frame it as authorised validation, emulation, prioritisation, and reporting.
- Select 2 to 5 techniques if possible.
- Do NOT invent technique IDs, CVEs, services, or ports.
- Do NOT provide exploit commands, payloads, intrusion steps, or credential theft guidance.
- Prioritise by severity, linked CVEs, exposed services/ports, repeated findings, and mapper_reason.
- Use the actual scan context. Do NOT copy placeholder text.
- Keep reasoning concise and report-ready.

Mode behaviour:
- auto: choose highest-confidence techniques for automatic planning.
- hybrid: recommend strong techniques but mention analyst review.
- manual: suggest techniques but leave final choice to analyst.

Input:
{json.dumps(safe_input, indent=2)}

Return ONLY valid JSON with this structure:
{{
  "selected_technique_ids": [],
  "reasoning": "",
  "technique_explanations": [
    {{
      "technique_id": "",
      "technique_name": "",
      "why_recommended": "",
      "caldera_validation": ""
    }}
  ],
  "next_steps": []
}}

Field requirements:
- reasoning: 2 to 4 sentences explaining why the selected techniques fit the scan and mode.
- why_recommended: specific link to detected service, port, CVE, severity, or mapper_reason.
- caldera_validation: high-level safe validation goal only.
- next_steps: 3 to 4 safe follow-up actions.
"""

    plan = safe_json_loads(
        ask_llm_json(prompt)
    )

    llm_available = plan.get(
        "llm_available",
        True,
    )

    if not llm_available:
        plan["reasoning"] = (
            f"AutoPenTest could not receive a live Ollama response, "
            f"so the selected {preferred_mode.upper()} mode was applied "
            f"using the mapped MITRE ATT&CK techniques from the scan "
            f"results. The final recommendations were prioritised using "
            f"service exposure, linked CVEs, severity, and mapper relevance."
        )

        plan["next_steps"] = [
            "Confirm Ollama is running before requesting a fully LLM-generated recommendation.",
            "Review the mapped MITRE ATT&CK techniques and linked CVEs.",
            "Check CALDERA ability coverage for each selected technique.",
            "Run only supported techniques within the authorised lab environment.",
            "Document unsupported techniques as manual validation or reporting items.",
        ]

    allowed_ids = {
        tech["id"]
        for tech in allowed_techniques
        if tech.get("id")
    }

    raw_selected_ids = plan.get(
        "selected_technique_ids",
        [],
    )

    if not isinstance(
        raw_selected_ids,
        list,
    ):
        raw_selected_ids = []

    selected_ids = []

    for tid in raw_selected_ids:
        technique_id = str(tid).strip()

        if (
            technique_id in allowed_ids
            and technique_id not in selected_ids
        ):
            selected_ids.append(
                technique_id
            )

        if (
            len(selected_ids)
            >= MAX_SELECTED_TECHNIQUES
        ):
            break

    if not selected_ids:
        selected_ids = choose_fallback_selected_ids(
            allowed_techniques
        )

    if (
        len(selected_ids) == 1
        and len(allowed_techniques) > 1
    ):
        selected_ids = choose_fallback_selected_ids(
            allowed_techniques[:3]
        )

    selected_ids = expand_attack_path_selection(
        selected_ids,
        allowed_techniques,
    )

    technique_explanations = (
        normalise_technique_explanations(
            plan=plan,
            selected_ids=selected_ids,
            allowed_techniques=allowed_techniques,
        )
    )

    coverage_info = None

    if caldera_client:
        try:
            from caldera.coverage_checker import (
                CoverageChecker,
            )

            checker = CoverageChecker(
                caldera_client
            )

            coverage_info = (
                checker.check_technique_coverage(
                    selected_ids
                )
            )

        except Exception as e:
            logging.warning(
                f"Could not check CALDERA coverage: {e}"
            )

            coverage_info = None

    technique_explanations = (
        enrich_explanations_with_coverage(
            technique_explanations,
            coverage_info,
        )
    )

    return {
        "recommended_mode": preferred_mode,

        "selected_technique_ids": selected_ids,

        "reasoning": shorten_text(
            plan.get(
                "reasoning",
                (
                    "The selected techniques were prioritised "
                    "because they match the mapped scan findings, "
                    "linked CVE context, and MITRE ATT&CK relevance."
                ),
            ),
            900,
        ),

        "technique_explanations": technique_explanations,

        "next_steps": clean_text_list(
            plan.get("next_steps"),
            [
                "Check CALDERA ability coverage for the selected technique IDs.",
                "Run only supported techniques inside the authorised lab.",
                "Compare CALDERA output with scan findings and linked CVEs.",
                "Document unsupported techniques as manual validation or reporting items.",
            ],
        ),

        "allowed_techniques": allowed_techniques,

        "caldera_coverage": coverage_info,
    }