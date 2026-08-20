import json
import logging

from ai.llm_client import ask_llm_json

from ai.technique_helpers import (
    MAX_SELECTED_TECHNIQUES,
    shorten_text,
    clean_text_list,
    choose_fallback_selected_ids,
    expand_attack_path_selection,
)

from ai.technique_processing import (
    extract_allowed_techniques,
    safe_json_loads,
    normalise_technique_explanations,
    enrich_explanations_with_coverage,
)


ALLOWED_MODES = {"auto", "hybrid", "manual"}


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

    if len(allowed_techniques) == 1:
        tech = allowed_techniques[0]

        return {
            "selected_technique_ids": [tech.get("id")],
            "reasoning": (
                f"{tech.get('id')} ({tech.get('name')}) "
                "is the only ATT&CK technique supported by the scan context."
            ),
        }

    print("\n" + "=" * 60)
    print("AI PLANNER DEBUG")
    print("=" * 60)

    print("mapping_result type:", type(mapping_result))

    if isinstance(mapping_result, dict):
        print("mapping_result keys:", list(mapping_result.keys()))

    print("allowed_techniques count:", len(allowed_techniques))

    print("\nALLOWED TECHNIQUES:")
    for tech in allowed_techniques:
        print(
            "  ID:",
            tech.get("id"),
            "| NAME:",
            tech.get("name"),
            "| SEVERITY:",
            tech.get("max_severity"),
        )

    print("=" * 60 + "\n")

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
                250,
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