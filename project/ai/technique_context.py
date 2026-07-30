from ai.technique_helpers import ATTACK_PATH_PRIORITY, severity_rank
from ai.technique_intel import (
    get_mitre_technique_info,
    build_mitre_url,
    extract_cves_from_mapping,
    get_cves_for_technique,
)


def extract_allowed_techniques(mapping_result: dict) -> list[dict]:
    allowed = []
    cve_context = extract_cves_from_mapping(mapping_result)

    for tech in mapping_result.get("recommended_techniques", []):
        technique_id = tech.get("id") or tech.get("technique_id")

        if not technique_id:
            continue

        technique_id = str(technique_id).strip()
        mitre_info = get_mitre_technique_info(technique_id)

        linked_cve_ids = get_cves_for_technique(technique_id, mapping_result)
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
            "mitre_url": mitre_info.get("mitre_url", build_mitre_url(technique_id)),
            "mitre_description": mitre_info.get("description", ""),
            "mitre_tactics": mitre_info.get("tactics", []),
            "mitre_platforms": mitre_info.get("platforms", []),
            "mitre_data_sources": mitre_info.get("data_sources", [])[:8],
            "mitre_detection": mitre_info.get("detection", ""),
            "linked_cves": linked_cves,
            "linked_cve_ids": linked_cve_ids,
            "cve_ids": linked_cve_ids,
            "attack_path_stage": tech.get("attack_path_stage", "Validation / Discovery"),
            "supporting_services": tech.get("supporting_services", []),
            "mapper_reason": tech.get(
                "reason",
                " ".join(tech.get("reasons", [])[:2]) or
                f"This technique appeared in {tech.get('count', 0)} mapped finding(s), "
                f"with maximum severity {max_severity}."
            ),
        })

    allowed.sort(
        key=lambda item: (
            ATTACK_PATH_PRIORITY.get(item.get("id"), 999),
            -item.get("severity_rank", 0),
            -len(item.get("linked_cves", [])),
            -item.get("count", 0),
        ),
    )

    return allowed