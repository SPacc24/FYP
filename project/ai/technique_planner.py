import json
import os
import re
import time
from typing import Any, Optional

import requests

from ai.llm_client import ask_llm_json


ALLOWED_MODES = {"auto", "hybrid", "manual"}

MITRE_ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cache")
MITRE_CACHE_FILE = os.path.join(CACHE_DIR, "enterprise_attack.json")
CVE_CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")

MITRE_CACHE_TTL_SECONDS = 60 * 60 * 24 * 7
CVE_CACHE_TTL_SECONDS = 60 * 60 * 24

REQUEST_TIMEOUT = 12
MAX_SELECTED_TECHNIQUES = 5


DEFAULT_AI_NEXT_STEPS = [
    "Review the mapped MITRE ATT&CK techniques and linked CVEs.",
    "Check CALDERA ability coverage for each selected technique.",
    "Run only supported techniques within the authorised lab environment.",
    "Flag unsupported techniques as manual validation or reporting items.",
]


def build_mitre_url(technique_id: str) -> str:
    """
    Converts ATT&CK technique IDs into MITRE ATT&CK URLs.
    T1046 -> https://attack.mitre.org/techniques/T1046/
    T1021.002 -> https://attack.mitre.org/techniques/T1021/002/
    """
    technique_id = str(technique_id).strip()

    if "." in technique_id:
        main_id, sub_id = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{main_id}/{sub_id}/"

    return f"https://attack.mitre.org/techniques/{technique_id}/"


def ensure_cache_dir() -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)


def read_json_file(path: str, default: Any) -> Any:
    try:
        if not os.path.exists(path):
            return default

        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return default


def write_json_file(path: str, data: Any) -> None:
    try:
        ensure_cache_dir()

        with open(path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)

    except Exception:
        pass


def cache_is_fresh(path: str, ttl_seconds: int) -> bool:
    if not os.path.exists(path):
        return False

    age = time.time() - os.path.getmtime(path)
    return age < ttl_seconds


def shorten_text(text: str, max_chars: int = 950) -> str:
    if not text:
        return ""

    cleaned = re.sub(r"\s+", " ", str(text)).strip()

    if len(cleaned) <= max_chars:
        return cleaned

    return cleaned[:max_chars].rsplit(" ", 1)[0] + "..."


def extract_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref.get("external_id")

    return None


def extract_mitre_reference_url(obj: dict, technique_id: str) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref.get("url")

    return build_mitre_url(technique_id)


def load_mitre_attack_lookup() -> dict:
    """
    Loads MITRE ATT&CK Enterprise techniques from the public ATT&CK STIX dataset.
    Cached locally so your app does not download it every scan.
    """
    if cache_is_fresh(MITRE_CACHE_FILE, MITRE_CACHE_TTL_SECONDS):
        cached = read_json_file(MITRE_CACHE_FILE, {})
        if cached:
            return cached

    lookup = {}

    try:
        response = requests.get(MITRE_ATTACK_ENTERPRISE_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        tactic_lookup = {}

        for obj in data.get("objects", []):
            if obj.get("type") != "x-mitre-tactic":
                continue

            tactic_shortname = obj.get("x_mitre_shortname")
            tactic_name = obj.get("name")

            if tactic_shortname and tactic_name:
                tactic_lookup[tactic_shortname] = tactic_name

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            technique_id = extract_external_id(obj)

            if not technique_id:
                continue

            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactics = []

            for phase in kill_chain_phases:
                phase_name = phase.get("phase_name")
                if phase_name:
                    tactics.append(tactic_lookup.get(phase_name, phase_name))

            lookup[technique_id] = {
                "id": technique_id,
                "name": obj.get("name", "MITRE ATT&CK Technique"),
                "description": shorten_text(obj.get("description", "")),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": shorten_text(obj.get("x_mitre_detection", ""), 700),
                "mitre_url": extract_mitre_reference_url(obj, technique_id),
            }

        if lookup:
            write_json_file(MITRE_CACHE_FILE, lookup)

    except Exception:
        lookup = read_json_file(MITRE_CACHE_FILE, {})

    return lookup


def get_mitre_technique_info(technique_id: str) -> dict:
    mitre_lookup = load_mitre_attack_lookup()

    if technique_id in mitre_lookup:
        return mitre_lookup[technique_id]

    return {
        "id": technique_id,
        "name": "MITRE ATT&CK Technique",
        "description": (
            "MITRE ATT&CK details could not be loaded. Review the official ATT&CK page "
            "for the full technique description."
        ),
        "tactics": [],
        "platforms": [],
        "data_sources": [],
        "detection": "",
        "mitre_url": build_mitre_url(technique_id),
    }


def load_cve_cache() -> dict:
    return read_json_file(CVE_CACHE_FILE, {})


def save_cve_cache(cache: dict) -> None:
    write_json_file(CVE_CACHE_FILE, cache)


def get_cvss_from_nvd(vulnerability: dict) -> dict:
    metrics = vulnerability.get("metrics", {})

    metric_groups = [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for group in metric_groups:
        values = metrics.get(group)

        if not values:
            continue

        first = values[0]
        cvss_data = first.get("cvssData", {})

        return {
            "version": cvss_data.get("version", ""),
            "score": cvss_data.get("baseScore", ""),
            "severity": (
                first.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or ""
            ),
            "vector": cvss_data.get("vectorString", ""),
        }

    return {
        "version": "",
        "score": "",
        "severity": "",
        "vector": "",
    }


def fetch_cve_from_nvd(cve_id: str) -> dict:
    """
    Fetches CVE details from NVD CVE API 2.0.
    Uses a simple local cache to avoid repeated API calls.
    """
    cve_id = str(cve_id).strip().upper()

    if not cve_id.startswith("CVE-"):
        return {}

    cache = load_cve_cache()
    cached = cache.get(cve_id)

    if cached:
        cached_time = cached.get("_cached_at", 0)
        if time.time() - cached_time < CVE_CACHE_TTL_SECONDS:
            return cached

    headers = {}

    # Optional: set NVD_API_KEY in your environment if you have one.
    # Without a key, it still works, just with stricter rate limits.
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_CVE_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {}

        vuln = vulnerabilities[0].get("cve", {})
        descriptions = vuln.get("descriptions", [])

        english_description = ""

        for item in descriptions:
            if item.get("lang") == "en":
                english_description = item.get("value", "")
                break

        references = []

        for ref in vuln.get("references", {}).get("referenceData", []):
            url = ref.get("url")
            source = ref.get("source", "")

            if url:
                references.append({
                    "source": source,
                    "url": url,
                })

        result = {
            "id": cve_id,
            "description": shorten_text(english_description, 650),
            "cvss": get_cvss_from_nvd(vuln),
            "published": vuln.get("published", ""),
            "last_modified": vuln.get("lastModified", ""),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "references": references[:5],
            "_cached_at": time.time(),
        }

        cache[cve_id] = result
        save_cve_cache(cache)

        return result

    except Exception:
        return cached or {}


def normalise_cve_ids(value: Any) -> list[str]:
    if not value:
        return []

    if isinstance(value, list):
        raw = " ".join(str(v) for v in value)
    else:
        raw = str(value)

    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", raw.upper())))


def extract_cves_from_mapping(mapping_result: dict) -> dict:
    """
    Builds CVE lookup from mapping_result["vulnerabilities"].

    Expected flexible input examples:
    item["cve_ids"] = ["CVE-2021-41773"]
    item["cve"] = "CVE-2021-41773"
    item["title"] contains CVE text
    """
    cve_context = {}

    vulnerabilities = mapping_result.get("vulnerabilities", [])

    for item in vulnerabilities:
        possible_sources = [
            item.get("cve_ids"),
            item.get("cve"),
            item.get("cve_id"),
            item.get("title"),
            item.get("description"),
        ]

        found_cves = []

        for source in possible_sources:
            found_cves.extend(normalise_cve_ids(source))

        for cve_id in sorted(set(found_cves)):
            if cve_id not in cve_context:
                cve_context[cve_id] = {
                    "id": cve_id,
                    "mapped_findings": [],
                    "nvd": fetch_cve_from_nvd(cve_id),
                }

            cve_context[cve_id]["mapped_findings"].append({
                "port": item.get("port"),
                "service": item.get("service"),
                "severity": item.get("severity"),
                "priority_score": item.get("priority_score"),
                "title": item.get("title"),
            })

    return cve_context


def get_cves_for_technique(technique_id: str, mapping_result: dict) -> list[str]:
    """
    Links CVEs to a technique when vulnerability mapping has both CVE data and
    recommended technique data.

    This is intentionally flexible because your mapper structure may change.
    """
    linked_cves = set()

    vulnerabilities = mapping_result.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_text = json.dumps(vuln, default=str)
        cves = normalise_cve_ids(vuln_text)

        technique_text = " ".join([
            str(vuln.get("technique_id", "")),
            str(vuln.get("technique_ids", "")),
            str(vuln.get("attack_technique", "")),
            str(vuln.get("mitre_technique", "")),
            str(vuln.get("mapped_techniques", "")),
            str(vuln.get("recommended_techniques", "")),
        ])

        if technique_id in technique_text:
            linked_cves.update(cves)

    # Fallback: if your current mapper does not store per-vuln technique IDs,
    # attach all CVEs as general context instead of losing them.
    if not linked_cves:
        for vuln in vulnerabilities:
            linked_cves.update(normalise_cve_ids(json.dumps(vuln, default=str)))

    return sorted(linked_cves)


def severity_rank(severity: str) -> int:
    ranks = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
        "unknown": 0,
        "": 0,
    }

    return ranks.get(str(severity).lower(), 0)


def extract_allowed_techniques(mapping_result: dict) -> list[dict]:
    """
    Only allow the AI to choose techniques already produced by your mapper.
    Enrich each technique with MITRE and CVE context.
    """
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
            "mapper_reason": tech.get(
                "reason",
                f"This technique appeared in {tech.get('count', 0)} mapped finding(s), "
                f"with maximum severity {max_severity}."
            ),
        })

    allowed.sort(
        key=lambda item: (
            item.get("severity_rank", 0),
            len(item.get("linked_cves", [])),
            item.get("count", 0),
        ),
        reverse=True,
    )

    return allowed


def safe_json_loads(raw: str) -> dict:
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {
            "selected_technique_ids": [],
            "reasoning": (
                "The LLM response could not be parsed. Falling back to the highest-priority "
                "mapped techniques for analyst review."
            ),
            "technique_explanations": [],
            "next_steps": DEFAULT_AI_NEXT_STEPS,
        }

    if not isinstance(parsed, dict):
        return {
            "selected_technique_ids": [],
            "reasoning": (
                "The LLM returned an unexpected JSON shape. Falling back to the "
                "highest-priority mapped techniques for analyst review."
            ),
            "technique_explanations": [],
            "next_steps": DEFAULT_AI_NEXT_STEPS,
        }

    return parsed


def clean_text_list(value: Any, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return fallback

    cleaned = []

    for item in value:
        text = shorten_text(str(item), 220)
        if text:
            cleaned.append(text)

    return cleaned or fallback


def normalise_technique_explanations(
    plan: dict,
    selected_ids: list[str],
    allowed_techniques: list[dict],
) -> list[dict]:
    explanations = plan.get("technique_explanations", [])

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
        allowed = allowed_lookup.get(technique_id, {})
        existing = explanation_lookup.get(technique_id, {})

        linked_cves = allowed.get("linked_cves", [])
        linked_cve_ids = [cve.get("id") for cve in linked_cves if cve.get("id")]

        final_explanations.append({
            "technique_id": technique_id,
            "technique_name": existing.get(
                "technique_name",
                allowed.get("name", "MITRE ATT&CK Technique"),
            ),
            "mitre_url": allowed.get("mitre_url", build_mitre_url(technique_id)),
            "mitre_tactics": allowed.get("mitre_tactics", []),
            "linked_cves": linked_cves,
            "linked_cve_ids": linked_cve_ids,
            "mitre_summary": existing.get(
                "mitre_summary",
                allowed.get(
                    "mitre_description",
                    "This technique was mapped from the detected attack surface.",
                ),
            ),
            "why_recommended": existing.get(
                "why_recommended",
                allowed.get(
                    "mapper_reason",
                    "Recommended because it matches the detected services, vulnerabilities, or attack surface.",
                ),
            ),
            "cve_relevance": existing.get(
                "cve_relevance",
                (
                    f"Linked CVEs considered: {', '.join(linked_cve_ids)}."
                    if linked_cve_ids
                    else "No direct CVE was linked to this technique by the current mapper."
                ),
            ),
            "caldera_validation": existing.get(
                "caldera_validation",
                (
                    "Check whether CALDERA has a matching ability for this technique and use it "
                    "only for safe authorised emulation."
                ),
            ),
            "limitation": existing.get(
                "limitation",
                (
                    "This recommendation does not prove exploitation. It identifies a mapped "
                    "technique that should be validated or documented."
                ),
            ),
        })

    return final_explanations


def choose_fallback_selected_ids(allowed_techniques: list[dict]) -> list[str]:
    selected = []

    for tech in allowed_techniques:
        technique_id = tech.get("id")

        if technique_id and technique_id not in selected:
            selected.append(technique_id)

        if len(selected) >= MAX_SELECTED_TECHNIQUES:
            break

    return selected


def enrich_explanations_with_coverage(
    technique_explanations: list[dict],
    coverage_info: Optional[dict] = None,
) -> list[dict]:
    """
    Enrich technique explanations with CALDERA coverage status.
    If coverage_info is provided, add coverage details to each explanation.
    If not provided (coverage checker unavailable), add a note to check manually.
    """
    if not coverage_info:
        # Coverage checker not available or not called
        for explanation in technique_explanations:
            explanation["caldera_coverage"] = {
                "supported": None,
                "ability_count": None,
                "abilities": [],
                "note": "Coverage status could not be determined. Check CALDERA manually.",
            }
        return technique_explanations

    techniques_coverage = coverage_info.get("techniques", {})

    for explanation in technique_explanations:
        technique_id = explanation.get("technique_id", "").upper()
        coverage_data = techniques_coverage.get(technique_id, {})

        explanation["caldera_coverage"] = {
            "supported": coverage_data.get("supported", False),
            "ability_count": coverage_data.get("ability_count", 0),
            "abilities": coverage_data.get("abilities", []),
            "note": (
                f"CALDERA has {coverage_data.get('ability_count', 0)} ability/ies for this technique."
                if coverage_data.get("supported")
                else "This technique has no matching abilities in CALDERA. Consider manual validation."
            ),
        }

    return technique_explanations


def generate_ai_technique_plan(
    mapping_result: dict,
    preferred_mode: str = "hybrid",
    caldera_client=None,
) -> dict:
    preferred_mode = str(preferred_mode).lower()

    if preferred_mode not in ALLOWED_MODES:
        preferred_mode = "hybrid"

    allowed_techniques = extract_allowed_techniques(mapping_result)

    safe_input = {
        "selected_mode_by_user": preferred_mode,
        "top_risks": mapping_result.get("top_risks", []),
        "severity_counts": mapping_result.get("severity_counts", {}),
        "attack_chain": mapping_result.get("attack_chain", []),
        "allowed_techniques": allowed_techniques,
    }

    prompt = f"""
You are an AI cybersecurity analyst for an authorised Final Year Project lab.

The target has already been scanned. The backend has mapped findings to candidate MITRE ATT&CK techniques.
Your job is to choose the most relevant mapped techniques for CALDERA emulation or manual validation.

Safety rules:
- Choose ONLY from allowed_techniques.
- Do NOT invent technique IDs.
- Do NOT provide exploit commands, payloads, credential attacks, malware steps, or step-by-step exploitation instructions.
- Do NOT explain how to break into a system.
- Focus on safe planning, emulation, validation, prioritisation, and reporting.
- Output valid JSON only.

User-selected technique mode:
{preferred_mode}

Mode behaviour:
- auto: choose the clearest, highest-priority techniques for automatic CALDERA planning.
- hybrid: choose useful techniques but explain that analyst review is expected before execution.
- manual: provide strong technique suggestions, but make clear that the analyst should manually choose before execution.

Selection rules:
- Select 2 to 5 techniques if enough relevant options exist.
- Prefer techniques with higher max_severity, stronger CVE linkage, repeated findings, and clearer MITRE relevance.
- Use linked_cves, CVSS severity, CVE description, MITRE description, tactics, service/port context, and mapper_reason.
- Do not select only T1046 unless it is the only relevant allowed technique.
- If SMB, Windows file-sharing, NetBIOS, or port 445 risks are present, consider both discovery and SMB-related remote service techniques.
- If RDP is present, consider RDP-related remote service validation.
- If web service vulnerabilities or public-facing software risks are present, consider public-facing application exposure.
- If domain services are present, consider domain/account discovery-related techniques.
- Be precise: explain the relationship between the detected vulnerability/service and the selected ATT&CK technique.
- Do not overclaim. If a CVE only suggests exposure but not confirmed exploitability, say so.

For each selected technique, explain:
1. MITRE meaning: what the technique represents in ATT&CK.
2. Why recommended: why it matches the scan finding, exposed service, CVE, severity, or attack surface.
3. CVE relevance: how linked CVEs influenced prioritisation. Mention CVE IDs when useful.
4. CALDERA validation: what CALDERA should safely validate at a high level.
5. Limitation: what this technique does NOT prove or what may need manual validation.

Keep explanations meaningful but concise. Avoid generic one-liners.

Input JSON:
{json.dumps(safe_input, indent=2)}

Return JSON exactly in this shape:
{{
  "selected_technique_ids": ["T1046", "T1021.002", "T1135"],
  "reasoning": "Concise overall explanation of why these techniques were prioritised for the selected mode.",
  "technique_explanations": [
    {{
      "technique_id": "T1046",
      "technique_name": "Network Service Discovery",
      "mitre_summary": "Meaning of the technique based on MITRE context.",
      "why_recommended": "Specific reason using service, port, severity, mapper context, and/or attack surface.",
      "cve_relevance": "Explain whether any linked CVEs affected prioritisation.",
      "caldera_validation": "High-level safe validation goal for CALDERA.",
      "limitation": "What the result does not prove or what needs manual review."
    }}
  ],
  "next_steps": [
    "Check CALDERA ability coverage for the selected technique IDs.",
    "Run only supported techniques inside the authorised lab.",
    "Compare CALDERA output with scan findings and linked CVEs.",
    "Document unsupported techniques as manual validation or reporting items."
  ]
}}
"""

    raw = ask_llm_json(prompt)
    plan = safe_json_loads(raw)

    allowed_ids = {
        tech["id"]
        for tech in allowed_techniques
        if tech.get("id")
    }

    raw_selected_ids = plan.get("selected_technique_ids", [])

    if not isinstance(raw_selected_ids, list):
        raw_selected_ids = []

    selected_ids = []

    for tid in raw_selected_ids:
        technique_id = str(tid).strip()

        if technique_id in allowed_ids and technique_id not in selected_ids:
            selected_ids.append(technique_id)

        if len(selected_ids) >= MAX_SELECTED_TECHNIQUES:
            break

    if not selected_ids:
        selected_ids = choose_fallback_selected_ids(allowed_techniques)

    if len(selected_ids) == 1 and len(allowed_techniques) > 1:
        selected_ids = choose_fallback_selected_ids(allowed_techniques[:3])

    technique_explanations = normalise_technique_explanations(
        plan=plan,
        selected_ids=selected_ids,
        allowed_techniques=allowed_techniques,
    )

    # Try to check CALDERA coverage if client is provided
    coverage_info = None
    if caldera_client:
        try:
            from caldera.coverage_checker import CoverageChecker
            checker = CoverageChecker(caldera_client)
            coverage_info = checker.check_technique_coverage(selected_ids)
        except Exception as e:
            import logging
            logging.warning(f"Could not check CALDERA coverage: {e}")
            coverage_info = None

    # Enrich explanations with coverage data
    technique_explanations = enrich_explanations_with_coverage(
        technique_explanations,
        coverage_info,
    )

    return {
        # Keep this internally because other routes/templates may still expect it.
        "recommended_mode": preferred_mode,

        "selected_technique_ids": selected_ids,
        "reasoning": shorten_text(plan.get(
            "reasoning",
            (
                "The selected techniques were prioritised because they match the mapped scan "
                "findings, linked CVE context, and MITRE ATT&CK relevance."
            ),
        ), 900),
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
        "raw_llm_response": raw,
        "caldera_coverage": coverage_info,
    }
