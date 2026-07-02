import json
import os
import re
import time
from typing import Any

import requests

from ai.technique_helpers import (
    cache_is_fresh,
    read_json_file,
    write_json_file,
    shorten_text,
)


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

REQUEST_TIMEOUT = 120


# ---------------------------------------------------
# MITRE ATT&CK HELPERS
# ---------------------------------------------------

def build_mitre_url(technique_id: str) -> str:
    technique_id = str(technique_id).strip()

    if "." in technique_id:
        main_id, sub_id = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{main_id}/{sub_id}/"

    return f"https://attack.mitre.org/techniques/{technique_id}/"


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

            tactics = []

            for phase in obj.get("kill_chain_phases", []):
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
            write_json_file(MITRE_CACHE_FILE, lookup, CACHE_DIR)

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


# ---------------------------------------------------
# CVE / NVD HELPERS
# ---------------------------------------------------

def load_cve_cache() -> dict:
    return read_json_file(CVE_CACHE_FILE, {})


def save_cve_cache(cache: dict) -> None:
    write_json_file(CVE_CACHE_FILE, cache, CACHE_DIR)


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

        technique_ids = []

        for field in [
            item.get("technique_id"),
            item.get("technique_ids"),
            item.get("attack_technique"),
            item.get("mitre_technique"),
            item.get("mapped_techniques"),
            item.get("recommended_techniques"),
        ]:
            if isinstance(field, list):
                technique_ids.extend([str(x) for x in field])
            elif field:
                technique_ids.append(str(field))

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
                "description": item.get("description"),
                "technique_ids": technique_ids,
            })

    return cve_context


def get_cves_for_technique(technique_id: str, mapping_result: dict) -> list[str]:
    linked_cves = set()
    has_per_finding_technique_context = False

    vulnerabilities = mapping_result.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_text = json.dumps(vuln, default=str)
        cves = normalise_cve_ids(vuln_text)

        technique_text = " ".join([
            str(vuln.get("technique_id", "")),
            str(vuln.get("technique_ids", "")),
            str(vuln.get("attack_technique", "")),
            str(vuln.get("attack_techniques", "")),
            str(vuln.get("mitre_technique", "")),
            str(vuln.get("mapped_techniques", "")),
            str(vuln.get("recommended_techniques", "")),
        ])

        if technique_text.strip():
            has_per_finding_technique_context = True

        if technique_id in technique_text:
            linked_cves.update(cves)

    if not linked_cves and not has_per_finding_technique_context:
        for vuln in vulnerabilities:
            linked_cves.update(normalise_cve_ids(json.dumps(vuln, default=str)))

    return sorted(linked_cves)