import json
import os
import re
import time
from typing import Any


MAX_SELECTED_TECHNIQUES = 5

ATTACK_PATH_PRIORITY = {
    "T1046": 10,
    "T1135": 20,
    "T1210": 30,
    "T1021.002": 40,
    "T1059": 50,
}

DISCOVERY_ONLY_TECHNIQUES = {"T1046", "T1135", "T1018"}


def ensure_cache_dir(cache_dir: str) -> None:
    os.makedirs(cache_dir, exist_ok=True)


def read_json_file(path: str, default: Any) -> Any:
    try:
        if not os.path.exists(path):
            return default

        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return default


def write_json_file(path: str, data: Any, cache_dir: str) -> None:
    try:
        ensure_cache_dir(cache_dir)

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


def clean_text_list(value: Any, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return fallback

    cleaned = []

    for item in value:
        if isinstance(item, dict):
            step = item.get("step") or item.get("title") or ""
            description = item.get("description") or item.get("details") or ""

            if step and description:
                text = f"{step}: {description}"
            else:
                text = step or description
        else:
            text = str(item)

        text = shorten_text(text, 220)

        if text:
            cleaned.append(text)

    return cleaned or fallback


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


def choose_fallback_selected_ids(allowed_techniques: list[dict]) -> list[str]:
    selected = []

    ordered = sorted(
        allowed_techniques,
        key=lambda item: (
            ATTACK_PATH_PRIORITY.get(item.get("id"), 999),
            -item.get("severity_rank", 0),
            -len(item.get("linked_cves", [])),
            -item.get("count", 0),
        ),
    )

    for tech in ordered:
        technique_id = tech.get("id")

        if technique_id and technique_id not in selected:
            selected.append(technique_id)

        if len(selected) >= MAX_SELECTED_TECHNIQUES:
            break

    return selected


def expand_attack_path_selection(
    selected_ids: list[str],
    allowed_techniques: list[dict],
) -> list[str]:

    allowed_ids = [tech["id"] for tech in allowed_techniques if tech.get("id")]
    allowed_set = set(allowed_ids)

    final = [tid for tid in selected_ids if tid in allowed_set]

    has_smb_context = bool({"T1135", "T1021.002", "T1210"} & allowed_set)

    if has_smb_context:
        for tid in ["T1046", "T1135", "T1210", "T1021.002"]:
            if tid in allowed_set and tid not in final:
                final.append(tid)

    if final and set(final).issubset(DISCOVERY_ONLY_TECHNIQUES):
        for tid in ["T1210", "T1021.002", "T1059"]:
            if tid in allowed_set and tid not in final:
                final.append(tid)
                break

    if not final:
        final = choose_fallback_selected_ids(allowed_techniques)

    return final[:MAX_SELECTED_TECHNIQUES]