import os
import json
import re
import requests
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import urljoin


# ---------------------------------------------------
# OLLAMA SETTINGS
# ---------------------------------------------------

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DEFAULT_MODEL = "llama3.2:1b"
DEFAULT_TIMEOUT_SECONDS = 45
DEFAULT_PLANNER_TIMEOUT_SECONDS = 90


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _normalise_ollama_url(value: str = "") -> str:
    ollama_url = (value or os.getenv("OLLAMA_URL", "")).strip()
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip()

    if not ollama_url:
        return urljoin(base_url.rstrip("/") + "/", "api/generate")

    ollama_url = ollama_url.rstrip("/")

    if ollama_url.endswith(":11434") or ollama_url.endswith(".test"):
        return ollama_url + "/api/generate"

    if ollama_url.endswith("/api"):
        return ollama_url + "/generate"

    if not ollama_url.endswith("/api/generate"):
        return ollama_url + "/api/generate"

    return ollama_url


def _llm_model() -> str:
    return os.getenv("OLLAMA_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def _llm_timeout() -> int:
    return _env_int("OLLAMA_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)


def _planner_timeout() -> int:
    return _env_int("OLLAMA_PLANNER_TIMEOUT", DEFAULT_PLANNER_TIMEOUT_SECONDS)

# ---------------------------------------------------
# LOW-LEVEL OLLAMA CALL
# ---------------------------------------------------

def ask_ollama(
    prompt: str,
    timeout: int = None,
    num_predict: int = 300,
    temperature: float = 0.4,
    json_mode: bool = False,
) -> str:

    if timeout is None:
        timeout = _llm_timeout()

    ollama_url = _normalise_ollama_url()
    ollama_model = _llm_model()

    payload = {
        "model": ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
            "num_ctx": 4096
        },
    }

    if json_mode:
        payload["format"] = "json"

    try:
        print("==== OLLAMA DEBUG ====")
        print("OLLAMA_URL =", ollama_url)
        print("OLLAMA_MODEL =", ollama_model)
        print("timeout =", timeout)
        print("json_mode =", json_mode)
        print("prompt length =", len(prompt))
        print("num_predict =", num_predict)
        print("======================")

        response = requests.post(
            ollama_url,
            json=payload,
            timeout=timeout,
        )

        response.raise_for_status()

        data = response.json()
        return data.get("response", "").strip()

    except requests.exceptions.ConnectionError:
        return (
            "Local LLM unavailable. Please make sure Ollama is running, "
            "then try again."
        )

    except requests.exceptions.Timeout:
        return (
            f"Local LLM timeout after {timeout} seconds. "
            f"Try `ollama pull {DEFAULT_MODEL}` and set OLLAMA_MODEL={DEFAULT_MODEL} "
            f"if your current model is too slow."
        )

    except requests.exceptions.RequestException as e:
        return f"Local LLM request failed: {e}"

    except Exception as e:
        return f"Local LLM error: {e}"


# ---------------------------------------------------
# TEXT MODE - CHATBOX
# ---------------------------------------------------

def ask_llm_text(prompt: str) -> str:

    return ask_ollama(
        prompt,
        timeout=_llm_timeout(),
        num_predict=180,
        temperature=0.5,
        json_mode=False,
    )


# ---------------------------------------------------
# JSON MODE - AI TECHNIQUE PLANNER
# ---------------------------------------------------

def ask_llm_json(prompt: str) -> dict:

    # Keep the planner prompt smaller so Kali does not timeout
    if len(prompt) > 8000:
        prompt = prompt[:8000] + "\n...[prompt truncated for local LLM performance]"

    json_prompt = f"""
Return ONLY valid JSON.
Do not include markdown.
Do not include explanation outside the JSON.
Do not wrap the JSON in ```json fences.

The JSON must be an object.

Important JSON rules:
- selected_technique_ids must be a list of technique IDs.
- If you recommend or explain a technique in technique_explanations, its ID must also appear in selected_technique_ids.
- Do not leave selected_technique_ids empty unless there are no allowed techniques.
- The reasoning must be specific, not generic.
- The reasoning must explain why each selected technique matches the scan context.
- If selected techniques are similar, explain the difference between them.
- Mention relevant services, ports, CVEs, or mapper reasons if available.
- Avoid vague phrases like "safe validation" unless you explain what is being validated.
- Do not simply say "recommended due to open services"; explain what the services indicate.

Required JSON structure:
{{
  "selected_technique_ids": ["T1046", "T1135"],
  "reasoning": "Explain specifically why each selected technique fits the scan. If T1046 and T1135 are both selected, explain that T1046 is for exposed services/ports while T1135 is for network shares over SMB/NetBIOS.",
  "technique_explanations": [
    {{
      "technique_id": "T1046",
      "technique_name": "REPLACE_WITH_TECHNIQUE_NAME",
      "why_recommended": "Link this technique to a detected port, service, CVE, severity, or mapper reason.",
      "caldera_validation": "REPLACE_WITH_SAFE_VALIDATION_OR_REPORTING_APPROACH"
    }}
  ],
  "next_steps": [
    "REPLACE_WITH_ACTUAL_NEXT_STEP_1",
    "REPLACE_WITH_ACTUAL_NEXT_STEP_2",
    "REPLACE_WITH_ACTUAL_NEXT_STEP_3"
  ]
}}

Do NOT copy the placeholder values above.
Replace every REPLACE_THIS / REPLACE_WITH value with real content from the scan context.

{prompt}
"""

    text = ask_ollama(
        json_prompt,
        timeout=_planner_timeout(),
        num_predict=450,
        temperature=0.1,
        json_mode=True,
    )

    if not text:
        return _json_fallback("Empty LLM response.")

    error_prefixes = (
        "Local LLM unavailable",
        "Local LLM timeout",
        "The local LLM took too long",
        "Local LLM request failed",
        "Local LLM error",
    )

    if text.startswith(error_prefixes):
        return _json_fallback(text, raw=text)

    # First try direct JSON parse
    try:
        parsed = json.loads(text)

        if isinstance(parsed, dict):
            return _repair_llm_json(parsed)

        return _json_fallback(
            "LLM returned JSON, but it was not a JSON object.",
            raw=text,
        )

    except json.JSONDecodeError:
        pass

    # Fallback: extract first {...} block from messy response
    match = re.search(r"\{.*\}", text, re.DOTALL)

    if match:
        try:
            parsed = json.loads(match.group(0))

            if isinstance(parsed, dict):
                return _repair_llm_json(parsed)

            return _json_fallback(
                "Extracted JSON was not a JSON object.",
                raw=text,
            )

        except json.JSONDecodeError:
            pass

    return _json_fallback(
        "LLM response was not valid JSON.",
        raw=text,
    )


# ---------------------------------------------------
# JSON REPAIR
# ---------------------------------------------------

def _repair_llm_json(parsed: dict) -> dict:

    selected = parsed.get("selected_technique_ids")

    if not isinstance(selected, list):
        selected = []

    selected = [
        _normalise_technique_id(item)
        for item in selected
        if _normalise_technique_id(item)
    ]

    explanations = parsed.get("technique_explanations", [])

    if isinstance(explanations, list):
        for item in explanations:
            if not isinstance(item, dict):
                continue

            technique_id = (
                item.get("technique_id")
                or item.get("id")
                or item.get("technique")
            )

            technique_id = _normalise_technique_id(technique_id)

            if technique_id and technique_id not in selected:
                selected.append(technique_id)

    parsed["selected_technique_ids"] = selected

    if not parsed.get("reasoning"):
        parsed["reasoning"] = "AI selected techniques based on the mapped scan context."

    bad_reasoning_phrases = (
        "Brief reasoning based on the actual scan context",
        "REPLACE_THIS",
        "REPLACE_WITH",
    )

    reasoning = str(parsed.get("reasoning", ""))

    if any(phrase in reasoning for phrase in bad_reasoning_phrases):
        parsed["reasoning"] = "AI selected techniques based on the mapped services, CVEs, and MITRE ATT&CK context."
        
    if not isinstance(parsed.get("technique_explanations"), list):
        parsed["technique_explanations"] = []

    cleaned_explanations = []

    for item in parsed["technique_explanations"]:
        if not isinstance(item, dict):
            continue

        technique_id = _normalise_technique_id(
            item.get("technique_id")
            or item.get("id")
            or item.get("technique")
        )

        if not technique_id:
            continue

        technique_name = str(item.get("technique_name", "")).strip()
        why_recommended = str(item.get("why_recommended", "")).strip()
        caldera_validation = str(item.get("caldera_validation", "")).strip()

        if "REPLACE_WITH" in technique_name or not technique_name:
            technique_name = technique_id

        if "REPLACE_WITH" in why_recommended or not why_recommended:
            why_recommended = "Recommended based on the mapped scan findings and available MITRE ATT&CK context."

        if "REPLACE_WITH" in caldera_validation or not caldera_validation:
            caldera_validation = "Use only safe authorised validation or reporting steps."

        cleaned_explanations.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "why_recommended": why_recommended,
            "caldera_validation": caldera_validation,
        })

    parsed["technique_explanations"] = cleaned_explanations

    if not isinstance(parsed.get("next_steps"), list):
        parsed["next_steps"] = []
    bad_steps = {
        "Review selected techniques.",
        "Check CALDERA coverage.",
        "Run only authorised validation.",
        "REPLACE_WITH_ACTUAL_NEXT_STEP_1",
        "REPLACE_WITH_ACTUAL_NEXT_STEP_2",
        "REPLACE_WITH_ACTUAL_NEXT_STEP_3",
    }

    if isinstance(parsed.get("next_steps"), list):
        parsed["next_steps"] = [
            step for step in parsed["next_steps"]
            if step not in bad_steps and "REPLACE_WITH" not in str(step)
        ]

    if not parsed["next_steps"]:
        parsed["next_steps"] = [
            "Review the mapped open services and linked CVEs.",
            "Confirm that the selected MITRE techniques match the scan findings.",
            "Run only safe authorised CALDERA validation steps."
        ]
    return parsed


def _normalise_technique_id(value) -> str:
    technique_id = str(value or "").strip()

    if not technique_id:
        return ""

    if not technique_id.startswith("T"):
        technique_id = f"T{technique_id}"

    return technique_id


# ---------------------------------------------------
# STATUS
# ---------------------------------------------------

def get_llm_settings() -> dict:
    return {
        "url": _normalise_ollama_url(),
        "model": _llm_model(),
        "timeout": _llm_timeout(),
        "planner_timeout": _planner_timeout(),
    }


def _json_fallback(reason: str, raw: str = "") -> dict:
    return {
        "llm_available": False,
        "raw_response": raw,
        "selected_technique_ids": [],
        "reasoning": reason,
        "technique_explanations": [],
        "next_steps": [],
    }
