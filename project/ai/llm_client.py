import os
import json
import re
import requests
from urllib.parse import urljoin


# ---------------------------------------------------
# OLLAMA SETTINGS
# ---------------------------------------------------

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_URL = os.getenv("OLLAMA_URL", "")

if not OLLAMA_URL:
    OLLAMA_URL = urljoin(OLLAMA_BASE_URL.rstrip("/") + "/", "api/generate")
elif OLLAMA_URL.rstrip("/").endswith(":11434"):
    OLLAMA_URL = OLLAMA_URL.rstrip("/") + "/api/generate"
elif OLLAMA_URL.rstrip("/").endswith("/api"):
    OLLAMA_URL = OLLAMA_URL.rstrip("/") + "/generate"

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# ---------------------------------------------------
# LOW-LEVEL OLLAMA CALL
# ---------------------------------------------------

def ask_ollama(
    prompt: str,
    timeout: int = OLLAMA_TIMEOUT,
    num_predict: int = 300,
    temperature: float = 0.4,
    json_mode: bool = False,
) -> str:

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }

    # Ollama JSON mode, useful for the AI technique planner
    if json_mode:
        payload["format"] = "json"

    try:
        print("OLLAMA_URL =", OLLAMA_URL)
        print("OLLAMA_MODEL =", OLLAMA_MODEL)
        print("json_mode =", json_mode)

        response = requests.post(
            OLLAMA_URL,
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
        return f"Local LLM timeout after {timeout} seconds."

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
        timeout=OLLAMA_TIMEOUT,
        num_predict=300,
        temperature=0.5,
        json_mode=False,
    )


# ---------------------------------------------------
# JSON MODE - AI TECHNIQUE PLANNER
# ---------------------------------------------------

def ask_llm_json(prompt: str) -> dict:

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

Required JSON structure:
{{
  "selected_technique_ids": ["T1046", "T1135"],
  "reasoning": "Brief reasoning based on the actual scan context.",
  "technique_explanations": [
    {{
      "technique_id": "T1046",
      "technique_name": "Network Service Discovery",
      "why_recommended": "Brief reason.",
      "caldera_validation": "Safe validation or reporting approach."
    }}
  ],
  "next_steps": [
    "Review selected techniques.",
    "Check CALDERA coverage.",
    "Run only authorised validation."
  ]
}}

{prompt}
"""

    text = ask_ollama(
        json_prompt,
        timeout=OLLAMA_TIMEOUT,
        num_predict=900,
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

    if not isinstance(parsed.get("technique_explanations"), list):
        parsed["technique_explanations"] = []

    if not isinstance(parsed.get("next_steps"), list):
        parsed["next_steps"] = []

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
        "url": OLLAMA_URL,
        "model": OLLAMA_MODEL,
    }


def _json_fallback(reason: str, raw: str = "") -> dict:
    return {
        "raw_response": raw,
        "selected_technique_ids": [],
        "reasoning": reason,
        "technique_explanations": [],
        "next_steps": [],
    }