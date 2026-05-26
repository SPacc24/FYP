import json
import os
import requests


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL_NAME = "llama3.2:1b"
DEFAULT_TIMEOUT_SECONDS = 120


def _llm_unavailable_plan(reason: Exception) -> str:
    return json.dumps({
        "recommended_mode": "hybrid",
        "selected_technique_ids": [],
        "reasoning": (
            "The local LLM service is unavailable, so AutoPenTest used the "
            "highest-priority mapped techniques as a deterministic fallback."
        ),
        "validation_goal": "Analyst review required.",
        "confidence": "low",
        "llm_available": False,
        "llm_error": str(reason),
    })


def get_llm_settings() -> dict:
    """
    Resolve LLM settings at call time so .env/test overrides are respected.
    """
    timeout = os.getenv("OLLAMA_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS))

    try:
        timeout_seconds = int(timeout)
    except ValueError:
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    return {
        "url": os.getenv("OLLAMA_URL", DEFAULT_OLLAMA_URL),
        "model": os.getenv("OLLAMA_MODEL", DEFAULT_MODEL_NAME),
        "timeout": timeout_seconds,
    }


def _post_ollama(payload: dict) -> str:
    settings = get_llm_settings()
    payload = {
        "model": settings["model"],
        **payload,
    }

    response = requests.post(
        settings["url"],
        json=payload,
        timeout=settings["timeout"],
    )
    response.raise_for_status()

    data = response.json()
    return str(data.get("response", "")).strip()


def ask_llm_json(prompt: str) -> str:
    """
    Use this for structured JSON outputs, e.g. technique planner.
    """
    payload = {
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    try:
        return _post_ollama(payload)

    except (requests.RequestException, ValueError) as e:
        return _llm_unavailable_plan(e)


def ask_llm_text(prompt: str) -> str:
    """
    Use this for normal chatbot replies.
    """
    payload = {
        "prompt": prompt,
        "stream": False
    }

    try:
        return _post_ollama(payload)

    except (requests.RequestException, ValueError):
        return (
            "The local LLM service is unavailable. Start Ollama and confirm it is "
            "listening on the configured OLLAMA_URL, then try again."
        )
