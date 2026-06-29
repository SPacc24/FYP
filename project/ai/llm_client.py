import json
import os
import sys
import requests
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import urlparse


load_dotenv(Path(__file__).resolve().parents[1] / ".env")


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL_NAME = "llama3.2:1b"
DEFAULT_TIMEOUT_SECONDS = 180


def _llm_unavailable_plan(reason: Exception) -> str:
    # Print a concise server-side diagnostic so the Flask terminal tells you
    # exactly why AI planning fell back instead of silently failing.
    print("OLLAMA FAILED:", repr(reason), file=sys.stderr)

    return json.dumps({
        "recommended_mode": "hybrid",
        "selected_technique_ids": [],
        "reasoning": "",
        "technique_explanations": [],
        "next_steps": [],
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

    url = os.getenv("OLLAMA_URL", DEFAULT_OLLAMA_URL).strip()
    parsed = urlparse(url)
    if parsed.path in {"", "/"}:
        # Let users write OLLAMA_URL=http://127.0.0.1:11434 in .env without
        # needing to remember Ollama's /api/generate path.
        url = url.rstrip("/") + "/api/generate"

    return {
        "url": url,
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

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = response.text[:500] if response is not None else ""
        raise requests.HTTPError(f"{exc}; Ollama response body: {body}") from exc

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

    except (requests.RequestException, ValueError) as e:
        print("OLLAMA CHAT FAILED:", repr(e), file=sys.stderr)
        return (
            "The local LLM service is unavailable. Start Ollama and confirm it is "
            "listening on the configured OLLAMA_URL, then try again."
        )
