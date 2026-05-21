import json
import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:1b"


def ask_llm_json(prompt: str) -> str:
    """
    Use this for structured JSON outputs, e.g. technique planner.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")

    except requests.RequestException as e:
        return json.dumps({
            "recommended_mode": "hybrid",
            "selected_technique_ids": [],
            "reasoning": f"Local LLM unavailable: {e}",
            "validation_goal": "Analyst review required.",
            "confidence": "low"
        })


def ask_llm_text(prompt: str) -> str:
    """
    Use this for normal chatbot replies.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "").strip()

    except requests.RequestException as e:
        return f"Local LLM unavailable: {e}"