from ai import llm_client
import requests


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"response": "configured reply"}


def test_ollama_settings_are_loaded_from_environment(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv("OLLAMA_URL", "http://ollama.test/api/generate")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2:3b")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "33")
    monkeypatch.setattr(llm_client.requests, "post", fake_post)

    reply = llm_client.ask_llm_text("hello")

    assert reply == "configured reply"
    assert captured["url"] == "http://ollama.test/api/generate"
    assert captured["json"]["model"] == "llama3.2:3b"
    assert captured["json"]["prompt"] == "hello"
    assert captured["timeout"] == 33


def test_invalid_timeout_falls_back_to_default(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv("OLLAMA_TIMEOUT", "not-a-number")
    monkeypatch.setattr(llm_client.requests, "post", fake_post)

    llm_client.ask_llm_text("hello")

    assert captured["timeout"] == llm_client.DEFAULT_TIMEOUT_SECONDS


def test_ollama_base_url_gets_generate_path(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setenv("OLLAMA_URL", "http://ollama.test")
    monkeypatch.setattr(llm_client.requests, "post", fake_post)

    llm_client.ask_llm_text("hello")

    assert captured["url"] == "http://ollama.test/api/generate"


def test_json_timeout_fallback_marks_llm_unavailable(monkeypatch):
    def fake_post(url, json, timeout):
        raise requests.exceptions.Timeout()

    monkeypatch.setenv("OLLAMA_PLANNER_TIMEOUT", "7")
    monkeypatch.setattr(llm_client.requests, "post", fake_post)

    fallback = llm_client.ask_llm_json("select techniques")

    assert fallback["llm_available"] is False
    assert fallback["reasoning"].startswith("Local LLM timeout after 7 seconds.")
