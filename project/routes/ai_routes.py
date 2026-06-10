import json
from urllib.parse import urlparse, urlunparse

import requests
from flask import jsonify, request, session

from ai.llm_client import ask_llm_text, get_llm_settings
from ai.safety import SAFE_REFUSAL, is_unsafe_user_request, sanitize_llm_reply

from core.helpers import (
    _active_ai_plan,
    _active_attack_plan,
    _active_mapping_results,
    _active_operation_results,
    _active_scan_record,
    _active_validation_results,
)


def register_routes(app):
    @app.route("/ai/chat", methods=["POST"])
    def ai_chat():
        try:
            data = request.get_json(silent=True) or {}
            user_message = data.get("message", "").strip()

            if not user_message:
                return jsonify({
                    "ok": False,
                    "reply": "Please enter a question."
                }), 400

            if is_unsafe_user_request(user_message):
                return jsonify({
                    "ok": False,
                    "reply": SAFE_REFUSAL
                }), 400

            mapping_results = _active_mapping_results()
            ai_plan = _active_ai_plan()
            attack_plan = _active_attack_plan()
            operation_results = _active_operation_results()
            validation_results = _active_validation_results()
            risk_score = (
                _active_scan_record().get("risk")
                or session.get("risk_score", {})
            )

            safe_context = {
                "mapping_summary": {
                    "severity_counts": mapping_results.get("severity_counts", {}),
                    "top_risks": mapping_results.get("top_risks", []),
                    "recommended_techniques": [
                        {
                            "id": tech.get("id"),
                            "name": tech.get("name"),
                            "count": tech.get("count"),
                            "max_severity": tech.get("max_severity"),
                            "mitre_url": (
                                f"https://attack.mitre.org/techniques/{tech.get('id').replace('.', '/')}/"
                                if tech.get("id") else ""
                            )
                        }
                        for tech in mapping_results.get("recommended_techniques", [])
                    ],
                    "attack_chain": mapping_results.get("attack_chain", []),
                },
                "ai_plan": ai_plan,
                "attack_plan": attack_plan,
                "operation_summary": {
                    "total": operation_results.get("total", 0),
                    "success_count": operation_results.get("success_count", 0),
                    "fail_count": operation_results.get("fail_count", 0),
                    "techniques_run": operation_results.get("techniques_run", []),
                },
                "exploitability_validation": {
                    "mode": validation_results.get("mode"),
                    "target": validation_results.get("target"),
                    "confirmed": validation_results.get("confirmed", 0),
                    "potential": validation_results.get("potential", 0),
                    "findings": validation_results.get("findings", []),
                },
                "risk_score": risk_score,
            }

            message_lower = user_message.lower().strip()

            simple_greetings = {
                "hello", "hi", "hey", "yo", "sup",
                "hello!", "hi!", "hey!"
            }

            if message_lower in simple_greetings:
                return jsonify({
                    "ok": True,
                    "reply": (
                        "Hello. You can ask me about the scan findings, MITRE techniques, "
                        "CALDERA validation, CVEs, risk score, or general cybersecurity concepts."
                    )
                })

            prompt = f"""
You are AutoPenTest's AI assistant for an authorised cybersecurity Final Year Project dashboard.

You can answer in two modes:

1. Normal chat / concept mode:
If the user asks a greeting, general cybersecurity concept, or basic technical question,
answer naturally and directly. Do not force MITRE ATT&CK mapping.

2. Project context mode:
If the user asks about scan findings, open ports, vulnerabilities, CVEs, MITRE ATT&CK,
CALDERA, selected techniques, risk score, or report output, use the project context.

Safety rules:
- Do not provide exploit commands, payloads, credential theft steps, malware instructions, bypass steps, or intrusion walkthroughs.
- Keep guidance focused on authorised lab validation, explanation, prioritisation, reporting, and remediation.
- If the project context does not contain enough information, say what is missing instead of inventing facts.
- For normal definitions like "what is SMB", answer using general cybersecurity knowledge.
- Only recommend MITRE ATT&CK technique IDs that appear in the project context.
- Reply in normal plain text, not JSON.
- Keep replies concise and useful.

Formatting rules:
- For normal chat or definitions, answer naturally in 1 to 3 short paragraphs.
- For project-specific technique questions, use this structure only when useful:
  Observation:
  Risk meaning:
  Recommended next step:
- Do not include MITRE ATT&CK mapping unless the user asks about techniques, attack mapping, scan findings, or validation.
- Do not force every answer into a report format.

Current project context:
{json.dumps(safe_context, indent=2, default=str)}

User question:
{user_message}

Reply:
"""

            reply = sanitize_llm_reply(ask_llm_text(prompt))

            return jsonify({
                "ok": True,
                "reply": reply
            })

        except Exception as e:
            return jsonify({
                "ok": False,
                "reply": f"AI chat error: {e}"
            }), 500

    @app.route("/ai/status", methods=["GET"])
    def ai_status():
        settings = get_llm_settings()
        parsed = urlparse(settings["url"])
        tags_url = urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))

        try:
            response = requests.get(tags_url, timeout=2)
            response.raise_for_status()

            models = response.json().get("models", [])
            model_names = [
                item.get("name")
                for item in models
                if item.get("name")
            ]

            return jsonify({
                "ok": True,
                "available": True,
                "url": settings["url"],
                "model": settings["model"],
                "model_installed": settings["model"] in model_names,
                "models": model_names,
            })

        except Exception as exc:
            return jsonify({
                "ok": True,
                "available": False,
                "url": settings["url"],
                "model": settings["model"],
                "error": str(exc),
            })