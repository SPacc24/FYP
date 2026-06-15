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


PROJECT_KEYWORDS = {
    "scan", "scanned", "scanning",
    "port", "ports", "open port",
    "service", "services",
    "vulnerability", "vulnerabilities", "vuln", "vulns",
    "cve", "cvss", "nvd",
    "mitre", "att&ck", "attack", "technique", "techniques",
    "caldera", "operation", "agent", "ability",
    "risk", "score", "report", "remediation", "recommendation",
    "exploitability", "validation", "finding", "findings",
    "smb", "ssh", "ftp", "http", "https", "winrm", "rdp", "nmap",
    "445", "22", "21", "80", "443", "3389", "5985", "5986",
}


def _is_project_related(message: str) -> bool:

    message_lower = message.lower()

    return any(
        keyword in message_lower
        for keyword in PROJECT_KEYWORDS
    )


def _build_safe_context():
    mapping_results = _active_mapping_results()
    ai_plan = _active_ai_plan()
    attack_plan = _active_attack_plan()
    operation_results = _active_operation_results()
    validation_results = _active_validation_results()

    risk_score = (
        _active_scan_record().get("risk")
        or session.get("risk_score", {})
    )

    return {
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
                    ),
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


def _build_general_prompt(user_message: str) -> str:

    return f"""
You are a helpful AI assistant inside an authorised cybersecurity Final Year Project dashboard.

The user may be casually chatting or asking a general cybersecurity question.

For casual chat:
- Reply naturally and casually.
- Do not ask for more context unless the message is genuinely unclear.
- Do not mention scans, CVEs, MITRE, CALDERA, reports, or the dashboard unless the user brings them up.

For general cybersecurity questions:
- Explain clearly and simply.
- Keep it educational and safe.
- Do not provide exploit commands, payloads, credential theft steps, malware instructions, bypass steps, or intrusion walkthroughs.
- You may explain concepts, defensive reasoning, safe lab validation ideas, and remediation.

Style:
- Reply in plain text only.
- Keep it short unless the user asks for more detail.
- Sound natural, not like a formal report.

User message:
{user_message}

Reply:
"""


def _build_project_prompt(user_message: str, safe_context: dict) -> str:

    context_text = json.dumps(safe_context, default=str)

    if len(context_text) > 5000:
        context_text = context_text[:5000] + "\n...[project context truncated]"

    return f"""
You are AutoPenTest's AI assistant for an authorised cybersecurity Final Year Project dashboard.

The user is asking about the project, scan results, open ports, vulnerabilities, CVEs, MITRE ATT&CK, CALDERA, risk score, validation, or reporting.

Use the project context below when useful.
If the context does not contain enough information, say what is missing instead of inventing facts.

Safety rules:
- Do not provide exploit commands, payloads, credential theft steps, malware instructions, bypass steps, or intrusion walkthroughs.
- Keep guidance focused on authorised lab explanation, validation, prioritisation, reporting, and remediation.
- Only recommend MITRE ATT&CK technique IDs that appear in the project context.

Style:
- Reply in plain text only.
- Keep it concise and useful.
- Use simple wording.
- Do not force every answer into a report format.
- Use this structure only when it helps:
  Observation:
  Risk meaning:
  Recommended next step:

Project context:
{context_text}

User message:
{user_message}

Reply:
"""


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

            if _is_project_related(user_message):
                safe_context = _build_safe_context()
                prompt = _build_project_prompt(user_message, safe_context)
            else:
                prompt = _build_general_prompt(user_message)

            reply = sanitize_llm_reply(
                ask_llm_text(prompt)
            )

            if not reply:
                reply = "I could not generate a response. Please try again."

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
        tags_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/tags",
                "",
                "",
                "",
            )
        )

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