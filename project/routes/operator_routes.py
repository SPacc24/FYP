from __future__ import annotations

import secrets

from flask import jsonify, request, session

from config import Config


def register_routes(app):
    def _operator_token() -> str:
        return str(getattr(Config, "OPERATOR_TOKEN", "") or "").strip()

    def _operator_authenticated() -> bool:
        # If no OPERATOR_TOKEN is configured, allow normal/local use.
        if not _operator_token():
            return True

        return session.get("operator_authenticated") is True

    def _csrf_token() -> str:
        token = session.get("_csrf_token")

        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token

        return token

    @app.context_processor
    def inject_operator_context():
        return {
            "operator_gate_required": bool(_operator_token()),
            "operator_authenticated": _operator_authenticated(),
            "operator_token_configured": bool(_operator_token()),
            "operator_csrf_token": _csrf_token(),
        }

    @app.route("/operator/unlock", methods=["POST"])
    def operator_unlock():
        token = _operator_token()

        # If OPERATOR_TOKEN is not set, allow access.
        if not token:
            session["operator_authenticated"] = True

            return jsonify({
                "ok": True,
                "message": "Operator access allowed.",
                "csrf_token": _csrf_token(),
            })

        data = request.get_json(silent=True) or {}

        supplied = str(
            data.get("operator_token")
            or request.form.get("operator_token")
            or ""
        )

        if secrets.compare_digest(supplied, token):
            session["operator_authenticated"] = True

            return jsonify({
                "ok": True,
                "csrf_token": _csrf_token(),
            })

        return jsonify({
            "ok": False,
            "error": "Invalid operator token."
        }), 403

    @app.route("/operator/lock", methods=["POST"])
    def operator_lock():
        session.pop("operator_authenticated", None)

        return jsonify({
            "ok": True
        })