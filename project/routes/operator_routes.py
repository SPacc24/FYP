"""Operator-session authentication and CSRF protection."""

from __future__ import annotations

import ipaddress
import secrets

from flask import jsonify, render_template, request, session

from config import Config


PUBLIC_ENDPOINTS = {
    "index",
    "operator_unlock",
    "redeem_proof_of_access",
    "static",
}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def register_routes(app):
    def _is_local_request() -> bool:
        remote_addr = request.remote_addr or ""
        try:
            return ipaddress.ip_address(remote_addr).is_loopback
        except ValueError:
            return remote_addr in {"localhost", ""}

    def _operator_token() -> str:
        return str(getattr(Config, "OPERATOR_TOKEN", "") or "").strip()

    def _operator_authenticated() -> bool:
        if not _operator_token():
            return _is_local_request() or bool(
                getattr(Config, "ALLOW_INSECURE_OPERATOR_ACCESS", False)
            )
        return session.get("operator_authenticated") is True

    def _csrf_token() -> str:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def _csrf_valid() -> bool:
        if request.method in SAFE_METHODS or not _operator_token():
            return True

        data = request.get_json(silent=True) or {}
        supplied = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("_csrf_token")
            or data.get("_csrf_token")
            or ""
        )
        expected = session.get("_csrf_token") or ""
        return bool(
            expected
            and supplied
            and secrets.compare_digest(str(supplied), str(expected))
        )

    def _denied_response(message: str):
        wants_json = request.is_json or request.path.startswith(
            (
                "/ai/",
                "/api/",
                "/caldera/",
                "/exploitation/",
                "/pentest/",
                "/proof-of-access/",
                "/scan/status/",
                "/api/mission",
                "/mission/",
            )
        )
        if wants_json:
            return jsonify({"ok": False, "error": message}), 403
        return render_template("error.html", error_message=message), 403

    @app.before_request
    def enforce_operator_session():
        if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
            return None

        if not _operator_authenticated():
            return _denied_response(
                "Operator token required. Unlock this browser session and retry."
            )

        if not _csrf_valid():
            return _denied_response("Invalid or missing CSRF token.")

        return None

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

        if not token:
            if not _operator_authenticated():
                return jsonify({
                    "ok": False,
                    "error": (
                        "OPERATOR_TOKEN is not configured; remote operator access "
                        "is disabled."
                    ),
                }), 403

            session["operator_authenticated"] = True
            return jsonify({
                "ok": True,
                "message": "Local operator session is allowed.",
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
            return jsonify({"ok": True, "csrf_token": _csrf_token()})

        return jsonify({"ok": False, "error": "Invalid operator token."}), 403

    @app.route("/operator/lock", methods=["POST"])
    def operator_lock():
        session.pop("operator_authenticated", None)
        session.pop("_csrf_token", None)
        return jsonify({"ok": True})
