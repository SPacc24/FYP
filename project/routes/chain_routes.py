"""Routes for the one-button demo kill chain."""
from __future__ import annotations

import secrets
import threading


from flask import jsonify, request, render_template  # add render_template

from core.services import chain_orchestrator


def register_routes(app):

    @app.route("/pentest/chain", methods=["GET"])
    def chain_page():
            return render_template("chain_run.html")

    @app.route("/pentest/chain/run", methods=["POST"])
    def chain_run():
        data = request.get_json(silent=True) or {}
        web_target = str(data.get("web_target") or "").strip()
        internal_range = str(data.get("internal_range") or "").strip()
        if not web_target or not internal_range:
            return jsonify({"ok": False,
                            "error": "web_target and internal_range are required"}), 400
        run_id = f"chain_{secrets.token_hex(8)}"
        threading.Thread(
            target=chain_orchestrator.run_chain,
            kwargs={
                "run_id": run_id,
                "web_target": web_target,
                "internal_range": internal_range,
                "smb_username": str(data.get("smb_username") or "smbtest").strip(),
                "smb_share": str(data.get("smb_share") or "PrivEscLab").strip(),
                "smb_password": str(data.get("smb_password") or "").strip(),
                "quick": bool(data.get("quick", False)),
            },
            daemon=True,
        ).start()
        return jsonify({"ok": True, "run_id": run_id,
                        "status_url": f"/pentest/chain/status/{run_id}"})

    @app.route("/pentest/chain/status/<run_id>", methods=["GET"])
    def chain_status(run_id: str):
        result = chain_orchestrator.get_run_status(run_id)
        if result.get("status") == "not_found":
            return jsonify({"ok": False, **result}), 404
        return jsonify({"ok": True, **result})

    @app.route("/pentest/chain/history", methods=["GET"])
    def chain_history():
        return jsonify({"ok": True, "runs": chain_orchestrator.history()})

