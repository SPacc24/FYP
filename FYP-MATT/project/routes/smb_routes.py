"""Flask routes for the controlled SMB lab workflow."""

from __future__ import annotations

import logging
import secrets

from flask import jsonify, request

from config import Config
from core.helpers import _load_current_scan_results
from core.services import smb_exploiter


log = logging.getLogger(__name__)


def _request_data() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _current_target(data: dict) -> str:
    target = str(data.get("target") or "").strip()

    if target:
        return target

    scan_results = _load_current_scan_results() or {}

    return str(
        scan_results.get("target_ip")
        or scan_results.get("target_input")
        or scan_results.get("target")
        or ""
    ).strip()


def _disabled_response():
    return jsonify({
        "ok": False,
        "error": (
            "SMB exploitation is disabled. "
            "Set ENABLE_SMB_EXPLOITATION=1 and restart the application."
        ),
    }), 403


def register_routes(app):

    @app.route("/pentest/smb/propose", methods=["POST"])
    def smb_propose():
        try:
            if not Config.ENABLE_SMB_EXPLOITATION:
                return _disabled_response()

            scan_results = _load_current_scan_results() or {}

            if not scan_results:
                return jsonify({
                    "ok": False,
                    "error": "No scan results available. Run a scan first.",
                }), 400

            actions = smb_exploiter.propose_actions(scan_results)

            return jsonify({
                "ok": True,
                "actions": actions,
                "count": len(actions),
                "error": (
                    None
                    if actions
                    else "No SMB service was detected on port 139 or 445."
                ),
            })

        except Exception as exc:
            log.exception("SMB proposal failed")
            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500

    @app.route("/pentest/smb/fingerprint", methods=["POST"])
    def smb_fingerprint():
        try:
            if not Config.ENABLE_SMB_EXPLOITATION:
                return _disabled_response()

            data = _request_data()
            target = _current_target(data)

            if not target:
                return jsonify({
                    "ok": False,
                    "error": "No SMB target was supplied.",
                }), 400

            result = smb_exploiter.run_smb_fingerprint(target)

            # Match the field expected by dashboard.js.
            result["port_open"] = result.get("port_445_open", False)

            return jsonify(result)

        except Exception as exc:
            log.exception("SMB fingerprinting failed")
            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500

    @app.route("/pentest/smb/hydra", methods=["POST"])
    def smb_hydra():
        try:
            if not Config.ENABLE_SMB_EXPLOITATION:
                return _disabled_response()

            data = _request_data()
            target = _current_target(data)
            username = str(data.get("username") or "smbtest").strip()

            if not target:
                return jsonify({
                    "ok": False,
                    "error": "No SMB target was supplied.",
                }), 400

            result = smb_exploiter.run_hydra_bruteforce(
                target=target,
                username=username,
            )

            return jsonify(result)

        except Exception as exc:
            log.exception("SMB credential validation failed")
            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500

    @app.route("/pentest/smb/file-ops", methods=["POST"])
    def smb_file_operations():
        try:
            if not Config.ENABLE_SMB_EXPLOITATION:
                return _disabled_response()

            data = _request_data()
            target = _current_target(data)
            share = str(data.get("share") or "PrivEscLab").strip()
            username = str(data.get("username") or "smbtest").strip()
            password = str(data.get("password") or "")

            if not target:
                return jsonify({
                    "ok": False,
                    "error": "No SMB target was supplied.",
                }), 400

            if not password:
                return jsonify({
                    "ok": False,
                    "error": "An SMB password is required.",
                }), 400

            result = smb_exploiter.run_file_operations(
                target=target,
                share=share,
                username=username,
                password=password,
            )

            result["ok"] = True
            result["summary"] = (
                f"{result.get('success_count', 0)} file operations completed. "
                f"Added: {len(result.get('added', []))}; "
                f"removed: {len(result.get('removed', []))}."
            )

            return jsonify(result)

        except Exception as exc:
            log.exception("SMB file operations failed")
            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500

    @app.route("/pentest/smb/chain", methods=["POST"])
    def smb_chain():
        try:
            if not Config.ENABLE_SMB_EXPLOITATION:
                return _disabled_response()

            data = _request_data()
            target = _current_target(data)
            username = str(data.get("username") or "smbtest").strip()
            password = str(data.get("password") or "")

            if not target:
                return jsonify({
                    "ok": False,
                    "error": "No SMB target was supplied.",
                }), 400

            run_id = f"smb_{secrets.token_hex(8)}"

            result = smb_exploiter.run_full_chain(
                target=target,
                run_id=run_id,
                username=username,
                password=password,
            )

            return jsonify({
                "ok": True,
                **result,
            })

        except Exception as exc:
            log.exception("SMB chain failed to start")
            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500

    @app.route(
        "/pentest/smb/chain/status/<run_id>",
        methods=["GET"],
    )
    def smb_chain_status(run_id: str):
        result = smb_exploiter.get_run_status(run_id)

        if result.get("status") == "not_found":
            return jsonify({
                "ok": False,
                **result,
            }), 404

        return jsonify({
            "ok": True,
            **result,
        })