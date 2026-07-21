"""Mission console API + UI routes for closed-loop orchestration."""

from __future__ import annotations

import json
from typing import Any

from flask import jsonify, render_template, request

from automation.mission_service import get_mission_service
from automation.playbook_loader import list_playbooks


def _body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return dict(request.form or {})


def _load_scan_results(scan_id: str) -> dict[str, Any] | None:
    if not scan_id:
        return None
    try:
        from storage import scan_store

        record = None
        if hasattr(scan_store, "get_scan"):
            record = scan_store.get_scan(scan_id)
        elif hasattr(scan_store, "get"):
            record = scan_store.get(scan_id)
        if isinstance(record, dict):
            return record.get("results") or record.get("parsed_results") or record
    except Exception:
        pass
    # Disk fallback under storage/results
    try:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1] / "storage" / "results"
        for pattern in (f"{scan_id}*.json", f"*{scan_id}*.json"):
            for path in root.glob(pattern):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict):
                    return data.get("results") or data
    except Exception:
        pass
    return None


def register_routes(app):
    svc = get_mission_service

    @app.route("/mission")
    @app.route("/mission/")
    def mission_console():
        return render_template(
            "mission_console.html",
            playbooks=list_playbooks(),
            missions=svc().list_missions(limit=30),
        )

    @app.route("/mission/<mission_id>")
    def mission_detail_page(mission_id: str):
        mission = svc().get(mission_id)
        if not mission:
            return render_template(
                "error.html",
                error_message=f"Mission not found: {mission_id}",
            ), 404
        return render_template(
            "mission_console.html",
            playbooks=list_playbooks(),
            missions=svc().list_missions(limit=30),
            active_mission_id=mission_id,
            active_mission=mission,
        )

    @app.route("/api/mission/playbooks", methods=["GET"])
    def api_mission_playbooks():
        return jsonify({"ok": True, "playbooks": list_playbooks()})

    @app.route("/api/mission/list", methods=["GET"])
    def api_mission_list():
        limit = request.args.get("limit", 50, type=int)
        return jsonify({"ok": True, "missions": svc().list_missions(limit=limit or 50)})

    @app.route("/api/mission/<mission_id>", methods=["GET"])
    def api_mission_get(mission_id: str):
        mission = svc().get(mission_id)
        if not mission:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/start", methods=["POST"])
    def api_mission_start():
        body = _body()
        playbook_id = str(body.get("playbook_id") or "").strip() or None
        risk_posture = str(body.get("risk_posture") or "").strip() or None
        scan_id = str(body.get("scan_id") or "").strip()
        notes = str(body.get("notes") or "")
        scope = body.get("scope") if isinstance(body.get("scope"), dict) else {}
        parsed = body.get("parsed_results") if isinstance(body.get("parsed_results"), dict) else None
        if not parsed and scan_id:
            parsed = _load_scan_results(scan_id)

        # Minimal empty surface if none provided (demo interior loop)
        if not parsed:
            hosts = body.get("hosts")
            ports = body.get("ports")
            if isinstance(ports, list):
                parsed = {
                    "target": str(body.get("target") or "0.0.0.0"),
                    "ports": ports,
                    "hosts": hosts or [],
                }
            elif isinstance(hosts, list):
                parsed = {"hosts": hosts, "target": str(body.get("target") or "")}

        try:
            mission = svc().start(
                playbook_id=playbook_id,
                parsed_results=parsed,
                scope=scope,
                risk_posture=risk_posture,
                scan_id=scan_id,
                notes=notes,
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/advance", methods=["POST"])
    def api_mission_advance(mission_id: str):
        body = _body()
        parsed = body.get("parsed_results") if isinstance(body.get("parsed_results"), dict) else None
        try:
            mission = svc().advance(mission_id, parsed_results=parsed)
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/continue", methods=["POST"])
    def api_mission_continue(mission_id: str):
        body = _body()
        parsed = body.get("parsed_results") if isinstance(body.get("parsed_results"), dict) else None
        try:
            mission = svc().continue_mission(mission_id, parsed_results=parsed)
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/approve", methods=["POST"])
    def api_mission_approve(mission_id: str):
        body = _body()
        queue_id = str(body.get("action_queue_id") or body.get("queue_id") or "").strip()
        if not queue_id:
            return jsonify({"ok": False, "error": "action_queue_id required"}), 400
        approved = body.get("approved", True)
        if isinstance(approved, str):
            approved = approved.strip().lower() in {"1", "true", "yes", "approve", "approved"}
        note = str(body.get("operator_note") or body.get("note") or "")
        try:
            mission = svc().approve(
                mission_id,
                queue_id,
                approved=bool(approved),
                operator_note=note,
            )
        except KeyError as exc:
            msg = str(exc)
            if mission_id in msg or msg == f"'{mission_id}'":
                return jsonify({"ok": False, "error": "Mission not found"}), 404
            return jsonify({"ok": False, "error": f"Unknown action: {exc}"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/outcome", methods=["POST"])
    def api_mission_outcome(mission_id: str):
        body = _body()
        outcome = str(body.get("outcome") or "").strip()
        if not outcome:
            return jsonify({"ok": False, "error": "outcome required"}), 400
        flags = body.get("set_flags")
        if not isinstance(flags, list):
            flags = None
        try:
            mission = svc().record_outcome(
                mission_id,
                action_queue_id=str(body.get("action_queue_id") or ""),
                catalog_key=str(body.get("catalog_key") or ""),
                outcome=outcome,
                detail=str(body.get("detail") or ""),
                set_flags=flags,
            )
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/validate-safe", methods=["POST"])
    def api_mission_validate_safe(mission_id: str):
        """Bulk-record outcomes for queued_auto safe/auxiliary actions (lab closed loop)."""
        body = _body()
        try:
            mission = svc().validate_safe_actions(
                mission_id,
                detail=str(
                    body.get("detail")
                    or "Operator-validated safe auxiliary / non-impact probe"
                ),
                outcome=str(body.get("outcome") or "success").strip() or "success",
            )
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/proof", methods=["POST"])
    def api_mission_proof(mission_id: str):
        body = _body()
        evidence = str(body.get("evidence") or "").strip()
        if not evidence:
            return jsonify({"ok": False, "error": "evidence required for proof record"}), 400
        techs = body.get("technique_ids")
        if not isinstance(techs, list):
            techs = []
        try:
            mission = svc().attach_proof(
                mission_id,
                action_id=str(body.get("action_id") or ""),
                catalog_key=str(body.get("catalog_key") or ""),
                target=str(body.get("target") or ""),
                technique_ids=[str(t) for t in techs],
                proof_type=str(body.get("proof_type") or "operator_attested"),
                evidence=evidence,
                artifact_path=str(body.get("artifact_path") or ""),
                extra=body.get("extra") if isinstance(body.get("extra"), dict) else None,
            )
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>/abort", methods=["POST"])
    def api_mission_abort(mission_id: str):
        body = _body()
        try:
            mission = svc().abort(mission_id, reason=str(body.get("reason") or ""))
        except KeyError:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        return jsonify({"ok": True, "mission": mission})

    @app.route("/api/mission/<mission_id>", methods=["DELETE"])
    def api_mission_delete(mission_id: str):
        ok = svc().delete(mission_id)
        if not ok:
            return jsonify({"ok": False, "error": "Mission not found"}), 404
        return jsonify({"ok": True})
