"""Bridge execution outcomes back into active missions.

When MetasploitService.run_action, web_exploiter, or validator completes,
call report_*() to push the outcome into any mission whose queue contains
a matching action. This closes the evidence loop without requiring
the operator to manually enter outcomes.

If no active mission exists (e.g. operator ran MSF from /pentest/metasploit/run
directly, outside the orchestration flow), the bridge auto-creates a lightweight
ad-hoc mission so the evidence is never lost and the closed-loop timeline
stays complete.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_active_mission(scan_id: str = "") -> dict[str, Any] | None:
    """Find the most recent running mission, optionally filtered by scan_id."""
    try:
        from automation.mission_service import get_mission_service

        svc = get_mission_service()
        missions = svc.list_missions(limit=50)
    except Exception:
        return None

    for m in missions:
        if m.get("status") not in {"running", "awaiting_approval", "awaiting_operator"}:
            continue
        if scan_id and m.get("scan_id") != scan_id:
            continue
        return svc.get(m["mission_id"])
    return None


def _match_queue_action(
    mission: dict[str, Any],
    catalog_key: str,
    target: str,
) -> str:
    """Return the action_queue_id of a queued action matching catalog_key + target."""
    queue = mission.get("action_queue") or []
    for action in queue:
        if action.get("status") not in {"queued_auto", "queued_approval", "queued_execute"}:
            continue
        action_catalog = str(action.get("catalog_key") or action.get("key") or "")
        action_target = str(action.get("target") or "")
        if action_catalog == catalog_key and (not target or action_target == target):
            return str(action.get("queue_id") or action.get("id") or "")
    return ""


def _create_ad_hoc_mission(
    catalog_key: str,
    target: str,
    scan_id: str = "",
) -> dict[str, Any] | None:
    """Create a lightweight ad-hoc mission so the bridge always has a target.

    Used when the operator runs exploitation directly (e.g. /pentest/metasploit/run)
    without starting a formal orchestrated mission.
    """
    try:
        from automation.mission_service import get_mission_service

        svc = get_mission_service()
    except Exception:
        return None

    mission_id = f"msn_ad_hoc_{secrets.token_hex(6)}"
    now = _utc_now()

    m: dict[str, Any] = {
        "mission_id": mission_id,
        "playbook_id": "edge_to_internal_proof",
        "playbook_title": "Edge to internal impact proof",
        "goal": "Evidence-closed-loop ad-hoc bridge mission",
        "summary": "Auto-created by execution bridge for direct exploitation run.",
        "risk_posture": "validate",
        "status": "running",
        "created_at": now,
        "updated_at": now,
        "scan_id": scan_id,
        "scope": {},
        "notes": "Ad-hoc mission — created automatically because operator ran exploitation outside a formal mission.",
        "stage_index": 0,
        "current_stage_id": "surface_recon",
        "stages": [],
        "flags": [],
        "evidence_flags": {},
        "action_queue": [],
        "attack_graph": {},
        "branch_events": [],
        "event_log": [
            {"at": now, "kind": "mission_start", "message": "Ad-hoc bridge mission auto-created"}
        ],
        "evidence": {},
        "proofs": [],
        "research_queue": [],
        "pending_approvals": [],
        "parsed_results_snapshot": {},
        "debrief": {},
    }

    # Inject the action that just ran into the queue so the bridge can match it
    queue_id = f"act_{secrets.token_hex(8)}"
    m["action_queue"].append(
        {
            "queue_id": queue_id,
            "catalog_key": catalog_key,
            "target": target,
            "title": catalog_key,
            "status": "queued_auto",
            "source": "ad_hoc_bridge",
            "queued_at": now,
        }
    )

    # Persist directly (bypasses start() which runs full stage 1)
    try:
        svc._persist(m)
    except AttributeError:
        path = svc._path(mission_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        import json
        path.write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
        svc._cache[mission_id] = m

    log.info("Execution bridge: created ad-hoc mission %s for %s/%s", mission_id, catalog_key, target)
    return m


def report_msf_outcome(
    catalog_key: str,
    target: str,
    outcome: str,
    detail: str = "",
    scan_id: str = "",
    set_flags: list[str] | None = None,
) -> bool:
    """Push an MSF execution result into any matching active mission action.

    If no active mission exists, auto-creates an ad-hoc bridge mission so
    the evidence loop is never broken.
    """
    try:
        mission = _get_active_mission(scan_id=scan_id)

        if not mission:
            mission = _create_ad_hoc_mission(
                catalog_key=catalog_key,
                target=target,
                scan_id=scan_id,
            )
            if not mission:
                return False

        queue_id = _match_queue_action(mission, catalog_key, target)
        if not queue_id:
            log.debug("No matching queued action for %s/%s", catalog_key, target)
            return False

        from automation.mission_service import get_mission_service

        get_mission_service().record_outcome(
            mission["mission_id"],
            action_queue_id=queue_id,
            catalog_key=catalog_key,
            outcome=outcome,
            detail=detail,
            set_flags=set_flags,
        )
        log.info(
            "Execution bridge: %s/%s -> outcome=%s for mission %s",
            catalog_key,
            target,
            outcome,
            mission["mission_id"],
        )
        return True
    except Exception as exc:
        log.warning("Execution bridge failed: %s", exc)
        return False


def report_web_outcome(
    profile_key: str,
    target: str,
    outcome: str,
    detail: str = "",
    scan_id: str = "",
) -> bool:
    """Push a web exploitation outcome into any matching active mission action."""
    return report_msf_outcome(
        catalog_key=profile_key,
        target=target,
        outcome=outcome,
        detail=detail,
        scan_id=scan_id,
    )


def report_safe_validation_bulk(
    scan_id: str = "",
) -> bool:
    """Bulk-validate all queued_auto safe actions in the active mission."""
    try:
        mission = _get_active_mission(scan_id=scan_id)
        if not mission:
            return False

        from automation.mission_service import get_mission_service

        get_mission_service().validate_safe_actions(
            mission["mission_id"],
            detail="Auto-validated safe auxiliary actions from execution pipeline",
            outcome="success",
        )
        return True
    except Exception as exc:
        log.warning("Bulk validation bridge failed: %s", exc)
        return False
