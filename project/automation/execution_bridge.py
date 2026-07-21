"""Bridge execution outcomes back into active missions.

When MetasploitService.run_action, web_exploiter, or validator completes,
call report_*() to push the outcome into any mission whose queue contains
a matching action. This closes the evidence loop without requiring
the operator to manually enter outcomes.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


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


def report_msf_outcome(
    catalog_key: str,
    target: str,
    outcome: str,
    detail: str = "",
    scan_id: str = "",
    set_flags: list[str] | None = None,
) -> bool:
    """Push an MSF execution result into any matching active mission action."""
    try:
        mission = _get_active_mission(scan_id=scan_id)
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
            "Execution bridge: %s/%s → outcome=%s for mission %s",
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
