"""Evidence-closed-loop playbook engine.

Stages, branches, and detectors come from playbook JSON.
Catalog module paths come from exploit_module_catalog.json.
Nothing high-risk auto-executes — approval flags are enforced here.
"""

from __future__ import annotations

import copy
import secrets
from datetime import datetime, timezone
from typing import Any

from automation.attack_graph import build_attack_graph
from automation.playbook_loader import load_playbook
from exploitation.module_catalog import (
    PortEvidence,
    extract_port_evidence,
    get_module_catalog,
    normalise_service,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _module_applicable_to_row(mod, row: PortEvidence) -> bool:
    """Suppress clearly incompatible modules and enforce their canonical port."""
    key = str(getattr(mod, "key", "") or "").lower()
    product = str(getattr(row, "product", "") or "").lower()
    port = int(getattr(row, "port", 0) or 0)
    if "ms17_010" in key and port != 445:
        return False
    if "psexec" in key and port != 445:
        return False
    if ("windows xp" in product or "server 2003" in product) and any(
        token in key for token in ("smbghost", "zerologon", "printnightmare", "bluekeep")
    ):
        return False
    return True


class PlaybookEngine:
    """Stateful mission runner driven entirely by declarative playbooks."""

    def __init__(self, playbook: dict[str, Any] | None = None, playbook_id: str | None = None):
        self.playbook = playbook or load_playbook(playbook_id)
        self.playbook_id = str(self.playbook.get("id") or playbook_id or "unknown")

    def start_mission(
        self,
        *,
        parsed_results: dict[str, Any] | None = None,
        scope: dict[str, Any] | None = None,
        risk_posture: str | None = None,
        scan_id: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        stages = sorted(
            list(self.playbook.get("stages") or []),
            key=lambda s: int(s.get("order") or 0),
        )
        if not stages:
            raise ValueError("Playbook has no stages")

        mission: dict[str, Any] = {
            "mission_id": _new_id("msn"),
            "playbook_id": self.playbook_id,
            "playbook_title": self.playbook.get("title") or self.playbook_id,
            "goal": self.playbook.get("goal") or "",
            "summary": self.playbook.get("summary") or "",
            "risk_posture": risk_posture
            or self.playbook.get("risk_posture_default")
            or "validate",
            "status": "running",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "scan_id": scan_id,
            "scope": scope or {},
            "notes": notes,
            "stage_index": 0,
            "current_stage_id": stages[0]["id"],
            "stages": [
                {
                    "id": s["id"],
                    "title": s.get("title") or s["id"],
                    "order": int(s.get("order") or 0),
                    "description": s.get("description") or "",
                    "status": "pending",
                    "auto_advance": bool(s.get("auto_advance", True)),
                    "requires_unlock_flag": s.get("requires_unlock_flag") or "",
                }
                for s in stages
            ],
            "flags": [],
            "evidence_flags": {},
            "action_queue": [],
            "branch_events": [],
            "event_log": [],
            "research_queue": [],
            "proofs": [],
            "attack_graph": {"nodes": [], "edges": [], "stats": {}},
            "pending_approvals": [],
            "debrief": None,
            "parsed_results_snapshot": self._thin_results(parsed_results),
        }
        mission["stages"][0]["status"] = "active"
        self._log(mission, "mission_started", f"Mission started: {mission['playbook_title']}")
        return self.advance(mission, parsed_results=parsed_results, max_steps=32)

    def advance(
        self,
        mission: dict[str, Any],
        *,
        parsed_results: dict[str, Any] | None = None,
        max_steps: int = 16,
    ) -> dict[str, Any]:
        """Run auto stages until blocked on approval, unlock, or completion."""
        mission = copy.deepcopy(mission)
        results = parsed_results or mission.get("parsed_results_snapshot") or {}
        if parsed_results:
            mission["parsed_results_snapshot"] = self._thin_results(parsed_results)

        for _ in range(max_steps):
            if mission.get("status") in {"completed", "aborted", "failed"}:
                break

            stage = self._current_stage_def(mission)
            if stage is None:
                mission["status"] = "completed"
                break

            unlock = str(stage.get("requires_unlock_flag") or "").strip()
            flags = set(mission.get("flags") or [])
            if unlock and unlock not in flags:
                if self._can_skip_locked_stage(mission, stage):
                    self._complete_stage(mission, stage["id"], skipped=True)
                    if not self._move_next_stage(mission):
                        mission["status"] = "completed"
                    continue
                # Peek ahead: if remaining stages after this one are all skippable
                # and we can't unlock, still wait only when unlock might still arrive.
                mission["status"] = "blocked_unlock"
                self._log(
                    mission,
                    "stage_blocked_unlock",
                    f"Stage '{stage.get('title')}' waiting for flag '{unlock}'",
                )
                # Prefer skip-to-debrief when later stages can skip and current is dead-end
                if self._should_force_skip_to_debrief(mission, stage):
                    self._complete_stage(mission, stage["id"], skipped=True)
                    if not self._move_next_stage(mission):
                        mission["status"] = "completed"
                    mission["status"] = "running"
                    continue
                break

            self._activate_stage(mission, stage["id"])
            self._run_stage_actions(mission, stage, results)

            self._refresh_evidence_flags(mission, results)
            self._apply_branches(mission)

            mission["attack_graph"] = build_attack_graph(
                results,
                flags=set(mission.get("flags") or []),
            )

            pending = [
                a
                for a in mission.get("action_queue") or []
                if a.get("status") == "awaiting_approval"
                and a.get("stage_id") in {stage["id"], "", None}
                or (
                    a.get("status") == "awaiting_approval"
                    and a.get("stage_id") == stage["id"]
                )
            ]
            # Broader: all awaiting when stage is non-auto
            if not bool(stage.get("auto_advance", True)):
                pending = [
                    a
                    for a in mission.get("action_queue") or []
                    if a.get("status") == "awaiting_approval"
                ]
            mission["pending_approvals"] = [
                a
                for a in mission.get("action_queue") or []
                if a.get("status") == "awaiting_approval"
            ]

            if mission["pending_approvals"] and not bool(stage.get("auto_advance", True)):
                mission["status"] = "awaiting_approval"
                self._log(
                    mission,
                    "awaiting_approval",
                    f"{len(mission['pending_approvals'])} high-risk action(s) need operator approval",
                )
                break

            # Stage complete
            self._complete_stage(mission, stage["id"])
            if stage.get("id") == "mission_debrief" or any(
                (a.get("kind") == "compile_debrief") for a in (stage.get("actions") or [])
            ):
                mission["debrief"] = self._compile_debrief(mission)
                mission["status"] = "completed"
                self._log(mission, "mission_completed", "Mission debrief compiled")
                break

            if not bool(stage.get("auto_advance", True)):
                if not mission["pending_approvals"]:
                    mission["status"] = "awaiting_operator"
                    self._log(
                        mission,
                        "awaiting_operator",
                        f"Stage '{stage.get('title')}' requires operator continue",
                    )
                break

            if not self._move_next_stage(mission):
                mission["debrief"] = self._compile_debrief(mission)
                mission["status"] = "completed"
                self._log(mission, "mission_completed", "All stages finished")
                break

        mission["updated_at"] = _utc_now()
        return mission

    def continue_mission(
        self,
        mission: dict[str, Any],
        *,
        parsed_results: dict[str, Any] | None = None,
        skip_locked: bool = True,
    ) -> dict[str, Any]:
        mission = copy.deepcopy(mission)
        if mission.get("status") in {"awaiting_operator", "awaiting_approval", "blocked_unlock"}:
            pending = [
                a for a in (mission.get("action_queue") or [])
                if a.get("status") == "awaiting_approval"
            ]
            if pending and mission.get("status") == "awaiting_approval":
                return mission
            stage = self._current_stage_def(mission)
            if stage:
                if mission.get("status") == "blocked_unlock" and skip_locked:
                    self._complete_stage(mission, stage["id"], skipped=True)
                    self._log(
                        mission,
                        "stage_skipped_by_operator",
                        f"Operator continued past locked stage {stage.get('title')}",
                    )
                elif mission.get("status") != "blocked_unlock":
                    self._complete_stage(mission, stage["id"])
                if mission.get("status") != "blocked_unlock" or skip_locked:
                    if not self._move_next_stage(mission):
                        mission["debrief"] = self._compile_debrief(mission)
                        mission["status"] = "completed"
                        mission["updated_at"] = _utc_now()
                        return mission
            mission["status"] = "running"
        return self.advance(mission, parsed_results=parsed_results)

    def approve_action(
        self,
        mission: dict[str, Any],
        action_queue_id: str,
        *,
        approved: bool = True,
        operator_note: str = "",
    ) -> dict[str, Any]:
        mission = copy.deepcopy(mission)
        found = None
        for action in mission.get("action_queue") or []:
            if action.get("queue_id") == action_queue_id:
                found = action
                break
        if not found:
            raise KeyError(f"Unknown action queue id: {action_queue_id}")

        if found.get("status") not in {"awaiting_approval", "approved", "skipped", "queued_auto"}:
            raise ValueError(f"Action not approvable in status={found.get('status')}")

        if approved:
            found["status"] = "approved"
            found["approved_at"] = _utc_now()
            found["operator_note"] = operator_note
            self._log(
                mission,
                "action_approved",
                f"Approved {found.get('title') or found.get('catalog_key')}",
            )
            key = str(found.get("catalog_key") or "")
            kind = str(found.get("kind") or "")
            if kind == "web_profile" or "web" in key or key.startswith("cmdi"):
                self._add_flag(mission, "web_path_approved")
            if "ms17" in key and "exploit" in key:
                self._add_flag(mission, "ms17_exploit_approved")
            if kind == "pivot_segment":
                self._add_flag(mission, "pivot_approved")
        else:
            found["status"] = "skipped"
            found["skipped_at"] = _utc_now()
            found["operator_note"] = operator_note or "skipped by operator"
            self._log(
                mission,
                "action_skipped",
                f"Skipped {found.get('title') or found.get('catalog_key')}",
            )

        mission["pending_approvals"] = [
            a
            for a in mission.get("action_queue") or []
            if a.get("status") == "awaiting_approval"
        ]

        if not mission["pending_approvals"] and mission.get("status") == "awaiting_approval":
            stage = self._current_stage_def(mission)
            if stage:
                self._complete_stage(mission, stage["id"])
                if self._move_next_stage(mission):
                    mission["status"] = "running"
                    return self.advance(mission)
                mission["debrief"] = self._compile_debrief(mission)
                mission["status"] = "completed"
        mission["updated_at"] = _utc_now()
        return mission

    def record_outcome(
        self,
        mission: dict[str, Any],
        *,
        action_queue_id: str = "",
        catalog_key: str = "",
        outcome: str,
        detail: str = "",
        set_flags: list[str] | None = None,
    ) -> dict[str, Any]:
        mission = copy.deepcopy(mission)
        outcome_n = str(outcome or "").strip().lower()
        matched_key = catalog_key
        for action in mission.get("action_queue") or []:
            if action_queue_id and action.get("queue_id") != action_queue_id:
                continue
            if catalog_key and action.get("catalog_key") != catalog_key and not action_queue_id:
                continue
            if action_queue_id or catalog_key:
                action["execution_outcome"] = outcome_n
                action["execution_detail"] = detail
                action["executed_at"] = _utc_now()
                matched_key = str(action.get("catalog_key") or catalog_key)
                if outcome_n in {"success", "vulnerable", "confirmed"}:
                    action["status"] = "succeeded"
                elif outcome_n in {"failed", "not_vulnerable", "patched", "denied"}:
                    action["status"] = "failed"
                break

        key_l = (matched_key or action_queue_id or "").lower()
        matched_action = None
        for action in mission.get("action_queue") or []:
            if action_queue_id and action.get("queue_id") == action_queue_id:
                matched_action = action
                break
            if not action_queue_id and catalog_key and action.get("catalog_key") == catalog_key:
                matched_action = action
                break

        kind_l = str((matched_action or {}).get("kind") or "").lower()
        if outcome_n in {"vulnerable", "success"} and "ms17" in key_l:
            if "check" in key_l or "scan" in key_l or "auxiliary" in key_l:
                self._add_flag(mission, "ms17_vulnerable")
                self._add_flag(mission, "ms17_check_done")
            if "exploit" in key_l:
                self._add_flag(mission, "ms17_exploit_succeeded")
                # Foothold still requires an attached proof artefact (not silent auto-trust).
                self._add_flag(mission, "impact_confirmed")
        if outcome_n in {"not_vulnerable", "patched"} and "ms17" in key_l:
            self._add_flag(mission, "ms17_check_done")
            flags = set(mission.get("flags") or [])
            flags.discard("ms17_vulnerable")
            mission["flags"] = sorted(flags)
            self._add_flag(mission, "ms17_not_exploitable")

        if outcome_n in {"success", "vulnerable", "confirmed"}:
            if kind_l in {"web_profile", "web"} or "web" in key_l or key_l.startswith("cmdi"):
                self._add_flag(mission, "web_impact_confirmed")
                self._add_flag(mission, "impact_confirmed")
            if kind_l in {"lateral", "lateral_technique"} or "exploit" in key_l:
                self._add_flag(mission, "impact_confirmed")

        for flag in set_flags or []:
            self._add_flag(mission, str(flag))

        self._log(
            mission,
            "outcome_recorded",
            f"{outcome_n}: {catalog_key or action_queue_id} {detail}",
        )
        results = mission.get("parsed_results_snapshot") or {}
        self._refresh_evidence_flags(mission, results)
        self._apply_branches(mission)
        mission["attack_graph"] = build_attack_graph(
            results, flags=set(mission.get("flags") or [])
        )
        mission["updated_at"] = _utc_now()
        return mission

    def validate_safe_actions(
        self,
        mission: dict[str, Any],
        *,
        detail: str = "Operator-validated safe auxiliary / non-impact probe",
        outcome: str = "success",
    ) -> dict[str, Any]:
        """Mark queued_auto non-impact actions as executed (lab closed-loop).

        Does not auto-succeed exploits, high-risk items awaiting approval, or
        pivot segments — those stay under approval + proof gates.
        """
        mission = copy.deepcopy(mission)
        outcome_n = str(outcome or "success").strip().lower() or "success"
        count = 0
        blocked_types = {"exploit"}
        for action in mission.get("action_queue") or []:
            status = str(action.get("status") or "")
            if status not in {"queued_auto"}:
                continue
            risk = str(action.get("risk") or "medium").lower()
            mtype = str(action.get("module_type") or "").lower()
            kind = str(action.get("kind") or "").lower()
            if mtype in blocked_types or kind in {"pivot_segment", "research_probe"}:
                continue
            if risk in {"critical"}:
                continue
            # high-risk only if already classified as auxiliary scan (e.g. ms17 check)
            if risk == "high" and mtype not in {"auxiliary", "scanner", "check", ""}:
                if "check" not in str(action.get("catalog_key") or "").lower():
                    continue
            action["execution_outcome"] = outcome_n
            action["execution_detail"] = detail
            action["executed_at"] = _utc_now()
            if outcome_n in {"success", "vulnerable", "confirmed", "validated"}:
                action["status"] = "succeeded"
            elif outcome_n in {"failed", "not_vulnerable", "patched", "denied"}:
                action["status"] = "failed"
            count += 1
            key_l = str(action.get("catalog_key") or "").lower()
            if outcome_n in {"not_vulnerable", "patched"} and "ms17" in key_l:
                self._add_flag(mission, "ms17_check_done")
                self._add_flag(mission, "ms17_not_exploitable")
            if outcome_n in {"vulnerable", "success"} and "ms17" in key_l and (
                "check" in key_l or mtype in {"auxiliary", "scanner", "check"}
            ):
                self._add_flag(mission, "ms17_check_done")
                if outcome_n == "vulnerable":
                    self._add_flag(mission, "ms17_vulnerable")

        self._add_flag(mission, "safe_validation_recorded")
        self._log(
            mission,
            "safe_validation_bulk",
            f"Recorded outcome={outcome_n} on {count} safe queued action(s)",
        )
        results = mission.get("parsed_results_snapshot") or {}
        self._refresh_evidence_flags(mission, results)
        self._apply_branches(mission)
        mission["attack_graph"] = build_attack_graph(
            results, flags=set(mission.get("flags") or [])
        )
        mission["updated_at"] = _utc_now()
        return mission

    def attach_proof(self, mission: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
        mission = copy.deepcopy(mission)
        proofs = list(mission.get("proofs") or [])
        proofs.append(proof)
        mission["proofs"] = proofs
        self._add_flag(mission, "foothold_proved")
        self._log(
            mission,
            "proof_attached",
            f"Proof {proof.get('proof_id')} attached — foothold_proved set",
        )
        results = mission.get("parsed_results_snapshot") or {}
        self._refresh_evidence_flags(mission, results)
        self._apply_branches(mission)
        mission["attack_graph"] = build_attack_graph(
            results, flags=set(mission.get("flags") or [])
        )
        if mission.get("status") in {"blocked_unlock", "awaiting_operator", "completed", "awaiting_approval"}:
            # Re-open pivot stage when proof arrives after premature completion
            stages = mission.get("stages") or []
            for st in stages:
                if st.get("id") == "pivot_expand" and st.get("status") in {"skipped", "pending", "completed"}:
                    if "foothold_proved" in set(mission.get("flags") or []):
                        st["status"] = "pending"
                        mission["current_stage_id"] = "pivot_expand"
            # Clear debrief so it recompiles after pivot
            if mission.get("status") == "completed":
                mission["debrief"] = None
            mission["status"] = "running"
            return self.advance(mission, parsed_results=results)
        mission["updated_at"] = _utc_now()
        return mission

    def abort(self, mission: dict[str, Any], reason: str = "") -> dict[str, Any]:
        mission = copy.deepcopy(mission)
        mission["status"] = "aborted"
        mission["debrief"] = self._compile_debrief(mission)
        self._log(mission, "mission_aborted", reason or "aborted by operator")
        mission["updated_at"] = _utc_now()
        return mission

    # ── stage runners ─────────────────────────────────────────────

    def _run_stage_actions(
        self,
        mission: dict[str, Any],
        stage: dict[str, Any],
        results: dict[str, Any],
    ) -> None:
        for action_def in stage.get("actions") or []:
            kind = str(action_def.get("kind") or "").strip()
            if kind == "ingest_scan":
                self._action_ingest_scan(mission, results)
            elif kind == "build_attack_graph":
                mission["attack_graph"] = build_attack_graph(
                    results, flags=set(mission.get("flags") or [])
                )
                self._log(
                    mission,
                    "graph_built",
                    f"Graph hosts={mission['attack_graph'].get('stats', {}).get('hosts', 0)}",
                )
            elif kind == "propose_catalog_actions":
                self._action_propose_catalog(mission, results, action_def)
            elif kind == "queue_actions":
                self._action_queue_filtered(mission, results, action_def)
            elif kind == "queue_lateral":
                self._action_queue_lateral(mission, results, action_def)
            elif kind == "evaluate_branches":
                self._refresh_evidence_flags(mission, results)
                self._apply_branches(mission)
            elif kind == "recommend_pivot":
                self._action_recommend_pivot(mission, action_def)
            elif kind == "compile_debrief":
                mission["debrief"] = self._compile_debrief(mission)
            else:
                self._log(mission, "unknown_action_kind", f"Ignored kind={kind}")

            self._mark_stage_action_done(mission, stage["id"], action_def)

    def _action_ingest_scan(self, mission: dict[str, Any], results: dict[str, Any]) -> None:
        rows = list(extract_port_evidence(results) or [])
        mission["evidence"] = {
            "host_count": len({r.target for r in rows}),
            "port_count": len(rows),
            "services": sorted({r.service for r in rows if r.service}),
        }
        self._refresh_evidence_flags(mission, results)
        self._log(
            mission,
            "scan_ingested",
            f"{mission['evidence']['host_count']} host(s), "
            f"{mission['evidence']['port_count']} port row(s)",
        )

    def _action_propose_catalog(
        self,
        mission: dict[str, Any],
        results: dict[str, Any],
        action_def: dict[str, Any],
    ) -> None:
        filt = action_def.get("filter") or {}
        catalog = get_module_catalog()
        rows = list(extract_port_evidence(results) or [])
        proposed = []
        include_types = {
            str(x).lower()
            for x in (filt.get("include_module_types") or ["auxiliary", "exploit"])
        }

        for row in rows:
            if "auxiliary" in include_types or "exploit" in include_types:
                for mod in catalog.matching_msf_modules(row):
                    if not _module_applicable_to_row(mod, row):
                        continue
                    if mod.module_type.lower() not in include_types:
                        continue
                    if mission.get("risk_posture") == "safe-only" and mod.module_type == "exploit":
                        continue
                    proposed.append(
                        self._queue_item_from_msf(mod, row, action_def, status="hypothesized")
                    )

            if filt.get("include_web_profiles") and mission.get("risk_posture") != "safe-only":
                for profile in catalog.matching_web_profiles(row):
                    proposed.append(
                        self._queue_item_from_web(profile, row, action_def, status="hypothesized")
                    )
                    self._add_flag(mission, "web_profile_matched")

            if filt.get("include_lateral"):
                for tech in catalog.matching_lateral(
                    target_type=row.target_type,
                    service=row.service,
                    port=row.port,
                    cves=list(row.cves),
                ):
                    proposed.append(
                        self._queue_item_from_lateral(tech, row, action_def, status="hypothesized")
                    )

        if filt.get("include_research_unknown"):
            research = self._detect_unknown_surfaces(rows, catalog)
            if research:
                self._add_flag(mission, "unknown_surface_present")
                mission["research_queue"] = research
                for item in research:
                    proposed.append(
                        {
                            "queue_id": _new_id("rq"),
                            "kind": "research_probe",
                            "title": item.get("title") or "Unknown surface",
                            "catalog_key": "",
                            "action_id": f"research:{item.get('target')}:{item.get('port')}",
                            "target": item.get("target"),
                            "port": item.get("port"),
                            "service": item.get("service"),
                            "risk": "info",
                            "auto": True,
                            "requires_approval": False,
                            "status": "research",
                            "reason": item.get("reason"),
                            "module_type": "research",
                            "stage_id": self._current_stage_id(mission),
                            "class_hints": item.get("recommended_class_hints") or [],
                        }
                    )

        self._merge_queue(mission, proposed)
        self._log(mission, "hypotheses_ready", f"{len(proposed)} catalog/research hypothese(s)")

    def _action_queue_filtered(
        self,
        mission: dict[str, Any],
        results: dict[str, Any],
        action_def: dict[str, Any],
    ) -> None:
        filt = action_def.get("filter") or {}
        catalog = get_module_catalog()
        rows = list(extract_port_evidence(results) or [])
        module_types = {
            str(x).lower() for x in (filt.get("module_types") or ["auxiliary"])
        }
        risks = {str(x).lower() for x in (filt.get("risks") or [])}
        require_approval = filt.get("require_approval")
        include_web = bool(filt.get("include_web_profiles"))
        queued = []
        flags = set(mission.get("flags") or [])

        for row in rows:
            for mod in catalog.matching_msf_modules(row):
                if not _module_applicable_to_row(mod, row):
                    continue
                if mod.module_type.lower() not in module_types:
                    continue
                if risks and str(mod.risk).lower() not in risks:
                    continue
                if mission.get("risk_posture") == "safe-only" and (
                    mod.module_type == "exploit" or mod.requires_approval
                ):
                    continue
                if (
                    "ms17" in mod.key
                    and mod.module_type == "exploit"
                    and flags.intersection({"ms17_not_exploitable", "branch_ms17_suppressed"})
                    and "ms17_vulnerable" not in flags
                    and "ms17_cve_evidence" not in flags
                ):
                    continue
                needs_appr = bool(
                    mod.requires_approval
                    or mod.module_type == "exploit"
                    or require_approval is True
                )
                if require_approval is False and mod.module_type != "exploit":
                    needs_appr = False
                status = "awaiting_approval" if needs_appr else "queued_auto"
                item = self._queue_item_from_msf(mod, row, action_def, status=status)
                item["auto"] = not needs_appr
                item["requires_approval"] = needs_appr
                item["stage_id"] = self._current_stage_id(mission)
                queued.append(item)

            if include_web and mission.get("risk_posture") != "safe-only":
                for profile in catalog.matching_web_profiles(row):
                    item = self._queue_item_from_web(
                        profile, row, action_def, status="awaiting_approval"
                    )
                    item["auto"] = False
                    item["requires_approval"] = True
                    item["stage_id"] = self._current_stage_id(mission)
                    queued.append(item)
                    self._add_flag(mission, "web_profile_matched")

        self._merge_queue(mission, queued, promote_hypotheses=True)
        auto_n = sum(1 for q in queued if q.get("status") == "queued_auto")
        appr_n = sum(1 for q in queued if q.get("status") == "awaiting_approval")
        self._log(mission, "actions_queued", f"queued_auto={auto_n} awaiting_approval={appr_n}")

    def _action_queue_lateral(
        self,
        mission: dict[str, Any],
        results: dict[str, Any],
        action_def: dict[str, Any],
    ) -> None:
        filt = action_def.get("filter") or {}
        exclude = {str(x) for x in (filt.get("exclude_keys") or [])}
        catalog = get_module_catalog()
        rows = list(extract_port_evidence(results) or [])
        queued = []
        for row in rows:
            matches = catalog.matching_lateral(
                target_type=row.target_type,
                service=row.service,
                port=row.port,
                cves=list(row.cves),
            )
            for tech in matches:
                if tech.key in exclude:
                    continue
                item = self._queue_item_from_lateral(
                    tech, row, action_def, status="queued_auto"
                )
                item["stage_id"] = self._current_stage_id(mission)
                queued.append(item)
        self._merge_queue(mission, queued)
        self._log(mission, "lateral_queued", f"{len(queued)} lateral technique(s)")

    def _action_recommend_pivot(
        self, mission: dict[str, Any], action_def: dict[str, Any]
    ) -> None:
        segments = list(self.playbook.get("pivot_segments") or [])
        # Allow scope override (no hardcode of lab CIDRs in Python)
        scope_segments = (mission.get("scope") or {}).get("pivot_segments")
        if isinstance(scope_segments, list) and scope_segments:
            segments = scope_segments
        for seg in segments:
            if not isinstance(seg, dict):
                continue
            item = {
                "queue_id": _new_id("pvt"),
                "kind": "pivot_segment",
                "title": f"Pivot scan {seg.get('label') or seg.get('cidr')}",
                "catalog_key": str(seg.get("id") or ""),
                "action_id": f"pivot:{seg.get('id')}",
                "target": str(seg.get("cidr") or ""),
                "port": 0,
                "service": "pivot",
                "risk": "high",
                "auto": False,
                "requires_approval": True,
                "status": "awaiting_approval",
                "reason": "Internal Ethernet segment expansion after foothold proof",
                "module_type": "pivot",
                "cidr": seg.get("cidr"),
                "stage_id": self._current_stage_id(mission),
            }
            self._merge_queue(mission, [item])
        self._log(mission, "pivot_recommended", f"{len(segments)} segment(s)")

    # ── evidence + branches ───────────────────────────────────────

    def _refresh_evidence_flags(
        self, mission: dict[str, Any], results: dict[str, Any]
    ) -> None:
        rows = list(extract_port_evidence(results) or [])
        detectors = list(self.playbook.get("evidence_detectors") or [])
        evidence_flags: dict[str, bool] = {}

        for det in detectors:
            flag = str(det.get("flag") or "").strip()
            if not flag:
                continue
            match = det.get("match") or {}
            evidence_flags[flag] = self._detector_matches(match, rows)

        for flag in mission.get("flags") or []:
            evidence_flags[str(flag)] = True

        if any(a.get("kind") == "web_profile" for a in (mission.get("action_queue") or [])):
            evidence_flags["web_profile_matched"] = True

        if mission.get("research_queue"):
            evidence_flags["unknown_surface_present"] = True

        mission["evidence_flags"] = evidence_flags
        for flag, val in evidence_flags.items():
            if val:
                self._add_flag(mission, flag)

    def _detector_matches(self, match: dict[str, Any], rows: list[PortEvidence]) -> bool:
        ports = set()
        for p in match.get("ports") or []:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
        services = {normalise_service(str(s)) for s in (match.get("services") or [])}
        cves = {str(c).upper() for c in (match.get("cves") or [])}

        if cves:
            for row in rows:
                if row.cves.intersection(cves):
                    return True
            return False

        for row in rows:
            svc = normalise_service(row.service)
            if ports and services:
                if row.port in ports or svc in services:
                    return True
            elif ports and row.port in ports:
                return True
            elif services and svc in services:
                return True
        return False

    def _apply_branches(self, mission: dict[str, Any]) -> None:
        flags = set(mission.get("flags") or [])
        evidence = {
            k for k, v in (mission.get("evidence_flags") or {}).items() if v
        }
        effective = flags | evidence
        branches = sorted(
            list(self.playbook.get("branches") or []),
            key=lambda b: -int(b.get("priority") or 0),
        )
        fired = {e.get("branch_id") for e in (mission.get("branch_events") or [])}

        for branch in branches:
            bid = str(branch.get("id") or "")
            if not bid or bid in fired:
                continue
            when = branch.get("when") or {}
            if not self._eval_condition(when, effective):
                continue
            for flag in branch.get("set_flags") or []:
                self._add_flag(mission, str(flag))
            event = {
                "branch_id": bid,
                "message": branch.get("message") or bid,
                "at": _utc_now(),
                "set_flags": list(branch.get("set_flags") or []),
            }
            mission.setdefault("branch_events", []).append(event)
            self._log(mission, "branch_fired", event["message"])
            effective = set(mission.get("flags") or []) | {
                k for k, v in (mission.get("evidence_flags") or {}).items() if v
            }

    def _eval_condition(self, node: Any, flags: set[str]) -> bool:
        if not isinstance(node, dict):
            return False
        if "flag" in node:
            return str(node["flag"]) in flags
        if "not" in node:
            return not self._eval_condition(node["not"], flags)
        if "all" in node:
            return all(self._eval_condition(x, flags) for x in (node["all"] or []))
        if "any" in node:
            return any(self._eval_condition(x, flags) for x in (node["any"] or []))
        return False

    # ── helpers ───────────────────────────────────────────────────

    def _detect_unknown_surfaces(self, rows: list[PortEvidence], catalog) -> list[dict[str, Any]]:
        research = []
        for row in rows:
            msf = catalog.matching_msf_modules(row)
            web = catalog.matching_web_profiles(row)
            if msf or web:
                continue
            research.append(
                {
                    "target": row.target,
                    "port": row.port,
                    "service": row.service or "unknown",
                    "product": row.product,
                    "title": f"Unknown surface {row.target}:{row.port}/{row.service or '?'}",
                    "reason": (
                        "No catalog module/profile matched this service. "
                        "Zero-day readiness: classify class, safe-probe only, analyst review."
                    ),
                    "recommended_class_hints": self._class_hints(row),
                }
            )
        return research

    @staticmethod
    def _class_hints(row: PortEvidence) -> list[str]:
        svc = (row.service or "").lower()
        if svc in {"http", "https", "http-alt"}:
            return ["injection", "auth_bypass", "misconfig"]
        if svc in {"smb", "microsoft-ds"}:
            return ["auth", "relay", "signing"]
        if svc in {"ssh"}:
            return ["cred_reuse", "weak_crypto"]
        return ["generic_exposure"]

    def _queue_item_from_msf(self, mod, row: PortEvidence, action_def, status: str) -> dict:
        needs_appr = bool(
            mod.requires_approval
            or mod.module_type == "exploit"
            or action_def.get("requires_approval")
        )
        return {
            "queue_id": _new_id("act"),
            "kind": "metasploit",
            "title": mod.title,
            "catalog_key": mod.key,
            "action_id": f"{mod.key}:{row.target}:{row.port}",
            "target": row.target,
            "port": row.port,
            "service": row.service,
            "risk": mod.risk,
            "module_type": mod.module_type,
            "module_name": mod.module_name,
            "auto": bool(action_def.get("auto", True)) and not needs_appr,
            "requires_approval": needs_appr,
            "status": status,
            "reason": mod.description or f"Catalog match on {row.service}/{row.port}",
            "matched_cves": sorted(row.cves),
            "stage_id": "",
            "executor": "metasploit",
        }

    def _queue_item_from_web(self, profile, row: PortEvidence, action_def, status: str) -> dict:
        return {
            "queue_id": _new_id("web"),
            "kind": "web_profile",
            "title": profile.title,
            "catalog_key": profile.key,
            "action_id": f"{profile.key}:{row.target}:{row.port}",
            "target": row.target,
            "port": row.port,
            "service": row.service or "http",
            "risk": profile.risk,
            "module_type": "web",
            "auto": False,
            "requires_approval": True,
            "status": status,
            "reason": profile.description or "Web catalog profile matched",
            "endpoint": profile.endpoint,
            "parameter": profile.parameter,
            "technique_ids": list(profile.technique_ids or []),
            "executor": "web_exploiter",
            "stage_id": "",
        }

    def _queue_item_from_lateral(self, tech, row: PortEvidence, action_def, status: str) -> dict:
        return {
            "queue_id": _new_id("lat"),
            "kind": "lateral",
            "title": tech.title,
            "catalog_key": tech.key,
            "action_id": f"{tech.key}:{row.target}:{row.port}",
            "target": row.target,
            "port": row.port,
            "service": row.service,
            "risk": "medium",
            "module_type": "lateral",
            "auto": True,
            "requires_approval": False,
            "status": status,
            "reason": tech.recommendation or tech.title,
            "command_template": tech.command_template,
            "executor": "pivot",
            "stage_id": "",
        }

    def _merge_queue(
        self,
        mission: dict[str, Any],
        items: list[dict[str, Any]],
        *,
        promote_hypotheses: bool = False,
    ) -> None:
        queue = list(mission.get("action_queue") or [])
        by_action = {
            (a.get("action_id") or a.get("queue_id")): a
            for a in queue
            if a.get("action_id") or a.get("queue_id")
        }
        for item in items:
            if not item.get("stage_id"):
                item["stage_id"] = self._current_stage_id(mission)
            key = item.get("action_id") or item.get("queue_id")
            if key in by_action:
                existing = by_action[key]
                if promote_hypotheses and existing.get("status") == "hypothesized":
                    for field in ("status", "auto", "requires_approval", "reason", "stage_id"):
                        if field in item:
                            existing[field] = item[field]
                continue
            queue.append(item)
            by_action[key] = item
        mission["action_queue"] = queue

    def _compile_debrief(self, mission: dict[str, Any]) -> dict[str, Any]:
        queue = mission.get("action_queue") or []
        proofs = mission.get("proofs") or []
        flags = set(mission.get("flags") or [])
        suppressed = [
            a
            for a in queue
            if a.get("status") in {"skipped", "failed"}
        ]
        blue = []
        for tpl in self.playbook.get("blue_team_timeline_templates") or []:
            stage_id = tpl.get("stage")
            stage_rec = next(
                (s for s in (mission.get("stages") or []) if s.get("id") == stage_id),
                None,
            )
            if stage_rec and stage_rec.get("status") in {"completed", "active", "skipped"}:
                blue.append(
                    {
                        "stage": stage_id,
                        "alert": tpl.get("alert"),
                        "severity": tpl.get("severity"),
                        "response": tpl.get("response"),
                    }
                )

        goal_met = "partial"
        if proofs and flags.intersection({"foothold_proved"}):
            goal_met = "met"
        elif mission.get("status") == "aborted":
            goal_met = "aborted"

        return {
            "goal": mission.get("goal"),
            "goal_status": goal_met,
            "playbook_id": mission.get("playbook_id"),
            "flags": sorted(flags),
            "branch_events": list(mission.get("branch_events") or []),
            "proofs": list(proofs),
            "confirmed_findings_count": len(proofs),
            "suppressed_or_failed": [
                {
                    "title": a.get("title"),
                    "catalog_key": a.get("catalog_key"),
                    "status": a.get("status"),
                    "reason": a.get("reason"),
                }
                for a in suppressed
            ],
            "research_queue": list(mission.get("research_queue") or []),
            "action_summary": {
                "total": len(queue),
                "queued_auto": sum(1 for a in queue if a.get("status") == "queued_auto"),
                "approved": sum(1 for a in queue if a.get("status") == "approved"),
                "awaiting_approval": sum(
                    1 for a in queue if a.get("status") == "awaiting_approval"
                ),
                "succeeded": sum(1 for a in queue if a.get("status") == "succeeded"),
                "research": sum(1 for a in queue if a.get("status") == "research"),
            },
            "blue_team_timeline": blue,
            "attack_graph_stats": (mission.get("attack_graph") or {}).get("stats") or {},
            "professional_notes": self._professional_notes(mission, flags),
            "compiled_at": _utc_now(),
        }

    @staticmethod
    def _professional_notes(mission: dict[str, Any], flags: set[str]) -> list[str]:
        notes = []
        if "ms17_not_exploitable" in flags or "branch_ms17_suppressed" in flags:
            notes.append(
                "MS17-010/EternalBlue class path suppressed — target not evidenced as vulnerable. "
                "This is a correct automated outcome, not a tool failure."
            )
        if "unknown_surface_present" in flags:
            notes.append(
                "Unknown surfaces entered research queue (zero-day readiness). "
                "No exploit modules were invented by the LLM or browser."
            )
        if "foothold_proved" in flags:
            notes.append("At least one proof-of-impact artifact is on record.")
        if "impact_confirmed" in flags and "foothold_proved" not in flags:
            notes.append(
                "Impact was operator-confirmed but no foothold proof artefact is on file — "
                "pivot stayed locked (correct custody)."
            )
        queue = mission.get("action_queue") or []
        still_auto = sum(1 for a in queue if a.get("status") == "queued_auto")
        if still_auto:
            notes.append(
                f"{still_auto} safe action(s) remained queued_auto at debrief — "
                "use Validate safe queue or wire live MSF callbacks for full evidence closure."
            )
        if mission.get("risk_posture") == "safe-only":
            notes.append("Mission ran under safe-only posture — impact actions never queued.")
        if not notes:
            notes.append(
                "Mission followed evidence-closed-loop orchestration with catalog custody of modules."
            )
        return notes

    def _current_stage_def(self, mission: dict[str, Any]) -> dict[str, Any] | None:
        sid = mission.get("current_stage_id")
        for stage in self.playbook.get("stages") or []:
            if stage.get("id") == sid:
                return stage
        return None

    def _current_stage_id(self, mission: dict[str, Any]) -> str:
        return str(mission.get("current_stage_id") or "")

    def _activate_stage(self, mission: dict[str, Any], stage_id: str) -> None:
        for stage in mission.get("stages") or []:
            if stage.get("id") == stage_id and stage.get("status") == "pending":
                stage["status"] = "active"
                stage["started_at"] = _utc_now()
                self._log(mission, "stage_active", f"Entered stage {stage.get('title')}")

    def _complete_stage(
        self, mission: dict[str, Any], stage_id: str, *, skipped: bool = False
    ) -> None:
        for stage in mission.get("stages") or []:
            if stage.get("id") == stage_id:
                stage["status"] = "skipped" if skipped else "completed"
                stage["completed_at"] = _utc_now()

    def _move_next_stage(self, mission: dict[str, Any]) -> bool:
        stages = sorted(
            list(self.playbook.get("stages") or []),
            key=lambda s: int(s.get("order") or 0),
        )
        ids = [s["id"] for s in stages]
        cur = mission.get("current_stage_id")
        try:
            idx = ids.index(cur)
        except ValueError:
            return False
        if idx + 1 >= len(ids):
            return False
        mission["current_stage_id"] = ids[idx + 1]
        mission["stage_index"] = idx + 1
        return True

    def _can_skip_locked_stage(
        self, mission: dict[str, Any], stage: dict[str, Any]
    ) -> bool:
        """Skip locked stages only when they are structurally unreachable.

        Pivot stays blocked until foothold proof when an impact path was taken —
        so attach_proof can reopen expansion instead of rushing to debrief.
        """
        sid = stage.get("id")
        flags = set(mission.get("flags") or [])
        if sid == "impact_gate" and "impact_path_available" not in flags:
            return True
        if sid == "alternate_lateral" and "alternate_lateral_enabled" not in flags:
            return True
        if sid == "pivot_expand" and "foothold_proved" not in flags:
            # If operator earlier approved an impact path, wait for proof.
            if flags.intersection(
                {
                    "web_path_approved",
                    "ms17_exploit_approved",
                    "impact_path_available",
                    "pivot_ready",
                }
            ):
                return False
            return True
        return False

    def _should_force_skip_to_debrief(
        self, mission: dict[str, Any], stage: dict[str, Any]
    ) -> bool:
        # Never auto force-skip pivot; operator continue or abort decides.
        if stage.get("id") == "pivot_expand":
            return False
        return self._can_skip_locked_stage(mission, stage)

    def _mark_stage_action_done(
        self, mission: dict[str, Any], stage_id: str, action_def: dict[str, Any]
    ) -> None:
        for stage in mission.get("stages") or []:
            if stage.get("id") != stage_id:
                continue
            done = list(stage.get("completed_actions") or [])
            aid = action_def.get("id") or action_def.get("kind")
            if aid not in done:
                done.append(aid)
            stage["completed_actions"] = done

    def _add_flag(self, mission: dict[str, Any], flag: str) -> None:
        flag = str(flag or "").strip()
        if not flag:
            return
        flags = list(mission.get("flags") or [])
        if flag not in flags:
            flags.append(flag)
            mission["flags"] = flags

    def _log(self, mission: dict[str, Any], kind: str, message: str) -> None:
        mission.setdefault("event_log", []).append(
            {"at": _utc_now(), "kind": kind, "message": message}
        )
        if len(mission["event_log"]) > 500:
            mission["event_log"] = mission["event_log"][-500:]

    @staticmethod
    def _thin_results(parsed_results: dict[str, Any] | None) -> dict[str, Any]:
        if not parsed_results:
            return {}
        keep_keys = {
            "target",
            "target_ip",
            "hosts",
            "ports",
            "services",
            "os",
            "web_inventory",
            "cves",
            "vulnerabilities",
        }
        thin = {k: parsed_results[k] for k in keep_keys if k in parsed_results}
        if not thin and "ports" in parsed_results:
            thin = {"ports": parsed_results.get("ports")}
        if not thin:
            thin = {
                k: parsed_results[k]
                for k in list(parsed_results)[:20]
                if not str(k).startswith("raw")
            }
        return thin
