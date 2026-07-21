"""Persist missions and orchestrate PlaybookEngine + ProofStore."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from automation.playbook_engine import PlaybookEngine
from automation.playbook_loader import default_playbook_id, list_playbooks, load_playbook
from automation.proof_store import ProofStore

PROJECT_DIR = Path(__file__).resolve().parents[1]


def _writable_dir(env_name: str, default: Path, fallback: Path) -> Path:
    configured = os.getenv(env_name)
    candidates = [Path(configured)] if configured else []
    candidates.extend([default, fallback])
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue
    raise PermissionError(f"No writable storage directory found for {env_name}")


class MissionService:
    """File-backed mission store with thread-safe CRUD."""

    def __init__(
        self,
        missions_dir: str | Path | None = None,
        proofs_dir: str | Path | None = None,
    ) -> None:
        self.missions_dir = (
            Path(missions_dir)
            if missions_dir
            else _writable_dir(
                "AUTOPENTEST_MISSIONS_DIR",
                PROJECT_DIR / "storage" / "missions",
                Path("/tmp/autopentest/missions"),
            )
        )
        self.proofs = ProofStore(
            proofs_dir
            or _writable_dir(
                "AUTOPENTEST_PROOFS_DIR",
                PROJECT_DIR / "storage" / "proofs",
                Path("/tmp/autopentest/proofs"),
            )
        )
        self._lock = threading.RLock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        for path in sorted(self.missions_dir.glob("msn_*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            mid = str(data.get("mission_id") or path.stem)
            self._cache[mid] = data

    def _path(self, mission_id: str) -> Path:
        return self.missions_dir / f"{mission_id}.json"

    def _persist(self, mission: dict[str, Any]) -> dict[str, Any]:
        mid = str(mission.get("mission_id") or "")
        if not mid:
            raise ValueError("mission_id required")
        # Drop bulky optional raw blobs occasionally present
        payload = dict(mission)
        path = self._path(mid)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        self._cache[mid] = payload
        return payload

    def list_playbooks(self) -> list[dict[str, Any]]:
        return list_playbooks()

    def list_missions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._cache.values())
        items.sort(key=lambda m: str(m.get("updated_at") or m.get("created_at") or ""), reverse=True)
        slim = []
        for m in items[: max(1, limit)]:
            slim.append(
                {
                    "mission_id": m.get("mission_id"),
                    "playbook_id": m.get("playbook_id"),
                    "playbook_title": m.get("playbook_title"),
                    "status": m.get("status"),
                    "risk_posture": m.get("risk_posture"),
                    "current_stage_id": m.get("current_stage_id"),
                    "created_at": m.get("created_at"),
                    "updated_at": m.get("updated_at"),
                    "scan_id": m.get("scan_id"),
                    "flags": m.get("flags") or [],
                    "pending_approvals": len(
                        [a for a in (m.get("action_queue") or []) if a.get("status") == "awaiting_approval"]
                    ),
                    "proof_count": len(m.get("proofs") or []),
                }
            )
        return slim

    def get(self, mission_id: str) -> dict[str, Any] | None:
        with self._lock:
            m = self._cache.get(mission_id)
            if m:
                return json.loads(json.dumps(m))  # deep copy via json
            path = self._path(mission_id)
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self._cache[mission_id] = data
                return json.loads(json.dumps(data))
        return None

    def start(
        self,
        *,
        playbook_id: str | None = None,
        parsed_results: dict[str, Any] | None = None,
        scope: dict[str, Any] | None = None,
        risk_posture: str | None = None,
        scan_id: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        pid = playbook_id or default_playbook_id()
        engine = PlaybookEngine(playbook_id=pid)
        with self._lock:
            mission = engine.start_mission(
                parsed_results=parsed_results,
                scope=scope,
                risk_posture=risk_posture,
                scan_id=scan_id,
                notes=notes,
            )
            return self._persist(mission)

    def advance(
        self,
        mission_id: str,
        *,
        parsed_results: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.advance(mission, parsed_results=parsed_results)
            return self._persist(updated)

    def continue_mission(
        self,
        mission_id: str,
        *,
        parsed_results: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.continue_mission(mission, parsed_results=parsed_results)
            return self._persist(updated)

    def approve(
        self,
        mission_id: str,
        action_queue_id: str,
        *,
        approved: bool = True,
        operator_note: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.approve_action(
                mission,
                action_queue_id,
                approved=approved,
                operator_note=operator_note,
            )
            return self._persist(updated)

    def record_outcome(
        self,
        mission_id: str,
        *,
        action_queue_id: str = "",
        catalog_key: str = "",
        outcome: str,
        detail: str = "",
        set_flags: list[str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.record_outcome(
                mission,
                action_queue_id=action_queue_id,
                catalog_key=catalog_key,
                outcome=outcome,
                detail=detail,
                set_flags=set_flags,
            )
            return self._persist(updated)

    def attach_proof(
        self,
        mission_id: str,
        *,
        action_id: str = "",
        catalog_key: str = "",
        target: str = "",
        technique_ids: list[str] | None = None,
        proof_type: str = "operator_attested",
        evidence: str = "",
        artifact_path: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            proof = self.proofs.record(
                mission_id=mission_id,
                action_id=action_id,
                catalog_key=catalog_key,
                target=target,
                technique_ids=technique_ids,
                proof_type=proof_type,
                evidence=evidence,
                artifact_path=artifact_path,
                extra=extra,
            )
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.attach_proof(mission, proof)
            return self._persist(updated)

    def abort(self, mission_id: str, reason: str = "") -> dict[str, Any]:
        with self._lock:
            mission = self.get(mission_id)
            if not mission:
                raise KeyError(mission_id)
            engine = PlaybookEngine(playbook_id=mission.get("playbook_id"))
            updated = engine.abort(mission, reason=reason)
            return self._persist(updated)

    def delete(self, mission_id: str) -> bool:
        with self._lock:
            self._cache.pop(mission_id, None)
            path = self._path(mission_id)
            if path.is_file():
                path.unlink()
                return True
            return False


_SERVICE: MissionService | None = None
_SERVICE_LOCK = threading.Lock()


def get_mission_service() -> MissionService:
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = MissionService()
        return _SERVICE


def reset_mission_service() -> None:
    """Test helper."""
    global _SERVICE
    with _SERVICE_LOCK:
        _SERVICE = None
