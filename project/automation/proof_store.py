"""Proof-of-impact objects — no proof, no confirmed finding."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_PROOF_DIR = Path(__file__).resolve().parent.parent / "storage" / "proofs"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


class ProofStore:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else DEFAULT_PROOF_DIR
        _safe_mkdir(self.root)

    def record(
        self,
        *,
        mission_id: str,
        action_id: str = "",
        catalog_key: str = "",
        target: str = "",
        technique_ids: list[str] | None = None,
        proof_type: str = "operator_attested",
        evidence: str = "",
        artifact_path: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        proof_id = f"proof_{secrets.token_hex(8)}"
        payload = {
            "proof_id": proof_id,
            "mission_id": mission_id,
            "action_id": action_id,
            "catalog_key": catalog_key,
            "target": target,
            "technique_ids": list(technique_ids or []),
            "proof_type": proof_type,
            "evidence": str(evidence or "")[:4000],
            "artifact_path": artifact_path,
            "created_at": _utc_now(),
            "extra": extra or {},
        }
        path = self.root / f"{mission_id}_{proof_id}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        payload["storage_path"] = str(path)
        return payload

    def list_for_mission(self, mission_id: str) -> list[dict[str, Any]]:
        out = []
        for path in sorted(self.root.glob(f"{mission_id}_proof_*.json")):
            try:
                out.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return out
