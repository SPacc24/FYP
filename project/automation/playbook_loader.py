"""Load mission playbooks from policies/playbooks (JSON only)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "policies" / "playbooks"


class PlaybookLoadError(ValueError):
    """Raised when playbook JSON is missing or invalid."""


def _playbook_dir(path: str | Path | None = None) -> Path:
    if path:
        return Path(path)
    return DEFAULT_PLAYBOOK_DIR


def list_playbooks(playbook_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """Return registry entries from index.json (fallback: scan *.json)."""
    root = _playbook_dir(playbook_dir)
    index_path = root / "index.json"
    if index_path.is_file():
        data = json.loads(index_path.read_text(encoding="utf-8"))
        entries = []
        for item in data.get("playbooks") or []:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            entries.append(
                {
                    "id": str(item["id"]),
                    "title": str(item.get("title") or item["id"]),
                    "path": str(item.get("path") or f"{item['id']}.json"),
                    "default": bool(item.get("default")),
                }
            )
        if entries:
            return entries

    entries = []
    for path in sorted(root.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        pid = str(raw.get("id") or path.stem)
        entries.append(
            {
                "id": pid,
                "title": str(raw.get("title") or pid),
                "path": path.name,
                "default": False,
            }
        )
    return entries


def default_playbook_id(playbook_dir: str | Path | None = None) -> str:
    entries = list_playbooks(playbook_dir)
    for entry in entries:
        if entry.get("default"):
            return entry["id"]
    if entries:
        return entries[0]["id"]
    raise PlaybookLoadError("No playbooks registered in policies/playbooks")


@lru_cache(maxsize=16)
def _load_playbook_cached(playbook_id: str, root_str: str) -> str:
    """Cache raw JSON text; parse outside cache for mutability safety."""
    root = Path(root_str)
    entries = {e["id"]: e for e in list_playbooks(root)}
    if playbook_id not in entries:
        # Allow direct filename stem load
        candidate = root / f"{playbook_id}.json"
        if not candidate.is_file():
            raise PlaybookLoadError(f"Unknown playbook id: {playbook_id}")
        return candidate.read_text(encoding="utf-8")
    path = root / entries[playbook_id]["path"]
    if not path.is_file():
        raise PlaybookLoadError(f"Playbook file missing: {path}")
    return path.read_text(encoding="utf-8")


def load_playbook(
    playbook_id: str | None = None,
    playbook_dir: str | Path | None = None,
) -> dict[str, Any]:
    root = _playbook_dir(playbook_dir)
    pid = playbook_id or default_playbook_id(root)
    raw = _load_playbook_cached(pid, str(root.resolve()))
    data = json.loads(raw)
    if not isinstance(data, dict) or not data.get("id"):
        raise PlaybookLoadError(f"Invalid playbook document: {pid}")
    data.setdefault("stages", [])
    data.setdefault("branches", [])
    data.setdefault("evidence_detectors", [])
    data.setdefault("pivot_segments", [])
    data.setdefault("blue_team_timeline_templates", [])
    return data


def reload_playbooks() -> None:
    _load_playbook_cached.cache_clear()
