from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable


KB_PATTERN = re.compile(r"^KB\d{5,8}$", re.I)


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _normalise_record(raw: dict[str, Any], source_file: Path) -> dict[str, Any] | None:
    host = _text(raw.get("host") or raw.get("computer_ip") or raw.get("ip"))
    if not host:
        return None
    product = _text(raw.get("ProductName") or raw.get("product_name") or raw.get("product"))
    edition = _text(raw.get("EditionID") or raw.get("edition"))
    display_version = _text(raw.get("DisplayVersion") or raw.get("display_version"))
    current_build = _text(raw.get("CurrentBuildNumber") or raw.get("current_build"))
    ubr = _text(raw.get("UBR") or raw.get("ubr"))
    build = current_build
    if current_build and ubr and not current_build.endswith(f".{ubr}"):
        build = f"{current_build}.{ubr}"
    installed = raw.get("HotFixIDs") or raw.get("installed_kbs") or raw.get("hotfixes") or []
    if isinstance(installed, str):
        installed = re.split(r"[\s,;]+", installed)
    installed_kbs = sorted({
        str(value).upper()
        for value in installed
        if KB_PATTERN.fullmatch(str(value).strip())
    })
    return {
        "host": host,
        "product": product,
        "edition": edition,
        "display_version": display_version,
        "build": build,
        "architecture": _text(raw.get("OSArchitecture") or raw.get("architecture")),
        "installed_kbs": installed_kbs,
        "source_file": str(source_file),
    }


def load_authorised_inventory(hosts: Iterable[str]) -> list[dict[str, Any]]:
    """Load optional read-only inventory exported by an authorised operator.

    This module never accepts or stores credentials and never initiates a
    remote session. Only whitelisted identity and hotfix fields are retained.
    """
    directory_value = os.getenv("WINDOWS_INVENTORY_DIR", "").strip()
    if not directory_value:
        return []
    directory = Path(directory_value).expanduser()
    if not directory.is_dir():
        return []
    allowed_hosts = {str(host) for host in hosts}
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        values = payload if isinstance(payload, list) else [payload]
        for value in values:
            if not isinstance(value, dict):
                continue
            record = _normalise_record(value, path)
            if record and record["host"] in allowed_hosts:
                records.append(record)
    return records


def merge_inventory(
    identities: list[dict[str, Any]],
    inventory: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_host = {str(identity.get("host") or ""): dict(identity) for identity in identities}
    for record in inventory:
        host = str(record.get("host") or "")
        if not host:
            continue
        identity = by_host.setdefault(host, {
            "host": host,
            "vendor": "Microsoft",
            "product": "",
            "version": "",
            "build": "",
            "cpe": [],
            "computer_names": [],
            "domains": [],
            "evidence_sources": [],
            "evidence_gaps": [],
        })
        for field in ("product", "edition", "display_version", "build", "architecture"):
            if record.get(field):
                identity[field] = record[field]
        if record.get("build"):
            identity["version"] = record["build"]
        identity["installed_kbs"] = list(record.get("installed_kbs") or [])
        identity["patch_inventory_observed"] = True
        identity["identity_basis"] = "authorised_read_only_windows_inventory"
        identity.setdefault("evidence_sources", []).append({
            "source": "operator_supplied_windows_inventory",
            "evidence_file": record.get("source_file"),
            "retained_fields": [
                "product",
                "edition",
                "display_version",
                "build",
                "architecture",
                "installed_kbs",
            ],
        })
        gaps = [
            gap
            for gap in identity.get("evidence_gaps") or []
            if gap != "installed_kb_inventory_not_observed"
        ]
        identity["evidence_gaps"] = gaps
    return [by_host[host] for host in sorted(by_host)]
