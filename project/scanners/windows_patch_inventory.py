from __future__ import annotations

"""Local, operator-supplied Windows build and patch evidence.

This collector never authenticates to a target, opens a remote session,
queries WMI/DCOM, reads Remote Registry, or accepts credentials. The operator
may export a small JSON inventory locally on an authorised Windows host and
place it in ``WINDOWS_INVENTORY_DIR`` before scanning.
"""

from datetime import datetime, timezone
from typing import Any

from .windows_inventory import load_authorised_inventory


COLLECTOR_ID = "windows_patch_inventory"


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


def windows_target_applicability(
    identities: list[dict[str, Any]] | None,
) -> tuple[str, str]:
    rows = list(identities or [])
    if not rows:
        return (
            "unknown",
            "Host operating-system identity was not established; local inventory may resolve it.",
        )
    blobs = [
        " ".join(
            _text(row.get(key)).lower()
            for key in ("vendor", "family", "product", "name", "raw")
        )
        for row in rows
    ]
    if any(
        "windows" in blob or ("microsoft" in blob and "linux" not in blob)
        for blob in blobs
    ):
        return "applicable", "Observed host evidence indicates Microsoft Windows."
    non_windows = (
        "linux", "ubuntu", "debian", "red hat", "rhel", "centos", "fedora",
        "darwin", "macos", "mac os", "freebsd", "openbsd", "netbsd",
        "solaris", "aix",
    )
    if any(any(token in blob for token in non_windows) for blob in blobs):
        return "not_applicable", "Observed host evidence indicates a non-Windows OS."
    return "unknown", "Host operating-system identity remains ambiguous."


def collect_windows_patch_inventory(
    target: str,
    *,
    timeout_seconds: int = 30,
    **_compatibility_arguments: Any,
) -> dict[str, Any]:
    """Load a whitelisted local inventory record for ``target``.

    ``timeout_seconds`` and extra keyword arguments are accepted only for
    compatibility with the existing collector interface; no network operation
    is performed.
    """
    base: dict[str, Any] = {
        "collector": COLLECTOR_ID,
        "host": str(target),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "method": "operator-supplied local Windows inventory JSON",
        "credential_source": "none",
        "mutates_target": False,
        "remote_session_opened": False,
    }
    records = load_authorised_inventory([str(target)])
    record = next(
        (item for item in records if str(item.get("host") or "") == str(target)),
        None,
    )
    if not record:
        return {
            **base,
            "ok": False,
            "status": "deferred",
            "lifecycle_state": "deferred",
            "message": (
                "No operator-supplied Windows inventory matched this host. "
                "Set WINDOWS_INVENTORY_DIR to a directory containing an exported JSON record."
            ),
        }

    product = _text(record.get("product"))
    build = _text(record.get("build"))
    installed_kbs = sorted({
        _text(value).upper()
        for value in record.get("installed_kbs") or []
        if _text(value)
    })
    return {
        **base,
        "ok": bool(product or build or installed_kbs),
        "status": "collected",
        "lifecycle_state": "executed_evidence",
        "message": "Local Windows identity and patch evidence was retained.",
        "product": product,
        "edition": _text(record.get("edition")),
        "release": _text(record.get("display_version")),
        "version": build,
        "build": build,
        "ubr": "",
        "architecture": _text(record.get("architecture")),
        "hostname": "",
        "domain": "",
        "installed_kbs": installed_kbs,
        "installed_updates": [{"kb": kb} for kb in installed_kbs],
        "hotfix_count": len(installed_kbs),
        "registry_evidence_status": "not_applicable",
        "source_file": _text(record.get("source_file")),
        "evidence_limitations": [
            "Inventory reflects the operator-supplied export time.",
            "Only whitelisted OS identity and KB fields are retained.",
            "No remote credential or target session is used.",
        ],
    }


def inventory_host_identity(
    inventory: dict[str, Any],
    evidence_reference: str = "",
) -> dict[str, Any] | None:
    if not inventory.get("ok"):
        return None
    product = _text(inventory.get("product"))
    version = _text(inventory.get("version"))
    build = _text(inventory.get("build"))
    if not (product or version or build):
        return None
    return {
        "host": _text(inventory.get("host")),
        "scope": "host_os",
        "name": product,
        "vendor": "Microsoft" if "windows" in product.lower() else "",
        "family": "Windows" if "windows" in product.lower() else "",
        "product": product,
        "version": version,
        "build": build,
        "release": _text(inventory.get("release")),
        "architecture": _text(inventory.get("architecture")),
        "hostnames": [],
        "domains": [],
        "source": COLLECTOR_ID,
        "evidence_kind": "operator_inventory",
        "evidence_reference": evidence_reference,
        "installed_kbs": list(inventory.get("installed_kbs") or []),
        "raw": (
            "Operator-supplied local Windows inventory; "
            f"build={build}; version={version}; hotfixes={inventory.get('hotfix_count', 0)}"
        ),
    }
