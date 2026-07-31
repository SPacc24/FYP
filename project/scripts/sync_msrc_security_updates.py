#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanners.msrc_client import lookup_cve_remediations, status, sync_recent_months

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def recent_release_ids(count: int) -> list[str]:
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month
    out: list[str] = []
    for _ in range(max(1, min(int(count), 36))):
        out.append(f"{year:04d}-{MONTHS[month - 1]}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Cache Microsoft Security Update Guide CVRF remediation data.")
    parser.add_argument("--cve", action="append", default=[], help="Targeted CVE remediation lookup; may be repeated.")
    parser.add_argument("--months", type=int, default=3, help="Recent monthly CVRF documents to cache when no --cve is supplied (default: 3).")
    parser.add_argument("--force", action="store_true", help="Bypass the normal local cache TTL.")
    args = parser.parse_args()

    if args.cve:
        rows = []
        for cve_id in args.cve:
            remediations, diagnostic = lookup_cve_remediations(cve_id, force=args.force)
            rows.append({"cve_id": cve_id.upper(), "remediation_count": len(remediations), "diagnostic": diagnostic})
        result = {"mode": "targeted_cve", "lookups": rows, "status": status()}
    else:
        release_ids = recent_release_ids(args.months)
        result = {"mode": "recent_months", "release_ids": release_ids, "sync": sync_recent_months(release_ids, force=args.force), "status": status()}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.cve:
        statuses = [str((row.get("diagnostic") or {}).get("status") or "") for row in result.get("lookups") or []]
        return 0 if any(value in {"available", "no_remediation_metadata"} for value in statuses) else 2
    return 0 if bool((result.get("sync") or {}).get("available")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
