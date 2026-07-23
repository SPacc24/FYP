#!/usr/bin/env python3
"""RQ1–RQ3 evaluation harness: three evidence conditions + naive baseline.

Run from project/ :
  python scripts/run_orchestration_evaluation.py
  python scripts/run_orchestration_evaluation.py --out storage/reports/eval_latest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _fixture_web_smb(target: str = "10.10.10.20") -> dict[str, Any]:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [
                    {"port": 80, "state": "open", "service": "http", "product": "Apache"},
                    {"port": 445, "state": "open", "service": "microsoft-ds", "product": "Windows"},
                    {"port": 22, "state": "open", "service": "ssh"},
                ],
            }
        ],
    }


def _fixture_ms17_cve(target: str = "10.10.10.30") -> dict[str, Any]:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [{"port": 445, "state": "open", "service": "microsoft-ds"}],
            }
        ],
        "vulnerabilities": [{"host": target, "port": 445, "cve": "CVE-2017-0144"}],
    }


def _fixture_unknown(target: str = "10.10.10.40") -> dict[str, Any]:
    return {
        "target": target,
        "hosts": [
            {
                "ip": target,
                "ports": [
                    {
                        "port": 31337,
                        "state": "open",
                        "service": "custom-proto",
                        "product": "LabApp",
                    }
                ],
            }
        ],
    }


def _naive_unsupported_exploit_pressure(results: dict[str, Any]) -> dict[str, Any]:
    """Baseline: naive policy would pressure exploits/lateral moves without gating."""
    from exploitation.module_catalog import extract_port_evidence, get_module_catalog

    catalog = get_module_catalog()
    rows = list(extract_port_evidence(results) or [])
    would_attempt: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []

    cves_present = {
        str(v.get("cve") or "").upper()
        for v in (results.get("vulnerabilities") or [])
        if isinstance(v, dict)
    }

    def _is_ms17_class(key: str, title: str) -> bool:
        text = f"{key} {title}".lower()
        return "ms17" in text or "eternal" in text or "cve-2017-0144" in text

    for row in rows:
        # Naive Metasploit path: any matched exploit module would be queued.
        for mod in catalog.matching_msf_modules(row):
            if str(mod.module_type).lower() != "exploit":
                continue
            entry = {
                "key": mod.key,
                "module": getattr(mod, "module", None) or getattr(mod, "path", None),
                "host": row.target,
                "port": row.port,
                "source": "msf_exploit",
            }
            would_attempt.append(entry)
            row_cves = {str(c).upper() for c in (row.cves or [])}
            all_cves = row_cves | cves_present
            if _is_ms17_class(mod.key, getattr(mod, "title", "")) and not all_cves:
                unsupported.append(entry)
            elif not all_cves and getattr(mod, "requires_approval", True):
                unsupported.append(entry)

        # Naive lateral path: catalog lists MS17-010 as a lateral technique,
        # so a naive planner that follows service-to-technique mappings would
        # attempt it without waiting for CVE evidence.
        for tech in catalog.matching_lateral(
            target_type=row.target_type,
            service=row.service,
            port=row.port,
            cves=row.cves,
        ):
            entry = {
                "key": tech.key,
                "module": getattr(tech, "command", None) or getattr(tech, "tool", None),
                "host": row.target,
                "port": row.port,
                "source": "lateral_technique",
            }
            if _is_ms17_class(tech.key, getattr(tech, "title", "")):
                would_attempt.append(entry)
                row_cves = {str(c).upper() for c in (row.cves or [])}
                if not (row_cves | cves_present):
                    unsupported.append(entry)

    return {
        "would_attempt_exploits": len(would_attempt),
        "unsupported_exploit_pressure": len(unsupported),
        "unsupported_keys": sorted({u["key"] for u in unsupported}),
        "would_attempt_keys": sorted({u["key"] for u in would_attempt}),
    }


def _path_signature(mission: dict[str, Any]) -> str:
    flags = sorted(str(f) for f in (mission.get("flags") or []))
    kinds = sorted(
        {
            f"{a.get('kind')}:{a.get('status')}:{a.get('module_type') or ''}"
            for a in (mission.get("action_queue") or [])
        }
    )
    research_n = len(mission.get("research_queue") or [])
    blob = json.dumps({"flags": flags, "kinds": kinds, "research": research_n}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _summarise_mission(mission: dict[str, Any]) -> dict[str, Any]:
    queue = mission.get("action_queue") or []
    high_risk_auto = [
        a
        for a in queue
        if str(a.get("module_type") or "").lower() == "exploit"
        and a.get("status") == "queued_auto"
    ]
    exploit_awaiting = [
        a
        for a in queue
        if str(a.get("module_type") or "").lower() == "exploit"
        and a.get("status") == "awaiting_approval"
    ]
    return {
        "mission_id": mission.get("mission_id"),
        "status": mission.get("status"),
        "flags": sorted(mission.get("flags") or []),
        "research_queue_size": len(mission.get("research_queue") or []),
        "queued_auto": sum(1 for a in queue if a.get("status") == "queued_auto"),
        "awaiting_approval": sum(1 for a in queue if a.get("status") == "awaiting_approval"),
        "high_risk_auto_count": len(high_risk_auto),
        "exploit_awaiting_approval": len(exploit_awaiting),
        "path_signature": _path_signature(mission),
        "branch_events": list(mission.get("branch_events") or []),
    }


def run_evaluation() -> dict[str, Any]:
    tmp = tempfile.mkdtemp(prefix="autopentest_eval_")
    os.environ["AUTOPENTEST_MISSIONS_DIR"] = str(Path(tmp) / "missions")
    os.environ["AUTOPENTEST_PROOFS_DIR"] = str(Path(tmp) / "proofs")

    from automation import mission_service as ms
    from automation.playbook_engine import PlaybookEngine

    ms.reset_mission_service()

    conditions = {
        "C_web_smb_no_cve": _fixture_web_smb(),
        "C_smb_ms17_cve": _fixture_ms17_cve(),
        "C_unknown_surface": _fixture_unknown(),
    }

    rows: dict[str, Any] = {}
    for name, fixture in conditions.items():
        engine = PlaybookEngine(playbook_id="edge_to_internal_proof")
        mission = engine.start_mission(parsed_results=fixture)
        gated = _summarise_mission(mission)
        naive = _naive_unsupported_exploit_pressure(fixture)
        flags = set(gated["flags"])
        rows[name] = {
            "gated": gated,
            "naive_baseline": naive,
            "rq1_gated_beats_naive": (
                gated["high_risk_auto_count"] == 0
                and naive["unsupported_exploit_pressure"]
                >= 0  # always true; real win checked below for web_smb
            ),
            "ms17_suppressed": bool(
                flags.intersection({"branch_ms17_suppressed", "ms17_not_exploitable"})
            ),
            "unknown_research": gated["research_queue_size"] > 0,
        }

    signatures = {name: rows[name]["gated"]["path_signature"] for name in rows}
    distinct = len(set(signatures.values()))

    web = rows["C_web_smb_no_cve"]
    rq1_pass = (
        web["naive_baseline"]["unsupported_exploit_pressure"]
        > web["gated"]["high_risk_auto_count"]
        and web["gated"]["high_risk_auto_count"] == 0
        and (
            web["ms17_suppressed"]
            or web["naive_baseline"]["unsupported_exploit_pressure"] == 0
        )
    )
    # Stronger RQ1: naive would pressure ms17-class without CVE, gated does not auto it
    if web["naive_baseline"]["unsupported_exploit_pressure"] > 0:
        rq1_pass = web["gated"]["high_risk_auto_count"] == 0 and web["ms17_suppressed"]

    rq2_pass = distinct >= 3
    rq3_pass = all(rows[n]["gated"]["high_risk_auto_count"] == 0 for n in rows)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "playbook_id": "edge_to_internal_proof",
        "conditions": rows,
        "path_signatures": signatures,
        "distinct_path_signatures": distinct,
        "research_questions": {
            "RQ1_unsupported_exploit_pressure": {
                "pass": rq1_pass,
                "detail": {
                    "naive_unsupported": web["naive_baseline"]["unsupported_exploit_pressure"],
                    "gated_high_risk_auto": web["gated"]["high_risk_auto_count"],
                    "ms17_suppressed": web["ms17_suppressed"],
                },
            },
            "RQ2_path_diversity": {
                "pass": rq2_pass,
                "distinct": distinct,
                "signatures": signatures,
            },
            "RQ3_zero_high_risk_auto": {
                "pass": rq3_pass,
            },
        },
        "overall_pass": bool(rq1_pass and rq2_pass and rq3_pass),
    }
    ms.reset_mission_service()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write JSON report to this path",
    )
    args = parser.parse_args()
    report = run_evaluation()
    text = json.dumps(report, indent=2)
    print(text)

    out = args.out
    if out is None:
        default_dir = ROOT / "storage" / "reports"
        default_dir.mkdir(parents=True, exist_ok=True)
        out = default_dir / "orchestration_evaluation_latest.json"
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
    print(f"\nWrote {out}", file=sys.stderr)
    print(
        f"OVERALL: {'PASS' if report['overall_pass'] else 'FAIL'} "
        f"(RQ1={report['research_questions']['RQ1_unsupported_exploit_pressure']['pass']} "
        f"RQ2={report['research_questions']['RQ2_path_diversity']['pass']} "
        f"RQ3={report['research_questions']['RQ3_zero_high_risk_auto']['pass']})",
        file=sys.stderr,
    )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
