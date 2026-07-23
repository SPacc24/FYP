# Cyber Range Demo Flow (bulletproof)

## Positioning (say first — 20s)

Evidence-gated **orchestrator** for authorised labs. Safe checks auto; impact human-gated; dead paths branch; proofs unlock pivots. AI optional and cannot invent modules.

## Principle

**Orchestration first, tools second.**  
If Nmap/MSF/CALDERA/Ollama/Chisel are unhappy, the mission story still lands with fixtures.

## 8-minute path that cannot die

### Minute 0–1 — Context

- Lab topology one slide (attacker Kali / edge segment / internal VLAN concept).
- Open Mission Console `/mission`.

### Minute 1–4 — Three evidence shapes (use fixtures if live flaky)

| Condition | Evidence | What judges must see |
|-----------|----------|----------------------|
| A | HTTP + SMB, **no** MS17 CVE | `branch_ms17_suppressed` / not exploitable; web impact **awaiting_approval** |
| B | SMB + CVE-2017-0144 present | MS17 class becomes candidate under gate (still not auto-shell) |
| C | Unknown high port | Research queue; **no** invented catalog key |

Live command if needed:

```bash
cd project
python scripts/run_orchestration_evaluation.py
# shows three path signatures + naive vs gated unsupported pressure
```

### Minute 4–6 — Closed loop on Condition A

1. Start `edge_to_internal_proof` with web+smb results.
2. **Validate safe** queue (auxiliaries succeed / recorded).
3. Show pending **approval** on web impact — click Approve (lab only).
4. Record outcome success → flags `impact_confirmed` class.
5. Attach **proof** → `foothold_proved` → pivot segments appear, still approval-gated.
6. Abort or continue → **debrief** professional note on MS17 suppression.

### Minute 6–7 — Report

Export text/PDF report → Mission Orchestration section lists missions, flags, proofs, notes.

### Minute 7–8 — Optional single live provider (pick ONE)

- MSF aux against open lab service, **or**
- Web validation against authorised diagnostics host, **or**
- CALDERA agent ability  

Never stack all three under time pressure.

## Safe-only alternate (if assessor hates exploitation)

Start playbook `surface_validation_only` — completes without impact gate. Still proves orchestration + catalog custody.

## Blue-team handoff line

Ethernet-only blue LAN teammate gets debrief timeline templates + suppressed-path notes — not a free attack on their segment.

## Failure reframes (practice aloud)

| Apparent failure | Correct line |
|------------------|--------------|
| EternalBlue fails | “Patched host — system suppressed celebrity path; that is the deliverable.” |
| Ollama down | “Advisor offline; deterministic plan and playbooks continue.” |
| MSF RPC down | “Execution provider offline; queue and gates still demonstrate custody.” |
| No shell | “We require proof artefacts before calling impact confirmed in debrief counts.” |

## Old flow (still valid after mission story)

1. Live Nmap, mapping, optional AI technique display  
2. Lab exploitability validation  
3. CALDERA post-access simulation  
4. Final report  

Use only after the closed-loop mission narrative is secure.
