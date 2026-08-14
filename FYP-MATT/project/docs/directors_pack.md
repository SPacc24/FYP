# Director Slide Pack — AutoPenTest

*8 slides + speaker notes. Use as Markdown, or import into PowerPoint/Google Slides.*

---

## Slide 1: Title

**AutoPenTest: Evidence-Driven Penetration-Testing Orchestration**

BEng Cybersecurity FYP — Singapore Polytechnic

> *An orchestrator that converts reconnaissance findings into adaptive, ATT&CK-aligned assessment playbooks. Safe checks are automated; high-impact actions stay operator-controlled; every decision is preserved for reporting.*

---

## Slide 2: The Problem

- Penetration testing is still largely manual.
- Scanners produce **noise**, not decisions.
- Chaining recon → validation → impact → report is hard to repeat and harder to audit.
- Students need a safe cyber-range platform that teaches the *process*, not just the tools.

**Project brief asks for**: survey of new PT techniques → working POCs → automated-PT MVP in a cyber range.

---

## Slide 3: Research Foundation — MITRE ATT&CK

- ATT&CK is a **behaviour matrix**, not an exploit database.
- It organises adversary actions into tactics: Initial Access → Execution → Persistence → Privilege Escalation → Credential Access → Discovery → Lateral Movement → Impact.
- It gives the MVP a **structured vocabulary** and repeatable coverage metrics.
- ATT&CK **complements** CVEs and exploit frameworks; it does not replace them.

---

## Slide 4: What We Built — AutoPenTest MVP

A Flask-based orchestrator with:

1. **Reconnaissance** — Nmap + collectors, async, policy-scoped.
2. **Evidence graph** — normalised findings + CVE correlation.
3. **Playbook engine** — JSON-driven stages, no hardcoded mission trees.
4. **Safe validation** — low-risk auxiliaries auto-queue.
5. **Impact gate** — high-risk actions wait for operator approval.
6. **Branching** — dead paths (e.g. patched MS17-010) are suppressed and alternatives unlock.
7. **Proof store** — foothold artefacts required before pivoting.
8. **Reporting** — mission debrief with confirmed findings, suppressed paths, research queue.

---

## Slide 5: The Closed-Loop Flow

```text
Scan evidence
     ↓
Attack graph + CVE/ATT&CK mapping
     ↓
Hypotheses from JSON catalog
     ↓
Safe auxiliaries ──► branch if path dies
     ↓
Operator approval gate
     ↓
Approved action (MSF / CALDERA / web)
     ↓
Proof of access
     ↓
Pivot recommendation
     ↓
Debrief report
```

**Every arrow is gated by evidence and policy.**

---

## Slide 6: Catalogue Reduces Hardcoding

| Hardcoded in many tools | In AutoPenTest |
|-------------------------|----------------|
| Fixed target lists | Per-mission scan evidence |
| Fixed exploit chains | JSON playbooks with branch rules |
| Module names in code | `policies/exploit_module_catalog.json` |
| Vendor-specific steps | Provider-agnostic transition model |

**Adding a new technique**: edit JSON → restart → test. No Python change required.

---

## Slide 7: Research Objectives — Status

| Objective | Status |
|-----------|--------|
| 1. Survey new PT techniques | **Partially met** — ATT&CK-based survey grounds the MVP |
| 2. Develop working POCs | **Partially met** — controlled-validation actions and catalog entries |
| 3. Build automated-PT MVP | **Met** — runnable Flask app, 155 passing tests, cyber-range ready |

**Honest scope**: we demonstrate orchestration and controlled validation, not full weaponised exploit development for every technique.

---

## Slide 8: Evaluation evidence (not feature theatre)

Research questions with machine-checked results:

| RQ | Question | Result source |
|----|----------|---------------|
| RQ1 | Fewer unsupported exploit attempts than naive matcher? | `run_orchestration_evaluation.py` |
| RQ2 | Three evidence shapes → three path signatures? | same |
| RQ3 | High-risk auto-execute always zero? | same |

Primary market: **cyber-range / training operators**.  
Not claiming commercial BAS parity.

---

## Slide 9: Contribution & Take-Away

**Core contribution: evidence-gated orchestration**

- Recon observations → hypotheses → controlled validation → policy decisions → execution evidence → adaptive next actions.
- Makes the assessment **repeatable**, **traceable**, and **safe**.

**Three concrete claims**

1. Evidence-gated transition model.
2. Provider-independent playbook orchestration.
3. Traceable human-in-the-loop automation.

**One-line close**

> AutoPenTest does not let AI invent attacks, and it does not hardcode them either. Evidence drives a closed loop of safe actions; policy and humans unlock impact.
