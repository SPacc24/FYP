# Evaluation Protocol — Research Questions & Experiments

This document answers the lecturer risk: *“Where is the research method?”*

## Primary user (commercial / academic honesty)

**Cyber-range operators and internal security training teams** who need repeatable, controlled attack-path validation in authorised labs.

Not: SME mass-market scanner replacement. Not: fully autonomous red team.

## Research questions (testable)

| ID | Question | Metric | Success criterion |
|----|----------|--------|-------------------|
| RQ1 | Does evidence-gated orchestration reduce **unsupported exploit attempts** vs a naive catalog matcher? | Count of exploit-class actions that would fire without sufficient evidence (e.g. MS17 without CVE) | Gated count **<** naive baseline on patched/no-CVE SMB fixture |
| RQ2 | Does adaptive branching produce **different paths** under different evidence? | Path signature = sorted flag set ∩ key queue kinds | ≥ 3 distinct signatures across web+smb / smb+cve / unknown-port fixtures |
| RQ3 | Does the engine keep **high-risk auto-execute = 0**? | Actions with `module_type=exploit` and status `queued_auto` | Always 0 |
| RQ4 | Does human-in-the-loop keep impact gated? | `awaiting_approval` for web/impact artifacts before proof | At least one gate on web fixture when impact posture is on |
| RQ5 | Does removing optional AI break core orchestration? | Mission start + branch flags with no Ollama | Same branch outcomes as with Ollama unavailable (deterministic) |
| RQ6 | Is LLM contribution optional? | Compare technique planner deterministic vs model path | System completes; AI is advisor-only |

## Experiment 1 — Three conditions, three paths

**Fixtures** (no live network required):

1. **C-web-smb**: HTTP + SMB open, **no** MS17 CVE  
2. **C-ms17-cve**: SMB open **with** CVE-2017-0144 evidence  
3. **C-unknown**: single uncatalogued high port  

**Playbook:** `edge_to_internal_proof`

**Procedure:**

```bash
cd project
python scripts/run_orchestration_evaluation.py --out storage/reports/eval_latest.json
```

**Measurements per condition:**

- flags (esp. `branch_ms17_suppressed`, `ms17_cve_evidence` / `http_present`, `unknown_surface_present`)
- `action_summary` from debrief after forced compile
- counts: `queued_auto`, `awaiting_approval`, research queue size
- path_signature hash

**Pass:** three different path_signature values; C-web-smb suppresses MS17 celebrity exploit path; C-unknown has research queue > 0.

## Experiment 2 — Baseline comparison (naive vs gated)

**Naive baseline:** for every port row, match *all* catalog MSF modules including exploits and treat every exploit as “would attempt” with no suppression and no approval concept.

**Gated system:** PlaybookEngine start_mission only.

**Metric:**

```text
unsupported_exploit_pressure =
  count(exploit matches that lack supporting CVE/flag evidence)
```

For C-web-smb (no CVE): naive pressure ≥ 1 (ms17-class); gated pressure = 0 queued exploit auto / suppressed celebrity branch.

**Pass:** gated_unsupported < naive_unsupported on C-web-smb; gated high_risk_auto == 0 on all conditions.

## Experiment 3 — Graceful degradation (manual or mocked)

| Provider off | Expected behaviour |
|--------------|--------------------|
| Ollama | Deterministic planning; mission engine unaffected |
| Metasploit RPC | Hypotheses + queue still form; live aux execution skipped/disabled |
| CALDERA | Mission + report continue |
| CVE index empty | Unenriched findings; no fabricated CVEs |
| Pivot tools missing | Pivot stage blocked with explicit reason after/without proof |

Checklist doc: `graceful_degradation.md`.

## Experiment 4 — Analyst effort (lightweight timing study)

Optional live lab exercise for the report:

| Mode | Script | Measure |
|------|--------|---------|
| Manual | Operator runs nmap + notes + msf by hand | wall clock to “SMB patched, try web, document” |
| Fixed script | Linear bash of modules ignoring evidence | attempts + false exploit tries |
| AutoPenTest gated | Mission console path | wall clock + unsupported attempts + gates |

Record N≥3 runs if time permits. Even N=1 with honest method section beats “feature list only.”

## What we do **not** claim from these experiments

- Commercial superiority to Pentera/AttackIQ  
- Zero-day discovery  
- Full reduction of expert pentester judgment  
- Statistical significance without larger N  

## Where results live

- Machine metrics: `python scripts/run_orchestration_evaluation.py`  
- Locked assertions: `tests/test_evaluation_conditions.py`  
- Interpretation for report sections 6.x of `research_to_implementation_narrative.md`
