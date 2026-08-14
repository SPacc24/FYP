# Anti-Rejection Checklist (pre-viva / pre-directors)

Tick before any external audience. If a box fails, fix before feature-creep resumes.

## Story

- [ ] 30-second pitch uses **orchestrator**, not “AI hacker” (`product_positioning_30s.md`)
- [ ] Contribution = evidence-gated loop (one diagram max)
- [ ] Research objectives show Met / Partially met / Unmet honestly
- [ ] ATT&CK ≠ CVE ≠ exploit said out loud once

## Demo that cannot die (8 minutes)

- [ ] Starts with fixture or prior scan JSON — not 12 daemons
- [ ] Shows **three** path intents OR at least: suppressed MS17 + gated web + research unknown
- [ ] Operator gate visibly blocks impact
- [ ] Proof unlock visibly enables pivot recommendation
- [ ] Report export contains Mission Orchestration section
- [ ] Optional live tool **after** the above, never before

## Claims hygiene

- [ ] Never say “eliminates hardcoding” → “reduces decision-tree hardcoding”
- [ ] Never say “autonomous pentest” → “human-in-the-loop automation”
- [ ] Never say “we found zero-days” → “unknown-surface research queue”
- [ ] Never say PDF if file is not PDF (fixed to ReportLab when available)
- [ ] No “51 tools / full enterprise” inflation without evidence

## Engineering hygiene

- [ ] `pytest tests -q` green
- [ ] `python scripts/run_orchestration_evaluation.py` green
- [ ] Empty docs filled (architecture / setup / test_cases)
- [ ] No secrets in zip; strip bulk `storage/results` / live missions if packaging for assessors
- [ ] `.pytest_cache` / `__pycache__` excluded from zip

## Degradation drill

- [ ] App starts with Ollama down
- [ ] Mission starts with MSF down
- [ ] Report exports with empty CALDERA op

## Team knowledge

- [ ] Every member can explain playbook JSON → engine flags
- [ ] Every member can explain why MS17 “failure” is a **feature**
- [ ] Every member knows LLM cannot supply module paths

## Hand-in package contents

- [ ] Source zip
- [ ] Directors pack (8 slides)
- [ ] Matrix 1-pager
- [ ] Narrative sections 3–6 backbone
- [ ] Evaluation metrics JSON snapshot
- [ ] Visual overview HTML (optional)
