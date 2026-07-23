# Test Cases (assessment-critical)

Automated suite (project root or `project/` with PYTHONPATH):

```bash
cd project && python -m pytest tests -q
python scripts/run_orchestration_evaluation.py
```

## Unit / integration (representative)

| ID | Case | Expected | File |
|----|------|----------|------|
| T01 | Playbooks load from JSON only | stages + branches + detectors present | `test_mission_orchestration.py` |
| T02 | Patched / no-CVE SMB path | `branch_ms17_suppressed` or `ms17_not_exploitable` | same |
| T03 | Safe-only playbook | no exploit module_type queued | same |
| T04 | Unknown port/service | research queue; no invented catalog_key | same |
| T05 | Proof required before pivot | pivot_segment only after attach_proof | same |
| T06 | Safe validation closes auxiliaries | `queued_auto` → succeeded without exploit auto-run | same |
| T07 | Operator gate on impact | web/high-risk status `awaiting_approval` | same |
| T08 | Catalog custody | LLM cannot invent MSF paths | `test_module_catalog.py`, `test_llm_safety.py` |
| T09 | Engagement denies public | public target rejected | scan / enterprise readiness tests |
| T10 | Three evidence conditions → three path signatures | evaluation harness metrics differ | `test_evaluation_conditions.py` |
| T11 | Baseline comparison | gated engine queues fewer unsupported exploits than naive matcher | same |

## Manual cyber-range cases (viva)

| ID | Setup | Steps | Pass criteria |
|----|-------|-------|---------------|
| M01 | Win10 patched SMB only | Start mission on SMB-only evidence | MS17 path suppressed; alternate lateral hypothesised if configured; report notes suppression |
| M02 | Lab web diagnostics host | Evidence includes HTTP + matching profile | Impact awaits approval; after approve + proof → pivot unlock |
| M03 | Unknown service port | Custom high port | Research queue only; no exploit invented |
| M04 | Kill Ollama | Stop Ollama; start scan/mission | Deterministic plan + playbook still run |
| M05 | Kill MSF RPC | Disable MSF env | Dashboard + mission queue/report still work |
| M06 | Safe-only playbook | `surface_validation_only` | Completes without impact gate |
| M07 | Export report | After any mission | Mission Orchestration section lists flags, proofs, suppressed notes |

## Negative / safety cases

| ID | Abuse attempt | Expected |
|----|---------------|----------|
| N01 | Public IP in targets | Engagement policy reject |
| N02 | Approve without operator session | 403 when token configured |
| N03 | Browser posts raw MSF module path | Ignored / only catalog keys executed |
| N04 | Claim recommender as finding | Confirmed findings count = proof count only |

## Evaluation metrics (see `evaluation_protocol.md`)

- Unsupported exploit attempts (gated vs naive baseline)
- High-risk auto-execute count (must stay 0)
- Distinct mission path signatures across conditions
- Graceful degradation when optional providers are off
