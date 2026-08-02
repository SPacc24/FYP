# Hostile Viva Q&A (drill this)

## Positioning

**Q: Isn’t this just a wrapper around Nmap/MSF/CALDERA?**  
**A:** The tools execute checks. The contribution is the **evidence-gated transition model**: observations → catalog hypotheses → safe auto validation → branch dead paths → human impact gate → proof-required pivot → debrief. Tools are replaceable providers; the loop is the product.  
**Evidence:** `automation/playbook_engine.py`, `policies/playbooks/`, `scripts/run_orchestration_evaluation.py` RQ1–RQ3.

**Q: What’s novel for an FYP?**  
**A:** Not a new CVE. A **measurable** reduction in unsupported exploit pressure and forced proof-before-pivot under declarative playbooks — demonstrated by evaluation harness, not marketing.  
**Evidence:** `docs/evaluation_protocol.md`, `tests/test_evaluation_conditions.py`.

## Research

**Q: ATT&CK is not research.**  
**A:** Agreed ATT&CK is a taxonomy. Research method is structured RQs (unsupported attempts, path diversity, zero high-risk auto) with fixtures and baseline comparison. Objectives 1–2 of the brief are **partially met**; objective 3 MVP is **met**.  
**Evidence:** matrix + evaluation_protocol.

**Q: What if we remove the LLM?**  
**A:** Core loop is unchanged. LLM is optional rank/explain only — cannot invent module paths.  
**Evidence:** catalog custody tests; planner allowlist.

## Hardcoding / lab lock-in

**Q: “No hardcoding” is false.**  
**A:** Correct integrantes: we **reduce** hardcoding of mission trees and module paths via JSON. Engineed defaults remain (approval concept, proof gate). Lab web fingerprint is env-overridable.  
**Evidence:** playbooks JSON; `LAB_WEB_*` env; README wording.

**Q: It only works on your deliberately broken lab.**  
**A:** Live exploits need lab services; **orchestration behaviour** is fixture-tested for three evidence shapes without network. Demo lead is the **suppression branch**, not EternalBlue success.  
**Evidence:** T02/T10; hostile demo script in `cyber_range_demo_flow.md`.

## Safety / ops

**Q: Can it attack the wrong host?**  
**A:** Engagement policy scopes targets; default denies public IPs; high-risk needs operator approve; catalog allowlist. Not multi-tenant enterprise IAM — lab trust model.  
**Evidence:** `engagement_policy.json`, mission approve routes.

**Q: Audit log / RBAC?**  
**A:** Mission event_log + proofs + debrief for single-operator lab. Full SSO/RBAC/immutable WORM store is future work — out of MVP claim set.

## Evaluation

**Q: 155 tests — are they mocks?**  
**A:** Many unit/integration tests mock external IO deliberately. Orchestration branching and baseline comparison are local and do not require MSF. Live MSF/CALDERA need lab. We disclose that.

**Q: Show numbers.**  
**A:** Run `python scripts/run_orchestration_evaluation.py` — flips naive vs gated unsupported pressure and three path signatures on record.

## Demo failure

**Q: MSF is down — your project is down?**  
**A:** No. Degradation matrix: mission + report without MSF. Demo order starts tool-free.  
**Evidence:** `graceful_degradation.md`.

## Commercial

**Q: Why not hire a pentester / buy Pentera?**  
**A:** We don’t replace experts or BAS vendors. First market: **cyber-range / training orchestration** with transparent open stack and evidence gates. ROI thesis: fewer wasted celebrity exploit tries + repeatable student debriefs — not SOC replacement.

## One-line kill-shot recovery

> “If all integrations die tomorrow, the execution providers vanish; evidence-gated playbooks, gates, proofs, and debriefs still demonstrate the contribution.”
