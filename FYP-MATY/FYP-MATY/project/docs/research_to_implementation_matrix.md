# Research-to-Implementation Matrix (1-page appendix)

| SP brief ask | Research input | Implementation in AutoPenTest | Status | Testable evidence |
|--------------|----------------|-------------------------------|--------|-------------------|
| Research new PT techniques | MITRE ATT&CK tactics/techniques matrix (`research_1.pdf`) | ATT&CK-mapped playbook stages; technique tags on actions | Partially met | `ai/technique_planner.py`, playbook JSON |
| Develop working POCs | ATT&CK technique examples + CVE records | Allowlisted catalog (`policies/exploit_module_catalog.json`) + policy-driven validation actions | Partially met | Catalog entries, web/SMB/aux profiles |
| Build automated-PT MVP | Behaviour-based attack chain + branching logic | Flask orchestrator with mission console, evidence graph, impact gates, reports | Met | 155 tests pass; runnable `/mission` console |
| Apply topics to real-world scenarios | Windows-domain / SMB / web foothold narrative | Cyber-range demo flow; engagement policy rejects public targets | Met | `docs/cyber_range_demo_flow.md`, `policies/engagement_policy.json` |
| Appreciate scoping & challenges | Scope policy and safe-by-default design | Public targets denied; high-impact actions gated | Met | Operator runbook, engagement policy |
| Enterprise tech (Windows domain, cloud) | Windows-domain lateral movement focus | SMB/aux checks, credential collectors, CALDERA/MSF integration | Partially met | Windows narrative implemented; cloud-native scenarios not in build |
| Enhance existing tools/frameworks | Metasploit, CALDERA, Nmap, CVE List | RPC/REST bridges, official CVE mirror, proof-of-access tickets | Met | `routes/msf_routes.py`, `routes/caldera_routes.py`, `scanners/mitre_cve.py` |

**Key distinctions maintained in the narrative**

- **ATT&CK technique** = adversary behaviour (e.g. T1021 Remote Services).
- **CVE record** = vulnerability identifier with affected product/version evidence from the official CVE List.
- **Exploit / module** = a concrete tool or script selected from the allowlisted catalog under operator control.

**Core contribution (evidence-gated orchestration)**

Evidence → attack graph → hypotheses → safe validation → branch on dead paths → operator impact gate → proof-required pivot → debrief.
