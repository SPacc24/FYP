# Research-to-Implementation Narrative

## How this document is used

This narrative is written for the final report (Sections 3–6) and the directors viva. Every claim below is either a **testable requirement** that can be checked against the code, or an explicit **research-objective status** (met / partially met / not met). It avoids absolute marketing language and keeps the distinction between ATT&CK techniques, CVE records, and exploit modules.

---

## 1. Elevator statements

**For a non-technical director / assessor**

> AutoPenTest is an evidence-driven penetration-testing orchestrator that converts reconnaissance findings into adaptive, ATT&CK-aligned assessment playbooks. Safe checks are automated, high-impact actions remain operator-controlled, and every decision and result is preserved for reporting.

**For a technical evaluator**

> The platform integrates reconnaissance, CVE correlation, ATT&CK mapping, controlled validation, Metasploit, CALDERA and pivot assessment through policy-defined playbooks that branch according to collected evidence.

---

## 2. The research chain: brief → structure → implementation

| Item | Role in the project | What it actually provides |
|------|---------------------|---------------------------|
| **SP project brief** | Motivation and scope | Asked for survey of PT techniques, working POCs, and an automated-PT MVP tested in a cyber range. |
| **MITRE ATT&CK research** (`research_1.pdf`) | Structure and vocabulary | A behaviour-based matrix of tactics (Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Discovery, Lateral Movement, etc.) and techniques (e.g. T1190, T1059, T1003, T1021). ATT&CK describes *what adversaries do*; it does not supply exploits, CVEs or automated vulnerability discovery. |
| **AutoPenTest MVP** | Implementation | An orchestrator that ingests scan evidence, maps it to ATT&CK techniques, correlates it with the official CVE List, and drives policy-defined playbooks that branch on evidence. |

The research paper’s conclusion is used directly: ATT&CK complements vulnerability scanning and exploitation frameworks, but does not replace them. AutoPenTest is therefore designed as an **orchestrator** that combines these separate sources, not as a replacement for any of them.

---

## 3. What ATT&CK is and is not in this project

**ATT&CK in AutoPenTest**

- Provides a shared vocabulary for tactics and techniques.
- Shapes the playbook stages (Initial Access → Execution → Privilege Escalation → Lateral Movement → Impact).
- Tags automated and operator-approved actions with technique IDs for coverage reporting.
- Helps decide which post-exploitation objectives are relevant after a foothold is proved.

**ATT&CK is not**

- A source of exploit code. Exploit modules are selected from the allowlisted `policies/exploit_module_catalog.json` (Metasploit modules, web profiles, lateral techniques).
- A vulnerability database. CVE correlation uses the official CVE List mirror (`CVEProject/cvelistV5`).
- A scanner. Reconnaissance is performed by Nmap and policy-registered collectors; ATT&CK mapping happens after evidence is collected.

**Consequence for report language**

Avoid saying *“the system uses ATT&CK to exploit CVEs”*. Say *“the system uses ATT&CK to structure the assessment, CVE records to prioritise candidate weaknesses, and an allowlisted catalog to select controlled validation actions.”*

---

## 4. Evidence-gated orchestration: the core contribution

The strongest, demonstrable contribution is an **evidence-gated transition model** between reconnaissance observations and assessment actions. The loop is:

1. **Observe** — Nmap + collectors produce normalised evidence (hosts, ports, services, versions, OS hints).
2. **Map** — evidence is matched against ATT&CK techniques and the CVE index to build a living attack graph.
3. **Hypothesise** — the playbook engine proposes safe auxiliaries, candidate web/SMB footholds, and lateral paths.
4. **Validate safely** — low/medium-risk auxiliaries may be auto-queued; everything else waits for an operator gate.
5. **Branch** — if a high-profile path is unsupported by evidence (e.g. MS17-010 on a patched host), the playbook records a suppressed path and enables alternate lateral options.
6. **Prove** — a foothold must be attached as a proof artefact before pivot segments are recommended.
7. **Decide / act** — operator-approved actions execute through Metasploit, CALDERA or the web-validation layer, with outcomes recorded.
8. **Report** — the debrief links confirmed findings to proofs, lists suppressed paths, and records the research queue.

This is not *autonomous hacking*. It is **human-in-the-loop automation** where every transition is gated by collected evidence and policy.

---

## 5. The three contribution claims

| # | Claim | What this means in the code | Confidence |
|---|-------|-----------------------------|------------|
| 1 | **Evidence-gated transition model** | `automation/attack_graph.py`, `automation/playbook_engine.py`, and `routes/mission_routes.py` only progress stages when flags such as `safe_validation_complete`, `impact_path_available`, and `foothold_proved` are set from real evidence. | Demonstrable |
| 2 | **Provider-independent playbook orchestration** | Playbooks, branch rules, detectors and catalog entries are JSON files in `policies/`. The engine reads them; it does not hardcode mission trees or vendor-specific steps. New techniques are added by editing JSON and restarting. | Demonstrable |
| 3 | **Traceable human-in-the-loop automation** | Missions persist under `storage/missions/`, proofs under `storage/proofs/`, and reports include mission summaries, suppressed paths and proof counts. Operator approval is required before high-impact actions (`routes/mission_routes.py` impact gates). | Demonstrable |

---

## 6. Research objectives mapped to the SP brief

The SP brief lists three deliverables:

| Brief objective | Status | Evidence in the project |
|-----------------|--------|-------------------------|
| **1. Survey newly published security techniques for PT** | **Partially met** | The literature review is based on the MITRE ATT&CK research (`research_1.pdf`) and CVE correlation methodology. The survey identifies relevant Windows-domain techniques and maps them to playbook stages. It is not an exhaustive literature review of every 2024–2025 publication; it is sufficient to ground the MVP. |
| **2. Develop POC codes or scripts for techniques tested to be working** | **Partially met** | Working POCs are the policy-defined playbook actions and the allowlisted catalog entries (e.g. web-validation profile, SMB auxiliary checks, lateral-technique templates). Full weaponised exploit development for each technique is out of scope; the project demonstrates controlled validation and chaining instead. |
| **3. Develop an MVP for automated PT based on the techniques researched** | **Met** | AutoPenTest is a runnable Flask application with asynchronous reconnaissance, mission orchestration, operator gates, proof-of-access tickets, Metasploit/CALDERA integration, pivoting support, and report generation. 155 tests pass and the full stack can be demonstrated in the cyber range. |

**Additional learning outcomes from the brief**

| Outcome | Status | Evidence |
|---------|--------|----------|
| Apply school topics to real-world scenarios | Met | Windows-domain / SMB / web foothold narrative, cyber-range demo flow. |
| Appreciate PT scoping and challenges | Met | `policies/engagement_policy.json` rejects public targets and the operator runbook documents scope controls. |
| Use enterprise technologies (Windows domain, Cloud concepts) | Partially met | The cyber-range narrative is Windows-domain focused; cloud-native attack scenarios are not implemented in this build. |
| Build enhancement modules on existing tools/frameworks | Met | Integration with Metasploit RPC, CALDERA, Nmap, and the official CVE List mirror. |

---

## 7. Testable requirements for demonstration

Use the following checklist when preparing the demo or viva. Each item can be verified by inspection of the named file or by running the application.

| ID | Requirement | Verification |
|----|-------------|--------------|
| R1 | Targets are validated against an engagement policy before scanning. | `policies/engagement_policy.json` + `routes/scan_routes.py` |
| R2 | Reconnaissance is asynchronous and produces normalised evidence. | `scanners/enumerator.py`, `scanners/nmap_runner.py`, storage under `storage/scans/` |
| R3 | CVE correlation uses only the official CVE List mirror. | `scanners/mitre_cve.py`, `docs/cve_source_policy_v31.md` |
| R4 | ATT&CK technique plans are generated and mapped to evidence. | `ai/technique_planner.py`, `ai/technique_intel.py` |
| R5 | Playbooks are JSON-driven and not hardcoded in Python. | `policies/playbooks/*.json`, `automation/playbook_engine.py` |
| R6 | Low-risk auxiliaries are queued automatically; high-impact actions require operator approval. | `routes/mission_routes.py` impact gate, `automation/playbook_engine.py` |
| R7 | Dead celebrity paths branch rather than fail silently. | `edge_to_internal_proof` playbook, `branch_ms17_suppressed` flag |
| R8 | Pivot recommendations require a recorded foothold proof. | `storage/proofs/`, mission `foothold_proved` flag |
| R9 | Reports include mission summaries, suppressed paths, and proof counts. | `project/reports/report_generator.py`, `_summarize_missions()` |
| R10 | Operator authentication gates sensitive actions. | `OPERATOR_TOKEN`, CSRF, `routes/operator_routes.py` |

---

## 8. How the catalogue reduces hardcoding

The `policies/exploit_module_catalog.json` and `policies/playbooks/*.json` files reduce the amount of hardcoded module names and mission steps in Python. They do not eliminate all defaults: the engine still knows the *concepts* of safe auxiliaries, web profiles and lateral techniques, and the default playbooks ship with example targets. The value is that **new techniques and branching logic can be added without changing Python code**.

Example of what is not hardcoded:

- Specific Metasploit module names (live in the catalog).
- Stage ordering and branch conditions (live in the playbook JSON).
- Target IP ranges and VLAN segments (supplied per mission or in scan evidence).

What remains as engineered defaults:

- The transition-model state machine (`queued_auto`, `awaiting_approval`, `completed`, `suppressed`).
- The rule that high-impact actions require operator approval.
- The requirement that a foothold proof unlocks pivot recommendations.

---

## 9. Mapping ATT&CK tactics to demonstrable features

| ATT&CK tactic | Technique examples | AutoPenTest feature | Evidence |
|---------------|--------------------|---------------------|----------|
| Reconnaissance / Discovery | T1046 Network Service Scanning, T1083 File and Directory Discovery | Nmap-driven recon, service workbench, attack graph | `scanners/enumerator.py`, `automation/attack_graph.py` |
| Initial Access | T1190 Exploit Public-Facing Application | Web validation profile and foothold approval gate | `policies/exploit_module_catalog.json`, `routes/web_validation_routes.py` |
| Initial Access | T1078 Valid Accounts | Credential-based checks (when configured) | `scanners/collectors/` credential collectors |
| Execution | T1059 Command and Scripting Interpreter | Metasploit / CALDERA actions after approval | `routes/msf_routes.py`, `routes/caldera_routes.py` |
| Persistence | T1543 Create or Modify System Process | CALDERA technique readiness (optional) | `routes/caldera_routes.py` |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation | High-impact action gate (requires approval) | `routes/mission_routes.py` |
| Credential Access | T1003 OS Credential Dumping | CALDERA / MSF credential modules after foothold | Catalog entries under `credential_access` |
| Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | SMB auxiliary checks, alternate lateral branching | `policies/playbooks/edge_to_internal_proof.json` |
| Command and Control | T1572 Protocol Tunneling | Chisel + proxychains pivot workflow (experimental) | `routes/pivot_routes.py` |
| Impact | T1490 Inhibit System Recovery | Only under explicit operator approval; not auto-executed | Mission impact gate |

---

## 10. Boundaries and honest limitations

Only claim features that can be demonstrated reliably:

- **EternalBlue / MS17-010**: the lab Win10 target is patched, so the path is correctly *suppressed and branched*, not successfully exploited. The demo value is the branching logic, not the exploit.
- **LLM / Ollama**: optional enrichment only; it ranks and explains catalog items. It cannot invent exploit modules or bypass the allowlist.
- **Web validation**: requires a complete private-lab fingerprint, an evidence-derived action ID, and explicit operator approval.
- **CALDERA / Metasploit execution**: disabled by default; requires keys, agents and operator approval.
- **Pivoting**: experimental; Chisel and proxychains are started through the UI, but the user must ensure the lab network layout permits the tunnel.
- **Cloud / multi-product soup**: not in scope. The project is a single orchestrator for an authorised lab segment, not an integration of multiple commercial products.

---

## 11. Recommended report structure (from this narrative)

Use these sections directly in the final report:

- **3.1 Project brief and motivation** — cite SP brief; explain why manual PT is hard to scale and why a cyber-range MVP is appropriate.
- **3.2 Literature review** — MITRE ATT&CK as a behaviour matrix; what it provides and what it does not; CVE vs exploit vs technique distinction.
- **3.3 Research objectives** — list the three SP objectives and their met/partial/unmet status.
- **3.4 Research gap** — existing tools do recon or exploitation well, but few close the loop between evidence, branching, human approval and traceable reporting in one policy-driven orchestrator.
- **3.5 Contribution statement** — evidence-gated orchestration; three claims from Section 5.
- **4.1 Requirements** — testable requirements from Section 7.
- **4.2 System architecture** — browser → Flask routes → recon pipeline → mission console → playbook engine → proof store → reports.
- **4.3 Reconnaissance and evidence normalisation** — Nmap, collectors, CVE correlation, attack graph.
- **4.4 Playbook engine and branching** — JSON playbooks, flags, suppression, alternate paths.
- **4.5 Controlled validation and impact gates** — safe auxiliaries, operator approval, Metasploit/CALDERA integration.
- **4.6 Proof of access and pivoting** — proof store, foothold requirement, Chisel/proxychains.
- **4.7 Reporting and closed-loop debrief** — mission summaries, suppressed paths, research queue.
- **5 Implementation** — screenshots and code references.
- **6 Evaluation** —
  - 6.1 Test results (155 passed).
  - 6.2 Cyber-range demo checklist.
  - 6.3 Objective attainment summary.
  - 6.4 Known limitations.
  - 6.5 Comparison with related work.
  - 6.6 Future work.
  - 6.7 Conclusion.

---

## 12. Quick viva talking points

1. **Start with the problem**: manual PT generates a lot of scanner noise and little traceability.
2. **Introduce ATT&CK**: it gives us a language for adversary behaviour, not exploits.
3. **Show the loop**: scan → map → hypothesise → safe validate → branch → approve → prove → pivot → report.
4. **Demonstrate the branch**: patched MS17-10 host → `branch_ms17_suppressed` → alternate lateral options appear.
5. **Show the gate**: high-impact actions remain disabled until the operator clicks approve.
6. **Close with the contribution**: evidence-gated orchestration makes the assessment repeatable, traceable and safe.
