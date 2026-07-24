# AutoPenTest Architecture

## One-sentence product

An evidence-gated, human-in-the-loop pentest **orchestrator** for authorised cyber ranges — not an AI auto-exploiter and not a commercial BAS product.

## Layers

```text
Browser UI (templates + static JS)
        │
        ▼
Flask routes (scan / mission / msf / caldera / pivot / report / ai)
        │
        ├─► Recon pipeline (Nmap + collectors → scan store)
        ├─► Evidence normalisers (ports, products, CVE index)
        ├─► Attack graph builder
        ├─► Playbook engine (JSON playbooks + evidence detectors)
        ├─► Module catalog (JSON: MSF / web / lateral)
        ├─► Impact approval gate + proof store
        └─► Report generator (mission debrief included)
```

## Core components

| Component | Path | Responsibility |
|-----------|------|----------------|
| App factory | `app.py` | Wire blueprints, session, CSRF, operator gate |
| Mission API | `routes/mission_routes.py` | Start / approve / proof / abort / validate-safe |
| Playbook engine | `automation/playbook_engine.py` | Stage advance, queue, branches, debrief |
| Mission service | `automation/mission_service.py` | Persistence under `storage/missions/` |
| Attack graph | `automation/attack_graph.py` | Host/service/hypothesis nodes from evidence |
| Proof store | `automation/proof_store.py` | Foothold artefacts unlock pivot |
| Catalog | `policies/exploit_module_catalog.json` + `exploitation/module_catalog.py` | Allowlisted modules only |
| Playbooks | `policies/playbooks/*.json` | Stages, detectors, branches |
| CVE matcher | `scanners/mitre_cve.py` | Official CVE List index only |
| Engagement scope | `policies/engagement_policy.json` | Deny public targets by default |
| Reports | `reports/report_generator.py` | Text + PDF export with mission summary |

## Data flow (happy path)

1. Operator unlocks session with `OPERATOR_TOKEN`.
2. Scan is scoped by engagement policy and runs asynchronously.
3. Parsed results (hosts/ports/products/CVEs) are stored under `storage/results/`.
4. Mission starts with a playbook ID + scan snapshot (or live `parsed_results`).
5. Engine: ingest → graph → hypotheses → auto-queue safe auxiliaries → branch dead celebrity paths → hold high-risk for approval.
6. Operator approves impact or skips; outcomes recorded; proof attached.
7. Pivot segment recommendations unlock only after foothold proof.
8. Debrief + report export include confirmed / suppressed / research queues.

## What is intentionally optional

| Integration | Default | If missing |
|-------------|---------|------------|
| Ollama / LLM | off / optional | Deterministic technique planning continues |
| Metasploit RPC | off | Safe queue + catalog hypotheses remain; live aux can’t execute |
| CALDERA | off | Reporting and mission flow continue |
| CVE index | may be empty until synced | Findings unenriched; no invented CVEs |
| Chisel/pivot | experimental | Mission stops cleanly at pivot stage with reason |
| Web validation | off | No live cmdi checks; profile still hypothesised from catalog |

## Trust boundaries

- Module **paths** never come from the browser or LLM — only catalog keys matched from evidence.
- High-risk actions require `requires_approval=true` and operator decision endpoints.
- Public IP targets are rejected by the default engagement policy.
- Operator token + CSRF gate state-changing routes when configured.

## Non-goals (important for assessment)

- Not multi-tenant SaaS.
- Not cloud-native attack coverage (Entra/K8s offensive chains).
- Not autonomous exploitation without a human.
- Not zero-day discovery; unknown surfaces go to a research queue only.
