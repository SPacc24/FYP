# Graceful Degradation Matrix

Design goal: **optional providers may die; the orchestrator must not.**

| Dependency | Detect | Degradation behaviour | Operator sees |
|------------|--------|----------------------|---------------|
| Ollama / LLM | `/ai/status`, connection error | Deterministic technique plan; mission engine ignores LLM | Advisor offline badge / empty chat |
| Metasploit RPC | env + RPC ping | Catalog still proposes; live run disabled | “MSF unavailable” / empty live results |
| CALDERA API | env + API key | Coverage UI empty; no ops created | Explicit not-configured |
| CVE index | matcher_status | Findings without CVE enrichment | `cve_index_unavailable` / unenriched |
| Nmap binary | tooling check | Scan fails closed with tool message | Coverage “Tool Unavailable” |
| Web validation flag | `ENABLE_WEB_VALIDATION` | Profile hypothesised; no live inject | Action remains gated/not executed |
| Chisel / proxychains | pivot routes | Pivot generate may fail; mission debrief still compiles | Error string, no silent success |
| Proof store dir | writable path fallback | Uses temp dir fallback | Mission continues on lab hosts |

## Demo rule

Never open with “all integrations on.” Open with:

1. Scan fixture or local recon (Nmap only if needed)  
2. Mission orchestration paths (branch + gate + proof)  
3. Report export  

Then, if time remains, show one live provider (MSF **or** web validation **or** CALDERA) — not all three.

## Code anchors

- CVE unavailable: `scanners/mitre_cve.py` (`matcher_status`)
- Tool fallback labels: `scanners/enumerator.py`
- Mission disk fallback: `automation/mission_service.py` `_writable_dir`
- AI fall back deterministic: `ai/technique_planner.py`
- Report still includes missions when ops empty: `reports/report_generator.py`
