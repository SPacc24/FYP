# Phase 2 Local-First Discovery Fix — 2026-08-11

## Implemented scope

This update addresses the Phase 2 demo issue where an operator-supplied entry IP could be assessed as a /32 without first enumerating the directly connected authorised subnet.

### 1. Local connected subnet is discovered first
- Phase 1 still validates the operator-supplied entry IP as a single supplied address.
- PenPilot then inspects the scanner's interface address and prefix information from `ip -j addr show`.
- If the entry IP belongs to an authorised directly connected interface network, that network becomes the first Phase 2 subnet scope.
- The kernel routing table is not used to derive this subnet.
- The subnet is enumerated with the selected interface, enabling normal Nmap/ARP local-layer discovery.

Example for the cyber-range demo:
- Entry IP: `192.168.1.1`
- Kali interface: `eth0 = 192.168.1.49/24`
- Derived local Phase 2 scope: `192.168.1.0/24`
- Hosts such as `192.168.1.42` can now be discovered before any infrastructure-control-plane query is required.

### 2. Local discovery and topology continuation are separate
- Local subnet discovery uses scanner interface address/prefix evidence and does not require `INFRA_TOPOLOGY_PROFILES_JSON`.
- Infrastructure profiles are only required when the operator selects a retained Layer-3 device and asks PenPilot to learn networks beyond the current subnet.
- The Phase 2 UI now states this distinction explicitly.

### 3. Phase 2 progression

`Entry IP -> derive connected authorised subnet -> enumerate subnet -> retain devices -> operator selects Layer-3 device -> query read-only topology -> choose deeper network -> enumerate -> repeat or finish`

### 4. Phase 2 stop reason
- Finishing Phase 2 now records a structured stop reason in the mission workflow.
- The stop reason is shown in the assessment results, PDF report and technical appendix.
- If the operator finishes after only local subnet enumeration, the report states that no further network layer was discovered or authorised before Phase 2 ended.

## Validation

Focused regression suite executed after the update:

- `project/scanners/tests`
- `project/tests/test_phase_workflow.py`
- `project/tests/test_topology_discovery_v6.py`

Result: **230 passed, 4 subtests passed**.

The complete application-level pytest suite was not runnable in the editing environment because Flask is not installed there; no application dependency files were changed by this fix.
