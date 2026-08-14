# Phase 2 Topology Discovery v12 — No Read-Only Access Panel

## Operator flow

Phase 2 follows the five-step operator loop:

1. **Discover Current Device** — enumerate the authorised current network and retain observed devices.
2. **Find Next Network** — select one retained router/firewall/Layer-3 device and collect bounded observable network evidence.
3. **Show to Operator** — display any explicit continuation network prefix, evidence source, and reachability state.
4. **Operator Decision** — continue to one branch or stop Phase 2.
5. **Repeat** — after access verification and enumeration, repeat from the new layer.

The former **Read-only topology access** section has been removed. The Phase 2 operator screen no longer exposes configured infrastructure profiles, SSH usernames/passwords, SNMP communities, or one-query credential forms.

## Continuation evidence

The active flow uses `scanners/topology_evidence.py`. It does not guess a hidden RFC1918 subnet. A branch is created only when an explicit network prefix is observed from bounded evidence associated with the selected device/current layer.

Possible evidence sources include an already-observed route via the selected device, passive control-plane advertisements, bounded UPnP metadata, bounded unauthenticated management metadata, and path evidence. Path/IP observations alone do not become a subnet unless an explicit prefix or address+mask pair is present.

## Reachability and traversal

A discovered prefix is not automatically treated as reachable. The operator selects the branch and access method. PenPilot then verifies direct access or an already-established SOCKS pivot before enumerating the approved network. PenPilot does not automatically create Linux routes or change firewall policy.

## Inventory handoff

Every eligible asset retained in Phase 1 and all visited Phase 2 layers remains available for Phase 3 selection. Stopping Phase 2 ends discovery traversal and proceeds to assessment configuration; it does not discard earlier assets.

## Main implementation files

- `project/templates/layer_decision.html` — simplified Phase 2 UI with no credential/profile panel.
- `project/routes/scan_routes.py` — `discover_device` action and asynchronous evidence collection.
- `project/scanners/phase_discovery.py` — current-layer state, evidence-backed branch creation, reachability verification, traversal, inventory accumulation, Phase 3 handoff.
- `project/scanners/topology_evidence.py` — bounded non-credentialed selected-device evidence collection.
- `project/tests/test_topology_discovery_v12_no_readonly_panel.py` — regression coverage for the removed panel and evidence-first default path.
