# Layered Network Discovery Implementation

## Current architecture (Topology v12)

Phase 2 is evidence-driven and operator-controlled. The active implementation is documented in `docs/TOPOLOGY_DISCOVERY_V12.md`.

The active workflow is:

1. Validate and retain the operator-supplied Phase 1 IP.
2. Derive and enumerate the authorised directly connected scanner subnet when interface address/prefix evidence supports it.
3. Pause in Phase 2 with the current layer and mission-wide retained inventory.
4. The operator selects a retained router, firewall, or other Layer-3 device and presses **Find Next Network**.
5. PenPilot collects bounded observable network evidence from the current vantage point. No infrastructure username, password, SNMP community, or topology profile is requested by the Phase 2 UI.
6. Only explicit observed network prefixes become continuation candidates; private CIDRs are never guessed blindly.
7. The operator selects one candidate branch and chooses direct access or an already-established SOCKS pivot.
8. PenPilot verifies the chosen access method and enumerates only that approved network.
9. Newly observed hosts are merged into the mission-wide inventory without deleting earlier Phase 1/2 discoveries.
10. The operator repeats the loop, revisits a previous layer, or chooses **Stop Phase 2 · Proceed to Phase 3**.
11. Phase 3 can select any eligible retained IP from the complete Phase 1/2 inventory.

## Network evidence used by the active flow

The selected-device evidence collector is bounded and non-credentialed. Depending on availability it can retain explicit network-prefix evidence from:

- existing route observations where the selected device is the recorded gateway;
- passive routing/control-plane advertisements attributed to the selected device;
- bounded UPnP/SSDP metadata;
- bounded unauthenticated management-page metadata; and
- path observations, which are retained as hints and do not become subnets unless an explicit prefix/mask is present.

Arbitrary IP literals are not converted into guessed subnets.

## Operator and safety properties

- Every continuation branch requires an operator decision.
- Discovery and reachability remain separate states.
- The scanner never adds Linux routes automatically.
- Already visited networks are not recursively followed again.
- The scanner/controller address remains non-selectable for Phase 3.
- Pivot traversal accepts only networks already retained by the active mission.
- Large or out-of-policy networks remain evidence only and cannot be enumerated.

## Phase 3 compatibility

The existing vulnerability-assessment pipeline remains responsible for service/version evidence, CVE correlation, CVSS, reports, and teammate handoffs. The Phase 2 redesign changes only discovery/retained access context and continues to hand the complete eligible Phase 1/2 inventory into Phase 3.
