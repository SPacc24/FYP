# PenPilot Operator Workflow v14

## Phase 1 — Entry Discovery

Phase 1 starts from one operator-provided, authorised IP address. It validates the address, collects low-impact reachability evidence, captures local interface and neighbour observations, and retains the entry asset for later assessment. Phase 1 does not infer a device role or hidden network from the address itself.

## Phase 2 — Network Discovery

If the entry address belongs to an authorised directly connected scanner interface network, PenPilot derives the current CIDR from that interface address and prefix and enumerates observable devices in that subnet. The active Phase 1/2 workflow does **not** read the Kali kernel routing table to discover the current or next network.

The Phase 2 operator screen presents discovered devices using retained evidence such as hostname, MAC/vendor, reachability and any established network-device role. Unknown hosts remain `Device Role Not Established`; selecting a host does not automatically promote it to infrastructure.

The operator may select multiple current-subnet devices. PenPilot checks those devices sequentially so mission state is updated by one worker at a time. Any explicit continuation network retained from selected-device evidence is linked to its source device. The operator chooses one continuation branch to verify and enumerate, or finishes Phase 2. Silent hosts or hidden networks are never claimed to be absent merely because no evidence was observed.

All eligible assets retained across Phase 1 and every visited Phase 2 layer remain available for Phase 3 selection.

## Pre-Phase 3 — Assessment Configuration

The operator selects one or more retained targets and configures TCP and UDP coverage. The UI shows the exact Essentials port lists from the same backend normalisation used by assessment submission. Custom port expressions are expanded live, deduplicated, sorted and validated against the same `1-65535` range and ascending-range rules. Full coverage is displayed as `1-65535` without rendering all 65,535 numbers.

## Phase 3 — Vulnerability Assessment Presentation

The existing Phase 3 scanner, security-tool commands, collector behaviour, CVE correlation, CVSS handling and NVD enrichment remain unchanged. The operator-facing flow is presented as:

1. Port & Service Enumeration
2. Service & Host Identification
3. Service-Specific Enumeration
4. Evidence Recovery
5. Per-Target Consolidation

Identity is reported only where sufficient retained evidence exists. Re-probing does not imply that every service version will be established.

## Command Evidence

Command tables show the exact recorded command with a **Copy Command** action and a **View Evidence** action. Large raw output is not inlined into command tables. If a scanner record appended the full generated XML/text artefact after an `[evidence file: ...]` marker, the operator view shows the console output separately and exposes the retained artefact by basename through a bounded evidence-file route. Persisted scanner evidence is not rewritten.

## Integration Boundary

v14 does not modify Phase 3 scanner command construction, service collectors, CVE/CVSS/NVD logic, Metasploit, CALDERA, AI, mapping, exploitation or report-generation modules. Phase 2 discovery changes are confined to the discovery workflow, its presentation, and operator selection plumbing.
