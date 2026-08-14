# Phase 2 Operator-Controlled Topology Discovery (v11)

## Purpose

Phase 2 implements an evidence-driven, operator-controlled discovery loop for authorised cyber-range networks. It separates two questions that must not be conflated:

1. **What network exists next?** — learned from explicit topology evidence.
2. **Can the scanner currently reach it?** — verified separately before enumeration.

PenPilot does not guess hidden RFC1918 ranges and does not use Kali's kernel routing table as the source of a hidden continuation network. It also does not create Linux routes, VPNs, interfaces, or firewall rules.

## Implemented operator loop

The Phase 2 page follows the five-step design:

```text
1. Discover Current Device
   -> enumerate the authorised current layer and retain observed assets

2. Find Next Network
   -> operator selects a retained router/firewall/L3-capable device
   -> collect read-only interface/routing information from that device

3. Show to Operator
   -> show device interface, interface IP, subnet, reachability state,
      evidence source, scope state, and eligible access methods

4. Operator Decision
   -> Continue Discovery on one branch, retry/query another device,
      revisit an earlier layer, or Stop Phase 2

5. Repeat
   -> after a selected branch is verified and enumerated, the new layer
      becomes current and the loop repeats
```

There is no automatic "target found" stop condition. The operator decides when enough network layers and assets have been discovered.

## Phase 1 to the first Phase 2 layer

The Phase 1 supplied IP remains the entry/seed target; it is not treated as the only eventual assessment target.

When the entry IP is inside one of Kali's directly attached interface networks, PenPilot derives the local CIDR only from the scanner interface **address and prefix** collected with `ip -j addr show`. That directly connected authorised subnet can then be enumerated to discover peers on the current layer.

This local-first step does not require an infrastructure credential profile because it does not claim to discover a hidden network. It is specifically useful for discovering a router or firewall that is a peer of the scanner on the same authorised Layer-2/Layer-3 segment.

If no safe directly connected subnet can be established from interface evidence, the workflow retains the host-only entry scope and waits for the operator instead of inventing a surrounding subnet.

## Current-layer discovery

Current-layer enumeration combines bounded observations rather than treating one collector as authoritative. Where applicable the workflow can retain evidence from:

- normal Nmap host discovery;
- complementary IP-layer ICMP/TCP Nmap discovery;
- the local neighbour table;
- `arp-scan` for a Layer-2-connected segment; and
- the scanner/controller record for provenance and exclusion.

The discovery record also reports collector health/capability state. The scanner/controller is retained for context but is excluded from Phase 3 target selection.

## Finding the next hidden network

A hidden continuation branch is created only from an **authenticated read-only infrastructure control-plane query** against an operator-selected retained device.

Supported platforms/transports are:

- Cisco IOS / IOS XE over SSH;
- Palo Alto PAN-OS over SSH;
- generic Linux/Unix Layer-3 devices over SSH; and
- SNMP v2c where an authorised read-only community is supplied.

Configured profiles use `INFRA_TOPOLOGY_PROFILES_JSON`. Automatic profile choice can be limited with `match_hosts` or `match_networks`, and an explicit operator profile selection is treated as an override.

The Phase 2 UI also supports **on-demand one-query credentials**. An operator can submit a read-only SSH password or SNMP community for the selected device without first editing `.env`. The secret is passed only to that query and is not written into the mission workflow, report, configured profile catalogue, or safe command log.

### Read-only device evidence

Cisco collection requests interface/routing output equivalent to:

```text
terminal length 0
show ip interface brief
show ip route connected
show ip route static
```

Palo Alto collection requests output equivalent to:

```text
set cli pager off
show interface all
show routing route
```

Generic SSH collection requests:

```text
ip -o addr show
ip route show
```

The returned interfaces/routes are parsed into dynamic CIDR records. No demonstration IP, VLAN, private subnet, or target network is embedded in the operational Phase 2 logic.

## Supplemental topology evidence

`INFRA_TOPOLOGY_SUPPLEMENTAL_EVIDENCE=1` can enable additional bounded evidence collection, such as passive routing advertisements or management metadata. This feature is **off by default**.

Supplemental evidence can corroborate a CIDR already reported by the authenticated device query, but it cannot independently create a continuation branch. This prevents generic web metadata, advertisements, or other weak observations from being promoted into a claimed hidden network.

## What the operator sees

For every continuation branch, the Phase 2 UI displays:

- source/current device;
- device interface;
- interface IP address;
- destination subnet;
- reachability state;
- evidence source(s);
- engagement/scope eligibility; and
- access choice: direct scanner path or an already established SOCKS pivot.

The reachability legend is:

- **Reachable** — connectivity was verified for the selected branch/access path.
- **Unknown** — the network exists in topology evidence but has not yet been verified from the selected access path.
- **Unreachable** — direct verification failed or was blocked.

A topology branch can therefore remain real even when direct reachability is unavailable. PenPilot does not misreport "unreachable" as "network does not exist".

## Continue Discovery

When the operator chooses a discovered branch:

1. scope and bounded-enumeration eligibility are checked;
2. the selected access method is validated;
3. direct reachability is tested, or an already established SOCKS pivot must be ready;
4. only then is the approved next layer enumerated;
5. observations are merged into the mission-wide retained inventory; and
6. the new layer becomes the current layer for another operator decision.

The exact visited-network set prevents circular topology from causing an endless traversal loop. Multiple branches discovered from different devices on the same layer are preserved so side networks are not falsely forced into a single inline path.

## Stop Phase 2 and Phase 3 handoff

**Stop Phase 2** does not close the assessment. It ends topology traversal and transitions the mission to Phase 3 configuration.

`workflow.asset_inventory` retains eligible assets discovered across:

- Phase 1 entry validation;
- the first directly connected Phase 2 subnet;
- every subsequently visited Phase 2 layer; and
- device interface IPs learned from authorised topology queries.

Duplicate observations are merged by IP. Routers, firewalls, servers, and endpoints can all remain valid assessment targets when retained evidence supports them. The scanner/controller is excluded.

Phase 3 presents the full eligible retained inventory, allowing one, multiple, or all eligible assets to be selected without discarding assets from earlier layers.

The Phase 2 stop reason is also retained, distinguishing cases such as:

- operator finished after local discovery;
- no additional continuation network was established from observable evidence;
- discovered branches were left unselected;
- layered traversal was completed; or
- no further eligible continuation was available.

## Security and scope controls

- Every active network is checked against the engagement policy.
- Oversized networks can remain visible as evidence but are not enumerated beyond the configured bound.
- Network-evidence queries are separated from data-plane access verification.
- Runtime secrets are not persisted in mission/report data.
- Safe command logs redact password/community material.
- Phase 2 does not automatically modify routes or firewall state.
- A SOCKS pivot is accepted only when already established and only for an approved discovered network.
- Operator topology queries, branch selections, revisits, retries, and the final Phase 2 stop are retained in decision/audit history.

## Configuration

Example `.env` profile catalogue:

```env
INFRA_TOPOLOGY_PROFILES_JSON={"cisco-readonly":{"label":"Cisco read-only","platform":"cisco_ios","transport":"ssh","username":"readonly","secret_env":"CISCO_TOPOLOGY_PASSWORD"},"palo-readonly":{"label":"Palo Alto read-only","platform":"palo_alto","transport":"ssh","username":"readonly","secret_env":"PALO_TOPOLOGY_PASSWORD"}}
INFRA_TOPOLOGY_DEFAULT_PROFILE=
INFRA_TOPOLOGY_SUPPLEMENTAL_EVIDENCE=0
CISCO_TOPOLOGY_PASSWORD=
PALO_TOPOLOGY_PASSWORD=
```

Profiles are optional because the Phase 2 UI can request one-query read-only access at runtime.

## Main implementation files

- `project/scanners/phase_discovery.py` — Phase 1/2 state machine, local-first discovery, topology branch handling, reachability verification, inventory accumulation, Phase 3 handoff.
- `project/scanners/infrastructure_discovery.py` — read-only SSH/SNMP collectors, device parsers, profile resolution, ephemeral runtime access.
- `project/scanners/topology_evidence.py` — optional supplemental topology observations; never authoritative for branch creation.
- `project/scanners/command_builders.py` — bounded external command construction.
- `project/routes/scan_routes.py` — operator actions, asynchronous topology query, Continue/Stop transitions, full-inventory Phase 3 handoff.
- `project/templates/layer_decision.html` — five-step operator loop, current-device selection, next-network evidence cards, reachability legend, retained inventory, revisit controls.
- `project/templates/assessment_config.html` — Phase 3 selection from the retained mission-wide inventory.
- `project/tests/test_topology_discovery_v11_image_flow.py` — v11-specific regression checks.

## Design invariants

The implementation is considered correct only while these invariants remain true:

1. No hidden subnet is guessed from common address ranges.
2. Kali's route table is not the authority for discovering the next hidden network.
3. A hidden branch requires explicit infrastructure interface/routing evidence.
4. Supplemental evidence cannot create a branch by itself.
5. Discovery and reachability are reported separately.
6. The operator selects every traversal branch.
7. Stop Phase 2 proceeds to Phase 3 instead of ending the mission.
8. Phase 3 retains eligible assets from all discovered layers.
9. No demonstration topology IPs/subnets are hardcoded in operational Phase 2 files.
10. The workflow does not automatically alter host routes, interfaces, VPNs, or firewall rules.
