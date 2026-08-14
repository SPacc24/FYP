# Phase 2 Topology-Driven Discovery (v6)

## Purpose

Phase 2 no longer uses Kali's kernel routing table to decide which hidden network exists next. The operator selects a retained network device, the scanner collects read-only interface/routing evidence from that device, and the scanner presents the discovered continuation networks for operator selection.

The workflow remains bounded by the engagement policy and by `MAX_EXPANDED_TARGETS`.

## Operator flow

```text
Phase 1 entry IP
    -> retain validated/discovered entry asset
    -> Phase 2 current layer
    -> operator selects router/firewall/L3 device
    -> read-only topology query
    -> show connected/routed networks
    -> operator selects one branch and access method
    -> verify direct access or require an established SOCKS pivot
    -> enumerate the approved network
    -> merge all observed hosts into one retained inventory
    -> operator either repeats the loop or finishes Phase 2
    -> Phase 3 can select any eligible retained IP from Phase 1 or Phase 2
```

There is no automatic "target found" stop condition. Phase 2 ends only when the operator chooses **Finish Phase 2**.


### Device selection and profile readiness

Selecting a retained Phase 2 device is always allowed. The **Continue Discovery**
action is controlled by device selection, not by global profile availability.
If the selected device does not yet have usable read-only topology access, the
mission remains in Phase 2, preserves the selected IP, and reports the exact
profile requirement instead of rejecting the operator action or implying that
no deeper network exists.

Automatic profile selection is target-aware. Profiles scoped with `match_hosts`
or `match_networks` are applied only to matching devices. An explicitly selected
profile is treated as an operator override. When a matching/default/unscoped
profile is ready, the topology query starts and discovered connected/routed
networks are returned as operator-selectable continuation branches.

The UI keeps local subnet discovery and infrastructure topology continuation as
separate stages: local enumeration requires no infrastructure credentials;
control-plane topology access is needed only for networks beyond the current
layer.

### On-demand access from the Phase 2 UI

A configured `.env` profile is no longer required just to make the selected
device actionable.  The Phase 2 page also provides **On-demand read-only
topology access** for the currently selected device.  The operator can choose:

- Cisco IOS / IOS XE, Palo Alto PAN-OS, or a generic Linux/Unix Layer-3 device;
- SSH with a read-only username/password and port; or
- SNMP v2c with an authorised read-only community.

The submitted password/community is passed directly to the one background query
and is not stored in mission JSON, the report, the configured profile catalogue,
or the redacted command log.  The retained topology observation records only
secret-free metadata such as platform, transport and `operator_ephemeral` access
source.  Saved `.env` profiles remain available for repeatable demonstrations,
but they are now optional rather than a prerequisite for continuing from a
selected device.

## Read-only topology profiles

Profiles are configured through `INFRA_TOPOLOGY_PROFILES_JSON`. A profile contains connection metadata only. Passwords/community strings are referenced through a separate environment-variable name and are not written into mission JSON or safe command logs.

Example:

```env
INFRA_TOPOLOGY_PROFILES_JSON={"cisco-readonly":{"label":"Cisco read-only","platform":"cisco_ios","transport":"ssh","username":"readonly","secret_env":"CISCO_TOPOLOGY_PASSWORD"},"palo-readonly":{"label":"Palo Alto read-only","platform":"palo_alto","transport":"ssh","username":"readonly","secret_env":"PALO_TOPOLOGY_PASSWORD"}}
INFRA_TOPOLOGY_DEFAULT_PROFILE=
CISCO_TOPOLOGY_PASSWORD=
PALO_TOPOLOGY_PASSWORD=
```

Supported profile values:

- `platform`: `cisco_ios`, `palo_alto`, or `generic`
- `transport`: `ssh` or `snmp_v2c`
- SSH: `username`, optional `port`, optional `identity_file`, or `secret_env`
- SNMP v2c: `secret_env` for the community string
- optional `match_hosts` / `match_networks` and `priority` to select a profile automatically

For password-backed SSH profiles, the installer now installs `sshpass`. Key-backed SSH is preferred where the lab supports it.

## Device evidence

Cisco SSH collection requests read-only output equivalent to:

```text
show ip interface brief
show ip route connected
show ip route static
```

Palo Alto SSH collection requests read-only output equivalent to:

```text
show interface all
show routing route
```

The scanner derives CIDRs from the returned interface/route evidence. It does not guess RFC1918 ranges and does not create a subnet merely because it is a common private range.

## Discovery state versus reachability

Topology evidence and data-plane access are separate:

- `discovered`: the selected infrastructure device reports that a network/interface exists.
- `verified_reachable`: the scanner established direct reachability to the discovered branch.
- `direct_reachability_not_established`: topology exists, but Kali could not establish direct data-plane access.
- `pivot_ready`: an already established SOCKS pivot is used for the approved discovered network.
- `visited`: the exact network was previously enumerated in the mission.
- `scope_exceeds_discovery_limit`: the network is retained as evidence but is too large for bounded enumeration.
- `outside_engagement_scope`: the network overlaps or falls outside the configured engagement policy.

No Linux route is added automatically by Phase 2.

## Branching topology

Each discovered network is retained as a path from the selected device and current segment. Multiple devices and multiple branches on the same layer are preserved. A DMZ or server zone therefore remains a side branch rather than becoming an artificial inline hop.

The visited-network set prevents circular topology from causing an endless discovery loop.

## Retained inventory and Phase 3

`workflow.asset_inventory` is the mission-wide inventory. It merges:

- Phase 1 entry/discovery assets
- Phase 2 host-enumeration results from every visited layer
- interface IPs learned from read-only infrastructure topology queries

Duplicate IP observations are merged. Scanner/controller addresses remain non-selectable.

Phase 3 no longer restricts target selection to the current layer. Any eligible retained IP can be selected individually, as a multi-target selection, or through **Select All**. This includes routers, firewalls, servers, and endpoints. Existing Phase 3 vulnerability-assessment logic is retained and receives the selected IP list plus per-target discovery context.

## Pivot integration

The shared pivot runtime is used by Phase 2. A SOCKS pivot may only be applied to a network already discovered by the active mission. The pivot scanner no longer supplies or falls back to hardcoded internal ranges.

Proxy-based network discovery uses TCP connect scanning (`nmap -sT -Pn`). ARP discovery is explicitly marked unavailable through SOCKS rather than being claimed as evidence.

When a Phase 3 target is retained only through a pivot segment, the VA pipeline preserves that access context. TCP-capable target collectors are routed through the established ProxyChains/SOCKS transport and Nmap is forced to `-sT -Pn`. Raw-IP/L2/UDP evidence types such as ARP, ICMP echo, Nmap `-sn`, active `-O` OS fingerprinting, and UDP scans are recorded as **not applicable through SOCKS** instead of being sent directly or falsely reported. This means the selected pivot-only asset still receives the full set of assessment checks that are technically valid over the established TCP transport.

## Security controls

- Read-only device commands only for topology collection.
- Secret values are resolved from environment variables at execution time.
- SSH password secrets use `SSHPASS` and are excluded from safe command logs.
- SNMP community values are redacted from safe command logs.
- Discovered networks are checked against `policies/engagement_policy.json` before they become enumeration candidates.
- Large networks remain visible as evidence but cannot be enumerated beyond the configured bound.
- Every topology query and continuation choice is written to the mission operator-decision/audit history.

## Main implementation files

- `scanners/infrastructure_discovery.py` — read-only device collectors and parsers
- `scanners/phase_discovery.py` — topology-driven Phase 2 state machine and retained inventory
- `routes/scan_routes.py` — simplified operator actions and all-inventory Phase 3 handoff
- `templates/layer_decision.html` — Phase 2 device/network/finish controls
- `templates/assessment_config.html` — all retained Phase 1/2 VA targets
- `pivot/runtime.py` — shared pivot engine
- `routes/pivot_routes.py` — discovered-network-only pivot scanning
- `tests/test_topology_discovery_v6.py` — topology, branching, inventory, parser, and secret-redaction regression tests
