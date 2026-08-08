# Layered Network Discovery Implementation

## Ownership boundary

This implementation changes only scanner-owned discovery, scanner persistence/report integration, scan-route integration, scanner templates, and scanner tests. It does not modify AI, exploitation, Caldera, mapping, or pivot implementation code. A route created by an existing VPN or pivot component may be observed through the Linux kernel route table, but the scanner never creates that route itself.

## Mission model

A mission is stored under one `scan_id` as a directed set of observed `segments` and `paths`.

- A **segment** is one route-verified enumeration scope with its network, route table, interface, source address, next hop, hosts, commands, and evidence.
- A **path** is one observed non-default kernel route from the current mission context to another destination prefix.
- A path is not treated as proof of a hidden topology, firewall, DMZ, VLAN, or vendor.
- Only one operator-selected path is reverified and followed at a time.
- Previously visited segments remain available as branch points and are reverified before reuse.

## Workflow

1. Validate one operator-supplied entry IP.
2. Collect bounded reachability and path observations.
3. Capture structured interface, route, and neighbour evidence.
4. Establish a host-scoped entry segment; do not invent a wider subnet.
5. Enumerate only the current segment.
6. Pause for the operator.
7. The operator may assess the current layer, follow one route, revisit a prior layer, refresh paths, retry discovery, or stop.
8. A selected route is refreshed and checked against the retained destination, interface, gateway, and route table before the destination layer is enumerated.
9. The operator selects one or more discovered current-layer hosts using checkboxes.
10. The validated host list is passed to the existing Phase 3 vulnerability-assessment pipeline.

## Discovery evidence

The scanner uses generic operating-system and network tools:

- `ip -j addr show`
- `ip -j route show table all`
- `ip -j route get <destination>`
- `ip -j neigh show`
- bounded `ping`
- bounded Nmap host discovery
- bounded `tracepath` or `traceroute` observation
- `arp-scan` only for a directly connected IPv4 layer

Trace output is retained as path observation only. Intermediate addresses do not become subnets or device classifications.

## Safety properties

- No fixed IP, CIDR, interface, VLAN, vendor, zone, or topology is required.
- No CIDR is derived from an entry address.
- A default route does not authorise scanning the scanner's management network.
- Routes exceeding `MAX_EXPANDED_TARGETS` remain visible as evidence but cannot be enumerated automatically.
- The scanner does not call `ip route add`, `ip addr add`, or equivalent network mutation commands.
- The scanner source address is never selectable as a Phase 3 target.
- Browser submissions are revalidated against persisted current-layer inventory.
- No-response evidence remains non-conclusive.
- DNS/hostname observations remain supplementary and conflicts are retained.

## Phase 3 compatibility

The existing assessment engine remains responsible for TCP/UDP scanning, service and protocol evidence, recovery, Windows evidence, CVE correlation, CVSS selection, reports, and teammate handoffs. The discovery workflow changes only how the target list and route context are supplied.
