# Scope-Aware Layered Discovery v4 — 2026-08-06

## Ownership boundary

This revision changes only scanner-owned discovery, scan persistence labels, the scan-route integration required to pause for operator decisions, scanner workflow templates, reports, and scanner workflow tests. It does not modify AI, exploitation, Caldera, mapping, or pivot implementation.

## Core behaviour

1. The initial address is persisted as an `entry_target` with `origin=operator_supplied`.
2. Phase 1 reachability probes verify that existing record; they never relabel it as independently discovered.
3. The entry scope remains a single-host `/32` or `/128`. No remote prefix is guessed.
4. A network becomes enumerable only when a kernel route or explicitly authorised retained route provides the prefix.
5. Kali’s initial interfaces, routes, and neighbours are captured as the mission baseline.
6. Baseline routes remain route observations unless evidence connects them to the current mission scope.
7. A route is automatically evidence-linked only when one of these generic conditions is satisfied:
   - the route appeared after the mission baseline;
   - the route contains the operator-supplied entry address and uses the entry route interface;
   - the route’s next hop is the operator-supplied entry address;
   - the route’s next hop is inside the current verified network scope;
   - the route signature or destination was supplied through the generic authorised-scope integration fields.
8. An operator may explicitly authorise a retained, bounded baseline route. This records a decision only; it does not add or alter any route.
9. Every selected path is reverified against the live route table, interface, source, gateway, and route table before enumeration.
10. One scope is processed at a time. Other branches remain persisted for later operator selection.
11. Phase 3 receives only checkbox-selected records from the current verified scope. At least one is required.
12. Existing Phase 3 TCP/UDP scanning, collectors, recovery, CVE correlation, CVSS, reporting, and teammate handoffs remain intact.

## Address provenance

Every address record preserves how it entered the mission:

- `operator_supplied` — initial entry target;
- `network_enumeration` — independently observed during a verified network scan;
- `local_interface_configuration` — Kali source address;
- route gateways and trace hops remain route/trace evidence and do not automatically become assessment targets.

If the same address is later observed through network enumeration, the record keeps both origins while retaining `operator_supplied` as the primary origin.

## Route observation versus continuation path

`route_observations` contains non-default unicast routes visible to Kali for each scope. Each observation has a scope-specific `observation_id`, route signature, baseline flag, mission-relationship state, source/interface/gateway context, bounded-enumeration status, and evidence.

`paths` contains only mission-related route observations. An unrelated connected network can be displayed for transparency but cannot be followed until the operator explicitly authorises it or later evidence connects it to mission progression.

## No network reconfiguration

The discovery module never runs route-add or address-add commands, never changes firewall configuration, and never performs pivoting. It can consume a route created by another authorised component after that route becomes visible to the kernel.

## Expected Windows VM result

For a supplied host reachable only through the default route, with unrelated networks already connected to Kali:

- operator-supplied entry targets: 1;
- responsive entry targets: 1 when a probe replies;
- additional hosts independently discovered: 0;
- unrelated baseline routes: retained as observations only;
- evidence-linked continuation paths: 0;
- Phase 3: available for the responsive entry target.

## Expected same-subnet result

When the kernel has a connected route containing the supplied entry target:

- the entry address remains operator-supplied;
- the connected prefix is offered as an evidence-linked path because the route contains the entry address and uses the selected entry interface;
- the operator may assess the supplied host immediately or follow the prefix to enumerate additional hosts.

## Expected segmented-range result

After enumerating a verified network scope, a specific route whose next hop is inside that current scope is offered as a continuation candidate. The operator selects one path, the scanner reverifies it, then enumerates only that destination network. Newly appearing VPN/pivot routes are detected during route refresh. Pre-existing authorised range routes can be explicitly associated with the mission by the operator.
