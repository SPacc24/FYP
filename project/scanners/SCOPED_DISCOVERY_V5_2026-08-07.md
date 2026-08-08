# Scope-Aware Discovery v5 — Operator Route Control

## Purpose

This revision keeps the existing vulnerability-assessment pipeline intact while correcting the operator workflow for segmented cyber-range environments.

## Route workflow

Every retained bounded route is shown to the operator. Route state is separated into three stages:

1. `observation_only` — the route exists in Kali and is retained as evidence.
2. `operator_authorized` — the operator explicitly includes that exact route signature in the mission.
3. `authorized_pending_verification` — the route is available for fresh verification and one-scope traversal.

Automatic evidence relationships such as a route that contains the entry target, a newly appearing route, or a next hop on the current scope are suggestions only. They do not bypass operator authorisation.

Route authorisation is mission metadata only. The scanner does not add, delete, or modify Linux routes, addresses, interfaces, VPNs, tunnels, or firewall rules.

## Free path selection

The operator may authorise any observed route that:

- is currently retained from the kernel route table;
- has a valid non-default destination prefix;
- is within the configured bounded discovery size; and
- belongs to the current scope's route-observation set.

A route may have existed before the mission, appeared after the baseline, been created by a VPN, been created by an authorised static route, or been exposed by a teammate-owned pivot component. Interface names and address classes are not used to infer meaning.

Immediately before traversal, the scanner refreshes the route table, verifies the exact destination/interface/gateway/table context, and then enumerates only the selected destination scope.

## Authorisation revocation

The operator may revoke an authorised path before traversal. Revocation removes only mission permission. The real Kali route remains unchanged and the original route observation remains in evidence.

## Inconclusive entry-host assessment

An operator-supplied host that does not answer ICMP, Nmap host discovery, or tracepath remains `reachability_not_established` and is excluded by default.

The operator may explicitly retain that entry target for Phase 3. This action:

- does not relabel the target responsive;
- records `operator_authorized_inconclusive_reachability`;
- marks the host selectable for this mission; and
- forces the existing Phase 3 assume-live service-discovery path for that selected target.

## Preserved boundaries

The revision does not modify:

- `project/ai/`
- `project/caldera/`
- `project/exploitation/`
- `project/mapping/`
- `project/pivot/`

It also does not reintroduce Candidate/Confirmed CVE classifications or change the existing TCP, UDP, evidence-recovery, CVE, CVSS, report, or teammate handoff logic.

## Expected segmented-range behaviour

When Kali initially knows only the external IP and its default route, the scanner can assess that host but cannot infer hidden networks. As VPN, static, second-interface, or pivot routes become visible, the operator can refresh route evidence, authorise one observed route, verify it, enumerate its network, and repeat one scope at a time.
