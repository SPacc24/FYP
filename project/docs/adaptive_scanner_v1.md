# Adaptive Scanner v1

## Operator contract

The dashboard exposes one vulnerability-scanning workflow. The required input is an authorised IP address, list, range, or CIDR. Port coverage and Advanced settings are optional controls with validated defaults.

TCP coverage is complete, common, or custom. Operators may add or exclude numerical ports. UDP is a separate disabled/common/complete/custom choice. The final report discloses any ports outside the selected coverage.

## Execution contract

1. Expand, deduplicate, and scope-check targets.
2. Use ARP where locally applicable; otherwise combine ICMP and TCP discovery. An explicitly supplied single address proceeds even when discovery receives no response.
3. Divide the numerical port set into ordered microbatches. One microbatch runs at a time for each target. Different targets may run concurrently up to the configured limit.
4. Submit every observed open port to Nmap version detection and banner collection. Port numbers may affect probe ordering but never prove service identity.
5. Dispatch protocol modules from collected service/product/tunnel evidence. Unknown services remain unknown and retain their raw evidence.
6. Consolidate fingerprints, contradictions, raw artefacts, commands, coverage, and evidence gaps.
7. Correlate sufficiently reliable product/version/CPE evidence with the locally indexed official CVE List.
8. Classify partial applicability as `candidate` and complete applicability evidence as `confirmed_affected`. Neither status claims successful exploitation.
9. Present the evidence and limitations for pentester review and export.

## Configurable data

- `policies/port_coverage.json`: coverage sets and Advanced defaults.
- `policies/recon_policy.json`: collector guardrails and fingerprint intensity.
- `policies/collector_registry.json`: protocol collector registration and hints.
- Local CVE mirror/index: current CVE records and affected-version data.

Runtime facts, service identities, CVE conclusions, evidence, and coverage statements are generated from the selected plan and collected output. They are not embedded as target-specific conclusions in the application code.
