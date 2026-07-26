# Scan Findings & Coverage Assurance — 2026-07-25

## Main assessment changes

- Replaced **Table 3 — Information Dump** with **Table 3 — Scan Findings**.
- Scan Findings is generated only from the retained `service_inventory` for the current scan.
- Displayed fields are host, port/protocol, state, service, product, version, fingerprint context, and evidence source.
- Missing product/version/evidence values remain missing; the UI does not infer them from port numbers or lab assumptions.
- Added an independent Scan Findings search field.

## Scan Summary / Coverage Assurance

- Added target reached/requested counts.
- Added TCP and UDP requested, actually scanned, open, closed, filtered, unknown/no-response, and untested counts.
- Untested coverage is calculated from configured scope versus batches that actually executed; it is never represented as closed or secure.
- Added TCP fingerprint coverage, observed endpoint count, versioned product count, evidence-check execution status, and unique CVE reference count.
- The same summary and Scan Findings view are included in both PDF rendering paths.

## Auditability

- Raw commands, parser evidence, CVE matching records, source IDs, and other detailed artefacts remain in the technical appendix / handoff data.
- No CVE identifiers, vulnerability facts, targets, product versions, or service identities were hardcoded for the new views.
