# Scanner Standards Alignment — 2026-07-22

## Scope

This change is confined to `project/scanners/`. It changes CVE applicability
candidate determination and CVSS severity handling. It does not modify the
teammate-owned exploitation, CALDERA, AI, mapping or route implementations.

## CVE applicability

Runtime candidates now require all of the following:

1. A CPE Name directly observed in scanner output.
2. A concrete part, vendor, product and version, as required by the NVD CVE API
   `cpeName` parameter.
3. Inclusion in an official NVD `cpeName` plus `isVulnerable` query result.
4. Evaluation of the CVE's NVD CPE configuration nodes, including AND, OR,
   negation and observed running-on/with dependencies.

The following inputs cannot emit a CVE candidate:

- product or service text;
- CVE description text;
- string similarity or token overlap;
- product alias tables;
- a private numeric fingerprint threshold;
- CVE List affected-product/version records without NVD CPE applicability;
- scanner-generated product-specific CPE strings.

An NVD CPE match is reported as `Potential Applicability`, not a confirmed
target vulnerability. Unresolved environment conditions are reported as
`Needs Context`. Target-specific proof is still required for confirmation.

## CVSS severity

- FIRST CVSS v4.0 is the default current standard.
- FIRST CVSS v3.1 remains explicitly selectable for legacy coverage.
- Only a source-published score for the selected version is accepted.
- The exact vector, version, provider and Base-score type are retained.
- Required Base metrics, metric names, Base values, score range and FIRST
  qualitative severity bands are validated.
- There is no conversion or fallback between CVSS versions.
- CVSS is never used as CVE match confidence or organisational risk.

## Authoritative references

- NIST IR 7696, CPE 2.3 Name Matching
- NVD CVE API 2.0 `cpeName`, `isVulnerable` and `noRejected` parameters
- NVD CPE applicability/configuration documentation
- FIRST CVSS v4.0 Specification Document, document version 1.2
- FIRST CVSS v4.0 Consumer Implementation Guide, published 2026-01-06

