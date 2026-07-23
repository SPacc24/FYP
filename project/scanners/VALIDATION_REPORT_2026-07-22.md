# Scanner Validation Report — 2026-07-22

## Result

- Python compilation of `project/scanners`: PASS
- Standards-alignment tests: 6 passed
- Adjacent scanner/UI/report regression tests: 50 passed
- Runtime fixed-CVE/private-target literal audit: PASS
- Original v1.6.0 comparison: only `project/scanners/` files changed

## Intentional compatibility changes

Two legacy tests expect banner parsing to manufacture this product-specific CPE:

`cpe:/a:unrealircd:unrealircd:<parsed-version>`

Those expectations are obsolete and intentionally fail. The version may still
be displayed as captured banner evidence, but a CPE used for CVE applicability
must be directly observed or independently resolved through an authoritative
CPE dictionary process. The scanner no longer hardcodes that identity.

Older tests that require CVE List product/version candidates, the private
fingerprint-confidence gate, `confirmed_affected` for an NVD CPE match, or CVSS
v3.1 as the default also represent removed v1.6.0 behavior.

## Scope check

The release was rebuilt from the original v1.6.0 ZIP and overlaid only with
files from `project/scanners/`. Teammate-owned source directories were retained
unchanged.

