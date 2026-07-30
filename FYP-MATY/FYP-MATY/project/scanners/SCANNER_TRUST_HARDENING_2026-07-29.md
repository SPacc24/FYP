# Scanner Trust Hardening — 2026-07-29

## Scope

This change is intentionally restricted to `project/scanners/`. It is based on the latest Host-Identity-CVE-Fix baseline and does not overwrite teammate `core/`, `routes/`, `templates/`, exploitation, Caldera, AI, or mapping code.

The scanner remains classification-neutral. No Candidate/Confirmed promotion model is required or inferred.

## CVE applicability

- Removed product-alias-registry use from CVE applicability.
- Removed description/prose-based version matching.
- Application CVEs require observed product/CPE identity plus official CVE affected entries.
- Host OS CPEs remain separated from application/service CPEs.
- Structured exact versions remain valid regardless of version scheme.
- Ordered ranges are evaluated only when the declared scheme has a trusted comparator.
- Debian/dpkg ordering is supported and independently cross-checked against native `dpkg`.
- Maven/RPM/custom ranges are held rather than guessed unless an exact endpoint can decide applicability.
- The official CVE Program index is the only baseline applicability source. If it is unavailable, no NVD fallback match is generated.
- NVD is limited to optional exact-CVE-ID CVSS enrichment after a canonical CVE reference already exists.
- CVSS 3.1 and 4.0 remain independent published metrics; no conversion is added.
- Existing CVSS verification status/integrity contracts are preserved.

## Command and credential safety

- Scanner-owned external argv construction is centralized in `command_builders.py`.
- Builders do not execute shells and do not choose scan timing/rate policy.
- Nmap timing/rate arguments come from the normalized scan policy.
- The legacy `nmap_runner.py` remains present but now delegates command construction to the central builder.
- CVE catalogue Git command construction is centralized without changing catalogue source behavior.
- Hardcoded SNMP community `public` was removed. `snmp_targeted_oids` now requires explicit authorised credentials and is deferred under the current IP/CIDR-only operator input contract.
- No production scanner Python file contains a fixed CVE ID or fixed IPv4 target literal.

## Coverage and readiness

- Existing timeout/completion/partial-output contracts are retained.
- Existing exact scanned-versus-untested port accounting is retained.
- Readiness now includes host-discovery binaries that are outside collector-plan entries.
- Credential-required collectors report `deferred_credentials` instead of silently guessing credentials.
- The native SSH KEXINIT collector no longer incorrectly requires the unrelated `ssh-audit` executable.
- Held CVE applicability decisions have canonical reason/resolution text and are included in the scanner PDF technical evidence output.

## Validation

Validated in the handover environment:

- `python -m compileall -q scanners` — pass.
- `python -m pytest scanners/tests -q` — 120 passed, 4 subtests passed.
- Debian comparator — 500 generated comparable version pairs cross-checked against native `dpkg`, zero mismatches.
- Production-source checks — no product-alias CVE matcher, no description-text CVE match bases, no guessed SNMP `public`, no fixed CVE IDs, no fixed IPv4 target literals.

The remaining non-Flask project tests also passed: 126 passed, 3 Flask-dependent tests deselected after four Flask-dependent collection modules were excluded. The full project suite additionally requires the dependencies declared in `project/requirements.txt`. In the isolated review environment Flask was not installed and package download access was unavailable; scanner validation did not depend on Flask.
