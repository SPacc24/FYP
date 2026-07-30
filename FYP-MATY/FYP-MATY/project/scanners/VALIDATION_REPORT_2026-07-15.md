# Scanner Validation Report — 2026-07-15

## Result

Status: PASS

- Python compilation: PASS
- Scanner unit/regression suite: 19/19 PASS
- Fixed CVE/private-target scanner-runtime gate: PASS
- CVE source contract test: PASS
- HTTP error/evidence-state test: PASS
- Policy conflict/fail-closed behavior test: PASS
- Downstream CVE sanitization test: PASS
- ZIP integrity test: performed during release packaging

## Commands

```bash
python -m compileall -q scanners
python -m unittest -v scanners.tests.test_scanner_hardening
rg -n --glob '*.py' --glob '!tests/**' 'CVE-[0-9]{4}-[0-9]{4,}|(?:192\.168\.|10\.(?:[0-9]{1,3}\.)|172\.(?:1[6-9]|2[0-9]|3[01])\.)' scanners
```

The final `rg` command returned no output, which is the expected passing result.

## Evidence-backed limitations

- No live target was scanned during release validation; tests use mocked transports and synthetic index records.
- A full TCP port sweep is not implied. Each runtime report records exact policy-selected coverage and the limitation.
- Downstream teammate mapping source remains outside scanner ownership. Scanner output is protected by a canonical CVE integration guard; teammate source remediation is documented separately.
