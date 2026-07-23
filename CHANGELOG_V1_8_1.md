# AutoPenTest v1.8.1 CVE correlation repair

- Rebuilt the CVE List V5 SQLite index as schema v3 with an FTS identity-retrieval table for legacy records.
- Kept structured `affected` product/platform/module/version evaluation as the primary matching path.
- Added a conservative legacy Candidate path requiring the exact observed product phrase and exact observed version token in the official CVE description.
- Added natural comparison for plain dotted upstream versions marked `custom` or `generic`; ecosystem package versions remain unresolved unless exactly equal.
- Added an explicit diagnostic when a product retrieves no structured or legacy identity records.
- Corrected the live scan counter from `Confirmed-Affected CVEs` to `CVE Candidates`.
- Added regression coverage for exact legacy matches, near-version rejection, custom dotted ranges, unsupported package versions, suppression, and missing selected CVSS.
- Removed obsolete pre-v1.8 NVD design documents so they cannot be mistaken for active setup or runtime instructions.

Candidate remains an AutoPenTest applicability classification. Only approved target-specific proof can promote a finding to Confirmed. CVSS remains published technical severity only.
