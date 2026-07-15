# v32.2 Front-End and Scan Profile Changes

- Current Activity is displayed first.
- Task Progress is the second row.
- Command Log is the final row with time, exact command, purpose, and captured output.
- Removed development-style wording such as processed evidence and live snapshot.
- Removed the database-index count from the user report summary.
- No-evidence statuses are greyed rather than green.
- Confirmed CVE Findings replaces the earlier strict-evidence label.
- Additional Relevant Evidence replaces lengthy version/exposure wording.
- Evidence Collection Summary replaces Tool Coverage.
- Evidence Type replaces Evidence Type.
- Default tools are reduced to essentials. Optional overlapping tools are disabled through `.env` unless needed.
- Preliminary CVE review starts after service fingerprints are available; final CVE findings are recomputed after evidence enrichment.
