# v32.5 Report Polish

- Fixed false timeout statuses when commands exit successfully but their output contains the word timeout.
- Replaced the unavailable `pgsql-info` NSE script with installed-script filtering and PostgreSQL-safe fallbacks.
- Removed internal formatting tools from user-facing reports and command logs.
- Reordered the report so confirmed CVEs and non-CVE security observations appear before candidate references and appendices.
- Grouped candidate CVE references by product/version and removed raw matcher-basis strings from the frontend.
- Removed mismatch/context-filter traces, Other Service Evidence repetition, and Evidence File Index from the visible report.
- Kept full raw evidence in the handoff JSON for downstream modules.
