# AutoPenTest v1.6.0 Validation Report

Date: 22 July 2026

## Result

- Automated tests: 238 passed
- Subtests: 4 passed
- Intentional skips: 1
- Python compilation: passed
- Jinja template parsing: passed
- ReportLab PDF generation with validated and analyst-review rows: passed
- Shell syntax (`install.sh`, `start.sh`, `test_full_chain.sh`): passed
- Scanner-owned JSON parsing: passed
- Runtime fixed-CVE/vector/legacy-description literal audit: passed
- Protected teammate source hashes: unchanged from v1.5.1

The single warning is ReportLab's notice that an internal Python AST compatibility symbol is deprecated. It does not affect report generation.

## Applicability regression coverage

The suite includes controlled tests for:

- authoritative NVD vulnerable-CPE query results;
- persistent per-CPE cache reuse;
- complete NVD offset pagination;
- exact CPE match;
- version-range decisions supplied by NVD rather than a private range parser;
- AND dependencies that require an OS/platform CPE;
- satisfied dependencies;
- contradictory dependency evidence;
- unresolved conditions placed in Analyst Review;
- analyst-review isolation from mapping, AI, risk, CALDERA and exploitation contracts;
- selected CVSS v3.1 and v4.0 integrity;
- rejection of cross-version, incomplete, malformed or severity-inconsistent metrics;
- no CVSS score conversion or fallback;
- no runtime `legacy_description` or `_text_version_match` path;
- no fixed runtime CVE identifiers in scanner/mapping code;
- canonical-only stored results and disabled browser vulnerability persistence.

## Dataset behavior

The release archive intentionally contains no stale CVE/NVD database snapshot. Fresh installation creates runtime storage, synchronises the complete CVE List index, then performs the NVD API's documented complete offset-paginated initial population. Subsequent runs use last-modified update windows. If an API/network interruption occurs, the UI reports partial status and the operator can resume with `python scripts/sync_nvd_database.py`.

Per-scan CPE applicability queries are fully paginated and cached. If the API is temporarily unavailable, only exact vulnerable-CPE records already present in the official local NVD repository can be used; the code never substitutes a private description parser or private version-range algorithm.

## Protected modules

SHA-256 file-list comparison confirms that these directories are byte-for-byte unchanged:

- `project/ai/`
- `project/caldera/`
- `project/exploitation/`
- `project/pivot/`

The inherited, unused `project/ai/mitre_attack_cache.json` is truncated JSON in v1.5.1 and remains byte-for-byte unchanged under the protected-module requirement. Runtime AI code references `project/ai/.cache/enterprise_attack.json`, not that legacy file. All scanner-owned JSON files passed parsing.

## Authoritative references

- NVD CVE API and applicability/configuration fields: <https://nvd.nist.gov/developers/vulnerabilities>
- NVD rate limits, initial population and incremental maintenance: <https://nvd.nist.gov/developers/start-here>
- CVE List V5: <https://github.com/CVEProject/cvelistV5>
- FIRST CVSS v3.1: <https://www.first.org/cvss/v3.1/specification-document>
- FIRST CVSS v4.0: <https://www.first.org/cvss/v4.0/specification-document>
