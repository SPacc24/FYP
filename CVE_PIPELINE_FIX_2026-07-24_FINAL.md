# CVE Pipeline Fix — 2026-07-24

## Fixed

1. CVE storage paths now resolve from the project directory rather than the shell's current working directory.
2. Exact product/version evidence from an uncorroborated Nmap fingerprint (confidence 0.60) is searched against the official local CVE index or targeted NVD API.
3. These low-confidence results are retained only as **Candidate CVEs**. They cannot be classified as confirmed CVEs.
4. Added `project/scripts/diagnose_cve_pipeline.py` to explain index status, skipped services, matcher diagnostics, and result counts.

## Run on Kali

```bash
cd ~/FYP/project
source venv/bin/activate 2>/dev/null || source .venv/bin/activate 2>/dev/null || true
python scripts/mitre_cve_status.py
python scripts/diagnose_cve_pipeline.py
```

If the local index is unavailable:

```bash
python scripts/sync_mitre_cve_database.py
python scripts/rebuild_mitre_cve_index.py
```

Then perform a new scan. Existing result JSON files are not retroactively rewritten.
