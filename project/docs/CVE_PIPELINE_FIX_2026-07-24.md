# CVE pipeline fix — 24 July 2026

This build fixes the CVE enrichment chain without weakening confirmed-finding rules.

- Service fingerprint JSON now exposes compatibility fields (`host`, `service`, `product`, `version`, `confidence`) in addition to the canonical consensus fields.
- Consensus product/version recovered from scripts or native protocol evidence is retained even below the strict confirmation threshold.
- Noisy Nmap Windows identities such as `Microsoft Windows 7 - 10 microsoft-ds 6.1` are normalised before NVD lookup.
- Low-confidence product/version observations may trigger targeted NVD enrichment, but every returned record stays labelled as a candidate requiring validation.
- Only corroborated fingerprints crossing the strict threshold may become confirmed CVE matches.

After upgrading, clear the NVD query cache and run a new scan:

```bash
rm -f project/storage/nvd_cache/service_queries.json
cd project
source .venv/bin/activate  # or source venv/bin/activate
python app.py
```
