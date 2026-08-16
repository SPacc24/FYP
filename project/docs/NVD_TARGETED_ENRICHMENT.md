# Targeted NVD CVE Enrichment

The scanner now uses the local CVE List index when it exists. If the large local index is absent, it falls back to targeted NVD API 2.0 requests based on high-confidence service product/version fingerprints.

## Configuration

Add to `project/.env`:

```env
NVD_ENRICHMENT_ENABLED=1
NVD_API_KEY=
NVD_REQUEST_DELAY_SECONDS=6.5
NVD_REQUEST_TIMEOUT_SECONDS=20
NVD_CACHE_TTL_SECONDS=604800
```

An API key is optional. Responses are cached in `project/storage/nvd_cache/service_queries.json`.

Keyword-only results remain candidate references. They are not presented as confirmed vulnerabilities unless stronger context such as exact CPE evidence exists.

Required attribution is displayed on the Results and Report pages.
