import json
from pathlib import Path

from scanners import nvd_client


def test_nvd_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(nvd_client, 'CACHE_DIR', tmp_path)
    monkeypatch.setattr(nvd_client, 'CACHE_FILE', tmp_path / 'service_queries.json')
    monkeypatch.setenv('NVD_ENRICHMENT_ENABLED', '1')
    monkeypatch.setenv('NVD_REQUEST_DELAY_SECONDS', '0')

    payload = {
        'vulnerabilities': [{
            'cve': {
                'id': 'CVE-TEST-0001',
                'descriptions': [{'lang': 'en', 'value': 'Test vulnerability'}],
                'references': [{'url': 'https://example.test'}],
                'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'baseScore': 9.8, 'baseSeverity': 'CRITICAL', 'vectorString': 'CVSS:3.1/AV:N'}}]},
                'configurations': [{
                    'nodes': [{
                        'operator': 'OR',
                        'cpeMatch': [{
                            'vulnerable': True,
                            'criteria': 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
                        }],
                    }],
                }],
            }
        }]
    }
    monkeypatch.setattr(nvd_client, '_request', lambda params: (payload, {}))
    observed_cpe = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
    rows, diagnostics = nvd_client.search('Apache httpd', '2.4.49', 'http', observed_cpe)
    assert rows[0]['cve_id'] == 'CVE-TEST-0001'
    assert rows[0]['upstream_source'] == 'NVD CVE API 2.0'
    assert nvd_client.CACHE_FILE.exists()

    monkeypatch.setattr(nvd_client, '_request', lambda params: (_ for _ in ()).throw(AssertionError('network should not be called')))
    cached_rows, _ = nvd_client.search('Apache httpd', '2.4.49', 'http', observed_cpe)
    assert cached_rows[0]['cve_id'] == 'CVE-TEST-0001'
