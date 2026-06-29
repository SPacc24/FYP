from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / 'project'
sys.path.insert(0, str(ROOT))

from enumeration.operational_maturity import (
    build_differential_recon,
    build_enumeration_cache,
    build_operational_metrics,
    build_service_confidence_breakdown,
)


def test_operational_metrics_are_descriptive_not_scores():
    metrics = build_operational_metrics('abc', [{'host': '1.1.1.1', 'port': 80}], [{'path': 'x'}], {'http_security_context': [{'host': '1.1.1.1'}]})
    assert metrics['service_records'] == 1
    assert 'risk' not in str(metrics).lower()
    assert 'priority' not in str(metrics).lower()


def test_service_confidence_breakdown_uses_sources():
    rows = build_service_confidence_breakdown(
        [{'host': '10.0.0.5', 'port': 80, 'protocol': 'tcp', 'service': 'http', 'product': 'Apache', 'version': '2.4'}],
        {'service_roles': [{'host': '10.0.0.5', 'role': 'Likely Web or Application Platform'}]},
        {'http_security_context': [{'host': '10.0.0.5'}]},
        {'findings': [{'host': '10.0.0.5'}]},
    )
    assert rows[0]['confidence'] == 'Supported'
    assert 'Validator evidence' in rows[0]['evidence_sources']


def test_enumeration_cache_writes_metadata(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = build_enumeration_cache('abc', '10.0.0.5', [{'host': '10.0.0.5', 'port': 22}], {'dns_context': [{'host': '10.0.0.5'}]}, {})
    assert cache['cache_file']
    assert Path(cache['cache_file']).exists()
    assert cache['reusable_collectors']


def test_differential_recon_first_run_has_baseline_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    diff = build_differential_recon('abc', '10.0.0.5', [{'host': '10.0.0.5', 'port': 22}], results_dir='storage/results')
    assert diff['baseline_found'] is False
    assert 'baseline' in diff['summary'].lower()
