from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scanners.enumerator import (
    _build_observed_security_conditions,
    _enrich_missing_cvss_from_nvd,
    _merge_service_identity_rows,
    _sanitise_export_paths,
    _structured_prerequisite_context,
)
from scanners import nvd_client


def test_observed_security_conditions_are_collector_data_driven():
    checks = [
        {
            'tool': 'example_protocol_check',
            'host': '198.51.100.10',
            'port': 4242,
            'rows': [
                {
                    'host': '198.51.100.10',
                    'port': 4242,
                    'protocol': 'tcp',
                    'scripts': [{'id': 'example-security-property', 'output': 'Explicit property observed'}],
                }
            ],
        },
        {
            'tool': 'example_native_check',
            'host': '198.51.100.10',
            'port': 4343,
            'parsed': {
                'evidence_state': 'observed',
                'fields': {'capabilities': ['feature-a'], 'setting': 'enabled'},
            },
        },
    ]
    rows = _build_observed_security_conditions(checks, {})
    evidence = ' '.join(row['evidence'] for row in rows)
    assert 'Explicit property observed' in evidence
    assert 'feature-a' in evidence
    assert all(row['classification'].startswith('Observed evidence') for row in rows)


def test_structured_prerequisite_context_does_not_change_applicability():
    match = {
        'structured_requirements': {
            'modules': ['example_module'],
            'platforms': [],
            'package_name': '',
        }
    }
    service = {
        'service': 'demo',
        'product': 'Example Product',
        'version': '1.0',
        'scripts': [{'output': 'example_module is enabled'}],
    }
    context = _structured_prerequisite_context(match, service)
    assert context['status'] == 'observed'
    assert context['published']['modules'] == ['example_module']

    absent = _structured_prerequisite_context({'structured_requirements': {}}, service)
    assert absent['status'] == 'not_published'


def test_version_recovery_merge_replaces_range_with_exact_observation():
    base = [{
        'host': '203.0.113.4', 'port': 1234, 'protocol': 'tcp',
        'service': 'demo', 'product': 'Example', 'version': '1.0 - 2.0',
        'evidence_sources': ['nmap'], 'cpe': [],
    }]
    recovered = [{
        'host': '203.0.113.4', 'port': 1234, 'protocol': 'tcp',
        'service': 'demo', 'product': 'Example', 'version': '1.7.2',
        'evidence_sources': ['nmap'], 'cpe': ['cpe:/a:example:example:1.7.2'],
    }]
    merged = _merge_service_identity_rows(base, recovered, 'nmap_version_recovery')
    assert merged[0]['version'] == '1.7.2'
    assert 'nmap_version_recovery' in merged[0]['evidence_sources']
    assert merged[0]['cpe'] == ['cpe:/a:example:example:1.7.2']


def test_export_path_sanitiser_keeps_evidence_identity_not_local_project_path():
    value = {
        'path': '/home/operator/Desktop/project/storage/scans/example.xml',
        'command': 'tool -o /tmp/work/storage/results/output.json target',
    }
    safe = _sanitise_export_paths(value)
    assert safe['path'] == 'evidence/example.xml'
    assert 'evidence/output.json' in safe['command']
    assert '/home/operator' not in str(safe)
    assert '/tmp/work' not in str(safe)


def test_nvd_exact_cve_metric_lookup_is_id_based_and_cached_without_matching():
    metric = {
        '3.1': {
            'cvss_score': 9.8,
            'cvss_severity': 'CRITICAL',
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'cvss_source': 'nvd@nist.gov',
            'cvss_provider_name': 'NVD',
        }
    }
    api_payload = {'vulnerabilities': [{'cve': {'id': 'CVE-2099-0001'}}]}
    with patch.object(nvd_client, '_load_metric_cache', return_value={}), \
         patch.object(nvd_client, '_save_metric_cache'), \
         patch.object(nvd_client, '_request', return_value=(api_payload, {})) as request, \
         patch.object(nvd_client, '_metrics', return_value=metric):
        metrics, diagnostic = nvd_client.lookup_cve_metrics('CVE-2099-0001')
    assert metrics == metric
    assert diagnostic['matcher_status'] == 'available'
    request.assert_called_once_with({'cveId': 'CVE-2099-0001'})


def test_nvd_enrichment_only_fills_unscored_rows_and_never_overwrites_cve_program_metric():
    cna_metric = {'3.1': {'cvss_score': 5.0, 'cvss_source': 'cna'}}
    nvd_metric = {'3.1': {'cvss_score': 9.8, 'cvss_source': 'NVD'}}
    rows = [
        {'cve_id': 'CVE-2099-0001', 'source_cvss_metrics': {}},
        {'cve_id': 'CVE-2099-0002', 'source_cvss_metrics': cna_metric},
    ]
    diagnostics = []
    with patch('scanners.enumerator.nvd_lookup_cve_metrics', return_value=(nvd_metric, {'matcher_status': 'available'})) as lookup:
        _enrich_missing_cvss_from_nvd(rows, diagnostics)
    assert rows[0]['effective_cvss_metrics']['3.1']['cvss_score'] == 9.8
    assert rows[1]['effective_cvss_metrics']['3.1']['cvss_score'] == 5.0
    assert lookup.call_count == 1


def test_nvd_enrichment_stops_repeated_queries_after_service_degrades():
    rows = [
        {'cve_id': 'CVE-2099-0101', 'source_cvss_metrics': {}},
        {'cve_id': 'CVE-2099-0102', 'source_cvss_metrics': {}},
    ]
    diagnostics = []
    with patch(
        'scanners.enumerator.nvd_lookup_cve_metrics',
        return_value=({}, {'matcher_status': 'degraded', 'reason': 'network'}),
    ) as lookup:
        _enrich_missing_cvss_from_nvd(rows, diagnostics)
    assert lookup.call_count == 1
    assert rows[0]['effective_cvss_metrics'] == {}
    assert rows[1]['effective_cvss_metrics'] == {}


def test_nvd_enrichment_status_is_explicit_for_unscored_rows():
    rows = [{'cve_id': 'CVE-2099-0201', 'source_cvss_metrics': {}}]
    diagnostics = []
    nvd_metric = {'3.1': {'cvss_score': 7.5, 'cvss_source': 'nvd@nist.gov', 'cvss_provider_name': 'NVD'}}
    with patch('scanners.enumerator.nvd_lookup_cve_metrics', return_value=(nvd_metric, {'matcher_status': 'available'})):
        _enrich_missing_cvss_from_nvd(rows, diagnostics)
    assert rows[0]['nvd_cvss_enrichment']['status'] == 'available'
    assert rows[0]['nvd_cvss_enrichment']['versions'] == ['3.1']


def test_version_recovery_preserves_different_identity_layer_and_updates_unknown_service():
    base = [{
        'host': '203.0.113.8', 'port': 8180, 'protocol': 'tcp',
        'service': 'unknown', 'product': 'Example Application', 'version': '5.5',
        'evidence_sources': ['httpx'], 'cpe': [],
    }]
    recovered = [{
        'host': '203.0.113.8', 'port': 8180, 'protocol': 'tcp',
        'service': 'http', 'product': 'Example Connector', 'version': '1.1',
        'evidence_sources': ['nmap'], 'cpe': ['cpe:/a:example:connector:1.1'],
    }]
    merged = _merge_service_identity_rows(base, recovered, 'nmap_version_recovery')
    row = merged[0]
    assert row['service'] == 'http'
    assert row['product'] == 'Example Application'
    assert row['version'] == '5.5'
    identities = {(i.get('product'), i.get('version')) for i in row.get('observed_identities') or []}
    assert ('Example Connector', '1.1') in identities


def test_version_recovery_still_replaces_range_when_same_product_identity():
    base = [{
        'host': '203.0.113.9', 'port': 5432, 'protocol': 'tcp',
        'service': 'demo', 'product': 'Example DB', 'version': '8.3.0 - 8.3.7',
        'evidence_sources': ['nmap'], 'cpe': [],
    }]
    recovered = [{
        'host': '203.0.113.9', 'port': 5432, 'protocol': 'tcp',
        'service': 'demo', 'product': 'Example DB', 'version': '8.3.4',
        'evidence_sources': ['nmap'], 'cpe': [],
    }]
    merged = _merge_service_identity_rows(base, recovered, 'nmap_version_recovery')
    assert merged[0]['version'] == '8.3.4'


def test_host_script_security_evidence_is_promoted_without_product_rules(tmp_path):
    xml = tmp_path / 'check.xml'
    xml.write_text('''<?xml version="1.0"?><nmaprun><host><hostscript><script id="example-protocols" output="Legacy dialect observed"/></hostscript></host></nmaprun>''', encoding='utf-8')
    checks = [{'tool': 'generic_security_collector', 'host': '198.51.100.20', 'port': 445, 'output_file': str(xml), 'rows': []}]
    rows = _build_observed_security_conditions(checks, {})
    assert any(row['check'] == 'example-protocols' and 'Legacy dialect observed' in row['evidence'] for row in rows)


def test_web_application_identity_requires_title_technology_corroboration():
    from scanners.enumerator import _web_application_identity
    identity = _web_application_identity({
        'title': 'Example Application/5.5',
        'tech': ['Example Application', 'Java'],
        'scheme': 'http',
    })
    assert identity['product'] == 'Example Application'
    assert identity['version'] == '5.5'
    assert _web_application_identity({'title': 'Example Application/5.5', 'tech': ['Unrelated'], 'scheme': 'http'}) is None


def test_non_executed_coverage_statuses_are_separated():
    from scanners.enumerator import _build_scan_summary
    summary = _build_scan_summary(
        targets_requested=1,
        live_hosts=['192.0.2.1'],
        scan_options={'port_selection': {'tcp': {'mode': 'custom', 'count': 1}, 'udp': {'mode': 'custom', 'count': 0}}},
        scanned_tcp_ports_by_host={'192.0.2.1': {80}},
        scanned_udp_ports_by_host={'192.0.2.1': set()},
        discovery_evidence={'192.0.2.1': {'ports': [{'port': 80, 'protocol': 'tcp', 'state': 'open'}], 'extraports': []}},
        open_map={'192.0.2.1': [80]},
        all_services=[{'host': '192.0.2.1', 'port': 80, 'protocol': 'tcp', 'service': 'http', 'product': 'Example', 'version': '1.0'}],
        public_coverage=[
            {'status': 'Completed'},
            {'status': 'No Evidence Observed'},
            {'status': 'Not Applicable'},
            {'status': 'Disabled by Policy/Profile'},
            {'status': 'Tool Unavailable'},
            {'status': 'Deferred'},
            {'status': 'Skipped by Policy'},
        ],
            cve_matches=[],
    )
    checks = summary['evidence_checks']
    assert checks['executed'] == 2
    assert checks['not_executed'] == 5
    assert checks['not_applicable'] == 1
    assert checks['disabled'] == 1
    assert checks['unavailable'] == 1
    assert checks['deferred'] == 1
    assert checks['skipped_policy'] == 1


def test_cve_matching_evaluates_versioned_observed_identity_variants():
    from scanners.enumerator import _match_cves
    from scanners.mitre_cve import OFFICIAL_CVE_SOURCE
    service = {
        'host': '203.0.113.10', 'port': 8180, 'protocol': 'tcp', 'service': 'http',
        'product': 'Example Connector', 'version': '1.1', 'cpe': [],
        'confidence_score': 0.95, 'recommended_for_cve': True,
        'observed_identities': [{
            'kind': 'web_application', 'service': 'http', 'product': 'Example Application',
            'version': '5.5', 'cpe': [], 'sources': ['httpx'],
        }],
    }
    def fake_search(product, version, service_name, cpe, **kwargs):
        if product == 'Example Application' and version == '5.5':
                return ([{
                    'cve_id': 'CVE-2099-5555', 'source': OFFICIAL_CVE_SOURCE,
                    'description': 'example', 'match_basis': 'structured_exact_version',
                    'matched_product_tokens': ['Example Application'],
                    'matched_version_tokens': ['5.5'],
                    'cvss_metrics': {},
                }], [])
        return ([], [])
    with patch('scanners.enumerator.mitre_search_with_held', side_effect=fake_search):
        strict, relevant = _match_cves([service])
    all_rows = strict + relevant
    assert any(row['cve_id'] == 'CVE-2099-5555' and row['product'] == 'Example Application' and row['version'] == '5.5' for row in all_rows)


def test_discovery_identity_is_preserved_as_alternate_service_name():
    from scanners.enumerator import _attach_discovery_observed_identities, _identity_context_text
    rows = [{'host': '198.51.100.30', 'port': 2049, 'protocol': 'tcp', 'service': 'rpcbind', 'product': '', 'version': ''}]
    discovery = {'198.51.100.30': {'ports': [{'port': 2049, 'protocol': 'tcp', 'state': 'open', 'service': 'nfs'}]}}
    _attach_discovery_observed_identities(rows, discovery)
    text = _identity_context_text(rows[0])
    assert 'nfs' in text.lower()
    assert rows[0]['service'] == 'rpcbind'


def test_client_report_sources_do_not_reintroduce_retired_cve_status_terms():
    project = Path(__file__).resolve().parents[1] / 'project'
    paths = [
        project / 'scanners' / 'pdf_export.py',
        project / 'templates' / 'pdf_report.html',
        project / 'templates' / 'scan_vul.html',
        project / 'templates' / 'results.html',
    ]
    visible = '\n'.join(path.read_text(encoding='utf-8') for path in paths)
    for phrase in ('Candidate CVE References', 'MITRE candidate references retained', 'Validated MITRE Reference', 'Key Exposure Indicators'):
        assert phrase not in visible
    assert 'Risk score' not in (project / 'templates' / 'results.html').read_text(encoding='utf-8')
