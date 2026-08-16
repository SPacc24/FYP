import json
from pathlib import Path
from unittest.mock import patch

from scanners import mitre_cve
from scanners.evidence_recovery import recovery_port_batches
from scanners.enumerator import (
    _build_collector_coverage_matrix,
    _build_cve_row,
    _build_unresolved_identity_queue,
    _group_cve_matches_by_host,
    _match_cves,
)
from scanners.platform_identity import extract_host_identities_from_nmap, host_identity_inventory, merge_host_identity_map


def _record(cve_id: str, version: str = '1.0') -> dict:
    return {
        'cve_id': cve_id,
        'description': 'fixture',
        'references': [],
        'source': mitre_cve.OFFICIAL_CVE_SOURCE,
        'record_state': 'PUBLISHED',
        'affected_vendors': ['Example Corporation'],
        'affected_products': ['Example Server'],
        'affected_versions': [version],
        'affected_entries': [{
            'vendor': 'Example Corporation', 'product': 'Example Server',
            'defaultStatus': 'unknown', 'versions': [{'version': version, 'status': 'affected'}], 'cpes': [],
        }],
        'cpes': [], 'cvss_metrics': {},
    }


def test_service_level_os_hint_never_becomes_host_identity():
    parsed = {'hosts': [{
        'address': '192.0.2.10', 'hostnames': [], 'scripts': [],
        'os_identities': [{
            'host': '192.0.2.10', 'product': 'Example Other OS', 'family': 'ExampleOther',
            'cpe': ['cpe:2.3:o:example:other_os:*:*:*:*:*:*:*:*'],
            'source': 'nmap_service_os_evidence', 'evidence_kind': 'service_os_hint',
        }],
        'ports': [{
            'port': 137, 'protocol': 'udp', 'service_attributes': {'ostype': 'Example Other OS'},
            'os_cpe': ['cpe:2.3:o:example:other_os:*:*:*:*:*:*:*:*'], 'scripts': [],
        }],
    }]}
    assert extract_host_identities_from_nmap(parsed, source='adaptive_evidence_recovery_udp_pass_1') == []


def test_externally_supplied_service_hint_is_supporting_only():
    identity_map = {}
    merge_host_identity_map(identity_map, [{
        'host': '192.0.2.11', 'product': 'Example Other OS', 'family': 'ExampleOther',
        'cpe': ['cpe:2.3:o:example:other_os:1:*:*:*:*:*:*:*'],
        'evidence_kind': 'service_os_hint', 'source': 'external-fixture',
    }])
    inventory = host_identity_inventory(identity_map)[0]
    assert inventory['cve_identities'] == []
    assert inventory['identities'][0]['reconciliation_status'] == 'service_hint_only'


def test_recovery_batches_respect_operator_batch_and_max_without_new_ports():
    batches = recovery_port_batches([53, 67, 68, 69, 88, 111, 123, 137, 138, 161], max_ports=9, batch_size=4)
    assert batches == [[53, 67, 68, 69], [88, 111, 123, 137], [138]]
    assert all(len(batch) <= 4 for batch in batches)


def test_unresolved_queue_recognises_adaptive_recovery_attempt():
    rows = _build_unresolved_identity_queue([{
        'host': '192.0.2.12', 'port': 25, 'protocol': 'tcp', 'service': 'smtp',
        'product': 'Example SMTP', 'version': '',
        'evidence_sources': ['nmap', 'adaptive_evidence_recovery_tcp_pass_1'],
    }])
    assert rows[0]['recovery_attempted'] is True


def test_collector_failure_kpi_includes_adaptive_pipeline_timeout():
    matrix = _build_collector_coverage_matrix(
        [{'host': '192.0.2.13', 'port': 53, 'protocol': 'udp', 'service': 'domain'}],
        {'collector_plan': {}},
        [{'tool': 'adaptive_evidence_recovery_udp_pass_1', 'lifecycle_state': 'executed_timeout', 'status': 'Timed Out - Incomplete'}],
        [],
    )
    assert matrix['summary']['endpoint_failed_actions'] == 0
    assert matrix['summary']['pipeline_failed_actions'] == 1
    assert matrix['summary']['failed_actions'] == 1


def test_vendor_gate_does_not_treat_missing_or_partial_published_vendor_as_match():
    assert mitre_cve._vendor_compatible('Microsoft', '') is False
    assert mitre_cve._vendor_compatible('Apache HTTP Server', 'Apache') is False
    assert mitre_cve._vendor_compatible('Example', 'Example Corporation') is True


def test_component_version_match_rejects_partial_and_prose_range():
    entry_partial = {'product': 'Example SMB', 'defaultStatus': 'unknown', 'versions': [{'version': 'SMB 1.5', 'status': 'affected'}]}
    entry_range = {'product': 'Example SMB', 'defaultStatus': 'unknown', 'versions': [{'version': 'SMB 1 through 3', 'status': 'affected'}]}
    assert mitre_cve._structured_component_version_match(entry_partial, 'smb', '1')[0] is False
    assert mitre_cve._structured_component_version_match(entry_range, 'smb', '1')[0] is False


def test_component_version_match_accepts_one_structured_point_version():
    entry = {'product': 'Example SMB', 'defaultStatus': 'unknown', 'versions': [{'version': 'SMBv1', 'status': 'affected'}]}
    ok, basis = mitre_cve._structured_component_version_match(entry, 'smb', '1')
    assert ok is True
    assert basis == 'structured_affected_component_exact_version'


def test_cve_record_processing_error_preserves_other_matches(tmp_path: Path):
    index = tmp_path / 'official.jsonl'
    records = [_record('CVE-2099-91001'), _record('CVE-2099-91002'), _record('CVE-2099-91003')]
    index.write_text(''.join(json.dumps(row) + '\n' for row in records), encoding='utf-8')
    original = mitre_cve._product_ok_for_record

    def selective(rec, spec, scope):
        if rec.get('cve_id') == 'CVE-2099-91002':
            raise RuntimeError('synthetic record failure')
        return original(rec, spec, scope)

    with patch.object(mitre_cve, 'INDEX', index), patch.object(mitre_cve, '_product_ok_for_record', side_effect=selective):
        mitre_cve._search_cached.cache_clear()
        rows, diagnostics = mitre_cve._search_cached('Example Server', '1.0', 'example', '', 'application_service')
    assert {row['cve_id'] for row in rows} == {'CVE-2099-91001', 'CVE-2099-91003'}
    assert any(item.get('reason') == 'cve_record_processing_error' and item.get('cve_id') == 'CVE-2099-91002' for item in diagnostics)


def test_cve_row_handoff_has_explicit_host_scoped_applicability_evidence():
    row = _build_cve_row(
        {'host': '192.0.2.14', 'port': 443, 'protocol': 'tcp', 'service': 'https', 'product': 'Example Server', 'version': '1.0', 'evidence_sources': ['nmap']},
        {**_record('CVE-2099-91004'), 'match_basis': 'structured_exact_version', 'product_match_basis': 'structured_affected_product'},
        'Baseline CVE Reference', 'fixture',
    )
    assert row['host'] == '192.0.2.14'
    assert row['applicability_evidence']['affected_host'] == '192.0.2.14'
    assert row['applicability_evidence']['observed_identity']['endpoints'] == ['443/tcp']


def test_legacy_component_point_version_wins_over_unrelated_platform_versions():
    entry = {
        'product': 'Example SMB',
        'defaultStatus': 'unknown',
        'versions': [{
            'version': 'The SMBv1 server in Example Platform 8.1 and Example Platform 10',
            'status': 'affected',
        }],
    }
    ok, basis = mitre_cve._structured_component_version_match(entry, 'smb', '1')
    assert ok is True
    assert basis == 'prose_affected_component_version_scrape'


def test_component_adjacent_point_version_does_not_collapse_newer_minor_version():
    entry = {
        'product': 'Example SMB',
        'defaultStatus': 'unknown',
        'versions': [{'version': 'SMB 1.5', 'status': 'affected'}],
    }
    assert mitre_cve._structured_component_version_match(entry, 'smb', '1')[0] is False


def test_cve_grouping_is_host_first_even_for_same_cve_id():
    rows = [
        {'host': '192.0.2.20', 'cve_id': 'CVE-2099-92001', 'port': 443, 'protocol': 'tcp', 'product': 'Example'},
        {'host': '192.0.2.21', 'cve_id': 'CVE-2099-92001', 'port': 443, 'protocol': 'tcp', 'product': 'Example'},
        {'host': '192.0.2.20', 'cve_id': 'CVE-2099-92002', 'port': 80, 'protocol': 'tcp', 'product': 'Example'},
    ]
    grouped = _group_cve_matches_by_host(rows)
    assert list(grouped) == ['192.0.2.20', '192.0.2.21']
    assert {row['cve_id'] for row in grouped['192.0.2.20']} == {'CVE-2099-92001', 'CVE-2099-92002'}
    assert [row['cve_id'] for row in grouped['192.0.2.21']] == ['CVE-2099-92001']
    assert grouped['192.0.2.20'][0] is not grouped['192.0.2.21'][0]


def test_legacy_component_candidate_search_uses_component_attached_version(tmp_path: Path):
    index = tmp_path / 'official-components.jsonl'
    record = {
        'cve_id': 'CVE-2099-92003',
        'description': 'fixture',
        'references': [],
        'source': mitre_cve.OFFICIAL_CVE_SOURCE,
        'record_state': 'PUBLISHED',
        'affected_vendors': ['Example Corporation'],
        'affected_products': ['Example SMB'],
        'affected_versions': ['legacy structured text'],
        'affected_entries': [{
            'vendor': 'Example Corporation',
            'product': 'Example SMB',
            'defaultStatus': 'unknown',
            'versions': [{
                'version': 'The SMBv1 server in Example Platform 8.1 and Example Platform 10',
                'status': 'affected',
            }],
            'cpes': [],
        }],
        'cpes': [],
        'cvss_metrics': {},
    }
    index.write_text(json.dumps(record) + '\n', encoding='utf-8')
    with patch.object(mitre_cve, 'INDEX', index):
        rows, diagnostics = mitre_cve.search_component_candidates('smb', '1', host_vendor='Example')
    assert [row['cve_id'] for row in rows] == ['CVE-2099-92003']
    assert rows[0]['match_basis'] == 'prose_affected_component_version_scrape'
    assert not [d for d in diagnostics if d.get('matcher_status') == 'error']


def test_component_cve_is_emitted_only_for_host_whose_platform_corroborates():
    candidate = {
        'cve_id': 'CVE-2099-92004',
        'description': 'fixture',
        'references': [],
        'source': mitre_cve.OFFICIAL_CVE_SOURCE,
        'identity_scope': 'platform_component',
        'cvss_metrics': {},
        'matched_product_tokens': ['Example SMB'],
        'matched_version_tokens': ['1'],
        'match_basis': 'prose_affected_component_version_scrape',
        'product_match_basis': 'structured_affected_component_product',
        'affected_vendors': ['Example Corporation'],
        'affected_products': ['Example SMB'],
        'affected_versions': ['SMBv1'],
        'affected_entries': [],
        'affected_cpes': [],
        'matched_affected_entry': {},
    }
    identities = [
        {'host': '192.0.2.30', 'scope': 'host_os', 'vendor': 'Example', 'product': 'Example OS', 'build': '1.0', 'cpe': ['cpe:/o:example:example_os:1.0']},
        {'host': '192.0.2.31', 'scope': 'host_os', 'vendor': 'Other', 'product': 'Other OS', 'build': '1.0', 'cpe': ['cpe:/o:other:other_os:1.0']},
    ]
    components = [
        {'host': '192.0.2.30', 'port': 445, 'protocol': 'tcp', 'service': 'netbios-ssn', 'component': 'smb', 'version': '1', 'evidence_sources': ['fixture']},
        {'host': '192.0.2.31', 'port': 445, 'protocol': 'tcp', 'service': 'netbios-ssn', 'component': 'smb', 'version': '1', 'evidence_sources': ['fixture']},
    ]

    with patch('scanners.enumerator.mitre_search_component_candidates', return_value=((candidate,), ())):
        rows, _ = _match_cves([], host_identities=identities, component_observations=components)

    component_rows = [row for row in rows if row.get('cve_id') == 'CVE-2099-92004']
    # Recon keeps both evidence-linked candidates. Host/platform applicability is
    # intentionally left to the downstream validation stage.
    assert len(component_rows) == 2
    assert {row['host'] for row in component_rows} == {'192.0.2.30', '192.0.2.31'}
    assert all(row['candidate_status'] == 'candidate' for row in component_rows)
    assert all(row['validation_state'] == 'not_performed' for row in component_rows)
