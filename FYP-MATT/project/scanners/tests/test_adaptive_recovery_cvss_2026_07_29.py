from __future__ import annotations

import inspect

from scanners import command_builders, mitre_cve
from scanners.collector_plan import COLLECTOR_PRODUCES, normalise_service_identity
from scanners.evidence_recovery import (
    collector_needed,
    merge_endpoint_observations,
    missing_evidence_types,
    recovery_candidates,
    recovery_intensity_ladder,
)
from scanners.scan_profiles import normalise_scan_options
from scanners.scoring_policy import apply_cvss_selection, cvss_sort_key, metric_for_version


def test_cvss_selection_defaults_to_31_and_supports_only_31_or_40():
    default = normalise_scan_options('full')
    assert default['cvss_selection'] == {'version': '3.1', 'label': 'CVSS 3.1'}

    selected = normalise_scan_options('full', cvss_version='4.0')
    assert selected['validation_errors'] == []
    assert selected['cvss_selection'] == {'version': '4.0', 'label': 'CVSS 4.0'}

    invalid = normalise_scan_options('full', cvss_version='2.0')
    assert invalid['validation_errors']
    assert 'Unsupported CVSS version' in invalid['validation_errors'][0]


def test_cvss_selected_metric_never_falls_back_between_versions():
    row = {
        'cve_id': 'CVE-2099-0002',
        'source_cvss_metrics': {
            '4.0': {
                'cvss_score': 8.4,
                'cvss_severity': 'HIGH',
                'cvss_vector': 'CVSS:4.0/AV:L',
                'cvss_source': 'fixture',
            }
        },
    }
    assert metric_for_version(row, '3.1') == {}
    apply_cvss_selection([row], '3.1')
    assert row['selected_cvss_status'] == 'not_published'
    assert row['source_cvss_score'] is None
    assert row['source_cvss_version'] == '3.1'


def test_cvss_sorting_uses_only_the_operator_selected_standard():
    rows = [
        {
            'cve_id': 'CVE-2099-0001',
            'effective_cvss_metrics': {
                '3.1': {'cvss_score': 6.7},
                '4.0': {'cvss_score': 8.4},
            },
        },
        {
            'cve_id': 'CVE-2099-0002',
            'effective_cvss_metrics': {
                '3.1': {'cvss_score': 8.1},
            },
        },
    ]
    by_31 = sorted(rows, key=lambda row: cvss_sort_key(row, '3.1'))
    by_40 = sorted(rows, key=lambda row: cvss_sort_key(row, '4.0'))
    assert [row['cve_id'] for row in by_31] == ['CVE-2099-0002', 'CVE-2099-0001']
    assert [row['cve_id'] for row in by_40] == ['CVE-2099-0001', 'CVE-2099-0002']


def test_canonical_cve_matcher_order_is_cvss_version_neutral():
    rows = [
        {'cve_id': 'CVE-2099-0002', 'cvss_metrics': {'4.0': {'cvss_score': 10.0}}},
        {'cve_id': 'CVE-2099-0001', 'cvss_metrics': {'3.1': {'cvss_score': 1.0}}},
    ]
    assert [row['cve_id'] for row in sorted(rows, key=mitre_cve._sort_key)] == [
        'CVE-2099-0001', 'CVE-2099-0002'
    ]


def test_recovery_intensity_ladder_is_bounded_and_transparent():
    assert recovery_intensity_ladder(0, 7, 3) == [3, 5, 7]
    assert recovery_intensity_ladder(2, 2, 2) == [2, 2]
    assert recovery_intensity_ladder(7, 2, 2) == [2, 2]
    assert recovery_intensity_ladder(-50, 99, 4) == [3, 5, 7, 9]


def test_udp_open_filtered_is_recoverable_without_becoming_open():
    row = {
        'host': '192.0.2.10', 'port': 53, 'protocol': 'udp', 'state': 'open|filtered',
        'service': 'domain', 'product': '', 'version': '',
    }
    candidates = recovery_candidates([row], protocol='udp', include_uncertain_udp=True)
    assert len(candidates) == 1
    assert 'endpoint_state' in candidates[0]['recovery_missing_evidence']
    assert recovery_candidates([row], protocol='udp', include_uncertain_udp=False) == []
    assert recovery_candidates([row], protocol='tcp', include_uncertain_udp=True) == []


def test_udp_recovery_observation_is_promoted_only_when_new_state_is_open():
    base = [{
        'host': '192.0.2.10', 'port': 161, 'protocol': 'udp', 'state': 'open|filtered',
        'service': 'snmp', 'product': '', 'version': '',
    }]
    unchanged = merge_endpoint_observations(base, [{
        'host': '192.0.2.10', 'port': 161, 'protocol': 'udp', 'state': 'open|filtered',
    }])
    assert unchanged[0]['state'] == 'open|filtered'
    promoted = merge_endpoint_observations(unchanged, [{
        'host': '192.0.2.10', 'port': 161, 'protocol': 'udp', 'state': 'open',
        'product': 'Example Agent', 'version': '1.2.3',
    }])
    assert promoted[0]['state'] == 'open'
    assert promoted[0]['product'] == 'Example Agent'
    assert promoted[0]['version'] == '1.2.3'


def test_udp_version_recovery_command_uses_udp_transport_and_selected_ports_only():
    udp = command_builders.nmap_service_fingerprint(
        'nmap', '192.0.2.10', [53, 161], 5, ['-T1'], '/tmp/udp-recovery.xml',
        banner_script=True, protocol='udp',
    )
    tcp = command_builders.nmap_service_fingerprint(
        'nmap', '192.0.2.10', [22], 5, ['-T1'], '/tmp/tcp-recovery.xml',
        protocol='tcp',
    )
    assert '-sU' in udp
    assert '-Pn' in udp
    assert udp[udp.index('-p') + 1] == '53,161'
    assert '-sU' not in tcp


def test_collector_capabilities_describe_evidence_not_target_facts():
    assert {'service_product', 'service_version'} <= set(COLLECTOR_PRODUCES['native_protocol_enrichment'])
    assert 'protocol_component' in COLLECTOR_PRODUCES['smb_protocol_security']
    assert 'host_build' in COLLECTOR_PRODUCES['ntlm_rdp_identity']
    source = inspect.getsource(__import__('scanners.collector_plan', fromlist=['*']))
    assert 'CVE-20' not in source


def test_auto_collector_relevance_comes_from_missing_evidence_and_capabilities():
    entry = {'mode': 'auto', 'produces': ['service_product', 'service_version']}
    unresolved = {'state': 'open', 'product': '', 'version': ''}
    resolved = {'state': 'open', 'product': 'Example', 'version': '1.2.3'}
    assert collector_needed(entry, unresolved) is True
    assert collector_needed(entry, resolved) is False
    assert missing_evidence_types(unresolved) >= {'service_product', 'service_version'}


def test_service_identity_normalisation_enables_bounded_tcp_udp_recovery():
    policy = {
        'version_evidence_recovery': {
            'enabled': True,
            'nmap_version_intensity': 7,
            'max_ports_per_host': 64,
        },
        'service_identity_defaults': {
            'version_intensity': 0,
            'recovery_attempts': 1,
        },
    }
    cfg = normalise_service_identity(policy, {
        'version_recovery': True,
        'recovery_attempts': 99,
        'recovery_intensity': 9,
    })
    assert cfg['adaptive_evidence_recovery'] is True
    assert cfg['udp_evidence_recovery'] is True
    assert cfg['recovery_attempts'] == 4
    assert cfg['recovery_intensity'] == 9


def test_adaptive_recovery_uses_operator_command_timeout_not_fixed_900_seconds():
    from scanners import enumerator
    source = inspect.getsource(enumerator)
    assert 'run_cmd(command, output_path, 900' not in source
    assert "command_timeout_seconds" in source


def test_nvd_cvss_enrichment_fills_only_the_missing_version(monkeypatch):
    from scanners import enumerator

    rows = [{
        'cve_id': 'CVE-2099-0099',
        'source_cvss_metrics': {
            '3.1': {
                'cvss_score': 7.5,
                'cvss_severity': 'HIGH',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'cvss_source': 'CNA',
            }
        },
    }]
    nvd = {
        '3.1': {'cvss_score': 9.9, 'cvss_severity': 'CRITICAL', 'cvss_vector': 'fixture', 'cvss_source': 'NVD'},
        '4.0': {'cvss_score': 8.0, 'cvss_severity': 'HIGH', 'cvss_vector': 'CVSS:4.0/AV:N', 'cvss_source': 'NVD'},
    }
    monkeypatch.setattr(
        enumerator,
        'nvd_lookup_cve_metrics',
        lambda _cve_id: (nvd, {'matcher_status': 'available', 'reason': 'fixture'}),
    )
    diagnostics = []
    enumerator._enrich_missing_cvss_from_nvd(rows, diagnostics)

    effective = rows[0]['effective_cvss_metrics']
    assert effective['3.1']['cvss_score'] == 7.5  # canonical source preserved
    assert effective['4.0']['cvss_score'] == 8.0  # only missing version filled
    assert rows[0]['nvd_cvss_metrics'] == {'4.0': nvd['4.0']}
    # PenPilot requests only the supported missing CVSS 4.0 metric here; the
    # existing CVSS 3.1 source remains untouched and unsupported legacy CVSS versions are not used.
    assert rows[0]['nvd_cvss_enrichment']['requested_versions'] == ['4.0']
    assert '3.0' not in rows[0]['nvd_cvss_metrics']
    assert effective['3.1']['cvss_score'] == 7.5


def test_secondary_nmap_parser_preserves_udp_open_filtered_state(tmp_path):
    from scanners.nmap_parser import parse_nmap_xml

    xml = tmp_path / 'udp.xml'
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/>'
        '<service name="domain" method="table" conf="3"/></port>'
        '</ports></host><runstats><finished/><hosts up="1" down="0" total="1"/></runstats></nmaprun>',
        encoding='utf-8',
    )
    data = parse_nmap_xml(xml)
    assert data['total_open_filtered_ports'] == 1
    assert data['hosts'][0]['open_filtered_ports'][0]['state'] == 'open|filtered'


def test_cvss_verifier_never_blocks_scanner_preflight():
    from scanners.result_contracts import build_selected_plan_readiness

    options = normalise_scan_options(
        'custom',
        [],
        tcp_port_mode='custom', tcp_custom_ports='22',
        udp_port_mode='custom', udp_custom_ports='53',
        service_identity_settings={
            'tcp_discovery_enabled': False,
            'udp_discovery_enabled': False,
            'service_fingerprinting_enabled': False,
        },
        cvss_version='4.0',
    )
    readiness = build_selected_plan_readiness(
        scan_options=options,
        cve_source_status={'available': True, 'records_indexed': 1},
        cvss_verifiers={
            '3.1': {'available': True, 'method': 'fixture'},
            '4.0': {'available': False, 'method': 'fixture'},
        },
        storage_paths=(),
        binary_resolver=lambda _name: '/usr/bin/fixture',
    )
    assert readiness['launch_blocked'] is False
    assert all(not str(item['component']).startswith('cvss_') for item in readiness['rows'])


def test_cvss_choice_does_not_change_scan_or_recovery_configuration():
    common = dict(
        tcp_port_mode='custom', tcp_custom_ports='22,443',
        udp_port_mode='custom', udp_custom_ports='53,161',
        service_identity_settings={
            'version_intensity': 1,
            'version_recovery': True,
            'recovery_intensity': 6,
            'recovery_attempts': 3,
        },
        advanced_settings={
            'command_timeout_seconds': 123,
            'parallel_scanning': True,
            'parallel_workers': 2,
        },
    )
    v31 = normalise_scan_options('custom', [], cvss_version='3.1', **common)
    v40 = normalise_scan_options('custom', [], cvss_version='4.0', **common)

    # CVSS selection is scoring metadata only. All execution/recovery inputs are identical.
    for key in ('host_discovery', 'service_identity', 'port_selection', 'advanced_settings', 'collector_plan', 'enabled_tools'):
        assert v31[key] == v40[key]
    assert v31['cvss_selection']['version'] == '3.1'
    assert v40['cvss_selection']['version'] == '4.0'


def test_cvss_selection_changes_scoring_view_not_finding_set():
    base = [
        {'cve_id': 'CVE-2099-0001', 'effective_cvss_metrics': {'3.1': {'cvss_score': 9.0}, '4.0': {'cvss_score': 5.0}}},
        {'cve_id': 'CVE-2099-0002', 'effective_cvss_metrics': {'3.1': {'cvss_score': 4.0}, '4.0': {'cvss_score': 9.0}}},
    ]
    import copy
    rows31 = copy.deepcopy(base)
    rows40 = copy.deepcopy(base)
    apply_cvss_selection(rows31, '3.1')
    apply_cvss_selection(rows40, '4.0')
    assert {row['cve_id'] for row in rows31} == {row['cve_id'] for row in rows40} == {'CVE-2099-0001', 'CVE-2099-0002'}
    assert len(rows31) == len(rows40) == 2
    assert [row['cve_id'] for row in rows31] != [row['cve_id'] for row in rows40]
