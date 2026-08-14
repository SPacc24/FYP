from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from scanners import command_builders, cpe_resolver, mitre_cve, nvd_client
from scanners.active_validation import build_information_gathering_summary, parse_external_result
from scanners.collector_plan import COLLECTOR_METADATA
from scanners.enumerator import (
    _build_protocol_component_observations,
    _build_collector_coverage_matrix,
    _collector_service_applicable,
    _match_cves,
)


def test_protocol_specific_collectors_do_not_cross_tcp_udp_boundaries():
    smb = COLLECTOR_METADATA['smb_protocol_security']
    netbios = COLLECTOR_METADATA['netbios_identity']
    udp_137 = {'host': '192.0.2.10', 'port': 137, 'protocol': 'udp', 'service': 'netbios-ns', 'product': ''}
    tcp_445 = {'host': '192.0.2.10', 'port': 445, 'protocol': 'tcp', 'service': 'microsoft-ds', 'product': 'Example SMB'}

    assert _collector_service_applicable(smb, udp_137) is False
    assert _collector_service_applicable(smb, tcp_445) is True
    assert _collector_service_applicable(netbios, udp_137) is True


def test_nmap_nse_builder_uses_observed_protocol():
    udp = command_builders.nmap_nse_collector(
        'nmap', '192.0.2.10', 137, ['nbstat'], ['-T1'], '/tmp/udp.xml', protocol='udp'
    )
    tcp = command_builders.nmap_nse_collector(
        'nmap', '192.0.2.10', 445, ['smb-protocols'], ['-T1'], '/tmp/tcp.xml', protocol='tcp'
    )
    assert '-sU' in udp
    assert '-sU' not in tcp


def test_microsoft_rpc_does_not_trigger_onc_rpc_or_nfs_collectors():
    msrpc = {'host': '192.0.2.10', 'port': 135, 'protocol': 'tcp', 'service': 'msrpc', 'product': 'Microsoft RPC'}
    rpcbind = {'host': '192.0.2.20', 'port': 111, 'protocol': 'tcp', 'service': 'rpcbind', 'product': 'rpcbind'}
    nfs = {'host': '192.0.2.20', 'port': 2049, 'protocol': 'tcp', 'service': 'nfs', 'product': 'NFS'}

    assert _collector_service_applicable(COLLECTOR_METADATA['rpcinfo_native'], msrpc) is False
    assert _collector_service_applicable(COLLECTOR_METADATA['showmount_native'], msrpc) is False
    assert _collector_service_applicable(COLLECTOR_METADATA['rpcinfo_native'], rpcbind) is True
    assert _collector_service_applicable(COLLECTOR_METADATA['showmount_native'], nfs) is True


def test_timeout_is_not_parsed_as_zero_rpc_or_zero_exports():
    timeout = {
        'success': False,
        'timed_out': True,
        'completion_reason': 'timeout',
        'stdout': '',
        'stderr': 'timeout',
    }
    rpc, rpc_produced = parse_external_result('rpcinfo_native', timeout)
    nfs, nfs_produced = parse_external_result('showmount_native', timeout)

    assert rpc_produced is False
    assert nfs_produced is False
    assert rpc['evidence_state'] == 'execution_timeout'
    assert nfs['evidence_state'] == 'execution_timeout'
    assert rpc['fields'] == {}
    assert nfs['fields'] == {}


def test_timeout_rows_are_excluded_from_information_gathering_summary():
    data = {
        'rpcinfo_native': [{
            'lifecycle_state': 'executed_timeout',
            'parsed': {'evidence_state': 'execution_timeout', 'fields': {}},
        }],
        'showmount_native': [{
            'lifecycle_state': 'executed_failed',
            'parsed': {'evidence_state': 'execution_failed', 'fields': {}},
        }],
    }
    summary = build_information_gathering_summary(data)
    assert not any('rpcinfo' in row for row in summary)
    assert not any('showmount' in row for row in summary)




def test_failed_raw_artifact_does_not_become_endpoint_evidence():
    services = [{'host': '192.0.2.20', 'port': 111, 'protocol': 'tcp', 'service': 'rpcbind', 'product': 'rpcbind'}]
    options = {'collector_plan': {'rpcinfo_native': {
        'scope': 'service', 'families': ['rpcbind'], 'protocols': ['tcp'],
        'requested': True, 'policy_state': 'permitted', 'mode': 'auto', 'group': 'file_directory',
    }}}
    coverage = [{
        'tool': 'rpcinfo_native', 'status': 'Failed - Incomplete',
        'note': '192.0.2.20:111/tcp; targeted information-gathering evidence only.',
        'lifecycle_state': 'executed_timeout',
    }]
    raw = [{'tool': 'rpcinfo_native', 'host': '192.0.2.20', 'port': 111, 'parsed': False, 'file': '/tmp/rpc.txt'}]
    matrix = _build_collector_coverage_matrix(services, options, coverage, raw)
    row = matrix['endpoint_rows'][0]
    assert row['lifecycle_state'] == 'executed_timeout'
    assert row['outcome'] != 'Evidence retained'

def test_direct_smbv1_evidence_becomes_protocol_component_observation():
    checks = [{
        'tool': 'smb_protocol_security',
        'host': '192.0.2.10',
        'port': 445,
        'protocol': 'tcp',
        'lifecycle_state': 'executed_evidence',
        'script_evidence': ['dialects: NT LM 0.12 (SMBv1) 2.0.2 2.1 3.0'],
        'output_file': '/tmp/smb.xml',
    }]
    plan = {'smb_protocol_security': {'component_families': ['smb']}}
    rows = _build_protocol_component_observations(checks, plan)
    assert len(rows) == 1
    assert rows[0]['component'] == 'smb'
    assert rows[0]['version'] == '1'
    assert rows[0]['protocol'] == 'tcp'



def test_protocol_component_observation_can_read_real_nmap_xml_when_script_evidence_not_duplicated(tmp_path: Path):
    xml = tmp_path / 'smb.xml'
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="445">'
        '<state state="open"/><service name="microsoft-ds"/></port></ports>'
        '<hostscript><script id="smb-protocols" output="dialects: NT LM 0.12 (SMBv1) 2.0.2 3.1.1"/>'
        '</hostscript></host></nmaprun>',
        encoding='utf-8',
    )
    checks = [{
        'tool': 'smb_protocol_security',
        'host': '192.0.2.10',
        'port': 445,
        'protocol': 'tcp',
        'lifecycle_state': 'executed_evidence',
        'output_file': str(xml),
    }]
    plan = {'smb_protocol_security': {'component_families': ['smb']}}
    rows = _build_protocol_component_observations(checks, plan)
    assert [(row['component'], row['version'], row['protocol']) for row in rows] == [('smb', '1', 'tcp')]


def test_protocol_component_observation_rejects_failed_xml_even_when_file_contains_component(tmp_path: Path):
    xml = tmp_path / 'failed_smb.xml'
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><hostscript>'
        '<script id="smb-protocols" output="dialects: NT LM 0.12 (SMBv1)"/>'
        '</hostscript></host></nmaprun>',
        encoding='utf-8',
    )
    checks = [{
        'tool': 'smb_protocol_security', 'host': '192.0.2.10', 'port': 445, 'protocol': 'tcp',
        'lifecycle_state': 'executed_timeout', 'output_file': str(xml),
    }]
    plan = {'smb_protocol_security': {'component_families': ['smb']}}
    assert _build_protocol_component_observations(checks, plan) == []

def _component_record(cve_id: str, *, description: str = 'fixture') -> dict:
    return {
        'cve_id': cve_id,
        'description': description,
        'references': [],
        'source': mitre_cve.OFFICIAL_CVE_SOURCE,
        'record_state': 'PUBLISHED',
        'affected_vendors': ['Example Corporation'],
        'affected_products': ['Example SMB'],
        'affected_versions': [],
        'affected_entries': [{
            'vendor': 'Example Corporation',
            'product': 'Example SMB',
            'defaultStatus': 'unknown',
            'versions': [{'version': 'The SMBv1 server in Example Operating System', 'status': 'affected'}],
            'cpes': [],
        }],
        'cpes': [],
        'cvss_metrics': {},
    }


def test_component_candidates_come_only_from_structured_affected_fields(tmp_path: Path):
    structured = _component_record('CVE-2099-81001')
    prose_only = {
        **_component_record('CVE-2099-81002', description='SMBv1 appears only in description'),
        'affected_products': ['Unrelated Product'],
        'affected_entries': [{
            'vendor': 'Example Corporation',
            'product': 'Unrelated Product',
            'defaultStatus': 'unknown',
            'versions': [{'version': '1', 'status': 'affected'}],
            'cpes': [],
        }],
    }
    index = tmp_path / 'official.jsonl'
    index.write_text(json.dumps(structured) + '\n' + json.dumps(prose_only) + '\n', encoding='utf-8')

    with patch.object(mitre_cve, 'INDEX', index):
        mitre_cve.build_lookup_index(index)
        rows, diagnostics = mitre_cve.search_component_candidates('smb', '1', host_vendor='Example')

    assert [row['cve_id'] for row in rows] == ['CVE-2099-81001']
    assert rows[0]['match_basis'] == 'prose_affected_component_version_scrape'
    assert not any(row.get('cve_id') == 'CVE-2099-81002' for row in rows)
    assert diagnostics == ()


def test_exact_id_nvd_configuration_corroborates_component_and_host_context():
    cve = {
        'id': 'CVE-2099-81003',
        'configurations': [{
            'operator': 'AND',
            'cpeMatch': [
                {
                    'vulnerable': True,
                    'criteria': 'cpe:2.3:a:example:server_message_block:1.0:*:*:*:*:*:*:*',
                },
                {
                    'vulnerable': False,
                    'criteria': 'cpe:2.3:o:example:operating_system_1507:-:*:*:*:*:*:*:*',
                },
            ],
        }],
    }
    with patch.object(nvd_client, '_fetch_exact_cve', return_value=(cve, {'reason': 'test', 'matcher_status': 'available'})):
        matched, basis, diagnostic = nvd_client.corroborate_cve_component_context(
            'CVE-2099-81003',
            'smb',
            '1',
            ['cpe:2.3:o:example:operating_system_1507:10.0.12345.7:*:*:*:*:*:*:*'],
        )
    assert matched is True
    assert basis.startswith('nvd_configuration:')
    assert diagnostic['matcher_status'] == 'available'



def test_cpe_resolver_falls_back_to_vendor_build_without_release_table(tmp_path: Path):
    candidate = {
        'products': [{
            'cpe': {
                'deprecated': False,
                'cpeName': 'cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20796:*:*:*:*:*:x64:*',
                'titles': [{'title': 'Microsoft Windows 10 1507 10.0.10240.20796 X64'}],
            }
        }]
    }
    calls = []
    def fake_request(params):
        calls.append(params['keywordSearch'])
        if len(calls) == 1:
            return {'products': []}, {'reason': 'test', 'matcher_status': 'available'}
        return candidate, {'reason': 'test', 'matcher_status': 'available'}

    with (
        patch.object(cpe_resolver, '_request', side_effect=fake_request),
        patch.object(cpe_resolver, '_load_cache', return_value={}),
        patch.object(cpe_resolver, '_save_cache'),
    ):
        cpes, diagnostics = cpe_resolver.resolve(
            'Windows 10 Enterprise 10240', '10.0.10240', part='o', vendor='Microsoft'
        )
    assert cpes == ('cpe:2.3:o:microsoft:windows_10_1507:10.0.10240.20796:*:*:*:*:*:x64:*',)
    assert calls == ['Microsoft Windows 10 Enterprise 10240 10.0.10240', 'Microsoft 10.0.10240']
    assert diagnostics[0]['fallback_used'] is True

def test_cpe_resolver_accepts_servicing_revision_prefix_without_build_table():
    assert cpe_resolver._version_compatible('10.0.12345', '10.0.12345.987') is True
    assert cpe_resolver._version_compatible('10.0', '10.0.12345.987') is False


def test_component_cve_integration_requires_exact_id_corroboration():
    candidate = {
        'cve_id': 'CVE-2099-81004',
        'description': 'Synthetic component fixture',
        'references': [],
        'source': mitre_cve.OFFICIAL_CVE_SOURCE,
        'cvss_metrics': {},
        'matched_product_tokens': ['Example SMB'],
        'matched_version_tokens': ['1'],
        'match_basis': 'structured_affected_component_version',
        'product_match_basis': 'structured_affected_component_product',
        'affected_vendors': ['Example Corporation'],
        'affected_products': ['Example SMB'],
        'affected_versions': [],
        'affected_entries': [],
    }
    host_identity = {
        'scope': 'host_os',
        'host': '192.0.2.10',
        'vendor': 'Example',
        'family': 'ExampleOS',
        'product': 'Example Operating System',
        'build': '10.0.12345',
        'cpe': [],
        'sources': ['test'],
    }
    component = {
        'host': '192.0.2.10', 'port': 445, 'protocol': 'tcp',
        'component': 'smb', 'version': '1', 'service': 'smb',
        'evidence_sources': ['smb_protocol_security'],
    }
    with (
        patch('scanners.enumerator.mitre_search_component_candidates', return_value=((candidate,), ())),
        patch('scanners.enumerator.mitre_search_with_held', return_value=((), ())),
    ):
        rows, _ = _match_cves([], [], [host_identity], [], [component])

    assert [row['cve_id'] for row in rows] == ['CVE-2099-81004']
    assert rows[0]['match_scope'] == 'platform_component'
    assert rows[0]['port'] == 445
    assert rows[0]['candidate_status'] == 'candidate'
    assert rows[0]['validation_state'] == 'not_performed'
    assert 'applicability_corroboration' not in rows[0]


def test_exact_id_host_only_corroboration_when_nvd_omits_application_cpe():
    cve = {
        'id': 'CVE-2099-82001',
        'configurations': [{
            'operator': 'OR',
            'cpeMatch': [{
                'vulnerable': True,
                'criteria': 'cpe:2.3:o:example:operating_system_1507:*:*:*:*:*:*:*:*',
                'versionStartIncluding': '10.0.12345',
                'versionEndExcluding': '10.0.12346',
            }],
        }],
    }
    with patch.object(nvd_client, '_fetch_exact_cve', return_value=(cve, {'reason': 'test', 'matcher_status': 'available'})):
        matched, basis, diagnostic = nvd_client.corroborate_cve_component_context(
            'CVE-2099-82001', 'smb', '1',
            ['cpe:2.3:o:example:operating_system_1507:10.0.12345.9:*:*:*:*:*:*:*'],
        )
    assert matched is True
    assert basis.startswith('nvd_configuration:')
    assert diagnostic['corroboration_mode'] == 'canonical_component_plus_host_configuration'
    assert diagnostic['primary_cpes'] == []


def test_exact_id_host_only_corroboration_rejects_unrelated_platform():
    cve = {
        'id': 'CVE-2099-82002',
        'configurations': [{
            'operator': 'OR',
            'cpeMatch': [{
                'vulnerable': True,
                'criteria': 'cpe:2.3:o:example:operating_system_1507:*:*:*:*:*:*:*:*',
            }],
        }],
    }
    with patch.object(nvd_client, '_fetch_exact_cve', return_value=(cve, {'reason': 'test', 'matcher_status': 'available'})):
        matched, basis, diagnostic = nvd_client.corroborate_cve_component_context(
            'CVE-2099-82002', 'smb', '1',
            ['cpe:2.3:o:other:other_os:1.0:*:*:*:*:*:*:*'],
        )
    assert matched is False
    assert basis == ''
    assert diagnostic['corroboration_mode'] == 'canonical_component_plus_host_configuration'
    assert diagnostic['matcher_status'] == 'held'


def test_exact_id_application_cpe_mismatch_does_not_bypass_to_host_only():
    cve = {
        'id': 'CVE-2099-82003',
        'configurations': [{
            'operator': 'OR',
            'cpeMatch': [
                {'vulnerable': True, 'criteria': 'cpe:2.3:a:example:unrelated_protocol:1.0:*:*:*:*:*:*:*'},
                {'vulnerable': True, 'criteria': 'cpe:2.3:o:example:operating_system_1507:*:*:*:*:*:*:*:*'},
            ],
        }],
    }
    with patch.object(nvd_client, '_fetch_exact_cve', return_value=(cve, {'reason': 'test', 'matcher_status': 'available'})):
        matched, basis, diagnostic = nvd_client.corroborate_cve_component_context(
            'CVE-2099-82003', 'smb', '1',
            ['cpe:2.3:o:example:operating_system_1507:10.0.12345:*:*:*:*:*:*:*'],
        )
    assert matched is False
    assert basis == ''
    assert diagnostic['reason'] == 'nvd_exact_cve_component_cpe_mismatch'
    assert diagnostic['corroboration_mode'] == 'component_cpe_present_but_not_matched'


def test_same_protocol_duplicate_merge_renders_each_endpoint_once():
    from scanners.enumerator import _merge_cve_duplicate

    existing = {'port': 139, 'protocol': 'tcp', 'observed_ports': ['139/tcp']}
    _merge_cve_duplicate(existing, {'port': 445, 'protocol': 'tcp'})

    # Existing downstream formatters append /<protocol> once.
    rendered = f"{existing['port']}/{existing['protocol']}"
    assert rendered == '139/tcp, 445/tcp'
    assert '/tcp/tcp' not in rendered
    assert existing['observed_ports'] == ['139/tcp', '445/tcp']


def test_component_dedupe_key_keeps_tcp_and_udp_separate():
    from scanners.enumerator import _cve_dedupe_key

    match = {'cve_id': 'CVE-2099-82004'}
    tcp = {'host': '192.0.2.10', 'product': 'Example SMB', 'version': '1', 'protocol': 'tcp'}
    udp = {**tcp, 'protocol': 'udp'}
    assert _cve_dedupe_key(tcp, match) != _cve_dedupe_key(udp, match)


def test_arp_readiness_reports_insufficient_privilege_without_claiming_unavailable_binary(tmp_path: Path):
    from scanners.result_contracts import build_selected_plan_readiness

    options = {
        'host_discovery': {'effective': {'arp_discovery': True}},
        'service_identity': {},
        'collector_plan': {},
    }
    readiness = build_selected_plan_readiness(
        scan_options=options,
        cve_source_status={'available': True, 'records_indexed': 1},
        cvss_verifiers={},
        storage_paths=(tmp_path,),
        binary_resolver=lambda binary: '/usr/sbin/arp-scan' if binary == 'arp-scan' else None,
        raw_socket_probe=lambda: (False, 'fixture raw socket denied'),
    )
    arp_row = next(row for row in readiness['rows'] if row['component'] == 'host_discovery:arp_discovery')
    assert arp_row['status'] == 'insufficient_privilege'
    assert readiness['status'] == 'degraded'
    assert 'host_discovery:arp_discovery' in readiness['degraded_components']


def test_kev_enrichment_only_annotates_existing_cve_rows(tmp_path: Path):
    from scanners import cisa_kev

    cache_file = tmp_path / 'known_exploited_vulnerabilities.json'
    cache_file.write_text(json.dumps({
        'catalogVersion': 'fixture',
        'dateReleased': '2099-01-01',
        'vulnerabilities': [{
            'cveID': 'CVE-2099-82005',
            'vendorProject': 'Example',
            'product': 'Example Product',
            'vulnerabilityName': 'Fixture',
            'dateAdded': '2099-01-01',
            'dueDate': '2099-01-22',
            'requiredAction': 'Apply vendor mitigations.',
            'knownRansomwareCampaignUse': 'Unknown',
            'notes': '',
        }],
    }), encoding='utf-8')
    rows = [{'cve_id': 'CVE-2099-82005'}, {'cve_id': 'CVE-2099-82006'}]
    original_ids = [row['cve_id'] for row in rows]
    with (
        patch.object(cisa_kev, 'CACHE_FILE', cache_file),
        patch.object(cisa_kev, '_cache_fresh', return_value=True),
    ):
        diagnostic = cisa_kev.enrich_cve_rows(rows)

    assert [row['cve_id'] for row in rows] == original_ids
    assert len(rows) == 2
    assert rows[0]['kev_listed'] is True
    assert rows[1]['kev_listed'] is False
    assert diagnostic['status'] == 'available'


def test_kev_unavailable_is_unknown_not_false_listing():
    from scanners import cisa_kev

    rows = [{'cve_id': 'CVE-2099-82007'}]
    with patch.object(cisa_kev, 'load_catalog', return_value=(None, {'status': 'unavailable', 'source': cisa_kev.SOURCE})):
        cisa_kev.enrich_cve_rows(rows)
    assert rows[0]['kev_listed'] is None
    assert rows[0]['kev_status'] == 'unavailable'


def test_msrc_json_parser_accepts_wrapped_cvrf_shapes():
    from scanners import windows_advisory

    document = {
        'ProductTree': {
            'FullProductName': [{
                'ProductID': {'Value': 'prod-1'},
                'Value': {'Value': 'Example Windows Product'},
            }],
        },
        'Vulnerability': [{
            'CVE': {'Value': 'CVE-2099-82008'},
            'ProductStatuses': [{
                'Type': 'Known Affected',
                'ProductID': [{'Value': 'prod-1'}],
            }],
            'Remediations': [{
                'ProductID': [{'Value': 'prod-1'}],
                'Description': {'Value': 'Security Update KB1234567'},
                'FixedBuild': {'Value': '10.0.12345.10'},
                'URL': {'Value': 'https://example.invalid/update'},
            }],
        }],
    }
    rows = windows_advisory._document_rows(document, '2099-Jan')
    assert len(rows) == 1
    assert rows[0]['cve_id'] == 'CVE-2099-82008'
    assert rows[0]['product'] == 'Example Windows Product'
    assert rows[0]['kb_ids'] == ['KB1234567']
    assert rows[0]['fixed_builds'] == ['10.0.12345.10']


def test_msrc_xml_parser_accepts_cvrf_product_status_and_remediation():
    from scanners import windows_advisory

    xml = b'''<?xml version="1.0" encoding="utf-8"?>
    <cvrfdoc xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1" xmlns:prod="http://www.icasi.org/CVRF/schema/prod/1.1" xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1">
      <prod:ProductTree>
        <prod:FullProductName ProductID="prod-xml">Example Windows XML Product</prod:FullProductName>
      </prod:ProductTree>
      <vuln:Vulnerability>
        <vuln:CVE>CVE-2099-82009</vuln:CVE>
        <vuln:ProductStatuses>
          <vuln:Status Type="Known Affected"><vuln:ProductID>prod-xml</vuln:ProductID></vuln:Status>
        </vuln:ProductStatuses>
        <vuln:Remediations>
          <vuln:Remediation Type="Vendor Fix">
            <vuln:Description>Security Update KB7654321</vuln:Description>
            <vuln:URL>https://example.invalid/xml-update</vuln:URL>
            <vuln:ProductID>prod-xml</vuln:ProductID>
            <vuln:FixedBuild>10.0.54321.11</vuln:FixedBuild>
          </vuln:Remediation>
        </vuln:Remediations>
      </vuln:Vulnerability>
    </cvrfdoc>'''
    rows = windows_advisory._document_rows_xml(xml, '2099-Feb')
    assert len(rows) == 1
    assert rows[0]['cve_id'] == 'CVE-2099-82009'
    assert rows[0]['product'] == 'Example Windows XML Product'
    assert rows[0]['kb_ids'] == ['KB7654321']
    assert rows[0]['fixed_builds'] == ['10.0.54321.11']


def test_msrc_zero_row_rebuild_does_not_replace_existing_index(tmp_path: Path):
    from scanners import windows_advisory

    index = tmp_path / 'official_msrc_windows_index.jsonl'
    index.write_text('{"existing": true}\n', encoding='utf-8')
    updates = {'value': [{'ID': '2099-Jan', 'CurrentReleaseDate': '2099-01-01'}]}
    empty_document = b'<?xml version="1.0"?><cvrfdoc></cvrfdoc>'
    with (
        patch.object(windows_advisory, 'BASE', tmp_path),
        patch.object(windows_advisory, 'INDEX', index),
        patch.object(windows_advisory, '_request_json', return_value=updates),
        patch.object(windows_advisory, '_request_document', return_value=empty_document),
    ):
        try:
            windows_advisory.build_index(2099)
        except RuntimeError as exc:
            assert 'no affected-product records' in str(exc)
        else:
            raise AssertionError('zero-row rebuild must fail closed')

    assert index.read_text(encoding='utf-8') == '{"existing": true}\n'
    assert not index.with_suffix('.tmp').exists()


def test_kev_disabled_does_not_use_existing_cache(tmp_path: Path):
    from scanners import cisa_kev

    cache_file = tmp_path / 'known_exploited_vulnerabilities.json'
    cache_file.write_text(json.dumps({
        'vulnerabilities': [{'cveID': 'CVE-2099-82010'}],
    }), encoding='utf-8')
    rows = [{'cve_id': 'CVE-2099-82010'}]
    with (
        patch.object(cisa_kev, 'CACHE_FILE', cache_file),
        patch.object(cisa_kev, 'enabled', return_value=False),
    ):
        diagnostic = cisa_kev.enrich_cve_rows(rows)
    assert diagnostic['status'] == 'disabled'
    assert rows[0]['kev_listed'] is None
    assert rows[0]['kev_status'] == 'disabled'


def test_display_context_surfaces_corroboration_patch_state_and_kev_without_reclassifying():
    from scanners.enumerator import _refresh_cve_display_context

    rows = [{
        'cve_id': 'CVE-2099-82011',
        'display_match_reason': 'Structured component evidence matched.',
        'reference_type': 'Baseline CVE reference',
        'applicability_corroboration': {
            'source': 'NVD exact-CVE configuration/CPE data',
            'mode': 'canonical_component_plus_host_configuration',
        },
        'patch_state': 'Not established from unauthenticated protocol evidence',
        'kev_listed': True,
    }]
    _refresh_cve_display_context(rows)
    text = rows[0]['display_match_reason']
    assert 'exact-CVE NVD configuration' in text
    assert 'Patch state:' in text
    assert 'not an applicability input' in text
    assert rows[0]['reference_type'] == 'Baseline CVE reference'
