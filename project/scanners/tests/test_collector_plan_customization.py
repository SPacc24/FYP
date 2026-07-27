from __future__ import annotations

import unittest
from pathlib import Path

from scanners.collector_plan import build_collector_catalog
from scanners.enumerator import (
    _build_collector_coverage_matrix,
    _build_scan_summary,
    _build_unresolved_identity_queue,
    _collector_service_applicable,
    _coverage_display_status,
)
from scanners.scan_profiles import TOOL_OPTIONS, collector_ui_context, normalise_scan_options

PROJECT_DIR = Path(__file__).resolve().parents[2]


class CollectorPlanCustomizationTests(unittest.TestCase):

    def test_windows_patch_inventory_requires_explicit_operator_selection(self):
        maximum = normalise_scan_options('full', collection_preset='maximum')
        self.assertFalse(maximum['collector_plan']['windows_patch_inventory']['requested'])
        custom = normalise_scan_options(
            'custom', collection_preset='custom',
            collector_plan={'windows_patch_inventory': {'mode': 'always'}},
        )
        row = custom['collector_plan']['windows_patch_inventory']
        self.assertTrue(row['requested'])
        self.assertTrue(row['effective_enabled'])
        self.assertTrue(row['credential_required'])

    def test_maximum_plan_keeps_policy_block_visible_and_not_effective(self):
        options = normalise_scan_options(
            'full',
            collection_preset='maximum',
            tcp_port_mode='essentials',
            udp_port_mode='essentials',
        )
        ssh_audit = options['collector_plan']['ssh_audit_native']
        self.assertTrue(ssh_audit['requested'])
        self.assertEqual(ssh_audit['policy_state'], 'blocked')
        self.assertFalse(ssh_audit['effective_enabled'])
        self.assertIn('ssh_audit_native', options['policy_conflicts'])
        self.assertGreater(options['collector_counts']['requested'], options['collector_counts']['permitted'])

    def test_custom_plan_can_disable_every_evidence_collector_without_disabling_core_discovery(self):
        options = normalise_scan_options(
            'custom',
            collection_preset='custom',
            collector_plan={},
            tcp_port_mode='custom', tcp_custom_ports='80',
            udp_port_mode='custom', udp_custom_ports='53',
        )
        self.assertEqual(options['collector_counts']['requested'], 0)
        self.assertIn('tcp_discovery', options['enabled_tools'])
        self.assertIn('udp_discovery', options['enabled_tools'])
        self.assertIn('service_fingerprint', options['enabled_tools'])

    def test_host_discovery_is_independently_operator_controlled_and_bounded(self):
        options = normalise_scan_options(
            'full',
            host_discovery_settings={
                'arp_discovery': False,
                'icmp_echo': True,
                'nmap_host_discovery': True,
                'reverse_dns': True,
                'route_trace': True,
                'icmp_attempts': 99,
                'icmp_timeout_seconds': 99,
                'route_max_hops': 999,
                'assume_single_target_live': False,
            },
        )
        host = options['host_discovery']
        self.assertFalse(host['requested']['arp_discovery'])
        self.assertTrue(host['effective']['icmp_echo'])
        self.assertTrue(host['effective']['nmap_host_discovery'])
        self.assertEqual(host['icmp_attempts'], 4)
        self.assertEqual(host['icmp_timeout_seconds'], 10)
        self.assertEqual(host['route_max_hops'], 30)
        self.assertFalse(host['assume_single_target_live'])

    def test_httpx_operator_settings_cannot_exceed_policy_ceiling(self):
        raw = {
            'httpx': {
                'mode': 'auto',
                'settings': {
                    'timeout_seconds': 999,
                    'rate_limit_per_second': 999,
                    'threads': 999,
                },
            }
        }
        options = normalise_scan_options('custom', collection_preset='custom', collector_plan=raw)
        settings = options['collector_plan']['httpx']['settings']
        self.assertEqual(settings['timeout_seconds'], 5)
        self.assertEqual(settings['rate_limit_per_second'], 1)
        self.assertEqual(settings['threads'], 1)


    def test_structured_collector_timeouts_are_bounded(self):
        options = normalise_scan_options(
            'custom', collection_preset='custom',
            collector_plan={
                'smb_protocol_security': {'mode':'auto','settings':{'timeout_seconds':999}},
                'tls_cipher_validation': {'mode':'auto','settings':{'timeout_seconds':1}},
                'winrm_wsman_probe': {'mode':'auto','settings':{'request_timeout_seconds':999}},
            },
        )
        self.assertEqual(options['collector_plan']['smb_protocol_security']['settings']['timeout_seconds'], 240)
        self.assertEqual(options['collector_plan']['tls_cipher_validation']['settings']['timeout_seconds'], 30)
        self.assertEqual(options['collector_plan']['winrm_wsman_probe']['settings']['request_timeout_seconds'], 5)

    def test_applicability_is_service_family_based_not_port_hardcoded(self):
        entry = {'scope': 'service', 'families': ['http']}
        self.assertTrue(_collector_service_applicable(entry, {
            'host': '192.0.2.10', 'port': 49152, 'service': 'http-alt',
            'product': 'Example Web Service', 'version': '1.0',
        }))
        self.assertFalse(_collector_service_applicable(entry, {
            'host': '192.0.2.10', 'port': 80, 'service': 'ssh',
            'product': 'Example SSH', 'version': '1.0',
        }))

    def test_coverage_matrix_separates_disabled_not_applicable_and_evidence(self):
        options = normalise_scan_options(
            'custom',
            collection_preset='custom',
            collector_plan={
                'httpx': {'mode': 'auto'},
                'ssh_auth_methods': {'mode': 'disabled'},
            },
        )
        services = [
            {'host': '192.0.2.10', 'port': 49152, 'protocol': 'tcp', 'service': 'http', 'product': 'Example Web', 'version': '1.2.3'},
            {'host': '192.0.2.10', 'port': 2222, 'protocol': 'tcp', 'service': 'ssh', 'product': 'Example SSH', 'version': ''},
        ]
        coverage = [
            {'tool': 'httpx', 'status': 'Completed', 'note': 'http://192.0.2.10:49152', 'lifecycle_state': 'executed_evidence'},
        ]
        raw = [{'tool': 'httpx', 'host': '192.0.2.10', 'port': 49152}]
        matrix = _build_collector_coverage_matrix(services, options, coverage, raw)
        http_rows = [r for r in matrix['endpoint_rows'] if r['endpoint'] == '49152/tcp' and r['collector'] == 'httpx']
        ssh_rows = [r for r in matrix['endpoint_rows'] if r['endpoint'] == '2222/tcp' and r['collector'] == 'ssh_auth_methods']
        self.assertEqual(http_rows[0]['lifecycle_state'], 'executed_evidence')
        self.assertEqual(ssh_rows[0]['lifecycle_state'], 'disabled_operator')
        # HTTPX is not even an applicable row on the SSH endpoint.
        self.assertFalse(any(r['endpoint'] == '2222/tcp' and r['collector'] == 'httpx' for r in matrix['endpoint_rows']))

    def test_unresolved_identity_queue_preserves_uncertainty(self):
        gaps = _build_unresolved_identity_queue([
            {'host': '192.0.2.10', 'port': 6667, 'protocol': 'tcp', 'service': 'irc', 'product': 'Example IRC', 'version': '', 'evidence_sources': ['nmap', 'nmap_version_recovery']},
            {'host': '192.0.2.10', 'port': 445, 'protocol': 'tcp', 'service': 'smb', 'product': 'Example SMB', 'version': '3.X - 4.X', 'evidence_sources': ['nmap']},
            {'host': '192.0.2.10', 'port': 80, 'protocol': 'tcp', 'service': 'http', 'product': 'Example HTTP', 'version': '1.2.3', 'evidence_sources': ['nmap']},
        ])
        self.assertEqual(len(gaps), 2)
        self.assertTrue(gaps[0]['recovery_attempted'])
        self.assertIn('Exact product version not established', gaps[0]['gaps'])
        self.assertIn('Only a version range was observed', gaps[1]['gaps'])

    def test_lifecycle_display_states_are_explicit(self):
        cases = {
            'executed_evidence': 'Completed',
            'executed_no_evidence': 'No Evidence Observed',
            'executed_failed': 'Failed - Incomplete',
            'not_applicable': 'Not Applicable',
            'disabled_operator': 'Disabled by Operator',
            'disabled_policy': 'Disabled by Policy',
            'tool_unavailable': 'Tool Unavailable',
            'scope_blocked': 'Scope Blocked',
            'deferred': 'Deferred',
            'assumed_live': 'Not Executed - Assumed Live',
        }
        for state, expected in cases.items():
            self.assertEqual(_coverage_display_status('x', '', result={'lifecycle_state': state}), expected)

    def test_scan_summary_counts_lifecycle_without_aggregate_double_counting(self):
        options = normalise_scan_options(
            'custom', collection_preset='custom', collector_plan={},
            tcp_port_mode='custom', tcp_custom_ports='80',
            udp_port_mode='custom', udp_custom_ports='53',
        )
        summary = _build_scan_summary(
            targets_requested=1, live_hosts=['192.0.2.10'], scan_options=options,
            scanned_tcp_ports_by_host={'192.0.2.10': {80}},
            scanned_udp_ports_by_host={'192.0.2.10': {53}},
            discovery_evidence={'192.0.2.10': {'ports': [
                {'protocol':'tcp','port':80,'state':'open'},
                {'protocol':'udp','port':53,'state':'open'},
            ], 'extraports': []}},
            open_map={'192.0.2.10':[80]},
            all_services=[{'host':'192.0.2.10','port':80,'protocol':'tcp','service':'http','product':'Example','version':'1.0'}],
            public_coverage=[
                {'tool':'httpx','status':'Completed','lifecycle_state':'executed_evidence'},
                {'tool':'nuclei_safe','status':'Not Applicable','lifecycle_state':'not_applicable'},
                {'tool':'ping','status':'Disabled by Operator','lifecycle_state':'disabled_operator'},
                {'tool':'passive_intelligence','status':'Completed','lifecycle_state':'executed_evidence'},
                {'tool':'credential_validation_handoff','status':'No Evidence Observed','lifecycle_state':''},
            ],
            cve_matches=[], relevant_cve_information=[],
        )
        checks = summary['evidence_checks']
        self.assertEqual(checks['executed'], 1)
        self.assertEqual(checks['produced_evidence'], 1)
        self.assertEqual(checks['not_executed'], 2)
        self.assertEqual(checks['not_applicable'], 1)
        self.assertEqual(checks['disabled_operator'], 1)

    def test_discovery_policy_does_not_hide_port_states_with_open_filter(self):
        import json
        policy = json.loads((PROJECT_DIR / 'policies' / 'recon_policy.json').read_text(encoding='utf-8'))
        self.assertNotIn('--open', (policy.get('tcp_micro_batching') or {}).get('nmap_options') or [])

    def test_native_protocol_enrichment_has_explicit_disabled_and_not_applicable_lifecycle(self):
        source = (PROJECT_DIR / 'scanners' / 'enumerator.py').read_text(encoding='utf-8')
        self.assertIn("native_entry = (scan_options.get('collector_plan') or {}).get('native_protocol_enrichment')", source)
        self.assertIn("'lifecycle_state': 'not_applicable'", source)
        self.assertIn("'lifecycle_state': state", source)


    def test_start_page_catalog_reports_runtime_binary_availability(self):
        catalog = collector_ui_context()['catalog']
        by_id = {item['id']: item for item in catalog}
        self.assertIn('runtime_available', by_id['httpx'])
        self.assertEqual(by_id['httpx']['runtime_requirement'], 'httpx-toolkit')
        self.assertIn('runtime_available', by_id['smb_protocol_security'])
        self.assertEqual(by_id['smb_protocol_security']['runtime_requirement'], 'nmap')

    def test_start_page_has_structured_plan_controls_without_raw_command_input(self):
        html = (PROJECT_DIR / 'templates' / 'index.html').read_text(encoding='utf-8')
        for marker in (
            'EVIDENCE COLLECTION PLAN', 'HOST DISCOVERY', 'SERVICE IDENTIFICATION',
            'collector_plan_json', 'host_discovery_json', 'service_identity_json',
            'savePlanBtn', 'exportPlanBtn', 'importPlanBtn', 'scanPlanPreview',
            'hostIcmpEcho', 'coreVersionIntensity', 'collector-mode',
            'collectorUnavailableCount', 'runtime-unavailable-badge',
        ):
            self.assertIn(marker, html)
        self.assertNotIn('name="raw_nmap_args"', html)
        self.assertNotIn('Custom Nmap arguments', html)

    def test_cvss_view_is_persistent_and_declared_once(self):
        html = (PROJECT_DIR / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
        self.assertEqual(html.count("const cvssView = document.getElementById('cveCvssView');"), 1)
        self.assertIn('autopentest.cvss-view.v1', html)
        for value in ('3.1', '4.0', 'both'):
            self.assertIn(f'data-cvss-view="{value}"', html)

    def test_freshness_and_matrix_are_present_in_browser_and_appendix(self):
        scan_html = (PROJECT_DIR / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
        appendix_html = (PROJECT_DIR / 'templates' / 'technical_appendix.html').read_text(encoding='utf-8')
        self.assertIn('Data Freshness', scan_html)
        self.assertIn('Collector Coverage', scan_html)
        self.assertIn('Evidence Gaps', scan_html)
        self.assertIn('Collector Coverage Matrix', appendix_html)
        self.assertIn('Unresolved Identity Queue', appendix_html)
        self.assertIn('Vulnerability Intelligence', appendix_html)


if __name__ == '__main__':
    unittest.main()
