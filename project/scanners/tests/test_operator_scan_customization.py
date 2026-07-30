from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scanners.scan_profiles import (
    normalise_scan_options,
    parse_port_spec,
    selected_ports,
)
from scanners.enumerator import _build_scan_summary, _chunk_ports, _run_cmd_with_retry

PROJECT_DIR = Path(__file__).resolve().parents[2]


class OperatorScanCustomizationTests(unittest.TestCase):
    def test_parse_custom_port_list_and_ranges(self):
        self.assertEqual(
            parse_port_spec('22,80,443,8000 - 8002 53'),
            [22, 53, 80, 443, 8000, 8001, 8002],
        )

    def test_invalid_port_input_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_port_spec('0,22')
        with self.assertRaises(ValueError):
            parse_port_spec('9000-8000')
        with self.assertRaises(ValueError):
            parse_port_spec('abc')

    def test_tcp_and_udp_modes_are_independent(self):
        options = normalise_scan_options(
            'custom',
            ['tcp_discovery', 'udp_discovery'],
            tcp_port_mode='custom',
            tcp_custom_ports='22,80,443',
            udp_port_mode='custom',
            udp_custom_ports='53,161',
        )
        self.assertEqual(options['validation_errors'], [])
        self.assertEqual(options['port_selection']['tcp']['ports'], [22, 80, 443])
        self.assertEqual(options['port_selection']['udp']['ports'], [53, 161])

    def test_full_mode_represents_complete_port_space_without_storing_65k_items(self):
        options = normalise_scan_options(
            'custom', ['tcp_discovery'], tcp_port_mode='full', udp_port_mode='essentials'
        )
        self.assertEqual(options['port_selection']['tcp']['count'], 65535)
        self.assertEqual(options['port_selection']['tcp']['ports'], [])
        ports = selected_ports(options, 'tcp')
        self.assertIsInstance(ports, range)
        self.assertEqual(ports.start, 1)
        self.assertEqual(ports.stop, 65536)

    def test_advanced_settings_are_bounded(self):
        options = normalise_scan_options(
            'custom',
            ['tcp_discovery'],
            advanced_settings={
                'command_timeout_seconds': 999999,
                'retry_failed_batches': True,
                'retry_count': 99,
                'ports_per_batch': 99999,
                'parallel_scanning': True,
                'parallel_workers': 99,
            },
        )
        advanced = options['advanced_settings']
        self.assertEqual(advanced['command_timeout_seconds'], 3600)
        self.assertEqual(advanced['retry_count'], 3)
        self.assertEqual(advanced['ports_per_batch'], 2048)
        self.assertEqual(advanced['parallel_workers'], 8)

    def test_parallel_off_forces_single_worker(self):
        options = normalise_scan_options(
            'custom',
            ['tcp_discovery'],
            advanced_settings={'parallel_scanning': False, 'parallel_workers': 8},
        )
        self.assertFalse(options['advanced_settings']['parallel_scanning'])
        self.assertEqual(options['advanced_settings']['parallel_workers'], 1)

    def test_port_batching_is_deterministic(self):
        self.assertEqual(
            _chunk_ports([21, 22, 23, 25, 53], 2),
            [[21, 22], [23, 25], [53]],
        )

    def test_failed_batch_retry_is_command_level_and_bounded(self):
        failed = {'success': False, 'error': 'timeout'}
        succeeded = {'success': True, 'returncode': 0}
        with patch('scanners.enumerator.run_cmd', side_effect=[failed, succeeded]) as mocked:
            result = _run_cmd_with_retry(
                'scan-test', ['nmap', '-p', '22', '127.0.0.1'], Path('/tmp/test.xml'),
                30, True, 1,
            )
        self.assertTrue(result['success'])
        self.assertEqual(result['attempts'], 2)
        self.assertEqual(mocked.call_count, 2)


    def test_scan_summary_uses_executed_evidence_and_keeps_untested_separate(self):
        summary = _build_scan_summary(
            targets_requested=1,
            live_hosts=['192.0.2.10'],
            scan_options={
                'port_selection': {
                    'tcp': {'mode': 'custom', 'count': 4},
                    'udp': {'mode': 'custom', 'count': 3},
                }
            },
            scanned_tcp_ports_by_host={'192.0.2.10': {80, 443, 445}},
            scanned_udp_ports_by_host={'192.0.2.10': {53, 161}},
            discovery_evidence={
                '192.0.2.10': {
                    'ports': [
                        {'port': 80, 'protocol': 'tcp', 'state': 'open'},
                        {'port': 445, 'protocol': 'tcp', 'state': 'open'},
                        {'port': 53, 'protocol': 'udp', 'state': 'open'},
                    ],
                    'extraports': [
                        {'protocol': 'tcp', 'state': 'closed', 'count': 1},
                        {'protocol': 'udp', 'state': 'closed', 'count': 1},
                    ],
                }
            },
            open_map={'192.0.2.10': [80, 445]},
            all_services=[
                {'host': '192.0.2.10', 'port': 80, 'protocol': 'tcp', 'service': 'http', 'product': 'Example HTTP', 'version': '1.2.3'},
                {'host': '192.0.2.10', 'port': 445, 'protocol': 'tcp', 'service': 'smb', 'product': '', 'version': ''},
                {'host': '192.0.2.10', 'port': 53, 'protocol': 'udp', 'service': 'domain', 'product': '', 'version': ''},
            ],
            public_coverage=[
                {'status': 'Completed'},
                {'status': 'No Evidence Observed'},
                {'status': 'Not Applicable'},
                {'status': 'Failed - Incomplete'},
            ],
            cve_matches=[{'cve_id': 'CVE-2026-0001'}],
        )
        self.assertEqual(summary['tcp']['requested'], 4)
        self.assertEqual(summary['tcp']['scanned'], 3)
        self.assertEqual(summary['tcp']['untested'], 1)
        self.assertEqual(summary['tcp']['open'], 2)
        self.assertEqual(summary['tcp']['closed'], 1)
        self.assertEqual(summary['udp']['requested'], 3)
        self.assertEqual(summary['udp']['scanned'], 2)
        self.assertEqual(summary['udp']['untested'], 1)
        self.assertEqual(summary['cve_review']['unique_references'], 1)
        self.assertEqual(summary['services']['versioned_products'], 1)
        self.assertEqual(summary['evidence_checks']['executed'], 3)
        self.assertEqual(summary['evidence_checks']['completed_without_error'], 2)
        self.assertEqual(summary['evidence_checks']['produced_evidence'], 1)
        self.assertEqual(summary['evidence_checks']['no_evidence'], 1)
        self.assertEqual(summary['evidence_checks']['failed'], 1)
        self.assertEqual(summary['evidence_checks']['not_executed'], 1)
        self.assertEqual(summary['evidence_checks']['not_applicable'], 1)
        self.assertEqual(summary['evidence_checks']['skipped'], 1)
        self.assertEqual(summary['services']['versioned_service_endpoints'], 1)

    def test_scan_findings_ui_replaces_information_dump(self):
        html = (PROJECT_DIR / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
        self.assertIn('Table 3 — Scan Findings', html)
        self.assertIn('Coverage &amp; Assurance', html)
        self.assertIn('Observed Security Conditions', html)
        self.assertIn('CVSS Integrity', html)
        self.assertIn('Selected TCP Scope', html)
        self.assertIn('scanFindingsSearch', html)
        self.assertNotIn('Information Dump', html)

    def test_index_contains_requested_operator_controls(self):
        html = (PROJECT_DIR / 'templates' / 'index.html').read_text(encoding='utf-8')
        for field in (
            'tcp_port_mode', 'tcp_custom_ports', 'udp_port_mode', 'udp_custom_ports',
            'command_timeout_seconds', 'retry_failed_batches', 'retry_count',
            'ports_per_batch', 'parallel_scanning', 'parallel_workers',
        ):
            self.assertIn(f'name="{field}"', html)

    def test_cvss_filter_is_prominent_and_split(self):
        html = (PROJECT_DIR / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
        self.assertIn('data-cvss-view="3.1"', html)
        self.assertIn('data-cvss-view="4.0"', html)
        self.assertIn('data-cvss-view="both"', html)
        self.assertIn('class="cvss31-col"', html)
        self.assertIn('class="cvss40-col"', html)


if __name__ == '__main__':
    unittest.main()
