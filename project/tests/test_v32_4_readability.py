from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'project'
sys.path.insert(0, str(PROJECT))


def test_pdf_fallback_module_exists():
    from scanners.pdf_export import build_pdf_report
    sample = {
        'hosts': ['192.0.2.1'], 'tcp_service_count': 1, 'udp_service_count': 0,
        'cve_matches': [], 'service_inventory': [],
        'tool_coverage': [], 'scan_options': {'profile_label': 'Fast Recon'}
    }
    data = build_pdf_report({'target': '192.0.2.1'}, sample)
    assert data[:4] == b'%PDF'


def test_vulnerability_review_uses_current_three_table_layout_without_retired_status_taxonomy():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    pdf = (PROJECT / 'templates' / 'pdf_report.html').read_text(encoding='utf-8').lower()
    mapping = (PROJECT / 'templates' / 'scan_vul.html').read_text(encoding='utf-8').lower()
    assert "'context' not in" not in html
    assert 'mismatch' not in html
    for surface in (html, pdf, mapping):
        assert 'candidate cve references' not in surface
        assert 'validated mitre reference' not in surface
        assert 'mitre candidate references retained' not in surface
    for heading in ('identifier', 'affected service', 'why it matched', 'published prerequisites', 'published by'):
        assert f'<th>{heading}</th>' in mapping
    assert '<th>cvss integrity</th>' in mapping
    for heading in ('host', 'port / protocol', 'state', 'service', 'product', 'version', 'fingerprint context', 'evidence'):
        assert f'<th>{heading}</th>' in mapping


def test_report_hides_internal_appendix_sections_raw_matcher_basis_and_proprietary_risk_score():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8')
    assert 'Other Service Evidence' not in html
    assert 'Evidence File Index' not in html
    assert 'match_basis' not in html
    assert 'Risk score' not in html
    assert '{% include "scan_vul.html" %}' in html


def test_no_user_facing_mismatch_filtering_text_in_results_template():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    assert 'mismatch' not in html
    assert "'context' not in" not in html
