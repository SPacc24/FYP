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

def test_vulnerability_mapping_has_no_reference_abstraction_or_mismatch_filters():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    pdf = (PROJECT / 'templates' / 'pdf_report.html').read_text(encoding='utf-8').lower()
    mapping = (PROJECT / 'templates' / 'scan_vul.html').read_text(encoding='utf-8').lower()
    assert "'context' not in" not in html
    assert 'mismatch' not in html
    assert 'candidate cve references' not in html
    assert 'candidate cve references' not in pdf
    assert 'candidate references' not in mapping
    assert all(f'<th>{heading}</th>' in mapping for heading in ['port', 'service', 'cve', 'severity', 'score', 'description'])


def test_report_hides_internal_appendix_sections_and_raw_matcher_basis():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8')
    assert 'Other Service Evidence' not in html
    assert 'Evidence File Index' not in html
    assert 'match_basis' not in html
    assert 'Candidate or Confirmed CVE findings, operational diagnostics, and dataset status.' in html


def test_no_user_facing_mismatch_filtering_text_in_results_template():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    assert 'mismatch' not in html
    assert "'context' not in" not in html
