from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT
def read(rel): return (PROJECT / rel).read_text(encoding='utf-8')
def test_live_command_log_has_modal_output_viewer():
    html=read('templates/scanning.html')
    assert 'Time</th><th>Purpose</th><th>Exact Command</th><th>Evidence' in html
    assert 'openOutputModal' in html
    assert 'modalCommand' in html and 'modalOutput' in html
    assert 'Live Enumeration Snapshot' not in html
    assert 'parsed evidence' not in html.lower()
def test_running_first_row_shows_target_current_next_profile():
    html=read('templates/scanning.html')
    assert 'Target</span>' in html
    assert 'Current Task</span>' in html
    assert 'Next Task</span>' in html
    assert 'Selected TCP Scope</span>' in html
    assert 'enabled_tool_labels' not in html

def test_report_uses_professional_cve_labels_and_cards():
    html=read('templates/results.html') + read('templates/attack_surface_workbench.html')
    mapping=read('templates/scan_vul.html')
    assert 'CVE Findings' in html
    assert 'Table 1 — Candidate CVE Review' in mapping
    assert all(f'<th>{heading}</th>' in mapping for heading in ['Identifier', 'Affected Service', 'Why It Matched', 'Published By', 'Links'])
    assert 'Candidate References' not in mapping
    assert 'mapping.vulnerabilities' not in mapping
    assert 'service-card' in html
    assert '100% Evidence-Backed' not in html
    assert 'Official CVE Records Indexed' not in html
    assert 'openRecordModal' in html

def test_optional_noisy_tools_remain_backend_configurable():
    import re
    cfg=read('config.py')
    for flag in ('ENABLE_HTTPX', 'ENABLE_DEEP_WEB_DISCOVERY', 'ENABLE_HYDRA', 'ENABLE_SMBMAP'):
        # Each optional tool stays backend-configurable via env, disabled by default.
        pattern = re.compile(
            rf'{flag}\s*=\s*\(\s*os\.getenv\(\s*"{flag}",\s*"0",\s*\)\s*==\s*"1"',
            re.S,
        )
        assert pattern.search(cfg), flag

def test_command_output_is_captured_from_real_result():
    enum=read('scanners/enumerator.py')
    assert 'log_command' in enum and '_captured_command_output' in enum and '[no console output captured]' in enum


def test_no_backend_internal_tools_in_results_template():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    assert 'json evidence formatting check' not in html
    assert 'python_normaliser' not in html


def test_results_partials_do_not_extend_the_scan_form_template():
    import re
    results = read('templates/results.html')

    assert '{% include "pivot_assessment.html" %}' not in results
    # Every partial composed into results.html must be a fragment, never a page
    # that extends the scan form (index.html) template.
    for name in re.findall(r'{%\s*include\s+"([^"]+)"\s*%}', results):
        partial = PROJECT / 'templates' / name
        if partial.exists():
            assert '{% extends' not in partial.read_text(encoding='utf-8'), name
