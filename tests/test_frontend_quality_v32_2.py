from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'project'
def read(rel): return (PROJECT / rel).read_text(encoding='utf-8')
def test_live_command_log_has_modal_output_viewer():
    html=read('templates/scanning.html')
    assert 'Time</th><th>Purpose</th><th>Exact Command</th><th>Output' in html
    assert 'openOutputModal' in html
    assert 'modalCommand' in html and 'modalOutput' in html
    assert 'Live Enumeration Snapshot' not in html
    assert 'parsed evidence' not in html.lower()
def test_running_first_row_shows_target_current_next_profile():
    html=read('templates/scanning.html')
    assert 'Target</span>' in html
    assert 'Current Task</span>' in html
    assert 'Next Task</span>' in html
    assert 'Scan Profile</span>' in html
    assert 'enabled_tool_labels' not in html

def test_report_uses_professional_cve_labels_and_cards():
    html=read('templates/results.html')
    assert 'CVE Findings' in html
    assert 'finding-card' in html
    assert '100% Evidence-Backed' not in html
    assert 'Official CVE Records Indexed' not in html
    assert 'openRecordModal' in html

def test_optional_noisy_tools_remain_backend_configurable():
    cfg=read('config.py')
    assert "ENABLE_HTTPX = os.getenv('ENABLE_HTTPX', '0') == '1'" in cfg
    assert "ENABLE_DEEP_WEB_DISCOVERY = os.getenv('ENABLE_DEEP_WEB_DISCOVERY', '0') == '1'" in cfg
    assert "ENABLE_HYDRA = os.getenv('ENABLE_HYDRA', '0') == '1'" in cfg
    assert "ENABLE_SMBMAP = os.getenv('ENABLE_SMBMAP', '0') == '1'" in cfg

def test_command_output_is_captured_from_real_result():
    enum=read('scanners/enumerator.py')
    assert 'log_command' in enum and '_captured_command_output' in enum and '[no console output captured]' in enum


def test_no_backend_internal_tools_in_results_template():
    html = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8').lower()
    assert 'json evidence formatting check' not in html
    assert 'python_normaliser' not in html
