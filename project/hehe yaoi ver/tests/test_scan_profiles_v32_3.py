
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / 'project'
sys.path.insert(0, str(ROOT))

from scanners.scan_profiles import normalise_scan_options, is_tool_enabled, TOOL_OPTIONS, profile_tool_ids


def test_legacy_fast_profile_maps_to_full_recon():
    options = normalise_scan_options('fast')
    assert options['profile'] == 'full'
    assert is_tool_enabled(options, 'tcp_discovery')
    assert is_tool_enabled(options, 'service_fingerprint')
    assert is_tool_enabled(options, 'http_security_context')
    assert is_tool_enabled(options, 'ldap_rootdse')


def test_full_profile_uses_policy_enabled_tools():
    options = normalise_scan_options('full')
    assert set(options['enabled_tools']) == set(profile_tool_ids('full'))
    assert set(options['enabled_tools']).issubset({tool['id'] for tool in TOOL_OPTIONS})


def test_custom_profile_respects_exact_user_selection():
    options = normalise_scan_options('custom', ['tcp_discovery', 'httpx', 'not_a_tool'])
    assert options['enabled_tools'] == ['httpx', 'tcp_discovery']
    assert is_tool_enabled(options, 'httpx')
    assert not is_tool_enabled(options, 'service_fingerprint')


def test_ui_contains_profile_and_tool_switches():
    index = (ROOT / 'templates' / 'index.html').read_text(encoding='utf-8')
    assert 'Full Recon' in index
    assert 'Custom Recon' in index
    assert 'name="tools"' in index
    assert 'Tool Selection' in index
