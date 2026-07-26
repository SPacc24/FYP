from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]
SCANNERS = ROOT / 'project' / 'scanners'
if str(ROOT / 'project') not in sys.path:
    sys.path.insert(0, str(ROOT / 'project'))

from scanners import mitre_cve


def test_apache_alias_does_not_match_unrelated_http_server_products():
    names = {'apache http server', 'apache httpd'}
    assert not mitre_cve._product_name_matches('http-server-node', names)
    assert not mitre_cve._product_name_matches('http-server', names)
    assert not mitre_cve._product_name_matches('http_server', names)
    assert mitre_cve._product_name_matches('Apache HTTP Server', names)


def test_exact_version_zero_is_not_treated_as_open_ended_minimum():
    entry = {
        'defaultStatus': 'unknown',
        'versions': [{'version': '0', 'status': 'affected'}],
    }
    ok, _, _ = mitre_cve._entry_version_match(entry, '2.2.8')
    assert not ok


def test_custom_wildcard_upper_bound_does_not_match_arbitrary_old_mysql():
    entry = {
        'defaultStatus': 'unknown',
        'versions': [
            {'version': '*', 'lessThanOrEqual': '8.0.39', 'versionType': 'custom', 'status': 'affected'},
            {'version': '*', 'lessThanOrEqual': '8.4.2', 'versionType': 'custom', 'status': 'affected'},
            {'version': '*', 'lessThanOrEqual': '9.0.1', 'versionType': 'custom', 'status': 'affected'},
        ],
    }
    ok, _, why = mitre_cve._entry_version_match(entry, '5.0.51a-3ubuntu5')
    assert not ok
    assert 'custom' in why or 'unknown' in why


def test_unknown_status_does_not_promote_to_affected():
    entry = {
        'defaultStatus': 'unknown',
        'versions': [{'version': '2.3.4', 'status': 'unknown'}],
    }
    ok, _, _ = mitre_cve._entry_version_match(entry, '2.3.4')
    assert not ok


def test_semver_range_can_be_evaluated_when_declared():
    entry = {
        'defaultStatus': 'unknown',
        'versions': [
            {
                'version': '1.0.0',
                'lessThan': '2.0.0',
                'versionType': 'semver',
                'status': 'affected',
            }
        ],
    }
    ok, _, basis = mitre_cve._entry_version_match(entry, '1.5.0')
    assert ok
    assert 'structured_affected_range:semver' in basis


def test_observed_nmap_version_range_is_not_treated_as_exact_version():
    entry = {
        'defaultStatus': 'unknown',
        'versions': [{'version': '8.3.0', 'status': 'affected'}],
    }
    ok, _, why = mitre_cve._entry_version_match(entry, '8.3.0 - 8.3.7')
    assert not ok
    assert why == 'observed_version_is_range'


def test_keyword_nvd_fallback_is_not_used_as_canonical_candidate_generator():
    source = (SCANNERS / 'mitre_cve.py').read_text(encoding='utf-8')
    fn = source.split('def search_with_held(', 1)[1].split('\ndef ', 1)[0]
    assert 'nvd_client.search' not in fn


def test_main_page_replaces_old_scan_and_vulnerability_tables():
    template = (ROOT / 'project' / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
    assert 'View Scan Findings' not in template
    assert 'View Vulnerability Mapping' not in template
    assert 'cveModal' not in template
    assert 'Table 1 — CVE References' in template
    assert 'Table 2 — Severity &amp; Triage' in template
    assert 'Table 3 — Scan Findings' in template
    assert 'Coverage &amp; Assurance' in template
    assert 'Information Dump' not in template


def test_cvss_selector_controls_columns_and_sort_key():
    template = (ROOT / 'project' / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
    assert 'data-cvss-view="3.1"' in template
    assert 'data-cvss-view="4.0"' in template
    assert 'data-cvss-view="both"' in template
    assert "activeScore(b, view) - activeScore(a, view)" in template
    assert 'class="cvss31-col"' in template
    assert 'class="cvss40-col"' in template
    assert 'metric31-detail' in template
    assert 'metric40-detail' in template
