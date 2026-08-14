from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'project'
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scanners import enumerator
from scanners.parsers import parse_nmap_xml
from scanners.platform_identity import host_identity_inventory


def _official_match(cve_id: str = 'CVE-2099-0001') -> dict:
    return {
        'cve_id': cve_id,
        'description': 'Synthetic CVE Program record for regression testing.',
        'source': enumerator.OFFICIAL_CVE_SOURCE,
        'matched_product_tokens': ['Example Service'],
        'matched_version_tokens': ['1.2.3'],
        'match_basis': 'structured_exact_version:status=affected',
        'product_match_basis': 'structured_affected_product',
        'structured_requirements': {},
        'affected_vendors': ['Example Vendor'],
        'affected_products': ['Example Service'],
        'affected_versions': ['1.2.3'],
        'affected_entries': [],
        'affected_cpes': [],
        'references': [],
        'cvss_metrics': {},
    }


def _service() -> dict:
    return {
        'host': '192.0.2.10',
        'port': 8080,
        'protocol': 'tcp',
        'service': 'http',
        'product': 'Example Service',
        'version': '1.2.3',
        'service_attributes': {'method': 'probed', 'conf': '10'},
        'evidence_sources': ['nmap_service_fingerprint'],
        'confidence_score': 0.35,
        'recommended_for_cve': False,
    }


def test_probabilistic_os_stays_unresolved_but_precise_hypothesis_is_candidate_eligible():
    host = '192.0.2.20'
    inv = host_identity_inventory({host: [
        {
            'host': host,
            'vendor': 'Linux',
            'family': 'Linux',
            'product': 'Linux 4.4',
            'version': '4.4',
            'accuracy': '94',
            'evidence_kind': 'probabilistic_fingerprint',
            'source': ['nmap_os_identity'],
        },
        {
            'host': host,
            'vendor': 'Linux',
            'family': 'Linux',
            'product': 'Linux 3.10 - 4.11',
            'version': '3.10 - 4.11',
            'accuracy': '95',
            'evidence_kind': 'probabilistic_fingerprint',
            'source': ['nmap_os_identity'],
        },
    ]})[0]
    assert inv['identity_state'] == 'unresolved_probabilistic'
    assert inv['best'] == {}
    assert inv['cve_identities'] == []
    assert any(x.get('candidate_eligible') for x in inv['candidate_identities'])
    assert any(x.get('product') == 'Linux 4.4' for x in inv['candidate_identities'])
    assert all('3.10 - 4.11' not in str(x.get('version') or '') for x in inv['candidate_identities'])


def test_candidate_cve_is_retained_even_when_fingerprint_confidence_is_low():
    with patch.object(enumerator, 'mitre_search_with_held', return_value=((_official_match(),), tuple())):
        candidates, review = enumerator._match_cves([_service()], [], return_review_candidates=True)
    assert len(candidates) == 1
    row = candidates[0]
    assert row['reference_type'] == 'Candidate CVE'
    assert row['candidate_status'] == 'candidate'
    assert row['validation_state'] == 'not_performed'
    assert row['applicability_state'] == 'candidate_unvalidated'
    assert 'candidate_evidence_strength' not in row
    assert 'candidate_confidence' not in row
    assert review[0] is row


def test_nvd_is_not_a_candidate_generator_in_matcher():
    source = (PROJECT / 'scanners' / 'enumerator.py').read_text(encoding='utf-8')
    fn = source.split('def _match_cves(', 1)[1].split('\ndef ', 1)[0]
    forbidden = (
        'nvd_search_candidates',
        'nvd_assess_exact_cve_applicability',
        'nvd_corroborate_component_with_host_context',
        'resolve_official_cpes',
    )
    for name in forbidden:
        assert name not in fn
    assert 'mitre_search_with_held' in fn


def test_nvd_enrichment_uses_exact_candidate_id_and_cannot_change_candidate_count():
    row = enumerator._build_cve_row(_service(), _official_match(), 'Candidate CVE', 'Synthetic candidate')
    rows = [row]
    before_ids = [x['cve_id'] for x in rows]
    metrics = {
        '3.1': {
            'cvss_version': '3.1',
            'cvss_score': 7.5,
            'cvss_severity': 'HIGH',
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'cvss_source': 'NVD',
        }
    }
    with patch.object(enumerator, 'nvd_lookup_cve_metrics', return_value=(metrics, {'matcher_status': 'available'})) as lookup:
        enumerator._enrich_missing_cvss_from_nvd(rows, [])
    lookup.assert_called_once_with('CVE-2099-0001')
    assert [x['cve_id'] for x in rows] == before_ids
    assert rows[0]['candidate_status'] == 'candidate'
    assert rows[0]['validation_state'] == 'not_performed'


def test_stronger_probed_service_identity_overrides_weak_table_hint_without_losing_provenance():
    base = [{
        'host': '192.0.2.30', 'port': 10000, 'protocol': 'tcp',
        'service': 'snet-sensor-mgmt', 'product': '', 'version': '',
        'service_attributes': {'method': 'table', 'conf': '3'},
        'evidence_sources': ['nmap_tcp_discovery'],
    }]
    recovery = [{
        'host': '192.0.2.30', 'port': 10000, 'protocol': 'tcp',
        'service': 'http', 'product': 'lighttpd', 'version': '1.4.39',
        'service_attributes': {'method': 'probed', 'conf': '10'},
        'evidence_sources': ['nmap_service_fingerprint'],
    }]
    merged = enumerator._merge_service_identity_rows(base, recovery, 'nmap_service_fingerprint')[0]
    assert merged['service'] == 'http'
    assert merged['product'] == 'lighttpd'
    assert merged['version'] == '1.4.39'
    assert merged['service_attributes']['method'] == 'probed'
    assert any(x.get('service') == 'snet-sensor-mgmt' for x in merged.get('observed_identities') or [])


def test_parser_preserves_ssl_tunnel_and_tls_is_applicable_without_port_hardcoding(tmp_path):
    xml = tmp_path / 'tls.xml'
    xml.write_text('''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.40" addrtype="ipv4"/><ports><port protocol="tcp" portid="9443"><state state="open"/><service name="http" product="Example TLS Service" version="1.0" tunnel="ssl" method="probed" conf="10"/></port></ports></host><runstats><finished/><hosts up="1" down="0" total="1"/></runstats></nmaprun>''', encoding='utf-8')
    parsed, warnings = parse_nmap_xml(xml)
    assert not warnings
    service = parsed['hosts'][0]['ports'][0]
    assert service['service_attributes']['tunnel'] == 'ssl'
    # Normalize exactly as the scanner does after merging/attachment.
    enumerator._refresh_transport_security(service)
    assert service['transport_security'] == 'tls'
    plan = {'scope': 'endpoint', 'protocols': ['tcp'], 'families': ['tls']}
    assert enumerator._collector_service_applicable(plan, service)


def test_persisted_assessment_target_and_unresolved_os_rules_are_encoded_in_results_adapter():
    source = (PROJECT / 'core' / 'helpers.py').read_text(encoding='utf-8')
    fn = source.split('def _stored_results_to_parsed_results(', 1)[1].split('\ndef ', 1)[0]
    assert 'workflow.get("assessment_target")' in fn
    assert 'host_row.get("identity_state") or "") != "established"' in fn
    assert 'established_os = "Unresolved"' in fn


def test_ui_labels_candidates_and_does_not_promote_probabilistic_best_os():
    results_template = (PROJECT / 'templates' / 'results.html').read_text(encoding='utf-8')
    scan_template = (PROJECT / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
    assert 'Candidate CVE' in scan_template
    assert 'Exact Candidate CVE IDs only' in scan_template
    assert 'OS: Unresolved' in results_template
    # An established identity may be shown, but a generic host_row.best must not be used as an unconditional OS label.
    assert 'host_row.best.product' not in results_template


def test_no_demo_target_or_demo_cve_is_hardcoded_into_modified_scanner_files():
    files = [
        PROJECT / 'scanners' / 'enumerator.py',
        PROJECT / 'scanners' / 'platform_identity.py',
        PROJECT / 'scanners' / 'parsers.py',
        PROJECT / 'scanners' / 'mitre_cve.py',
        PROJECT / 'core' / 'helpers.py',
        PROJECT / 'templates' / 'scan_vul.html',
        PROJECT / 'templates' / 'results.html',
    ]
    text = '\n'.join(p.read_text(encoding='utf-8') for p in files)
    for forbidden in ('192.168.1.1', 'MR7350', 'CVE-2021-3448'):
        assert forbidden not in text
