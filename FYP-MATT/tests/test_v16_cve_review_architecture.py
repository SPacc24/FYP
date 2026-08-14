from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'project') not in sys.path:
    sys.path.insert(0, str(ROOT / 'project'))

from scanners import enumerator
from scanners.platform_identity import host_identity_gaps, host_identity_inventory


def _canonical_match(cve_id: str = 'CVE-2099-0001') -> dict:
    return {
        'cve_id': cve_id,
        'description': 'Synthetic CVE Program record.',
        'source': enumerator.OFFICIAL_CVE_SOURCE,
        'matched_product_tokens': ['Widget'],
        'matched_version_tokens': ['1.5'],
        'match_basis': 'structured_exact_version:status=affected',
        'product_match_basis': 'structured affected product',
        'structured_requirements': {},
        'affected_vendors': ['Vendor'],
        'affected_products': ['Widget'],
        'affected_versions': ['1.5'],
        'affected_entries': [],
        'affected_cpes': [],
        'references': [],
        'cvss_metrics': {},
    }


def _service() -> dict:
    return {
        'host': '192.0.2.10', 'port': 80, 'protocol': 'tcp',
        'service': 'http', 'product': 'Widget', 'version': '1.5',
        'evidence_sources': ['nmap'], 'confidence_score': 0.4,
        'recommended_for_cve': False,
    }


def test_candidate_generation_uses_cve_program_only_and_does_not_call_nvd():
    with patch.object(enumerator, 'mitre_search_with_held', return_value=((_canonical_match(),), tuple())):
        rows, review = enumerator._match_cves([_service()], [], return_review_candidates=True)
    assert len(rows) == 1 and review[0] is rows[0]
    assert rows[0]['candidate_status'] == 'candidate'
    assert rows[0]['validation_state'] == 'not_performed'
    source = (ROOT / 'project' / 'scanners' / 'enumerator.py').read_text(encoding='utf-8')
    fn = source.split('def _match_cves(', 1)[1].split('\ndef ', 1)[0]
    assert 'nvd_search_candidates' not in fn
    assert 'nvd_assess_exact_cve_applicability' not in fn
    assert 'resolve_official_cpes' not in fn


def test_low_confidence_does_not_suppress_candidate_or_create_candidate_tiers():
    with patch.object(enumerator, 'mitre_search_with_held', return_value=((_canonical_match(),), tuple())):
        rows, _ = enumerator._match_cves([_service()], [])
    assert len(rows) == 1
    assert rows[0]['reference_type'] == 'Candidate CVE'
    assert rows[0]['candidate_status'] == 'candidate'
    assert 'candidate_evidence_strength' not in rows[0]
    assert 'candidate_confidence' not in rows[0]


def test_probabilistic_os_is_not_promoted_to_displayed_os_but_precise_hypotheses_feed_candidates():
    host = '192.0.2.20'
    observations = [
        {
            'host': host, 'vendor': 'Vendor A', 'family': 'Embedded',
            'product': 'Product A', 'version': '1.0', 'accuracy': '90',
            'evidence_kind': 'probabilistic_fingerprint', 'source': ['nmap_os_identity'],
        },
        {
            'host': host, 'vendor': 'Vendor B', 'family': 'Linux',
            'product': 'Product B', 'version': '4.4', 'accuracy': '90',
            'evidence_kind': 'probabilistic_fingerprint', 'source': ['nmap_os_identity'],
        },
    ]
    inventory = host_identity_inventory({host: observations})[0]
    assert inventory['best'] == {}
    assert inventory['cve_identities'] == []
    assert len(inventory['candidate_identities']) == 2
    assert inventory['identity_state'] == 'unresolved_probabilistic'
    gaps = host_identity_gaps({host: observations}, [host])
    assert 'Exact operating system was not established' in gaps[0]['remaining_gap']


def test_operator_asset_identity_is_not_an_input_to_candidate_generation():
    import inspect
    signature = inspect.signature(enumerator._match_cves)
    assert 'operator_asset_identities' not in signature.parameters
    template = (ROOT / 'project' / 'templates' / 'scan_vul.html').read_text(encoding='utf-8').lower()
    assert 'operator-confirmed asset identity' not in template


def test_review_summary_reports_one_candidate_state_without_tier_taxonomy():
    review = [
        {'cve_id': 'CVE-2099-1', 'candidate_status': 'candidate', 'candidate_basis': 'Direct service product/version'},
        {'cve_id': 'CVE-2099-2', 'candidate_status': 'candidate', 'candidate_basis': 'Probabilistic OS fingerprint'},
    ]
    summary = enumerator._build_cve_review_summary(review, review, [])
    assert summary['candidate_cves_retained'] == 2
    assert summary['unvalidated'] == 2
    assert 'strict_matched' not in summary
    assert 'conditional' not in summary
    assert summary['candidate_basis']['Direct service product/version'] == 1
    assert summary['candidate_basis']['Probabilistic OS fingerprint'] == 1
