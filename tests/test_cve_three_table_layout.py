from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / 'project' / 'templates' / 'scan_vul.html').read_text(encoding='utf-8')
MITRE = (ROOT / 'project' / 'scanners' / 'mitre_cve.py').read_text(encoding='utf-8')
ENUMERATOR = (ROOT / 'project' / 'scanners' / 'enumerator.py').read_text(encoding='utf-8')


def test_cve_review_has_exact_three_table_roles():
    assert 'Table 1 — CVE References' in TEMPLATE
    assert 'Table 2 — Severity &amp; Triage' in TEMPLATE
    assert 'Table 3 — Information Dump' in TEMPLATE


def test_table_one_is_reference_only():
    block = TEMPLATE.split('Table 1 — CVE References', 1)[1].split('Table 2 — Severity &amp; Triage', 1)[0]
    for heading in ('Identifier', 'Affected Service', 'Why It Matched', 'Published By', 'Links'):
        assert f'<th>{heading}</th>' in block
    assert '<th>Status</th>' not in block
    assert '<th>Verification</th>' not in block
    assert 'CVSS 3.1</th>' not in block
    assert 'CVSS 4.0</th>' not in block


def test_table_two_separates_score_source_vector_and_verification():
    block = TEMPLATE.split('Table 2 — Severity &amp; Triage', 1)[1].split('Table 3 — Information Dump', 1)[0]
    for heading in ('Identifier', 'Affected Service', 'Score Source', 'Vector', 'Verified'):
        assert f'<th>{heading}</th>' in block
    assert '<th class="cvss31-col">CVSS 3.1</th>' in block
    assert '<th class="cvss40-col">CVSS 4.0</th>' in block
    assert 'Not published' in block
    assert 'metric31-detail' in block and 'metric40-detail' in block


def test_cve_publisher_is_carried_separately_from_cvss_source():
    assert "'cve_publisher': str(cve_publisher)" in MITRE
    assert "'cve_publisher': rec.get('cve_publisher')" in MITRE
    assert "'cve_publisher': match.get('cve_publisher')" in ENUMERATOR


def test_tables_live_on_main_page_not_cve_popup():
    assert 'cveModal' not in TEMPLATE
    assert 'View Scan Findings' not in TEMPLATE
    assert 'View Vulnerability Mapping' not in TEMPLATE
    assert 'id="cve-review"' in TEMPLATE
    assert 'class="cve-reference-row"' in TEMPLATE
    assert 'class="cve-info-row"' in TEMPLATE
