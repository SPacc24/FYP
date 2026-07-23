import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'project'
sys.path.insert(0, str(PROJECT))

from scanners.parsers import parse_nmap_xml
from scanners.enumerator import _classify_cve_match, _credential_combo_file
from scanners.mitre_cve import OFFICIAL_CVE_SOURCE


def test_unrealircd_version_extracted_from_script_output(tmp_path):
    xml = tmp_path / 'irc.xml'
    xml.write_text('<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="6667"><state state="open"/><service name="irc" product="UnrealIRCd"/><script id="irc-info" output="server: Unreal3.2.8.1"/></port></ports></host></nmaprun>', encoding='utf-8')
    parsed, _warnings = parse_nmap_xml(str(xml))
    rows = parsed['services']
    assert rows[0]['product'] == 'UnrealIRCd'
    assert rows[0]['version'] == '3.2.8.1'
    # A product CPE must come from observed scanner evidence. The parser must
    # not manufacture one from banner text, even when product/version parsing
    # succeeds.
    assert rows[0]['cpe'] == []


def test_non_contract_cve_classification_is_not_accepted():
    assert _classify_cve_match({
        'source': OFFICIAL_CVE_SOURCE,
        'classification': 'Different value',
    }) is None


def test_packaged_default_credential_file_exists():
    path = _credential_combo_file()
    assert path
    assert Path(path).exists()
    assert 'msfadmin:msfadmin' in Path(path).read_text(encoding='utf-8')


def test_pdf_export_has_no_duplicate_paragraph_implementation():
    text = (PROJECT / 'scanners' / 'pdf_export.py').read_text(encoding='utf-8')
    assert 'def _small_para' in text
    assert 'return _para(value, style)' in text
