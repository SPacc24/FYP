import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'project'
sys.path.insert(0, str(PROJECT))

from scanners.parsers import parse_nmap_xml
from scanners.enumerator import _classify_cve_match, STRICT_CVE_MATCH, _credential_combo_file
from scanners.mitre_cve import OFFICIAL_CVE_SOURCE


def test_unrealircd_version_extracted_from_script_output(tmp_path):
    xml = tmp_path / 'irc.xml'
    xml.write_text('<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="6667"><state state="open"/><service name="irc" product="UnrealIRCd"/><script id="irc-info" output="server: Unreal3.2.8.1"/></port></ports></host></nmaprun>', encoding='utf-8')
    rows = parse_nmap_xml(str(xml))
    assert rows[0]['product'] == 'UnrealIRCd'
    assert rows[0]['version'] == '3.2.8.1'
    assert 'cpe:/a:unrealircd:unrealircd:3.2.8.1' in rows[0]['cpe']


def test_samba_2007_2447_is_reportable_when_official_version_match_exists():
    service = {'product': 'Samba smbd', 'version': '3.0.20-Debian', 'service': 'netbios-ssn'}
    match = {
        'source': OFFICIAL_CVE_SOURCE,
        'cve_id': 'CVE-2007-2447',
        'description': 'The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the username map script smb.conf option.',
        'match_basis': 'explicit_same_product_text_range:3.0.0..3.0.25rc3',
    }
    classification, reason = _classify_cve_match(service, match)
    assert classification == STRICT_CVE_MATCH
    assert 'product/version' in reason.lower()


def test_packaged_default_credential_file_exists():
    path = _credential_combo_file()
    assert path
    assert Path(path).exists()
    assert 'msfadmin:msfadmin' in Path(path).read_text(encoding='utf-8')


def test_pdf_export_has_no_duplicate_paragraph_implementation():
    text = (PROJECT / 'scanners' / 'pdf_export.py').read_text(encoding='utf-8')
    assert 'def _small_para' in text
    assert 'return _para(value, style)' in text
