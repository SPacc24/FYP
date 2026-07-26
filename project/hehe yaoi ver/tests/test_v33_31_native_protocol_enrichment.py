from project.scanners.enumerator import _apply_native_protocol_enrichment, _parse_mysql_handshake, _parse_vnc_probe, _parse_smtp_probe


def test_native_mysql_handshake_extracts_version():
    parsed = _parse_mysql_handshake('\x0a5.0.51a-3ubuntu5\x00')
    assert parsed['product'] == 'MySQL'
    assert parsed['version'] == '5.0.51a-3ubuntu5'


def test_native_vnc_parser_normalises_rfb_version():
    parsed = _parse_vnc_probe('RFB 003.003\n')
    assert parsed['product'] == 'RFB'
    assert parsed['version'] == '3.3'


def test_smtp_capability_parser_preserves_postfix_and_capabilities():
    parsed = _parse_smtp_probe('220 metasploitable.localdomain ESMTP Postfix\n250-PIPELINING\n250-STARTTLS\n250 SIZE 10240000\n')
    assert parsed['product'] == 'Postfix smtpd'
    assert 'PIPELINING' in parsed['capabilities']
    assert 'STARTTLS' in parsed['capabilities']


def test_native_enrichment_updates_generic_service_row():
    services = [{'host': '10.0.0.5', 'port': 3306, 'protocol': 'tcp', 'service': 'mysql', 'product': 'mysql', 'version': ''}]
    rows = [{'host': '10.0.0.5', 'port': 3306, 'tool': 'mysql_native_handshake', 'parsed': {'product': 'MySQL', 'version': '5.0.51a-3ubuntu5'}}]
    enriched = _apply_native_protocol_enrichment(services, rows)
    assert enriched[0]['product'] == 'MySQL'
    assert enriched[0]['version'] == '5.0.51a-3ubuntu5'
