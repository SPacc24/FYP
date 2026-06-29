from scanners.targets import expand_target_input


def test_expand_target_input_accepts_space_separated_hosts():
    assert expand_target_input('192.168.86.30 192.168.86.127') == ['192.168.86.30', '192.168.86.127']


def test_expand_target_input_accepts_mixed_separators_and_deduplicates():
    assert expand_target_input('192.168.86.30,192.168.86.127;192.168.86.30') == ['192.168.86.30', '192.168.86.127']


def test_expand_target_input_accepts_short_range():
    assert expand_target_input('192.168.86.30-32') == ['192.168.86.30', '192.168.86.31', '192.168.86.32']
