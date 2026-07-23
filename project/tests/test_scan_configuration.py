import pytest

from scanners.scan_configuration import (
    ScanConfigurationError,
    compact_port_ranges,
    iter_port_batches,
    normalise_scan_configuration,
    parse_port_expression,
    resolve_tcp_ports,
    resolve_udp_ports,
)


def test_complete_tcp_and_disabled_udp_are_defaults():
    options = normalise_scan_configuration({})
    assert len(resolve_tcp_ports(options)) == 65535
    assert resolve_udp_ports(options) == []
    assert options['advanced'] == {
        'ports_per_microbatch': 256,
        'concurrent_targets': 4,
        'probe_timeout_seconds': 3,
        'retry_limit': 1,
    }


def test_custom_additional_and_excluded_ports_are_combined_numerically():
    options = normalise_scan_configuration({
        'tcp_coverage': 'custom',
        'tcp_custom': '22,80,8000-8002',
        'tcp_additional': '443,8002',
        'tcp_excluded': '80',
        'udp_coverage': 'custom',
        'udp_custom': '53,123',
    })
    assert resolve_tcp_ports(options) == [22, 443, 8000, 8001, 8002]
    assert resolve_udp_ports(options) == [53, 123]


def test_microbatches_are_ordered_and_non_overlapping():
    batches = list(iter_port_batches([9, 1, 4, 3, 2, 8], 2))
    assert batches == [[1, 2], [3, 4], [8, 9]]


def test_coverage_ranges_are_compact_for_reports():
    assert compact_port_ranges([1, 2, 3, 7, 9, 10]) == ['1-3', '7', '9-10']


@pytest.mark.parametrize('value', ['0', '65536', '22;$(id)', 'one', '1-70000'])
def test_invalid_port_input_is_rejected(value):
    with pytest.raises(ScanConfigurationError):
        parse_port_expression(value)


def test_common_selection_is_data_driven_and_not_empty():
    options = normalise_scan_configuration({
        'tcp_coverage': 'common',
        'udp_coverage': 'common',
    })
    assert resolve_tcp_ports(options)
    assert resolve_udp_ports(options)
    assert options['port_policy_sha256']
