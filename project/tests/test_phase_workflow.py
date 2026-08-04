from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from scanners.phase_discovery import (
    DiscoveryWorkflowError,
    _candidate_network_records,
    _candidate_networks,
    _parse_host_inventory,
    validate_external_target,
)
from storage import scan_store


def test_phase1_accepts_one_ip_only():
    assert validate_external_target("10.10.10.1") == "10.10.10.1"
    for value in ("", "10.10.10.0/24", "10.10.10.1 10.10.10.2", "gateway.local"):
        with pytest.raises(DiscoveryWorkflowError):
            validate_external_target(value)


def test_private_connected_scope_is_selected_for_private_gateway():
    external = ipaddress.ip_address("10.10.10.1")
    routes = [{"dst": "10.10.10.0/24", "dev": "eth1", "scope": "link"}]
    addresses = [
        {
            "ifname": "eth1",
            "addr_info": [{"family": "inet", "local": "10.10.10.5", "prefixlen": 24}],
        }
    ]
    candidates, _ = _candidate_networks(external, "eth1", routes, addresses)
    assert [str(network) for network in candidates] == ["10.10.10.0/24"]


def test_default_internet_route_does_not_authorize_home_lan_scan():
    external = ipaddress.ip_address("8.8.8.8")
    routes = [{"dst": "default", "dev": "eth0", "gateway": "192.168.1.1"}]
    addresses = [
        {
            "ifname": "eth0",
            "addr_info": [{"family": "inet", "local": "192.168.1.20", "prefixlen": 24}],
        }
    ]
    candidates, _ = _candidate_networks(external, "eth0", routes, addresses)
    assert candidates == []


def test_phase2_inventory_marks_scanner_unselectable(tmp_path: Path):
    xml = tmp_path / "hosts.xml"
    xml.write_text(
        """<?xml version='1.0'?>
<nmaprun>
  <host><status state='up'/><address addr='10.10.10.5' addrtype='ipv4'/><hostnames><hostname name='kali'/></hostnames></host>
  <host><status state='up'/><address addr='10.10.10.20' addrtype='ipv4'/><address addr='00:11:22:33:44:55' addrtype='mac' vendor='Lab Vendor'/><hostnames><hostname name='server01'/></hostnames></host>
</nmaprun>""",
        encoding="utf-8",
    )
    hosts = _parse_host_inventory(xml, scanner_ip="10.10.10.5", gateway="10.10.10.1")
    assert hosts[0]["is_scanner"] is True
    assert hosts[0]["selectable"] is False
    assert hosts[1]["ip"] == "10.10.10.20"
    assert hosts[1]["hostname"] == "server01"
    assert hosts[1]["mac_vendor"] == "Lab Vendor"
    assert hosts[1]["selectable"] is True


def test_scan_store_appends_assessment_without_erasing_discovery():
    scan_id = scan_store.new_scan("10.10.10.1")
    scan_store.init_tasks(scan_id, ["Phase 1", "Phase 2"], phase="discovery")
    scan_store.set_task(scan_id, "Phase 1", scan_store.STATUS_SUCCESS)
    scan_store.set_task(scan_id, "Phase 2", scan_store.STATUS_SUCCESS)
    scan_store.update(scan_id, status=scan_store.STATUS_AWAITING_CONFIGURATION)

    assert scan_store.transition_status(
        scan_id,
        {scan_store.STATUS_AWAITING_CONFIGURATION},
        scan_store.STATUS_ASSESSMENT_RUNNING,
    )
    scan_store.append_tasks(scan_id, ["TCP Service Discovery"], phase="assessment")
    data = scan_store.get(scan_id)
    assert [task["name"] for task in data["tasks"]] == [
        "Phase 1",
        "Phase 2",
        "TCP Service Discovery",
    ]
    assert data["tasks"][-1]["phase"] == "assessment"
    assert not scan_store.transition_status(
        scan_id,
        {scan_store.STATUS_AWAITING_CONFIGURATION},
        scan_store.STATUS_ASSESSMENT_RUNNING,
    )


def test_phase3_template_keeps_existing_customisation_controls():
    template = Path("templates/assessment_config.html").read_text(encoding="utf-8")
    assert 'name="assessment_targets"' in template
    assert 'type="checkbox"' in template
    assert 'Select at least one discovered host' in template
    assert 'name="target"' not in template
    for control in (
        'name="tcp_port_mode"',
        'name="udp_port_mode"',
        'name="technique_mode"',
        'name="collector_plan_json"',
        'name="host_discovery_json"',
        'name="service_identity_json"',
        'name="command_timeout_seconds"',
        'name="ports_per_batch"',
    ):
        assert control in template


def test_specific_route_via_external_target_is_a_candidate_without_cidr_guessing():
    external = ipaddress.ip_address("198.51.100.10")
    routes = [
        {"dst": "10.20.30.0/24", "dev": "tun0", "gateway": "198.51.100.10"},
    ]
    records, _ = _candidate_network_records(external, "tun0", routes, [])
    assert [item["subnet"] for item in records] == ["10.20.30.0/24"]
    assert records[0]["relationship"] == "specific_route_via_external_target"


def test_multiple_route_candidates_are_retained_for_operator_selection():
    external = ipaddress.ip_address("10.0.0.1")
    routes = [
        {"dst": "10.20.30.0/24", "dev": "tun0", "gateway": "10.0.0.1"},
        {"dst": "10.20.40.0/24", "dev": "tun0", "gateway": "10.0.0.1"},
    ]
    records, _ = _candidate_network_records(external, "tun0", routes, [])
    assert {item["subnet"] for item in records} == {"10.20.30.0/24", "10.20.40.0/24"}


def test_command_builders_bind_phase_selected_interface(tmp_path: Path):
    from scanners import command_builders

    arp = command_builders.arp_scan("/usr/bin/arp-scan", "10.10.10.20", interface="eth7")
    nmap = command_builders.nmap_host_discovery(
        "/usr/bin/nmap", ["10.10.10.20"], tmp_path / "hosts.xml", interface="eth7"
    )
    assert "--interface" in arp and "eth7" in arp
    assert "-e" in nmap and "eth7" in nmap


def test_recovery_snapshot_reports_missing_facts_and_endpoints_separately():
    from scanners.evidence_recovery import recovery_snapshot

    snapshot = recovery_snapshot([
        {"host": "10.0.0.2", "port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "", "version": ""},
        {"host": "10.0.0.2", "port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "server", "version": "1.0"},
    ])
    assert snapshot["endpoints_considered"] == 2
    assert snapshot["unresolved_endpoint_count"] == 2
    assert snapshot["missing_fact_count"] >= 2


def test_phase3_backend_accepts_only_discovered_checkbox_targets():
    source = Path("routes/scan_routes.py").read_text(encoding="utf-8")
    assert 'request.form.getlist("assessment_targets")' in source
    assert "if not assessment_targets:" in source
    assert "target not in discovered_hosts" in source
    assert "ipaddress.ip_address(target) not in internal_network" in source
    assert 'target_input = ",".join(assessment_targets)' in source


def test_cve_ui_groups_and_filters_rows_within_each_target():
    template = Path("templates/scan_vul.html").read_text(encoding="utf-8")
    assert 'data-target-host="{{ current_host }}"' in template
    assert "const rowsByHost = new Map();" in template
    assert "hostOrder.forEach(host =>" in template
    assert "referenceByHost = new Map()" in template


def test_results_report_route_evidence_and_multiple_targets():
    results = Path("templates/results.html").read_text(encoding="utf-8")
    report = Path("templates/pdf_report.html").read_text(encoding="utf-8")
    appendix = Path("templates/technical_appendix.html").read_text(encoding="utf-8")
    for template in (results, report, appendix):
        assert "access_mode" in template
        assert "assessment_targets" in template
    assert "Selected Interface" in results
    assert "Phase 3 targets selected" in appendix


def test_arp_capability_setup_uses_discovered_binary_path():
    installer = Path("../install.sh").read_text(encoding="utf-8")
    assert 'ARP_SCAN_BIN="$(command -v arp-scan || true)"' in installer
    assert 'setcap cap_net_raw,cap_net_admin=eip "$ARP_SCAN_BIN"' in installer
    assert "/usr/bin/arp-scan" not in installer


def test_existing_tunnel_routes_are_candidates_when_external_endpoint_uses_management_interface():
    external = ipaddress.ip_address("198.51.100.10")
    routes = [
        {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"},
        {"dst": "10.30.40.0/24", "dev": "tun7"},
    ]
    addresses = [
        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.20", "prefixlen": 24}]},
        {"ifname": "tun7", "addr_info": [{"family": "inet", "local": "10.255.0.2", "prefixlen": 32}]},
    ]
    records, _ = _candidate_network_records(external, "eth0", routes, addresses)
    assert [item["subnet"] for item in records] == ["10.30.40.0/24"]
    assert records[0]["interface"] == "tun7"
    assert records[0]["access_mode"] == "tunnel"
