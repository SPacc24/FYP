from __future__ import annotations

from pathlib import Path

from scanners import infrastructure_discovery, phase_discovery


def test_runtime_ssh_access_bypasses_configured_profile_and_does_not_return_secret(monkeypatch):
    monkeypatch.delenv("INFRA_TOPOLOGY_PROFILES_JSON", raising=False)
    captured = {}

    def fake_collect(scan_id, host_ip, profile_ref, profile, *, runtime_secret=""):
        captured.update(
            {
                "scan_id": scan_id,
                "host_ip": host_ip,
                "profile_ref": profile_ref,
                "profile": dict(profile),
                "runtime_secret": runtime_secret,
            }
        )
        return "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0     192.168.1.42    YES DHCP   up                    up\nGigabitEthernet0/1     203.0.113.1     YES manual up                    up\nC    192.168.1.0/24 is directly connected, GigabitEthernet0/0\nC    203.0.113.0/24 is directly connected, GigabitEthernet0/1\n"

    monkeypatch.setattr(infrastructure_discovery, "_collect_ssh", fake_collect)

    result = infrastructure_discovery.collect_device_topology(
        "scan-v9",
        "192.168.1.42",
        runtime_profile={
            "platform": "cisco_ios",
            "transport": "ssh",
            "username": "readonly",
            "port": 22,
        },
        runtime_secret="super-secret",
    )

    assert captured["profile_ref"] == "operator_ephemeral"
    assert captured["runtime_secret"] == "super-secret"
    assert result["profile_ref"] == "operator_ephemeral"
    assert result["access_source"] == "operator_ephemeral"
    assert result["platform"] == "cisco_ios"
    assert "super-secret" not in repr(result)
    networks = {row["destination_network"] for row in result["networks"]}
    assert "192.168.1.0/24" in networks
    assert "203.0.113.0/24" in networks


def test_runtime_snmp_requires_no_env_profile(monkeypatch):
    monkeypatch.delenv("INFRA_TOPOLOGY_PROFILES_JSON", raising=False)
    captured = {}

    def fake_collect(scan_id, host_ip, profile_ref, profile, *, runtime_secret=""):
        captured["secret"] = runtime_secret
        return "[SNMP_ADDR]\nIP-MIB::ipAdEntAddr.192.168.1.42 = IpAddress: 192.168.1.42\n[SNMP_MASK]\nIP-MIB::ipAdEntNetMask.192.168.1.42 = IpAddress: 255.255.255.0\n"

    monkeypatch.setattr(infrastructure_discovery, "_collect_snmp", fake_collect)
    result = infrastructure_discovery.collect_device_topology(
        "scan-v9",
        "192.168.1.42",
        runtime_profile={"platform": "cisco_ios", "transport": "snmp_v2c"},
        runtime_secret="readonly-community",
    )
    assert captured["secret"] == "readonly-community"
    assert result["access_source"] == "operator_ephemeral"
    assert "readonly-community" not in repr(result)


def test_phase2_template_removes_on_demand_access_and_profiles():
    project_root = Path(phase_discovery.__file__).resolve().parents[1]
    template = (project_root / "templates/layer_decision.html").read_text(encoding="utf-8")
    route_source = (project_root / "routes/scan_routes.py").read_text(encoding="utf-8")

    assert "ON-DEMAND READ-ONLY TOPOLOGY ACCESS" not in template
    assert "Read-only topology access" not in template
    assert 'value="query_device_runtime"' not in template
    assert 'value="discover_device"' in template
    assert 'name="runtime_platform"' not in template
    assert 'name="runtime_transport"' not in template
    assert 'name="runtime_username"' not in template
    assert 'name="runtime_secret"' not in template
    assert 'action in {"discover_device", "query_device"}' in route_source
    assert "runtime_username" not in route_source
    assert "runtime_secret" not in route_source
    assert "public_profile_catalog" not in route_source
    assert "profile_selection_context" not in route_source


def test_runtime_secret_is_not_written_into_phase_discovery_workflow_source():
    source = Path(phase_discovery.__file__).read_text(encoding="utf-8")
    # The secret is only forwarded to the collector; it must never be assigned
    # into workflow/topology mission records.
    assert '"runtime_secret":' not in source
    assert "runtime_secret=runtime_secret" in source
