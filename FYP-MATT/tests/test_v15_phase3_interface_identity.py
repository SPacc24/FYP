from pathlib import Path
import ast
import ipaddress


ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_phase3_preserves_retained_phase2_interface_context():
    source = read("project/routes/scan_routes.py")
    assert "def _assessment_segment_contexts" in source
    assert "def _shared_assessment_network_context" in source
    assert '"interface": str(segment.get("interface") or "").strip()' in source
    assert '"scanner_ip": str(segment.get("source_address") or "").strip()' in source
    assert '"route_interface": shared_network_context.get("route_interface", "")' in source
    assert '"scanner_ip": shared_network_context.get("scanner_ip", "")' in source
    assert '"layer2_connected": bool(shared_network_context.get("layer2_connected"))' in source


def _load_shared_context_helper():
    source = read("project/routes/scan_routes.py")
    tree = ast.parse(source)
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "_shared_assessment_network_context"
    )
    namespace = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "scan_routes.py", "exec"), namespace)
    return namespace["_shared_assessment_network_context"]


def _load_target_context_helper():
    source = read("project/routes/scan_routes.py")
    tree = ast.parse(source)
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "_assessment_segment_contexts"
    )
    namespace = {"ipaddress": ipaddress}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "scan_routes.py", "exec"), namespace)
    return namespace["_assessment_segment_contexts"]


def test_target_context_prefers_phase2_network_over_entry_host_scope():
    helper = _load_target_context_helper()
    host = {
        "ip": "192.168.1.42",
        "segment_ids": ["entry", "lan"],
    }
    segments = {
        "entry": {
            "segment_id": "entry",
            "scope_kind": "entry_host",
            "network": "192.168.1.42/32",
            "layer_index": 0,
        },
        "lan": {
            "segment_id": "lan",
            "scope_kind": "local_connected_network",
            "network": "192.168.1.0/24",
            "interface": "eth1",
            "source_address": "192.168.1.29",
            "route_type": "local_interface",
            "access_mode": "directly_connected",
            "access_transport": "direct",
            "layer2_connected": True,
            "layer_index": 1,
        },
    }
    contexts = helper(host, segments)
    assert contexts[0]["segment_id"] == "lan"
    assert contexts[0]["interface"] == "eth1"
    assert contexts[0]["scanner_ip"] == "192.168.1.29"
    assert contexts[0]["contains_target"] is True


def test_shared_context_resolves_single_or_same_segment_targets():
    _shared_assessment_network_context = _load_shared_context_helper()
    contexts = {
            "192.168.1.42": [{
                "segment_id": "seg1",
                "network": "192.168.1.0/24",
                "interface": "eth1",
                "scanner_ip": "192.168.1.29",
                "gateway": "",
                "route_table": "",
                "route_type": "local_interface",
                "layer2_connected": True,
            }],
            "192.168.1.50": [{
                "segment_id": "seg1",
                "network": "192.168.1.0/24",
                "interface": "eth1",
                "scanner_ip": "192.168.1.29",
                "gateway": "",
                "route_table": "",
                "route_type": "local_interface",
                "layer2_connected": True,
            }],
        }
    resolved = _shared_assessment_network_context(contexts)
    assert resolved["route_interface"] == "eth1"
    assert resolved["scanner_ip"] == "192.168.1.29"
    assert resolved["internal_subnet"] == "192.168.1.0/24"
    assert resolved["layer2_connected"] is True
    assert resolved["context_state"] == "shared_segment"


def test_mixed_interfaces_do_not_bind_all_targets_to_wrong_nic():
    _shared_assessment_network_context = _load_shared_context_helper()
    contexts = {
            "192.168.1.42": [{"network": "192.168.1.0/24", "interface": "eth1", "scanner_ip": "192.168.1.29", "layer2_connected": True}],
            "10.10.10.11": [{"network": "10.10.10.0/24", "interface": "eth2", "scanner_ip": "10.10.10.20", "layer2_connected": True}],
        }
    resolved = _shared_assessment_network_context(contexts)
    assert resolved["route_interface"] == ""
    assert resolved["scanner_ip"] == ""
    assert resolved["layer2_connected"] is False
    assert resolved["context_state"] == "per_target_or_unresolved"


def test_results_use_discovery_network_device_identity_when_os_is_unresolved():
    routes = read("project/routes/results_routes.py")
    scan_routes = read("project/routes/scan_routes.py")
    template = read("project/templates/results.html")
    assert "def _discovery_identity_for_target" in routes
    assert '"hostname": hostname' in routes
    assert '"vendor": vendor' in routes
    assert '"device_label": device_label' in routes
    assert "discovery_identity=_discovery_identity_for_target(data)" in routes
    assert "def _discovery_identity_for_result" in scan_routes
    assert "discovery_identity=_discovery_identity_for_result(" in scan_routes
    assert "discovery_identity.get('primary_label')" in template
    assert "Operating-system identity not established" in template
    assert "Host identity not established" not in template
    assert "No open endpoints observed in the selected scope" in template
