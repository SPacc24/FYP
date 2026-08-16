from pathlib import Path
from unittest.mock import Mock, patch

from pivot.pivot_engine import PivotEngine


def test_client_command_uses_explicit_reverse_socks_and_http_url():
    engine = PivotEngine("192.168.50.20")
    engine._socks_port = 1080
    command = engine.generate_client_command("linux", 8080)
    assert "R:1080:socks" in command
    assert "http://192.168.50.20:8080" in command
    assert "command -v chisel" in command


def test_pivot_is_not_active_until_socks_listener_exists():
    engine = PivotEngine("192.168.50.20")
    with patch.object(engine, "_port_listening", return_value=False):
        assert engine.is_running is False
        assert engine.get_status()["socks_ready"] is False
    with patch.object(engine, "_port_listening", return_value=True):
        assert engine.is_running is True
        assert engine.get_status()["client_connected"] is True


def test_chisel_server_command_has_no_duplicate_socks_flags():
    engine = PivotEngine("192.168.50.20")
    process = Mock()
    process.poll.return_value = None
    with patch("pivot.pivot_engine.subprocess.Popen", return_value=process) as popen, patch("pivot.pivot_engine.time.sleep"):
        assert engine.start_chisel_server(8080, 1080) is True
    args = popen.call_args.args[0]
    assert args == [engine.__class__.__module__ and "/usr/bin/chisel", "server", "--reverse", "--port", "8080"] or args[1:] == ["server", "--reverse", "--port", "8080"]
    assert "--socks5" not in args


def test_eternalblue_path_remains_in_project():
    root = Path(__file__).resolve().parents[1]
    catalog = (root / "project/policies/exploit_module_catalog.json").read_text(encoding="utf-8")
    chain = (root / "project/test_full_chain.sh").read_text(encoding="utf-8")
    assert "windows/smb/ms17_010_eternalblue" in catalog
    assert "ms17_010_eternalblue" in chain
