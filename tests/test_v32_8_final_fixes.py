from pathlib import Path

from scanners.parsers import parse_gobuster, parse_nmap_xml
from scanners.enumerator import (
    _build_key_exposure_indicators,
    _coverage,
    _sanitize_hydra_combo_file,
)


def test_hydra_combo_sanitizer_removes_comments_blank_and_invalid_lines(tmp_path):
    source = tmp_path / "combo.txt"
    source.write_text("# comment\n\nmsfadmin:msfadmin\ninvalidline\nroot:\nadmin:admin\n", encoding="utf-8")
    sanitized = _sanitize_hydra_combo_file(str(source))
    assert sanitized
    lines = Path(sanitized).read_text(encoding="utf-8").splitlines()
    assert lines == ["msfadmin:msfadmin", "admin:admin"]
    assert all(":" in line and not line.startswith("#") for line in lines)


def test_gobuster_paths_parse_even_with_timeout_marker(tmp_path):
    evidence = tmp_path / "gobuster.txt"
    evidence.write_text(
        "index.jsp            (Status: 200) [Size: 8692]\n"
        "admin                (Status: 302) [Size: 0] [--> http://target/admin/]\n"
        "[TIMEOUT]\n",
        encoding="utf-8",
    )
    rows = parse_gobuster(str(evidence), "192.168.211.134", 8180)
    assert [r["path"] for r in rows] == ["/index.jsp", "/admin"]


def test_gobuster_timeout_with_paths_is_partial_not_zero(tmp_path):
    evidence = tmp_path / "gobuster.txt"
    evidence.write_text("manager (Status: 302) [Size: 0]\n[TIMEOUT]\n", encoding="utf-8")
    result = {"success": False, "error": "timeout", "stderr": "timeout", "returncode": -1, "output_file": str(evidence)}
    row = _coverage("gobuster", "failed", "web path discovery", "1 path(s) observed on http://x:8180", str(evidence), result)
    assert row["status"] == "Partial Results Captured"


def test_key_exposure_indicator_ports_are_preserved():
    indicators = _build_key_exposure_indicators([
        {"host": "192.168.211.134", "port": 512, "protocol": "tcp", "service": "exec", "observation": "Legacy r-service remote access surface exposed.", "evidence": "observed"},
        {"host": "192.168.211.134", "port": 513, "protocol": "tcp", "service": "login", "observation": "Legacy r-service remote access surface exposed.", "evidence": "observed"},
    ])
    legacy = [i for i in indicators if i["observation"] == "Legacy r-services exposed"][0]
    assert "512/tcp" in legacy["ports"]
    assert "513/tcp" in legacy["ports"]


def test_unrealircd_version_parsed_from_script_output(tmp_path):
    xml = tmp_path / "irc.xml"
    xml.write_text(
        """<?xml version='1.0'?><nmaprun><host><address addr='192.168.211.134' addrtype='ipv4'/><ports><port protocol='tcp' portid='6667'><state state='open'/><service name='irc' product='UnrealIRCd'/><script id='irc-info' output='server: Unreal3.2.8.1'/></port></ports></host></nmaprun>""",
        encoding="utf-8",
    )
    rows = parse_nmap_xml(str(xml))
    assert rows[0]["product"] == "UnrealIRCd"
    assert rows[0]["version"] == "3.2.8.1"
    assert "cpe:/a:unrealircd:unrealircd:3.2.8.1" in rows[0]["cpe"]
