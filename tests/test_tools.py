from unittest.mock import patch
from app.tools import port_scan, traceroute, device_info


def test_port_scan_rejects_public_target():
    try:
        port_scan("8.8.8.8")
    except ValueError as exc:
        assert "private/link-local" in str(exc)
    else:
        raise AssertionError("public target should be rejected")


def test_traceroute_rejects_public_target():
    try:
        traceroute("1.1.1.1")
    except ValueError as exc:
        assert "private/link-local" in str(exc)
    else:
        raise AssertionError("public target should be rejected")


def test_port_scan_parses_open_port():
    with patch("app.tools.shutil.which", return_value="/usr/bin/nmap"), patch(
        "app.tools._run", return_value=(0, "80/tcp open http\n443/tcp open https", 12.3)
    ):
        result=port_scan("192.168.1.1", "80,443")
    assert result["ok"] is True
    assert [p["port"] for p in result["ports"]] == ["80/tcp", "443/tcp"]
