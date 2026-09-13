from app.diagnostic_rules import analyze
from app.plugins import manifest
from app.tools import dns

def test_plugin_manifest_contains_core_features():
    ids = {item["id"] for item in manifest()}
    assert {"ARPSCAN", "NMAPDEV", "IPNEIGH", "WEBMON", "WOL", "PROMETHEUS"} <= ids

def test_diagnostic_rule_unreachable():
    result = analyze({"ping": {"ok": False}, "dns": {"ok": False}, "recommendations": []})
    assert result["severity"] == "warning"
    assert result["likely_cause"]

def test_dns_localhost():
    result = dns("localhost")
    assert result["ok"] is True
