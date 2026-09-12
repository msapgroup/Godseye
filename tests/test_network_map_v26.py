from pathlib import Path


def test_realistic_network_map_ui_contracts():
    text = Path("app/main.py").read_text()
    assert 'class="network-map-layout"' in text
    assert 'id="mapSelectedPanel"' in text
    assert 'id="mapConnectedDevices"' in text
    assert "function renderNetworkGraph()" in text
    assert "function setNetworkLayout(layout)" in text
    assert "function setMapFilter(filter)" in text
    assert "function selectMapNodeByIndex(i)" in text
    assert "topology-edge" in text
    assert "wireless" in text
    assert "/assets/device-icons/" in text
    assert "Auto Layout" in text
    assert "Hierarchical" in text
    assert "Circular" in text


def test_topology_payload_exposes_device_visual_metadata():
    text = Path("app/discovery_intelligence.py").read_text()
    assert '"classification":d.get("classification")' in text
    assert '"icon_key":d.get("icon_key") or "auto"' in text
    assert '"icon_data":d.get("icon_data")' in text


def test_version_is_v26_or_later():
    assert Path("VERSION").read_text().strip().startswith(("2.6.0-", "2.7.0-", "2.8.0-", "2.9.0-", "3.0.0-", "3.1.0-", "3.2.0-", "3.3.0-", "3.4.0-", "3.5.0-", "3.6.0-", "3.7.0-", "3.8.0-", "3.9.0-", "4.0.0-"))
