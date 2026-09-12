from pathlib import Path

def test_v39_version():
    assert Path("VERSION").read_text().strip().startswith(("3.9.0-","4.0.0-", "4.1.0-", "4.2.0-", "4.3.0-", "4.4.0-", "4.5.0-", "4.6.0-"))

def test_polished_traffic_source_cards_present():
    from app import main
    html=main.DASHBOARD
    assert 'class="traffic-source-grid"' in html
    for mode in ("unifi","snmp","span","inline"):
        assert f'data-traffic-mode="{mode}"' in html
        assert f"selectTrafficMode('{mode}')" in html
    assert 'id="trafficMode"' in html
    assert 'style="display:none"' in html

def test_traffic_summary_cards_present():
    from app import main
    html=main.DASHBOARD
    for element_id in ("trafficSourceLabel","traffic24Rx","traffic24Tx","trafficDeviceCount","trafficLastSample"):
        assert f'id="{element_id}"' in html

def test_traffic_collection_sections_are_structured():
    from app import main
    html=main.DASHBOARD
    assert "1. Choose traffic source" in html
    assert "2. Configure source" in html
    assert "Top Device Usage · Last 24 Hours" in html
    assert 'id="trafficModeHelpTitle"' in html
    assert 'id="trafficModeRequire"' in html

def test_render_updates_visual_source_state_and_summary():
    source=Path("app/main.py").read_text()
    assert "document.querySelectorAll('.traffic-source-card')" in source
    assert "trafficSourceLabel.textContent=" in source
    assert "traffic24Rx.textContent=fmtBytes" in source
    assert "traffic24Tx.textContent=fmtBytes" in source
    assert "trafficDeviceCount.textContent=String(rows.length)" in source
    assert "trafficCollectionState.className='traffic-state '+state" in source

def test_existing_backend_contracts_retained():
    source=Path("app/main.py").read_text()
    assert 'f"{router_prefix}/traffic/config"' in source
    assert 'f"{router_prefix}/traffic/collect-now"' in source
    assert 'f"{router_prefix}/traffic/ingest"' in source
