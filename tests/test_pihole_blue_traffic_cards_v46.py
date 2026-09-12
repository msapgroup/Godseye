from pathlib import Path

def test_v46_version():
    assert Path("VERSION").read_text().strip().startswith(("4.6.0-","4.7.0-"))

def test_dark_blue_is_standardized_to_pihole_blue():
    source=Path("app/main.py").read_text()
    assert "--gs-blue:#9cc9f5!important" in source
    for selector in (
        'html[data-theme="dark"] .integration-badge',
        'html[data-theme="dark"] .analytics-card .metric',
        'html[data-theme="dark"] .integration-card .integration-meta',
        'html[data-theme="dark"] .traffic-source-kind',
        'html[data-theme="dark"] .report-type-icon',
    ):
        assert selector in source

def test_traffic_source_cards_are_simplified():
    from app import main
    html=main.DASHBOARD
    start=html.index('class="traffic-source-grid"')
    end=html.index("</section>",start)
    block=html[start:end]
    assert block.count('class="traffic-source-card"')==4
    assert block.count('data-clean="1"')==4
    assert block.count('class="traffic-source-card-head"')==4
    assert block.count('class="traffic-source-divider"')==4
    assert block.count('class="traffic-source-meta"')==4
    assert block.count('class="traffic-source-foot"')==4
    assert "Best for" not in block
    assert "Setup</b>" not in block

def test_traffic_card_descriptions_are_shorter():
    from app import main
    html=main.DASHBOARD
    start=html.index('class="traffic-source-grid"')
    end=html.index("</section>",start)
    block=html[start:end]
    assert "Use device counters already collected by your UniFi controller." in block
    assert "Read mapped traffic counters from supported routers and switches." in block
    assert "Observe mirrored traffic without placing GODSEYE in the gateway path." in block
    assert "Measure traffic that actually passes through the GODSEYE appliance." in block
