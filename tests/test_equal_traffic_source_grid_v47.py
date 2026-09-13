from pathlib import Path

def test_v47_version():
    assert Path("VERSION").read_text().strip().startswith(("4.7.0-","4.8.0-", "4.9.0-"))

def test_traffic_source_grid_is_two_by_two():
    source=Path("app/main.py").read_text()
    assert "grid-template-columns:repeat(2,minmax(0,1fr))!important" in source
    assert "max-width:760px!important" in source

def test_all_traffic_source_cards_have_fixed_equal_size():
    source=Path("app/main.py").read_text()
    assert 'height:184px!important' in source
    assert 'min-height:184px!important' in source
    assert 'max-height:184px!important' in source

def test_four_source_cards_remain_present():
    from app import main
    html=main.DASHBOARD
    for mode in ("unifi","snmp","span","inline"):
        assert f'class="traffic-source-card" data-traffic-mode="{mode}"' in html
