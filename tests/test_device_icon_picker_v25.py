from pathlib import Path


def test_realistic_icon_picker_is_centered_and_categorized():
    from app import main
    html = main.DASHBOARD
    assert 'class="modal device-icon-modal"' in html
    assert 'class="modal-card device-icon-dialog"' in html
    assert 'Network Devices' in html
    assert 'Computers &amp; Mobile' in html
    assert 'Security' in html
    assert 'Home &amp; IoT' in html
    assert 'deviceIconCurrentPreview' in html
    assert "document.body.style.overflow='hidden'" in html
    assert "event.target===this" in html
    assert '.device-icon-modal{position:fixed!important;inset:0!important' in html
    assert 'place-items:center!important' in html


def test_realistic_icon_library_and_new_types_exist():
    from app import main
    expected = {'router','switch','access-point','firewall','modem','pc','laptop','server','nas','network-storage','camera','printer','phone','voip-phone','tablet','tv','game-console','iot','patch-panel','other'}
    assert expected <= main.VALID_DEVICE_ICONS
    for key in expected:
        p = main.DEVICE_ICON_DIR / f'{key}.svg'
        assert p.exists(), key
        text = p.read_text()
        assert '<linearGradient' in text or '<radialGradient' in text
        assert 'filter id="shadow"' in text


def test_new_icon_type_inference_contracts():
    from app import main
    html = main.DASHBOARD
    for snippet in [
        "t.includes('firewall')",
        "return'firewall'",
        "t.includes('modem')",
        "return'modem'",
        "t.includes('voip')",
        "return'voip-phone'",
        "t.includes('patch panel')",
        "return'patch-panel'",
    ]:
        assert snippet in html
