from pathlib import Path

def _hex_rgb(value):
    value=value.lstrip('#')
    return tuple(int(value[i:i+2],16)/255 for i in (0,2,4))

def _luminance(value):
    def linear(c):
        return c/12.92 if c <= .04045 else ((c+.055)/1.055)**2.4
    r,g,b=_hex_rgb(value)
    return .2126*linear(r)+.7152*linear(g)+.0722*linear(b)

def _contrast(fg,bg):
    a,b=sorted((_luminance(fg),_luminance(bg)),reverse=True)
    return (a+.05)/(b+.05)

def test_v40_version():
    assert Path('VERSION').read_text().strip()=='4.0.0-dark-mode'

def test_dark_mode_toggle_and_persistence_present():
    from app import main
    html=main.DASHBOARD
    assert 'id="themeToggle"' in html
    assert 'function toggleTheme()' in html
    assert 'function initializeTheme()' in html
    assert "localStorage.getItem('godseye_theme')" in html
    assert "localStorage.setItem('godseye_theme',next)" in html
    assert 'prefers-color-scheme: dark' in html

def test_dark_theme_covers_core_surfaces():
    source=Path('app/main.py').read_text()
    required=(
        '[data-theme="dark"] body',
        '[data-theme="dark"] .headerbar',
        '[data-theme="dark"] .panel',
        '[data-theme="dark"] table',
        '[data-theme="dark"] input',
        '[data-theme="dark"] .modal-card',
        '[data-theme="dark"] .traffic-source-card',
        '[data-theme="dark"] .traffic-config-card',
        '[data-theme="dark"] #reportSummary',
    )
    for token in required:
        assert token in source

def test_dark_mode_representative_text_contrast():
    pairs={
        'body':('#dce6f2','#0b1119'),
        'heading':('#eef5fc','#111a25'),
        'muted':('#91a2b7','#111a25'),
        'form_text':('#e6eef7','#0d1621'),
        'source_name':('#e2ecf6','#0f1823'),
        'source_description':('#90a2b7','#0f1823'),
        'help_copy':('#9aacbf','#0e1722'),
        'table_text':('#d6e1ec','#111a25'),
        'blue_link':('#6ab0ff','#111a25'),
    }
    for name,(fg,bg) in pairs.items():
        assert _contrast(fg,bg) >= 4.5, (name,_contrast(fg,bg))

def test_status_colors_are_readable():
    pairs={
        'success':('#73d3a6','#10271d'),
        'failure':('#ff8596','#2a1419'),
        'waiting':('#f2c95d','#2a2413'),
    }
    for name,(fg,bg) in pairs.items():
        assert _contrast(fg,bg) >= 4.5, (name,_contrast(fg,bg))

def test_each_traffic_mode_is_its_own_defined_card():
    from app import main
    html=main.DASHBOARD
    for mode in ('unifi','snmp','span','inline'):
        assert f'class="traffic-source-card" data-traffic-mode="{mode}"' in html
    assert html.count('class="traffic-source-kind"')==4
    assert html.count('class="traffic-source-divider"')==4
    assert html.count('class="traffic-source-meta"')==4
    assert html.count('class="traffic-source-foot"')==4
    assert 'Recommended' in html
    assert html.count('Advanced') >= 2
