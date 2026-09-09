from pathlib import Path


def test_sidebar_navigation_uses_delegated_handler():
    source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
    # Sidebar navigation must not depend on fragile inline onclick handlers.
    sidebar = source.split('<nav class="sidebar">', 1)[1].split('</nav>', 1)[0]
    assert 'onclick="showView(' not in sidebar
    assert 'data-view="overview"' in sidebar
    assert 'data-view="tools"' in sidebar
    assert 'data-view="audit"' in sidebar
    assert 'nav.addEventListener(\'click\'' in source
    assert 'window.showView=showView' in source
    assert "target.style.display='block'" in source
