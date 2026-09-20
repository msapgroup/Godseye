from pathlib import Path


SOURCE = Path("app/main.py").read_text(encoding="utf-8")


def test_shared_header_matches_reference_structure():
    assert 'class="headerbar v430-header"' in SOURCE
    assert 'id="v430PageTitle"' in SOURCE
    assert 'id="globalSearch"' in SOURCE
    assert '.v430-global-search{position:absolute!important;left:50%!important' in SOURCE
    assert 'html[data-theme="dark"] .view>.hero{display:grid!important' in SOURCE


def test_page_subtitles_remain_visible_and_layout_controls_are_out_of_hero():
    assert "if(!container.classList.contains('hero'))n.style.display='none';" in SOURCE
    assert "if(container.classList.contains('hero')){container.dataset.headerHelpReady='1';return}" in SOURCE
    assert 'Reorder Page' in SOURCE
    assert 'Reorder Sidebar' in SOURCE
    assert 'view.querySelectorAll(\':scope > .hero > .layout-admin-tools\').forEach(node=>node.remove());' in SOURCE


def test_direct_navigation_returns_to_top_of_page():
    assert "if(updateHash)window.scrollTo(0,0);" in SOURCE
