from pathlib import Path


def test_sidebar_navigation_has_one_authoritative_router():
    source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
    sidebar = source.split('<nav class="sidebar">', 1)[1].split('</nav>', 1)[0]

    # Sidebar navigation must use the delegated router, not fragile inline
    # handlers or a later reassignment that silently replaces the router.
    assert 'onclick="showView(' not in sidebar
    for view in (
        "overview", "devices", "network", "monitoring", "findings", "tools",
        "integrations", "reports", "health", "security", "rules", "users", "audit",
    ):
        assert f'data-view="{view}"' in sidebar
        assert f'id="view-{view}"' in source

    assert "nav.addEventListener('click'" in source
    assert "window.showView=showView" in source
    assert "target.style.display='block'" in source
    assert source.count("function showView(") == 1
    assert "showView=function" not in source
    assert "originalShowView" not in source


def test_devices_route_loads_inventory_table():
    source = (Path(__file__).parents[1] / "app" / "main.py").read_text()
    assert "devices:()=>loadInventory()" in source
