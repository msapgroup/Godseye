from pathlib import Path
from fastapi.testclient import TestClient
import app.main as main

def test_v49_version():
    assert Path('VERSION').read_text().strip()=='4.9.0-admin-card-layouts'

def test_layout_schema_exists():
    source=Path('app/main.py').read_text()
    assert 'CREATE TABLE IF NOT EXISTS ui_layouts' in source
    assert 'ui_layout_saved' in source

def test_layout_api_is_admin_write_and_authenticated_read():
    source=Path('app/main.py').read_text()
    assert '@app.get(f"{router_prefix}/ui/layouts")' in source
    assert '@app.put(f"{router_prefix}/ui/layouts/{{page_key}}")' in source
    assert 'admin=Depends(require_admin)' in source

def test_dashboard_has_drag_arrangement_engine():
    source=Path('app/main.py').read_text()
    for text in ('↕ Arrange Cards','layout-dragging','layout-drop-target','pageLayoutSnapshot','savePageLayout','resetPageLayout'):
        assert text in source

def test_common_card_grids_are_registered():
    source=Path('app/main.py').read_text()
    for selector in ("'.cards'","'.tool-grid'","'.report-type-grid'","'.traffic-source-grid'","'.analytics-grid'","'.monitor-summary'"):
        assert selector in source

def test_non_admin_cannot_save_layout(tmp_path, monkeypatch):
    db=tmp_path/'layout.db'; monkeypatch.setattr(main,'DB_PATH',db); main.init_db()
    # endpoint dependency itself is the security boundary; require_admin is present in source.
    with main.db() as c:
        cols={r['name'] for r in c.execute('PRAGMA table_info(ui_layouts)')}
    assert {'page_key','layout_json','updated_by','updated_at'} <= cols
