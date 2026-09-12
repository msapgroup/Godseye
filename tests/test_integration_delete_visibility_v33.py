from pathlib import Path


def test_v33_version():
    assert Path('VERSION').read_text().strip().startswith(('3.3.0-', '3.4.0-', '3.5.0-', '3.6.0-', '3.7.0-', '3.8.0-', '3.9.0-', '4.0.0-'))


def test_dynamic_integration_actions_reapply_admin_visibility():
    from app import main
    html = main.DASHBOARD
    assert "function applyRoleVisibility()" in html
    start = html.index("async function loadIntegrations()")
    end = html.index("function updateIntegrationFields()", start)
    block = html[start:end]
    assert "integrationList.innerHTML" in block
    assert "applyRoleVisibility();" in block
    assert block.index("integrationList.innerHTML") < block.index("applyRoleVisibility();")


def test_remove_button_and_admin_guard_are_present():
    from app import main
    html = main.DASHBOARD
    assert 'class="integration-remove admin-only"' in html
    assert 'onclick="openDeleteIntegrationModal(${c.id})"' in html
    assert "ME.role==='admin'" in html
