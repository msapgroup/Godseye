
def test_dashboard_summary_cards_are_clickable_and_returnable():
    from app import main
    html = main.DASHBOARD
    for target in ["devices", "online", "issues", "monitors"]:
        assert f"openDashboardSummary('{target}')" in html
    assert "function backToDashboard()" in html
    assert "← Back to Dashboard" in html
    assert "data-dashboard-return" in html
    assert "if(status)status.value='online'" in html


def test_network_map_has_polished_interactive_controls():
    from app import main
    html = main.DASHBOARD
    for element_id in [
        "mapGateway", "mapNodes", "mapLinks", "mapUpdated", "mapSearch",
        "networkViewport", "networkStage", "networkCanvas", "mapEvidence",
    ]:
        assert f'id="{element_id}"' in html
    for function_name in ["filterMapNodes", "zoomNetwork", "fitNetworkMap", "loadNetwork"]:
        assert f"function {function_name}" in html or f"async function {function_name}" in html
    assert "device-clickable" in html
    assert "goDevice(${Number(n.device_id)})" in html
    assert "Evidence sources:" in html
