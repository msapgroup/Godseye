from pathlib import Path

def test_v44_version():
    assert Path("VERSION").read_text().strip().startswith(("4.4.0-","4.5.0-", "4.6.0-", "4.7.0-", "4.8.0-"))

def test_prometheus_link_removed_from_integrations_screen():
    from app import main
    html=main.DASHBOARD
    start=html.index('id="view-integrations"')
    end=html.find('id="view-reports"', start)
    integrations=html[start:end]
    assert "Prometheus Metrics" not in integrations
    assert 'href="/metrics"' not in integrations
    assert "+ Add Integration" in integrations

def test_metrics_endpoint_backend_is_retained():
    source=Path("app/main.py").read_text()
    assert '@app.get("/metrics"' in source or '@app.get(f"{router_prefix}/metrics"' in source or 'def metrics' in source

def test_analytics_metric_and_subtext_use_pihole_blue():
    source=Path("app/main.py").read_text()
    assert '.analytics-card .metric{font-size:24px;font-weight:800;color:#1872d7}' in source
    assert '.analytics-card .sub{font-size:10px;color:#1872d7' in source
    assert 'html[data-theme="dark"] .analytics-card .metric' in source
    assert 'html[data-theme="dark"] .analytics-card .sub{color:#9cc9f5!important}' in source
