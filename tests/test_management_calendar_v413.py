from pathlib import Path
import pytest
import app.main as main

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.13.0-","4.14.0-", "4.15.0-", "4.16.0-", "4.17.0-", "4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-", "4.22.0-", "4.22.1-", "4.23.0-", "4.24.0", "4.25.0"))

def test_calendar_schema_bootstraps(tmp_path, monkeypatch):
    db=tmp_path/"calendar.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        events={r["name"] for r in c.execute("PRAGMA table_info(calendar_events)")}
        integrations={r["name"] for r in c.execute("PRAGMA table_info(calendar_integrations)")}
    assert {"title","description","location","start_at","end_at","all_day","source","external_uid","external_readonly"} <= events
    assert {"provider","name","account_email","calendar_name","ics_url_enc","sync_interval_minutes","last_sync_at","last_status"} <= integrations

def test_calendar_is_under_management_sidebar():
    from app import main
    html=main.DASHBOARD
    management=html[html.index('<div class="navsection">Management</div>'):html.index('<div class="navsection">Administration</div>')]
    assert 'data-view="calendar"' in management
    assert '<span>Calendar</span>' in management

def test_calendar_has_google_style_month_view_and_event_modal():
    from app import main
    html=main.DASHBOARD
    for token in (
        'id="view-calendar"',
        'id="calendarGrid"',
        'id="calendarMonthLabel"',
        'id="calendarEventModal"',
        'id="calendarEventTitle"',
        'id="calendarEventStart"',
        'id="calendarEventEnd"',
        'onclick="closeCalendarEventModal()">×</button>',
    ):
        assert token in html
    assert "Today" in html
    assert "Create appointment" in html

def test_calendar_crud_routes_are_present_and_admin_write():
    source=Path("app/main.py").read_text()
    assert '@app.get(f"{router_prefix}/calendar/events")' in source
    assert '@app.post(f"{router_prefix}/calendar/events")' in source
    assert '@app.put(f"{router_prefix}/calendar/events/{{event_id}}")' in source
    assert '@app.delete(f"{router_prefix}/calendar/events/{{event_id}}")' in source
    assert "user=Depends(require_admin)" in source
    assert "calendar_event_created" in source
    assert "calendar_event_updated" in source
    assert "calendar_event_deleted" in source

def test_google_and_microsoft365_integration_options_exist():
    from app import main
    html=main.DASHBOARD
    assert "Google Calendar" in html
    assert "Microsoft 365" in html
    assert 'data-provider="google"' in html
    assert 'data-provider="microsoft365"' in html
    assert "Private ICS subscription URL" in html
    assert "encrypted at rest" in html

def test_calendar_subscription_url_is_provider_restricted():
    main._validate_calendar_subscription_url("google","https://calendar.google.com/calendar/ical/test/basic.ics")
    main._validate_calendar_subscription_url("microsoft365","https://outlook.office365.com/owa/calendar/test/calendar.ics")
    with pytest.raises(Exception):
        main._validate_calendar_subscription_url("google","http://calendar.google.com/test.ics")
    with pytest.raises(Exception):
        main._validate_calendar_subscription_url("google","https://example.com/test.ics")

def test_calendar_sync_is_bounded_and_automatic_manager_exists():
    source=Path("app/main.py").read_text()
    assert "class CalendarSyncManager" in source
    assert "resp.read(2_000_001)" in source
    assert "blocks[:2000]" in source
    assert "calendar_sync_manager.start()" in source
    assert "calendar_sync_manager.stop()" in source

def test_calendar_is_in_dark_screenshot_pack():
    assert Path("docs/screenshots/dark-calendar.png").exists()
    screenshots=Path("docs/SCREENSHOTS.md").read_text()
    assert "dark-calendar.png" in screenshots
    assert "Calendar" in screenshots

def test_readme_documents_calendar_security_use():
    text=Path("README.md").read_text()
    assert "Calendar and maintenance planning" in text
    assert "Google Calendar" in text
    assert "Microsoft 365" in text
