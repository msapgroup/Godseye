from pathlib import Path
import re
import app.main as main

def test_version():
    assert Path("VERSION").read_text().strip()=="4.15.0-calendar-date-dblclick"

def test_calendar_days_expose_dblclick_data_date():
    source=Path("app/main.py").read_text()
    assert 'data-calendar-date="${createAt}"' in source
    assert 'title="Double-click to create an appointment"' in source
    assert "new Date(day.getFullYear(),day.getMonth(),day.getDate(),9,0)" in source

def test_delegated_double_click_opens_create_modal():
    source=Path("app/main.py").read_text()
    assert "function installCalendarDateInteractions()" in source
    assert "grid.addEventListener('dblclick'" in source
    assert "openCalendarEventModal(null,day.dataset.calendarDate)" in source
    assert "installCalendarDateInteractions();" in source

def test_event_double_click_does_not_create_second_event():
    source=Path("app/main.py").read_text()
    assert "if(e.target.closest('.calendar-event-chip'))return;" in source
    assert 'ondblclick="event.stopPropagation();openCalendarEventModal(${e.id})"' in source

def test_past_dates_are_not_blocked():
    source=Path("app/main.py").read_text()
    dblclick_section=source[source.index("function installCalendarDateInteractions"):source.index("function toggleCalendarSource")]
    assert "new Date()" not in dblclick_section
    assert "past" not in dblclick_section.lower()
    assert "disabled" not in dblclick_section.lower()

def test_calendar_modal_defaults_selected_date_to_9am_and_one_hour():
    source=Path("app/main.py").read_text()
    assert "new Date(day.getFullYear(),day.getMonth(),day.getDate(),9,0)" in source
    assert "new Date(start.getTime()+60*60*1000)" in source

def test_existing_event_click_still_opens_edit():
    source=Path("app/main.py").read_text()
    assert 'onclick="event.stopPropagation();openCalendarEventModal(${e.id})"' in source

def test_dark_calendar_interaction_styles_exist():
    source=Path("app/main.py").read_text()
    assert ".calendar-day:hover" in source
    assert 'html[data-theme="dark"] .calendar-day:hover' in source
