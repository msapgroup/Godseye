from urllib.parse import parse_qs, urlparse
import json

from app import event_ticketing
from app import main


def test_defrag_event_has_specific_actions_and_official_guidance():
    event = {
        "computer_name": "WORKSTATION1",
        "provider": "Microsoft-Windows-Defrag",
        "event_id": 264,
        "level": "Error",
        "message": "The storage optimizer could not complete re-trim.",
    }
    fix = event_ticketing.classify_windows_event(event)
    assert fix["category"] == "Storage Optimization"
    assert any("volume" in action.lower() for action in fix["actions"])
    links = event_ticketing.trusted_event_fix_links({**fix, **event})
    assert links[0]["url"].startswith("https://learn.microsoft.com/")
    assert "Optimize-Volume" in links[0]["label"]
    search = parse_qs(urlparse(links[1]["url"]).query)["q"][0]
    assert "Microsoft-Windows-Defrag" in search and "Event 264" in search
    assert "WORKSTATION1" not in search and "storage optimizer" not in search


def test_service_timeout_and_unknown_event_guidance():
    event = {"provider": "Service Control Manager", "event_id": 7009, "level": "Error"}
    fix = event_ticketing.classify_windows_event(event)
    assert fix["category"] == "Service"
    assert "time-out-error" in event_ticketing.trusted_event_fix_links({**fix, **event})[0]["url"]
    unknown = event_ticketing.trusted_event_fix_links({"category": "Windows", "provider": "Third Party", "event_id": 43})
    assert len(unknown) == 1 and "site:learn.microsoft.com" in parse_qs(urlparse(unknown[0]["url"]).query)["q"][0]


def test_event_finding_table_opens_readable_fix_links():
    html = main.DASHBOARD
    assert 'onclick="openEventFinding(${x.id},true)">Suggested Fix' in html
    assert 'id="eventFindingSuggestedFix"' in html
    assert 'rel="noopener noreferrer"' in html


def test_existing_defrag_finding_shows_new_fix_without_new_event():
    old = {
        "id": 5, "event_id": 264, "provider": "Microsoft-Windows-Defrag",
        "computer_name": "PC01", "category": "Windows", "title": "Microsoft-Windows-Defrag Event 264",
        "recommendation": "Review Windows event details", "suggested_actions_json": json.dumps(["Old generic step"]),
    }
    current = main._event_finding_public(old)
    assert current["category"] == "Storage Optimization"
    assert "volume" in current["suggested_actions"][0].lower()
    assert current["trusted_fix_links"][0]["source"] == "Microsoft Learn"
