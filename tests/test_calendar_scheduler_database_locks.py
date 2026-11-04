"""Regression: unattended calendar synchronization must not hold a writer lock
from one remote provider while contacting the next provider.
"""
import sqlite3

from app import main


def test_calendar_scheduler_commits_each_provider_before_next(tmp_path, monkeypatch):
    database = tmp_path / "calendar-scheduler.db"
    with sqlite3.connect(database) as c:
        c.execute("""CREATE TABLE calendar_integrations (
            id INTEGER PRIMARY KEY, enabled INTEGER, last_sync_at TEXT,
            sync_interval_minutes INTEGER, last_status TEXT, last_error TEXT,
            updated_at TEXT)""")
        for n in (1, 2):
            c.execute("INSERT INTO calendar_integrations(id, enabled, sync_interval_minutes) VALUES (?,1,5)", (n,))

    def db():
        c = sqlite3.connect(database, timeout=0)
        c.row_factory = sqlite3.Row
        return c

    class OneCycle:
        count = 0
        def wait(self, _timeout):
            self.count += 1
            return self.count > 1
        def is_set(self):
            return False

    manager = main.CalendarSyncManager(db)
    manager._stop = OneCycle()
    visited = []

    def fake_sync(c, row):
        if row["id"] == 2:
            # The previous provider's writes must already be committed.
            writer = sqlite3.connect(database, timeout=0)
            try:
                writer.execute("BEGIN IMMEDIATE")
            finally:
                writer.rollback()
                writer.close()
        visited.append(row["id"])
        c.execute("UPDATE calendar_integrations SET last_status='ok' WHERE id=?", (row["id"],))

    monkeypatch.setattr(main, "_sync_calendar_integration", fake_sync)
    manager._loop()
    assert visited == [1, 2]
    with db() as c:
        assert c.execute("SELECT COUNT(*) FROM calendar_integrations WHERE last_status='ok'").fetchone()[0] == 2
