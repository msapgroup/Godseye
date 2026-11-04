"""Regression checks for unattended server background worker stability.

These tests do not access or rebuild the Windows agent.
"""
import threading
import time
from types import SimpleNamespace

from app import plugin_runner, collectors


def plugin(name, action):
    return SimpleNamespace(plugin_id=name, enabled=True, run=action, schedule_seconds=1)


def test_plugin_guard_prevents_parallel_duplicate_runs():
    runner = plugin_runner.PluginRunner(max_workers=2)
    entered = threading.Event()
    release = threading.Event()
    counter = []
    def work():
        counter.append(1)
        entered.set()
        assert release.wait(2)
    item = plugin("one", work)
    thread = threading.Thread(target=runner.run_once, args=(item,))
    thread.start()
    try:
        assert entered.wait(1)
        assert runner.run_once(item) is False
        assert len(counter) == 1
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert runner.health()["one"]["running"] is False


def test_plugin_concurrency_limit_and_release_on_failure():
    runner = plugin_runner.PluginRunner(max_workers=1)
    entered = threading.Event()
    release = threading.Event()
    def blocking():
        entered.set()
        assert release.wait(2)
    first = plugin("busy", blocking)
    other = plugin("other", lambda: None)
    thread = threading.Thread(target=runner.run_once, args=(first,))
    thread.start()
    try:
        assert entered.wait(1)
        assert runner.run_once(other) is False
    finally:
        release.set()
        thread.join(timeout=2)
    assert runner.run_once(other) is True
    def error():
        raise RuntimeError("test failure")
    assert runner.run_once(plugin("bad", error)) is False
    assert runner.run_once(other) is True
    assert runner.health()["bad"]["last_error"] == "test failure"


def test_collectors_do_not_duplicate_running_monitor_threads(monkeypatch):
    manager = collectors.CollectorManager(lambda: None, lambda: "")
    monkeypatch.setattr(manager, "_loop", lambda: manager.stop_event.wait(2))
    first = manager.start()
    try:
        assert manager.start() is first
    finally:
        manager.stop()
    assert not first.is_alive()


def test_invalid_monitor_options_are_recorded_as_down(monkeypatch):
    class ResultDb:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, *_args):
            return self
    manager = collectors.CollectorManager(lambda: ResultDb(), lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(collectors, "ensure_schema", lambda _: None)
    monkeypatch.setattr(collectors, "monitor_result_findings", lambda *_: None, raising=False)
    # A malformed saved JSON configuration must not throw before _run's handler.
    monkeypatch.setattr(__import__("app.remediation", fromlist=["monitor_result_findings"]),
                        "monitor_result_findings", lambda *_: None)
    result = manager._run({"name": "bad", "kind": "website", "target": "example.com", "options_json": "{broken"})
    assert result["status"] == "down"
