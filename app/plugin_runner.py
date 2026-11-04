"""Bounded native plugin scheduler for GODSEYE.

A plugin is reserved under a lock before launching its worker. This prevents
duplicate background jobs and keeps a malfunctioning plugin from spawning an
unbounded number of threads during unattended operation.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .plugins import Plugin, enabled_plugins

log = logging.getLogger("godseye.plugin_runner")


@dataclass
class PluginState:
    last_run: float | None = None
    last_success: float | None = None
    last_error: str | None = None
    running: bool = False


class PluginRunner:
    def __init__(self, max_workers: int = 4):
        self.states: dict[str, PluginState] = {}
        self._stop = threading.Event()
        self._guard = threading.Lock()
        self._capacity = threading.BoundedSemaphore(max(1, min(int(max_workers), 16)))
        self._thread: threading.Thread | None = None

    def _reserve(self, plugin: Plugin) -> bool:
        if not plugin.run or not plugin.enabled:
            return False
        with self._guard:
            state = self.states.setdefault(plugin.plugin_id, PluginState())
            if state.running or not self._capacity.acquire(blocking=False):
                return False
            state.running = True
            state.last_run = time.time()
            return True

    def _execute(self, plugin: Plugin) -> bool:
        success = False
        try:
            plugin.run()
            with self._guard:
                state = self.states[plugin.plugin_id]
                state.last_success = time.time()
                state.last_error = None
            success = True
        except Exception as exc:
            with self._guard:
                self.states[plugin.plugin_id].last_error = str(exc)
            log.exception("GODSEYE plugin %s failed", plugin.plugin_id)
        finally:
            with self._guard:
                self.states[plugin.plugin_id].running = False
            self._capacity.release()
        return success

    def run_once(self, plugin: Plugin):
        if not self._reserve(plugin):
            return False
        return self._execute(plugin)

    def run_forever(self, tick_seconds: int = 5):
        while not self._stop.wait(max(1, int(tick_seconds))):
            try:
                now = time.time()
                for plugin in enabled_plugins():
                    if self._stop.is_set():
                        break
                    if plugin.schedule_seconds is None:
                        continue
                    with self._guard:
                        state = self.states.get(plugin.plugin_id)
                        due = state is None or state.last_run is None or now - state.last_run >= plugin.schedule_seconds
                    if not due or not self._reserve(plugin):
                        continue
                    try:
                        threading.Thread(target=self._execute, args=(plugin,),
                                         name=f"godseye-plugin-{plugin.plugin_id}"[:64],
                                         daemon=True).start()
                    except Exception:
                        with self._guard:
                            self.states[plugin.plugin_id].running = False
                        self._capacity.release()
                        log.exception("Could not start GODSEYE plugin %s", plugin.plugin_id)
            except Exception:
                log.exception("GODSEYE plugin scheduler failed; retrying next tick")

    def start(self):
        if self._thread and self._thread.is_alive():
            return self._thread
        self._stop.clear()
        self._thread = threading.Thread(target=self.run_forever, name="godseye-plugins", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def health(self):
        with self._guard:
            return {k: vars(v).copy() for k, v in self.states.items()}
