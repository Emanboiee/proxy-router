"""F14: shared worker start/stop serialization for the background workers."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import worker_lock


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class WorkerLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_lock_serializes_two_holders(self):
        lock_path = self.root / "state" / "x.lock"
        with worker_lock.exclusive(lock_path):
            with self.assertRaises(TimeoutError):
                with worker_lock.exclusive(lock_path, timeout=0.15):
                    pass
        with worker_lock.exclusive(lock_path, timeout=0.15):
            pass

    def test_lock_file_persists_after_release(self):
        lock_path = self.root / "state" / "y.lock"
        with worker_lock.exclusive(lock_path):
            pass
        self.assertTrue(lock_path.exists())


class ConcurrentStartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _race(self, launch, count=2):
        results = {}

        def worker(name):
            results[name] = launch()

        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def test_monitor_concurrent_starts_spawn_one_worker(self):
        monitor = _load("monitor")
        spawned = []

        def slow_popen(*args, **kwargs):
            time.sleep(0.25)
            spawned.append(4242)
            return SimpleNamespace(pid=4242)

        def fake_running(pid, root=None):
            return monitor.pid_file(root if root is not None else self.root).is_file()

        with mock.patch.object(monitor.subprocess, "Popen", side_effect=slow_popen), \
             mock.patch.object(monitor, "_pid_running", side_effect=fake_running), \
             mock.patch.object(monitor, "_monitor_settings",
                               return_value={"interval_seconds": 60}):
            results = self._race(lambda: monitor.start(self.root))
        self.assertEqual(len(spawned), 1, results)
        self.assertEqual(len([r for r in results.values() if r.get("started")]), 1, results)
        others = [r for r in results.values() if not r.get("started")]
        self.assertTrue(all(r.get("already_running") or r.get("error") for r in others), results)

    def test_watcher_concurrent_starts_spawn_one_worker(self):
        watcher = _load("route_watcher")
        spawned = []

        def slow_popen(*args, **kwargs):
            time.sleep(0.25)
            spawned.append(4242)
            return SimpleNamespace(pid=4242)

        def fake_status(root, **kwargs):
            running = watcher.pid_file(root).is_file()
            return {"running": running, "enabled": running, "pid": 4242 if running else None}

        with mock.patch.object(watcher.subprocess, "Popen", side_effect=slow_popen), \
             mock.patch.object(watcher, "status", side_effect=fake_status):
            results = self._race(lambda: watcher.start(self.root))
        self.assertEqual(len(spawned), 1, results)
        self.assertEqual(len([r for r in results.values() if r.get("started")]), 1, results)


class MonitorStopConfirmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_stop_confirms_exit_and_clears_markers(self):
        monitor = _load("monitor")
        monitor.monitor_dir(self.root).mkdir(parents=True, exist_ok=True)
        monitor.pid_file(self.root).write_text("4242")
        monitor.enabled_file(self.root).write_text("enabled\n")
        alive = {"value": True}

        def running(pid, root=None):
            return alive["value"]

        def terminate(pid, sig):
            alive["value"] = False

        with mock.patch.object(monitor, "_pid_running", side_effect=running), \
             mock.patch.object(monitor.os, "kill", side_effect=terminate):
            result = monitor.stop(self.root)

        self.assertTrue(result["stopped"])
        self.assertTrue(result["confirmed"])
        self.assertFalse(monitor.pid_file(self.root).exists())
        self.assertFalse(monitor.enabled_file(self.root).exists())

    def test_stop_reports_unconfirmed_when_worker_survives(self):
        monitor = _load("monitor")
        monitor.monitor_dir(self.root).mkdir(parents=True, exist_ok=True)
        monitor.pid_file(self.root).write_text("4242")
        monitor.enabled_file(self.root).write_text("enabled\n")
        with mock.patch.object(monitor, "_pid_running", return_value=True), \
             mock.patch.object(monitor, "STOP_CONFIRM_SECONDS", 0.1), \
             mock.patch.object(monitor.os, "kill"):
            result = monitor.stop(self.root)
        self.assertTrue(result["stopped"])
        self.assertFalse(result["confirmed"])


if __name__ == "__main__":
    unittest.main()
