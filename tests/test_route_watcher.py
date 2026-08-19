import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import route_watcher as w


class RouteWatcherTests(unittest.TestCase):
    def test_parse_ansi_target_and_client_lines(self):
        target = w.parse_line(
            "\x1b[36mINFO\x1b[0m[0020] inbound/mixed[local-proxy]: "
            "inbound connection to opencode.ai:443"
        )
        self.assertIsNotNone(target)
        assert target is not None
        self.assertEqual(target["kind"], "target")
        self.assertEqual(target["host"], "opencode.ai")
        self.assertFalse(target["failure"])

        client = w.parse_line(
            "INFO inbound/mixed[local-proxy]: inbound connection from 127.0.0.1:55180"
        )
        self.assertEqual(client, {
            "kind": "client",
            "source": "127.0.0.1",
            "line": "INFO inbound/mixed[local-proxy]: inbound connection from 127.0.0.1:55180",
        })

    def test_parse_transport_failure(self):
        event = w.parse_line(
            "ERROR connection: open connection to opencode.ai:443: "
            "TLS handshake timeout"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["host"], "opencode.ai")
        self.assertTrue(event["failure"])

    def test_guard_requires_two_failures_and_cooldown(self):
        guard = w.RotationGuard()
        self.assertFalse(guard.record_transport_failure(100.0))
        self.assertTrue(guard.record_transport_failure(101.0))
        self.assertFalse(guard.record_transport_failure(102.0))
        self.assertFalse(guard.record_transport_failure(222.0))
        self.assertTrue(guard.record_transport_failure(223.0))

    def test_guard_discards_old_failures(self):
        guard = w.RotationGuard()
        self.assertFalse(guard.record_transport_failure(100.0))
        self.assertFalse(guard.record_transport_failure(161.0))

    def test_probe_http_failure_is_not_transport_failure(self):
        def fake_runner(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="503", stderr="")

        result = w.probe_target(Path("/tmp"), "opencode.ai", runner=fake_runner)
        self.assertFalse(result["transport_failure"])
        self.assertEqual(result["status"], 503)
        self.assertTrue(result["ok"])

    def test_probe_transport_failure_is_rotation_signal(self):
        def fake_runner(*args, **kwargs):
            return SimpleNamespace(returncode=35, stdout="000", stderr="SSL_ERROR_SYSCALL")

        result = w.probe_target(Path("/tmp"), "opencode.ai", runner=fake_runner)
        self.assertTrue(result["transport_failure"])
        self.assertFalse(result["ok"])

    def test_start_redirects_worker_stderr_to_worker_log(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        captured: dict = {}

        def fake_popen(command, **kwargs):
            captured["stderr"] = kwargs.get("stderr")
            return SimpleNamespace(pid=4242)

        with mock.patch.object(w.subprocess, "Popen", side_effect=fake_popen):
            result = w.start(root)
        self.assertTrue(result["started"])
        log = w.worker_log_file(root)
        self.assertTrue(log.is_file())
        self.assertEqual(result["log"], str(log))
        self.assertEqual(captured["stderr"].name, str(log), "worker stderr must ride worker.log")

    def test_worker_exits_after_engine_down_grace(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with mock.patch.object(w, "engine_pid_alive", return_value=False):
            rc = w.worker(root, interval=0.05, sleep=lambda _: None)
        self.assertEqual(rc, 0)
        self.assertFalse(w.enabled_file(root).exists(), "worker must clean up its markers")
        self.assertFalse(w.pid_file(root).exists())

    def test_worker_keeps_running_while_engine_alive(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        ticks = 0

        def fake_sleep(_):
            nonlocal ticks
            ticks += 1
            if ticks >= 3:
                w.enabled_file(root).unlink(missing_ok=True)

        with mock.patch.object(w, "engine_pid_alive", return_value=True):
            rc = w.worker(root, interval=0.05, sleep=fake_sleep)
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(ticks, 3)

    def test_worker_sigterm_self_cleans_markers_after_exit(self):
        """AC4: a SIGTERM'd worker exits through its finally and removes its
        own markers; nobody has to unlink state under a live process."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        # Give the worker a live engine pid so it does NOT hit the
        # ENGINE_DOWN_GRACE exit and self-terminate before we SIGTERM it.
        (root / "sing-box.pid").write_text(str(os.getpid()))
        started = w.start(root, interval=0.05)
        self.assertTrue(started["started"])
        pid = started["pid"]
        self.assertTrue(w._pid_running(pid, root))
        # The signal handler is installed at the very top of worker(); give the
        # child a moment to boot before signaling, otherwise SIGTERM hits the
        # default disposition and the process dies without running its finally.
        time.sleep(0.3)

        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 5
        while time.time() < deadline and w._pid_running(pid, root):
            time.sleep(0.02)
        self.assertFalse(w._pid_running(pid, root), "worker must exit on SIGTERM")
        self.assertFalse(w.pid_file(root).exists(), "worker must clean pid marker")
        self.assertFalse(w.enabled_file(root).exists(), "worker must clean enabled marker")

    def test_stop_waits_for_exit_and_cleans_only_after_confirmed(self):
        """AC3+AC4: stop() is synchronous - it signals, waits for the worker to
        actually exit, and removes markers only after that exit is confirmed."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "sing-box.pid").write_text(str(os.getpid()))
        started = w.start(root, interval=0.05)
        self.assertTrue(started["started"])
        pid = started["pid"]

        result = w.stop(root)
        self.assertTrue(result["stopped"])
        self.assertFalse(w._pid_running(pid, root), "worker must be gone after stop")
        self.assertFalse(w.pid_file(root).exists())
        self.assertFalse(w.enabled_file(root).exists())

    def test_stop_never_signals_foreign_pid(self):
        """AC3: a stale/foreign pid file must never cause signal delivery to an
        unrelated process; stale markers are still cleaned up."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        victim = subprocess.Popen(["sleep", "30"])
        self.addCleanup(victim.kill)
        (root / "sing-box.pid").write_text(str(victim.pid))
        w.pid_file(root).parent.mkdir(parents=True, exist_ok=True)
        w.pid_file(root).write_text(str(victim.pid))
        w.enabled_file(root).write_text("enabled\n")

        result = w.stop(root)
        self.assertTrue(result["stopped"])
        self.assertEqual(victim.poll(), None, "foreign process must survive stop()")
        self.assertFalse(w.pid_file(root).exists(), "stale markers are removed")
        self.assertFalse(w.enabled_file(root).exists())

    def test_router_port_falls_back_to_2080(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.assertEqual(w.router_port(root), 2080)

    def test_router_port_reads_custom_port(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "router.json").write_text(json.dumps({"port": 2081}))
        self.assertEqual(w.router_port(root), 2081)

    def test_client_snapshot_uses_configured_port(self):
        """AC6: client_snapshot must probe the configured listener port, not a
        hardcoded 2080."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "router.json").write_text(json.dumps({"port": 2081}))
        captured: dict = {}

        def fake_runner(args, **kwargs):
            captured["args"] = args
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(w.sys, "platform", "darwin"):
            w.client_snapshot(root, runner=fake_runner)
        self.assertIn("-iTCP:2081", captured["args"], f"args: {captured['args']}")

    def test_probe_target_uses_configured_port(self):
        """AC6: probe_target must route through the configured port."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "router.json").write_text(json.dumps({"port": 2081}))
        captured: dict = {}

        def fake_runner(args, **kwargs):
            captured["args"] = args
            return SimpleNamespace(returncode=0, stdout="200", stderr="")

        result = w.probe_target(root, "opencode.ai", runner=fake_runner)
        self.assertTrue(result["ok"])
        self.assertIn("--proxy", captured["args"])
        self.assertIn("http://127.0.0.1:2081", captured["args"])

    def test_append_event_hands_ownership_back_to_sudo_user(self):
        """AC5: a root-owned worker hands fresh event files back to the user
        that elevated it, instead of stranding a 0600 root file."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        chowned: list[tuple] = []

        with mock.patch.object(os, "geteuid", return_value=0), \
             mock.patch.dict(os.environ, {"SUDO_UID": "501", "SUDO_GID": "20"}), \
             mock.patch.object(os, "chown", side_effect=lambda path, uid, gid: chowned.append((path, uid, gid))):
            w.append_event(root, {"kind": "probe", "host": "opencode.ai"})
        self.assertEqual(len(chowned), 1)
        path, uid, gid = chowned[0]
        self.assertEqual(str(path), str(w.events_file(root)))
        self.assertEqual(uid, 501)
        self.assertEqual(gid, 20)

    def test_append_event_does_not_touch_ownership_as_user(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with mock.patch.object(os, "geteuid", return_value=501), \
             mock.patch.object(os, "chown", side_effect=AssertionError("must not chown as user")):
            w.append_event(root, {"kind": "probe", "host": "opencode.ai"})
        self.assertTrue(w.events_file(root).is_file())


class EngineEnsureManualOffTests(unittest.TestCase):
    """AC1: manual-off is quiescent, not healthy - ensure must report a
    distinct code so supervisors stop maintenance instead of probing a
    deliberately disconnected tunnel."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "state").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_marker(self):
        (self.root / "state" / "manual-off").write_text("manual stop\n")

    def test_ensure_returns_quiescent_code_under_manual_off(self):
        import router as r
        # Patch module paths like the router test suite does.
        r.ROOT = self.root.resolve()
        r.MANUAL_OFF_FILE = self.root / "state" / "manual-off"
        self._write_marker()
        self.assertEqual(r.engine_ensure(), 3,
                         "manual-off must read as quiescent (3), not healthy (0)")


if __name__ == "__main__":
    unittest.main()
