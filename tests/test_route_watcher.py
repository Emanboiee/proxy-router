import os
import shutil
import tempfile
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


if __name__ == "__main__":
    unittest.main()
