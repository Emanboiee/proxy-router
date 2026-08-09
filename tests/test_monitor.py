"""Tests for the opt-in monitor; no network or real daemons."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import monitor


class FakeResponse:
    def __init__(self, payload=b"ok", status=200):
        self.payload = payload
        self.status = status
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        self.read_sizes.append(size)
        if size is None or size < 0:
            size = len(self.payload)
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk


class PingParsingTests(unittest.TestCase):
    def test_macos_ping_summary(self):
        result = monitor.parse_ping_output(
            "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
            "round-trip min/avg/max/stddev = 12.100/18.200/24.300/4.900 ms\n"
        )
        self.assertEqual(result["avg_ms"], 18.2)
        self.assertEqual(result["min_ms"], 12.1)
        self.assertEqual(result["max_ms"], 24.3)

    def test_unavailable_ping_is_explicit(self):
        result = monitor.parse_ping_output("ping: cannot resolve host")
        self.assertIsNone(result["avg_ms"])
        self.assertIn("error", result)


class ProbeTests(unittest.TestCase):
    def test_http_latency_uses_injected_opener(self):
        response = FakeResponse(b"x")
        clock = iter([10.0, 10.125])
        opened = []

        def opener(url, timeout):
            opened.append((url, timeout))
            return response

        result = monitor.measure_http_latency(
            "https://example.invalid", opener=opener, clock=lambda: next(clock), timeout=3
        )
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["target"], "example.invalid")
        self.assertEqual(result["latency_ms"], 125.0)
        self.assertEqual(opened, [("https://example.invalid", 3)])

    def test_download_is_bounded(self):
        response = FakeResponse(b"x" * 100)
        result = monitor.measure_download(
            "https://example.invalid", max_bytes=16, opener=lambda url, timeout: response,
            clock=iter([1.0, 1.1]).__next__, timeout=2,
        )
        self.assertEqual(result["bytes"], 16)
        self.assertTrue(all(size <= 16 for size in response.read_sizes if size >= 0))

    def test_upload_is_bounded(self):
        captured = {}
        response = FakeResponse(b"")

        def opener(request, timeout):
            captured["data"] = request.data
            return response

        result = monitor.measure_upload(
            "https://example.invalid", max_bytes=32, opener=opener,
            clock=iter([1.0, 1.2]).__next__, timeout=2,
        )
        self.assertEqual(result["bytes"], 32)
        self.assertEqual(len(captured["data"]), 32)

    def test_network_errors_redact_credential_bearing_url(self):
        url = "https://user:secret@example.invalid/check?token=super-secret"

        def opener(request_url, timeout):
            raise RuntimeError(f"request failed for {request_url}")

        result = monitor.measure_http_latency(url, opener=opener)
        self.assertNotIn("secret", result["error"])
        self.assertNotIn(url, result["error"])
        self.assertEqual(result["target"], "example.invalid")

    def test_worker_pid_identity_requires_monitor_worker_command(self):
        root = Path("/tmp/proxy-router-monitor")
        good = subprocess.CompletedProcess(
            [], 0, stdout=f"python monitor.py --worker --root {root.resolve()} --interval 60\n", stderr=""
        )
        with mock.patch.object(monitor.subprocess, "run", return_value=good):
            self.assertTrue(monitor._pid_matches(1234, root))
        bad = subprocess.CompletedProcess([], 0, stdout="python unrelated.py --root /tmp/proxy-router-monitor\n", stderr="")
        with mock.patch.object(monitor.subprocess, "run", return_value=bad):
            self.assertFalse(monitor._pid_matches(1234, root))

    def test_worker_command_is_explicit_and_detached(self):
        command = monitor.worker_command(Path("/tmp/router"), 77)
        self.assertIn("--worker", command)
        self.assertIn("--interval", command)
        self.assertIn("77", command)
        self.assertIn("/tmp/router", command)

    def test_malformed_monitor_settings_fall_back_to_safe_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({
                "monitor": {
                    "http_url": "file:///etc/passwd",
                    "download_url": 123,
                    "interval_seconds": "bad",
                    "ping_hosts": "1.1.1.1",
                }
            }))
            settings = monitor._monitor_settings(root)
        self.assertEqual(settings["http_url"], monitor.DEFAULT_HTTP_URL)
        self.assertEqual(settings["download_url"], monitor.DEFAULT_DOWNLOAD_URL)
        self.assertEqual(settings["interval_seconds"], monitor.DEFAULT_INTERVAL)
        self.assertEqual(settings["ping_hosts"], list(monitor.DEFAULT_PING_HOSTS))


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_does_not_probe_when_disabled(self):
        with mock.patch.object(monitor, "collect_sample", side_effect=AssertionError("probed")):
            result = monitor.status(self.root, pid_checker=lambda pid: True)
        self.assertFalse(result["enabled"])
        self.assertFalse(result["running"])

    def test_start_writes_private_state_and_builds_worker(self):
        proc = mock.Mock(pid=4321)
        with mock.patch.object(monitor.subprocess, "Popen", return_value=proc) as popen:
            result = monitor.start(self.root, interval=77)
        self.assertTrue(result["started"])
        self.assertEqual((self.root / "state" / "monitor" / "pid").read_text(), "4321")
        self.assertEqual(stat.S_IMODE((self.root / "state" / "monitor" / "pid").stat().st_mode), 0o600)
        self.assertTrue((self.root / "state" / "monitor" / "enabled").exists())
        command = popen.call_args.args[0]
        self.assertIn("--worker", command)

    def test_stop_does_not_signal_unowned_pid(self):
        path = monitor.pid_file(self.root)
        path.parent.mkdir(parents=True)
        path.write_text("4321")
        monitor.enabled_file(self.root).touch()
        with mock.patch.object(monitor, "_pid_running", return_value=False), \
             mock.patch.object(monitor.os, "kill") as kill:
            monitor.stop(self.root)
        kill.assert_not_called()
        self.assertFalse(path.exists())

    def test_logs_tail_is_bounded(self):
        path = self.root / "state" / "monitor" / "samples.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text("\n".join(json.dumps({"n": i}) for i in range(5)) + "\n")
        text = monitor.tail_logs(self.root, lines=2)
        self.assertEqual([json.loads(line)["n"] for line in text.splitlines()], [3, 4])


if __name__ == "__main__":
    unittest.main()
