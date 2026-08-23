"""Tests for the opt-in monitor; no network or real daemons."""
import ipaddress
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.request
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


class ValidatedTargetTests(unittest.TestCase):
    """Issue #64: monitor URLs are validated — no SSRF to loopback/LAN/
    link-local/metadata, no non-http schemes (arbitrary file reads), and
    resolved addresses re-checked at connection time against DNS rebinding."""

    def test_file_scheme_url_is_rejected(self):
        result = monitor.measure_http_latency("file:///etc/passwd")
        self.assertIn("unsafe monitor target", result["error"])
        self.assertIn("http/https", result["error"])

    def test_localhost_literal_is_rejected(self):
        for url in ("http://127.0.0.1:8080/admin", "https://localhost/",
                    "http://[::1]/", "http://0.0.0.0/"):
            result = monitor.measure_http_latency(url)
            self.assertIn("unsafe monitor target", result["error"], url)

    def test_private_lan_and_metadata_addresses_are_rejected(self):
        for url in ("http://10.1.2.3/", "http://192.168.1.1/",
                    "https://169.254.169.254/latest/meta-data/",
                    "http://172.16.0.9/", "http://metadata.google.internal/"):
            result = monitor.measure_http_latency(url)
            self.assertIn("unsafe monitor target", result["error"], url)

    def test_credentials_in_url_are_rejected(self):
        result = monitor.measure_http_latency("https://user:pass@example.com/")
        self.assertIn("unsafe monitor target", result["error"])

    def test_public_target_still_probes(self):
        response = FakeResponse(b"ok")
        opened = []

        def opener(url, timeout):
            opened.append(url)
            return response

        with mock.patch.object(monitor, "resolve_target_addresses",
                               return_value=["104.16.132.229"]):
            result = monitor.measure_http_latency(
                "https://example.invalid", opener=opener, clock=iter([1.0, 1.05]).__next__
            )
        self.assertEqual(result["status"], 200)
        self.assertEqual(opened, ["https://example.invalid"])

    def test_dns_rebinding_to_loopback_is_caught_at_connection_time(self):
        # config-time check passes for the public name, but resolution returns
        # 127.0.0.1 right before connecting -> refused without dialing.
        def opener(url, timeout):  # must never be reached
            raise AssertionError(f"dialed rebinding target {url}")

        with mock.patch.object(monitor, "resolve_target_addresses",
                               return_value=["127.0.0.1"]):
            result = monitor.measure_http_latency(
                "https://rebind.invalid/", opener=urllib.request.urlopen
            )
        self.assertIn("resolved to private/loopback", result["error"])
        self.assertIn("unsafe monitor target", result["error"])

    def test_explicit_opt_in_allows_private_targets(self):
        with mock.patch.dict(os.environ, {monitor.PRIVATE_TARGET_BYPASS_ENV: "1"}):
            violation = monitor.target_violation("http://127.0.0.1:9090/metrics")
            self.assertIsNone(violation)

    def test_download_and_upload_share_the_same_guard(self):
        download = monitor.measure_download(
            "https://169.254.169.254/latest/meta-data/", max_bytes=8,
            opener=lambda url, timeout: FakeResponse(b"x"), clock=iter([0.0, 0.1]).__next__,
        )
        upload = monitor.measure_upload(
            "http://10.0.0.1/upload", max_bytes=8,
            opener=lambda request, timeout: FakeResponse(b""), clock=iter([0.0, 0.1]).__next__,
        )
        for result in (download, upload):
            self.assertIn("unsafe monitor target", result["error"])

    def test_settings_fall_back_to_defaults_for_unsafe_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({
                "monitor": {
                    "http_url": "file:///etc/passwd",
                    "download_url": "http://192.168.0.1/speed",
                    "upload_url": "https://169.254.169.254/up",
                }
            }))
            settings = monitor._monitor_settings(root)
        self.assertEqual(settings["http_url"], monitor.DEFAULT_HTTP_URL)
        self.assertEqual(settings["download_url"], monitor.DEFAULT_DOWNLOAD_URL)
        self.assertEqual(settings["upload_url"], monitor.DEFAULT_UPLOAD_URL)


class PingHostValidationTests(unittest.TestCase):
    """Issue #64: configured ping hosts cannot inject options into argv."""

    def test_leading_hyphen_host_rejected_as_option_injection(self):
        ran = []
        result = monitor.measure_ping("-c", command_runner=lambda cmd, **kw: ran.append(cmd))
        self.assertFalse(ran, "ping must not run with an option-like host")
        self.assertIn("unsafe ping target", result["error"])
        self.assertIn("option injection", result["error"])

    def test_metacharacter_hosts_are_rejected(self):
        for host in ("1.1.1.1; reboot", "1.1.1.1 -i 0.001", "$(x)", "`x`", "a b"):
            ran = []
            result = monitor.measure_ping(
                host, command_runner=lambda cmd, **kw: ran.append(cmd)
            )
            self.assertFalse(ran, host)
            self.assertIn("unsafe ping target", result["error"], host)

    def test_valid_ip_and_hostname_still_run(self):
        captured = {}

        def runner(cmd, **kwargs):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0,
                                               stdout="min/avg/max/stddev = 1/2/3/4 ms",
                                               stderr="")

        for host in ("1.1.1.1", "dns.google", "[2606:4700:4700::1111]"):
            result = monitor.measure_ping(host, command_runner=runner)
            self.assertEqual(result.get("avg_ms"), 2.0, host)
            self.assertEqual(captured["cmd"][-1], host)

    def test_settings_drop_invalid_ping_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({
                "monitor": {"ping_hosts": ["-c", "1.1.1.1", "bad host", "3"]}
            }))
            settings = monitor._monitor_settings(root)
        self.assertEqual(settings["ping_hosts"], ["1.1.1.1"])


if __name__ == "__main__":
    unittest.main()
