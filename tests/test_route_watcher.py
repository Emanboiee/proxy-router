import json
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

    def test_guard_does_not_combine_different_targets(self):
        guard = w.RotationGuard()
        self.assertFalse(guard.record_transport_failure(100.0, "opencode.ai"))
        self.assertFalse(guard.record_transport_failure(101.0, "roblox.com"))
        self.assertTrue(guard.record_transport_failure(102.0, "opencode.ai"))

    def test_critical_domains_are_config_driven(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "router.json").write_text(json.dumps({
                "routes": [
                    {"id": "opencode-ai", "domains": ["opencode.ai", "api.opencode.ai"]},
                    {"id": "roblox", "domains": ["roblox.com"]},
                ],
            }))
            self.assertEqual(
                w.critical_domains(root),
                ("opencode.ai", "api.opencode.ai", "roblox.com"),
            )

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

    def test_worker_cleanup_cannot_remove_newer_worker_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state" / "route-watcher").mkdir(parents=True)
            w.pid_file(root).write_text("222\n")
            w.enabled_file(root).write_text("enabled\n")

            w._cleanup_worker_state(root, 111)

            self.assertEqual(w.pid_file(root).read_text(), "222\n")
            self.assertTrue(w.enabled_file(root).is_file())

    def test_worker_cleanup_removes_its_own_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state" / "route-watcher").mkdir(parents=True)
            w.pid_file(root).write_text("111\n")
            w.enabled_file(root).write_text("enabled\n")

            w._cleanup_worker_state(root, 111)

            self.assertFalse(w.pid_file(root).exists())
            self.assertFalse(w.enabled_file(root).exists())

    def test_worker_only_probes_configured_routed_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state" / "route-watcher").mkdir(parents=True)
            (root / "router.json").write_text(json.dumps({
                "routes": [{"id": "opencode", "domains": ["opencode.ai"]}],
            }))
            probed = []
            sleeps = 0

            def fake_sleep(_seconds):
                nonlocal sleeps
                sleeps += 1
                if sleeps == 1:
                    (root / "sing-box.log").write_text(
                        "INFO inbound connection to example.com:443\n"
                        "INFO inbound connection to opencode.ai:443\n"
                    )
                else:
                    raise StopIteration

            with mock.patch.object(w, "client_snapshot", return_value=[]), \
                    mock.patch.object(w, "probe_target", side_effect=lambda _root, host: probed.append(host) or {
                        "transport_failure": False, "host": host,
                    }):
                with self.assertRaises(StopIteration):
                    w.worker(root, interval=0.5, sleep=fake_sleep)

            self.assertEqual(probed, ["opencode.ai"])


if __name__ == "__main__":
    unittest.main()
