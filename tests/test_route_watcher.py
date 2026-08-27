import contextlib
import io
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

    def test_parse_provider_tag_from_endpoint_and_failure(self):
        event = w.parse_line(
            "ERROR endpoint/wireguard[cloudflare]: open connection to discord.com:443: TLS handshake timeout"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["provider"], "cloudflare")
        event = w.parse_line(
            "ERROR using outbound/wireguard[proton2]: open connection to discord.com:443: connection reset"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["provider"], "proton2")

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

    def _watcher_state(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        w.state_dir(root).mkdir(parents=True)
        w.pid_file(root).write_text("4242", encoding="ascii")
        w.enabled_file(root).write_text("enabled\n", encoding="ascii")
        return temp, root

    def test_stop_waits_until_matching_worker_exits(self):
        temp, root = self._watcher_state()
        self.addCleanup(temp.cleanup)
        with mock.patch.object(w, "_pid_running", side_effect=[True, True, False]), \
             mock.patch.object(w.os, "kill") as kill, \
             mock.patch.object(w.time, "sleep"):
            result = w.stop(root, timeout=1.0, poll_interval=0.01)
        kill.assert_called_once_with(4242, w.signal.SIGTERM)
        self.assertTrue(result["stopped"])
        self.assertFalse(w.pid_file(root).exists())
        self.assertFalse(w.enabled_file(root).exists())

    def test_stop_preserves_state_when_matching_worker_times_out(self):
        temp, root = self._watcher_state()
        self.addCleanup(temp.cleanup)
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds

        with mock.patch.object(w, "_pid_running", return_value=True), \
             mock.patch.object(w.os, "kill") as kill, \
             mock.patch.object(w.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(w.time, "sleep", side_effect=sleep):
            result = w.stop(root, timeout=0.2, poll_interval=0.1)
        kill.assert_called_once_with(4242, w.signal.SIGTERM)
        self.assertFalse(result["stopped"])
        self.assertTrue(w.pid_file(root).exists())
        self.assertTrue(w.enabled_file(root).exists())
        self.assertIn("timeout", result["error"])

    def test_stop_never_signals_pid_when_command_identity_mismatches(self):
        temp, root = self._watcher_state()
        self.addCleanup(temp.cleanup)
        foreign_root = root.parent / "foreign-root"
        foreign = SimpleNamespace(
            returncode=0,
            stdout=f"python route_watcher.py --worker --root {foreign_root.resolve()}",
            stderr="",
        )
        with mock.patch.object(w.subprocess, "run", return_value=foreign), \
             mock.patch.object(w.os, "kill") as kill:
            self.assertFalse(w._pid_matches(root, 4242))
            result = w.stop(root)
        kill.assert_not_called()
        self.assertTrue(result["stopped"])
        self.assertTrue(result["stale"])
        self.assertFalse(w.pid_file(root).exists())
        self.assertFalse(w.enabled_file(root).exists())

    def _assert_special_root_stops(self, dirname):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / dirname
        w.state_dir(root).mkdir(parents=True)
        w.pid_file(root).write_text("4242", encoding="ascii")
        w.enabled_file(root).write_text("enabled\n", encoding="ascii")
        matching = SimpleNamespace(
            returncode=0,
            stdout=(f"python {Path(w.__file__).resolve()} --worker "
                    f"--root {root.resolve()} --interval 2.0"),
            stderr="",
        )
        gone = SimpleNamespace(returncode=1, stdout="", stderr="")
        with mock.patch.object(
            w.subprocess, "run", side_effect=[matching, matching, gone]
        ), mock.patch.object(w.os, "kill") as kill:
            self.assertTrue(w._pid_matches(root, 4242))
            result = w.stop(root)
        self.assertTrue(result["stopped"])
        self.assertIn(mock.call(4242, 0), kill.call_args_list)
        self.assertIn(mock.call(4242, w.signal.SIGTERM), kill.call_args_list)
        self.assertFalse(w.pid_file(root).exists())
        self.assertFalse(w.enabled_file(root).exists())

    def test_stop_matches_and_signals_worker_with_spaced_root(self):
        self._assert_special_root_stops("root with space")

    def test_stop_matches_and_signals_worker_with_quote_in_root(self):
        self._assert_special_root_stops("root's data")

    def test_stop_cleans_already_stale_state_without_signal(self):
        temp, root = self._watcher_state()
        self.addCleanup(temp.cleanup)
        with mock.patch.object(w, "_pid_running", return_value=False), \
             mock.patch.object(w.os, "kill") as kill:
            result = w.stop(root)
        kill.assert_not_called()
        self.assertTrue(result["stopped"])
        self.assertTrue(result["stale"])
        self.assertFalse(w.pid_file(root).exists())
        self.assertFalse(w.enabled_file(root).exists())

    def test_cli_off_returns_nonzero_when_stop_times_out(self):
        with mock.patch.object(w, "stop", return_value={
            "stopped": False,
            "pid": 4242,
            "error": "timeout waiting for watcher",
        }), io.StringIO() as output, contextlib.redirect_stdout(output):
            rc = w.main(["off"], root=Path("/tmp/test-watcher-root"))
            payload = json.loads(output.getvalue())
        self.assertEqual(rc, 1)
        self.assertFalse(payload["stopped"])

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

    def test_worker_rotates_provider_from_outbound_tag(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        w.state_dir(root).mkdir(parents=True)
        (root / "router.json").write_text(json.dumps({
            "routes": [{"id": "discord", "domains": ["discord.com"], "provider": "cloudflare"}],
            "routing": {"mode": "vpn-list", "vpn_domains": ["discord.com"]},
        }))
        lines = [
            "ERROR using outbound/wireguard[cloudflare]: open connection to discord.com:443: connection reset\n",
            "ERROR using outbound/wireguard[cloudflare]: open connection to discord.com:443: connection reset\n",
        ]
        reads = [0]
        calls = []

        def fake_read(_path, offset):
            if reads[0] == 0:
                reads[0] += 1
                return offset, lines
            return offset, []

        def stop_after_tick(_seconds):
            w.enabled_file(root).unlink(missing_ok=True)

        with mock.patch.object(w, "engine_pid_alive", return_value=True), \
             mock.patch.object(w, "_read_new_lines", side_effect=fake_read), \
             mock.patch.object(w, "client_snapshot", return_value=[]), \
             mock.patch.object(w, "_network_check_hop"), \
             mock.patch.object(w, "probe_target", return_value={"transport_failure": False}), \
             mock.patch.object(w, "rotate_provider", side_effect=lambda *args, **kwargs: calls.append(args) or {"rotated": False}):
            rc = w.worker(root, interval=0.05, sleep=stop_after_tick)
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [(root.resolve(), "cloudflare")])

    def test_worker_sigterm_self_cleans_markers_after_exit(self):
        """AC4: a SIGTERM'd worker exits through its finally and removes its
        own markers; nobody has to unlink state under a live process.

        The real signal handler raises SystemExit from inside the sleep call;
        simulate it inline (spawning a real worker subprocess is blocked by
        the test safety harness) with a sleep that raises on the first tick.
        """
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        # Give the worker a live engine pid so it does NOT hit the
        # ENGINE_DOWN_GRACE exit and self-terminate before our simulated
        # SIGTERM lands.
        (root / "sing-box.pid").write_text(str(os.getpid()))
        with mock.patch.object(w, "engine_pid_alive", return_value=True):
            with self.assertRaises(SystemExit):
                w.worker(root, interval=0.05, sleep=lambda _: (_ for _ in ()).throw(SystemExit(0)))
        self.assertFalse(w.pid_file(root).exists(), "worker must clean pid marker")
        self.assertFalse(w.enabled_file(root).exists(), "worker must clean enabled marker")

    def test_stop_waits_for_exit_and_cleans_only_after_confirmed(self):
        """AC3+AC4: stop() is synchronous - it signals, waits for the worker to
        actually exit, and removes markers only after that exit is confirmed.

        Worker spawns are blocked by the test safety harness, so simulate the
        synchronous wait with a mocked _pid_running that goes live -> gone.
        """
        temp, root = self._watcher_state()
        self.addCleanup(temp.cleanup)
        with mock.patch.object(w, "_pid_running", side_effect=[True, True, False]), \
             mock.patch.object(w.os, "kill") as kill:
            result = w.stop(root)
        self.assertTrue(result["stopped"])
        kill.assert_called_once_with(4242, w.signal.SIGTERM)
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


class ProviderForHostTests(unittest.TestCase):
    def _root_with_routes(self, routes, routing=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = {"routes": routes}
        if routing is not None:
            data["routing"] = routing
        (root / "router.json").write_text(json.dumps(data))
        return root

    def test_maps_host_to_its_route_provider(self):
        root = self._root_with_routes([
            {"id": "twitch", "domains": ["twitch.tv"], "provider": "proton"},
            {"id": "school", "domains": ["discord.com"], "provider": "cloudflare"},
        ])
        self.assertEqual(w.provider_for_host(root, "discord.com"), "cloudflare")
        self.assertEqual(w.provider_for_host(root, "www.twitch.tv"), "proton")

    def test_vpn_list_ignores_unlisted_routes(self):
        root = self._root_with_routes([
            {"id": "direct", "domains": ["direct.example"], "provider": "proton"},
            {"id": "discord", "domains": ["discord.com"], "provider": "cloudflare"},
        ], {"mode": "vpn-list", "vpn_domains": ["discord.com"]})
        self.assertIsNone(w.provider_for_host(root, "direct.example"))
        self.assertEqual(w.provider_for_host(root, "discord.com"), "cloudflare")
        self.assertEqual(w.critical_domains(root), ("discord.com",))

    def test_empty_vpn_list_has_no_critical_targets(self):
        root = self._root_with_routes([
            {"id": "direct", "domains": ["direct.example"], "provider": "proton"},
        ], {"mode": "vpn-list", "vpn_domains": []})
        self.assertIsNone(w.provider_for_host(root, "direct.example"))
        self.assertEqual(w.critical_domains(root), ())

    def test_actual_outbound_provider_is_parsed(self):
        event = w.parse_line(
            "ERROR connection: open connection to discord.com:443 using "
            "outbound/wireguard[proton2]: connection reset"
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["provider"], "proton2")

    def test_first_matching_route_wins(self):
        root = self._root_with_routes([
            {"id": "a", "domains": ["x.com"], "provider": "proton"},
            {"id": "b", "domains": ["x.com"], "provider": "cloudflare"},
        ])
        self.assertEqual(w.provider_for_host(root, "x.com"), "proton")

    def test_unmatched_host_returns_none(self):
        root = self._root_with_routes([
            {"id": "a", "domains": ["x.com"], "provider": "proton"},
        ])
        self.assertIsNone(w.provider_for_host(root, "other.com"))

    def test_unreadable_config_returns_none(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.assertIsNone(w.provider_for_host(Path(tmp.name), "x.com"))
