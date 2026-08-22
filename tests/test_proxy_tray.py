"""Unit tests for proxy_tray.py (stdlib only, no GUI deps — the
module's pystray/PIL imports are guarded)."""
import importlib.util
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load_tray():
    if "proxy_tray" in sys.modules:
        return sys.modules["proxy_tray"]
    spec = importlib.util.spec_from_file_location(
        "proxy_tray", ROOT / "proxy_tray.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["proxy_tray"] = mod
    spec.loader.exec_module(mod)
    return mod


tray = _load_tray()


class RouterClientEngineOwnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.pid = Path(self.tmp.name) / "sing-box.pid"
        self.addCleanup(self.tmp.cleanup)

    def test_missing_pid_file_is_not_root(self):
        self.assertFalse(self.client._engine_runs_as_root())

    def test_user_owned_pid_file_is_not_root(self):
        self.pid.write_text("4242")
        with mock.patch("os.stat") as st:
            st.return_value.st_uid = 501
            self.assertFalse(self.client._engine_runs_as_root())

    def test_unreadable_root_pid_file_counts_as_root(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch("os.geteuid", return_value=501), \
             mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch("builtins.open", side_effect=PermissionError):
                self.assertTrue(self.client._engine_runs_as_root())

    def test_readable_root_pid_confirmed_by_ps(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch("os.geteuid", return_value=501), \
             mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch.object(tray.subprocess, "run") as run:
                run.return_value.stdout = "root\n"
                self.assertTrue(self.client._engine_runs_as_root())
        self.assertEqual(run.call_args.args[0], ["ps", "-o", "user=", "-p", "4242"])

    def test_never_root_outside_macos(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.sys, "platform", "linux"), \
             mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch("builtins.open", side_effect=PermissionError):
                self.assertFalse(self.client._engine_runs_as_root())


class RouterClientStartStopElevationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_stop_elevates_when_engine_root_owned(self):
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.stop()
        self.assertEqual((rc, out), (0, "elev"))
        elev.assert_called_once_with("stop")
        plain.assert_not_called()

    def test_start_elevates_when_engine_root_owned(self):
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.start()
        self.assertEqual((rc, out), (0, "elev"))
        elev.assert_called_once_with("start")
        plain.assert_not_called()

    def test_stop_stays_user_level_when_engine_user_owned(self):
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=False), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.stop()
        self.assertEqual((rc, out), (0, "plain"))
        plain.assert_called_once_with("stop")
        elev.assert_not_called()

    def test_start_stays_user_level_when_engine_user_owned(self):
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=False), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.start()
        self.assertEqual((rc, out), (0, "plain"))
        plain.assert_called_once_with("start")
        elev.assert_not_called()

    def test_rotate_elevates_when_engine_root_owned(self):
        # Issue #54: switching servers from the tray failed against a
        # root-owned engine because rotate stayed user-level.
        self.client._active_provider = "proton"
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.rotate()
        self.assertEqual((rc, out), (0, "elev"))
        elev.assert_called_once_with("rotate", "proton")
        plain.assert_not_called()

    def test_rotate_to_elevates_when_engine_root_owned(self):
        self.client._active_provider = "proton"
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.rotate_to("proton", "06-SG-FREE-4")
        self.assertEqual((rc, out), (0, "elev"))
        elev.assert_called_once_with("rotate", "proton", "--to", "06-SG-FREE-4")
        plain.assert_not_called()

    def test_rotate_to_force_elevates_with_force_flag(self):
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.rotate_to("proton", "06-SG-FREE-4", force=True)
        self.assertEqual((rc, out), (0, "elev"))
        elev.assert_called_once_with("rotate", "proton", "--to", "06-SG-FREE-4", "--force")
        plain.assert_not_called()

    def test_rotate_stays_user_level_when_engine_user_owned(self):
        self.client._active_provider = "proton"
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=False), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.rotate()
        self.assertEqual((rc, out), (0, "plain"))
        plain.assert_called_once_with("rotate", "proton")
        elev.assert_not_called()

    def test_rotate_without_active_provider_stays_user_level(self):
        # _active_provider is None (no status seen yet): do not invent an
        # elevated call with a None provider argument.
        with mock.patch.object(self.client, "_engine_runs_as_root", return_value=True), \
             mock.patch.object(self.client, "_run_elevated", return_value=(0, "elev")) as elev, \
             mock.patch.object(self.client, "_run", return_value=(0, "plain")) as plain:
            rc, out = self.client.rotate()
        self.assertEqual((rc, out), (0, "plain"))
        plain.assert_called_once()
        elev.assert_not_called()


class HumanizeTests(unittest.TestCase):
    def test_untouched_engine_shortcut_unchanged(self):
        self.assertEqual(
            tray._humanize("engine is untouched"), "saved — Connect to apply")

    def test_empty_output_is_empty(self):
        self.assertEqual(tray._humanize(""), "")

    def test_long_unmapped_detail_cap_is_above_160(self):
        # The CLI's missing-binary message lists every candidate; the old
        # 160-char cap cut it into an unexplained "Connect: Failed" (#11).
        out = "router: could not start sing-box: " + "candidate-path " * 40
        detail = tray._humanize(out)
        self.assertGreater(len(detail), 160)  # old cap would cut at 160
        self.assertEqual(len(detail), tray._MAX_DETAIL)  # cap keeps the full detail

    def test_sing_box_not_found_maps_to_friendly_next_step(self):
        detail = tray._humanize(
            "router: sing-box not found (tried: env SING_BOX=(unset), ...)")
        self.assertIn("install sing-box 1.12+", detail)
        self.assertIn("github.com/SagerNet/sing-box/releases", detail)

    def test_system_proxy_echo_line_is_stripped(self):
        # macOS start/stop end with "system proxy disabled on 1 network
        # service(s)"; showing that after "Connect: done" reads like a
        # failure (issue #50).
        detail = tray._humanize(
            "router: engine started\nsystem proxy disabled on 1 network service(s)")
        self.assertEqual(detail, "")

    def test_system_proxy_enabled_echo_line_is_stripped(self):
        detail = tray._humanize(
            "system proxy enabled on 2 network service(s) -> 127.0.0.1:2080")
        self.assertEqual(detail, "")


class RunElevatedFallbackTests(unittest.TestCase):
    """Legacy-named wrapper now runs only the normal user controller."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _probe(self, returncode, stdout="", stderr=""):
        return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()

    def test_controller_failure_never_falls_back_to_osascript(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(1, stderr="a password is required")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (1, "a password is required"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)

    def test_controller_sudoers_message_is_returned_without_tray_fallback(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(1, stderr="alice is not in the sudoers file")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (1, "alice is not in the sudoers file"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)

    def test_controller_command_failure_returns_unchanged(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(3, stderr="router: engine failed to start")
            rc, _out = self.client._run_elevated("stop")
        self.assertEqual(rc, 3)
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)

    def test_controller_success_returns_unchanged(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(0, stdout="stopped")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (0, "stopped"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)


class TransientProbePresentationTests(unittest.TestCase):
    def _status(self, record):
        return tray.RouterStatus(
            up=True,
            providers={
                "proton": {
                    "active": "06-SG-FREE-4",
                    "profiles": ["06-SG-FREE-4"],
                    "egress": {"06-SG-FREE-4": record},
                }
            },
        )

    def test_transport_probe_failure_is_quiet_but_stays_force_clickable(self):
        status = self._status({
            "ok": False,
            "status": None,
            "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
            "upstream_error": None,
            "blocked": False,
            "exhausted": False,
        })
        app = object.__new__(tray.TrayApp)
        self.assertEqual(status.profile_health("proton", "06-SG-FREE-4"), "")
        self.assertNotIn("▲", status.provider_label("proton"))
        self.assertTrue(app._exit_try_anyway(status, "proton", "06-SG-FREE-4"))

    def test_explicit_upstream_failure_stays_visible(self):
        status = self._status({
            "ok": True,
            "status": 200,
            "error": None,
            "upstream_error": "429",
            "blocked": False,
            "exhausted": True,
        })
        self.assertIn("▲", status.provider_label("proton"))
        self.assertIn("rate-limited", status.profile_health("proton", "06-SG-FREE-4"))


class MutationSerializationTests(unittest.TestCase):
    """Issue #60: tray mutations used to run on independent daemon threads.

    Two rapid clicks raced inside router.py, and an older completion or poll
    could overwrite newer status. These tests pin the contract: strict FIFO
    execution (no concurrency), newest-snapshot-wins publication, and a
    menu signature that covers every field the menu renders.
    """

    def _make_app(self):
        class FakeClient:
            def status(self):
                return tray.RouterStatus()
        app = tray.TrayApp(FakeClient(), None)
        return app

    def _wait_until(self, pred, timeout=2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.005)
        return pred()

    def test_overlapping_clicks_execute_serially_in_click_order(self):
        app = self._make_app()
        events = []
        lock = threading.Lock()

        def make_job(name, hold):
            def job():
                with lock:
                    running = getattr(app, "_concurrency_probe", 0)
                    app._concurrency_probe = running + 1
                    events.append(f"{name}:start")
                if hold:
                    time.sleep(0.15)  # long enough for the next click to land
                with lock:
                    app._concurrency_probe -= 1
                    events.append(f"{name}:done")
                return 0, "ok"
            return job

        # Click 1 starts a slow mutation; clicks 2..4 arrive while it runs.
        app._do(make_job("a", True), "a")
        app._do(make_job("b", False), "b")
        app._do(make_job("c", False), "c")
        app._do(make_job("d", False), "d")
        self.assertTrue(self._wait_until(
            lambda: len([e for e in events if e.endswith(":done")]) == 4))
        order = [e.split(":")[0] for e in events if e.endswith(":start")]
        dones = [e.split(":")[0] for e in events if e.endswith(":done")]
        self.assertEqual(order, ["a", "b", "c", "d"])
        self.assertEqual(dones, ["a", "b", "c", "d"])
        # No two bodies ever overlapped: the pump leaves no residual count.
        self.assertEqual(app._concurrency_probe, 0)

    def test_worker_exception_becomes_visible_failed_result(self):
        app = self._make_app()

        def boom():
            raise RuntimeError("kaboom")

        app._do(boom, "explode")
        self.assertTrue(self._wait_until(
            lambda: app.last_action_result
            and "failed" in app.last_action_result))
        self.assertIn("RuntimeError", app.last_action_result)

    def test_stale_poll_cannot_overwrite_newer_post_action_snapshot(self):
        # Deliberately inverted completion driven through the REAL poll
        # loop: the poll claims its slot and fetches status BEFORE the
        # action finishes, then publishes AFTER the post-action snapshot
        # landed. The newer post-action snapshot must win.
        gate = threading.Event()

        class BlockingStatusClient:
            root = "/tmp"

            def __init__(self):
                self.calls = 0

            def status(self):
                self.calls += 1
                if self.calls == 1:
                    gate.wait(2)  # poll fetch stalls "mid-network"
                    return tray.RouterStatus(up=False)
                return tray.RouterStatus()

        client = BlockingStatusClient()
        app = tray.TrayApp(client, None)
        app._publish_status(tray.RouterStatus(), None)  # baseline
        poller = threading.Thread(target=self._guarded_poll(app), daemon=True)
        poller.start()
        deadline = time.time() + 2
        while client.calls < 1 and time.time() < deadline:
            time.sleep(0.005)
        time.sleep(0.05)  # ensure the poll is parked inside its fetch

        # The mutation finishes meanwhile and publishes its fresh snapshot,
        # exactly like _mutation_worker does (new epoch, newest-wins).
        with app.lock:
            app._status_epoch += 1
        app._publish_status(tray.RouterStatus(up=True),
                            app._status_epoch)
        app.quit_flag.set()  # end the loop after this in-flight iteration
        gate.set()  # release the stale fetch; its publish lands LAST

        poller.join(5)
        self.assertTrue(
            app.latest.up,
            "stale poll overwrote the post-action snapshot")

    @staticmethod
    def _guarded_poll(app):
        def run():
            try:
                app.poll_loop()
            except Exception:
                pass
        return run

    def test_signature_changes_when_preset_or_profile_lists_change(self):
        # These fields are rendered by build_menu but were unsigned before
        # issue #60: preset changes and provider profile lists went stale.
        base = tray.RouterStatus()
        app = self._make_app()

        with_preset = tray.RouterStatus(preset="school-warp")
        self.assertNotEqual(app._status_signature(base),
                            app._status_signature(with_preset))

        no_profiles = tray.RouterStatus()
        info = dict(no_profiles.providers)
        info["proton"] = {"active": None,
                          "profiles": ["01-NL"], "egress": {}}
        with_profiles = tray.RouterStatus(providers=info)
        self.assertNotEqual(app._status_signature(no_profiles),
                            app._status_signature(with_profiles))

        plain = tray.RouterStatus()
        marked = dict(plain.providers)
        marked["proton"] = {"active": None, "profiles": [],
                            "egress": {"nl": {"ok": False, "error": None,
                                              "latency_ms": None,
                                              "status": None,
                                              "upstream_error": None,
                                              "blocked": True}}}
        self.assertNotEqual(
            app._status_signature(plain),
            app._status_signature(tray.RouterStatus(providers=marked)))

    def test_publish_status_without_epoch_always_installs(self):
        # Error snapshots from poll failures carry no epoch; they install
        # unconditionally so a broken CLI still surfaces in the menu.
        app = self._make_app()
        app._publish_status(tray.RouterStatus(up=True), 3)
        err = tray.RouterStatus(error="status exit 7")
        app._publish_status(err, None)
        self.assertEqual(app.latest.error, "status exit 7")

    def test_menu_controls_disabled_while_mutation_active(self):
        release = threading.Event()

        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus()

        app = tray.TrayApp(RootedClient(), None)

        def job():
            release.wait(2)
            return 0, "ok"

        app.latest = tray.RouterStatus(up=True, providers={
            "proton": {"active": "nl", "profiles": ["nl"], "egress": {}}})
        app._mutation_active = True
        menu = app.build_menu()
        labels = {item.text: item.enabled for item in menu}
        connect = next(v for k, v in labels.items() if k in ("Connect", "Reconnect"))
        disconnect = next(v for k, v in labels.items() if k == "Disconnect")
        rotate = next(v for k, v in labels.items() if k == "Switch VPN server")
        quit_item = next(v for k, v in labels.items() if k == "Quit")
        self.assertFalse(connect)
        self.assertFalse(disconnect)
        self.assertFalse(rotate)
        self.assertTrue(quit_item, "Quit must stay clickable")
        release.set()


class QuitActionTests(unittest.TestCase):
    """Quit must stop the engine BEFORE leaving the tray (issue #52):
    a quitting tray that leaves the proxy-router engine running strands
    the user with a live tunnel they can no longer control."""

    def _make_app(self, client, drain_ok=None):
        app = tray.TrayApp(client, None)
        if drain_ok is not None:
            # Shrink the quit drain window so a stuck mutation cannot slow
            # the suite; production uses MUTATION_DRAIN_TIMEOUT.
            app._drain_timeout = drain_ok
        return app

    def test_quit_stops_engine_then_tray(self):
        calls = []
        tray_stopped = threading.Event()

        class FakeClient:
            def stop(self):
                calls.append("engine")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                calls.append("tray")
                tray_stopped.set()

        app = self._make_app(FakeClient(), 2)
        app.tray = FakeTray()
        app.action_quit()
        self.assertTrue(tray_stopped.wait(2))
        self.assertEqual(calls, ["engine", "tray"])
        self.assertTrue(app.quit_flag.is_set())

    def test_quit_stops_tray_even_when_engine_stop_fails(self):
        tray_stopped = threading.Event()

        class FakeClient:
            def stop(self):
                return 1, "engine not running"

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 2)
        app.tray = FakeTray()
        app.action_quit()
        self.assertTrue(tray_stopped.wait(2))

    def test_quit_drains_in_flight_mutation_before_engine_stop(self):
        # Issue #60: quit used to race the per-click daemon threads. The
        # engine stop must land AFTER an already-running mutation finished.
        calls = []
        mutation_running = threading.Event()
        release_mutation = threading.Event()
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                calls.append("mutate-start")
                mutation_running.set()
                release_mutation.wait(2)
                calls.append("mutate-done")
                return 0, "ok"

            def status(self):
                return tray.RouterStatus(up=False)

            def stop(self):
                calls.append("engine-stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                calls.append("tray")
                tray_stopped.set()

        app = self._make_app(FakeClient(), 5)
        app.tray = FakeTray()
        app._do(app.client.mutate, "mutate")
        self.assertTrue(mutation_running.wait(2))
        app.action_quit()
        # Give quit's worker a beat to observe the in-flight mutation, then
        # let the mutation finish. Engine stop must come after "mutate-done"
        # and the tray must leave after the engine stopped.
        time.sleep(0.1)
        release_mutation.set()
        self.assertTrue(tray_stopped.wait(3))
        self.assertLess(calls.index("mutate-done"), calls.index("engine-stop"))
        self.assertLess(calls.index("engine-stop"), calls.index("tray"))

    def test_quit_after_mutation_finished_does_not_wait(self):
        # Once the pump is idle, quit stops the engine without any drain wait
        # (the idle condition is already true).
        calls = []
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                calls.append("mutate")
                return 0, "ok"

            def status(self):
                return tray.RouterStatus()

            def stop(self):
                calls.append("engine-stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 5)
        app.tray = FakeTray()
        app._do(app.client.mutate, "mutate")
        deadline = time.time() + 2
        while not app._mutation_idle() and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(app._mutation_idle())
        app.action_quit()
        self.assertTrue(tray_stopped.wait(3))
        # mutate ran on the pump before quit; engine stop came after it.
        self.assertIn("mutate", calls)
        self.assertLess(calls.index("mutate"),
                        calls.index("engine-stop"))


if __name__ == "__main__":
    unittest.main()


class DashboardOpenerTests(unittest.TestCase):
    """Tray one-click: open the full TUI in a terminal window."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "setup_tui.py").write_text("# tui")

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_tui_fails_quietly(self):
        (self.root / "setup_tui.py").unlink()
        self.assertFalse(tray.open_dashboard(self.root))

    @unittest.skipUnless(sys.platform == "darwin", "macOS Terminal path")
    def test_macos_opens_terminal_with_tui(self):
        calls = []
        def fake_popen(argv, **kwargs):
            calls.append(argv)
            return mock.Mock()
        with mock.patch.object(tray.subprocess, "Popen", side_effect=fake_popen):
            self.assertTrue(tray.open_dashboard(self.root))
        self.assertEqual(calls[0][0], "osascript")
        self.assertIn("setup_tui.py", " ".join(calls[0]))

    def test_macos_terminal_failure_fails_quietly(self):
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch.object(tray.subprocess, "Popen",
                               side_effect=OSError("no Terminal")):
            self.assertFalse(tray.open_dashboard(self.root))


class DashboardActionTests(unittest.TestCase):
    """The tray callback owns root forwarding and visible outcome state."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.app = tray.TrayApp(tray.RouterClient(str(self.root)), None)

    def tearDown(self):
        self._tmp.cleanup()

    def test_callback_passes_client_root_and_records_success(self):
        roots = []
        with mock.patch.object(
            tray, "open_dashboard", side_effect=lambda root: roots.append(root) or True
        ):
            self.app.action_dashboard()
        self.assertEqual(roots, [str(self.root)])
        self.assertEqual(self.app.last_action_result, "dashboard opened")

    def test_callback_records_visible_failure_without_raising(self):
        with mock.patch.object(tray, "open_dashboard", return_value=False):
            self.app.action_dashboard()
        self.assertEqual(self.app.last_action_result, "dashboard: no terminal")

    def test_callback_rebuilds_attached_tray_menu(self):
        sentinel = object()
        self.app.tray = SimpleNamespace(menu=None)
        self.app._menu_sig = "old"
        with mock.patch.object(tray, "open_dashboard", return_value=True), \
             mock.patch.object(self.app, "build_menu", return_value=sentinel) as build:
            self.app.action_dashboard()
        self.assertIsNone(self.app._menu_sig)
        self.assertIs(self.app.tray.menu, sentinel)
        build.assert_called_once_with()


class PrivilegedHelperTrayTests(unittest.TestCase):
    def test_root_action_uses_normal_controller_and_never_sudo_or_osascript(self):
        client = tray.RouterClient("/tmp/proxy-router")
        with mock.patch.object(client, "_run", return_value=(0, "ok")) as run, \
             mock.patch.object(tray.subprocess, "run") as subprocess_run:
            result = client._run_elevated("vpn", "on")

        self.assertEqual(result, (0, "ok"))
        run.assert_called_once_with("vpn", "on")
        subprocess_run.assert_not_called()


class PresetApplyReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.client = tray.RouterClient(self.tmp.name)

    def test_reload_runs_router_reload_subcommand(self):
        with mock.patch.object(self.client, "_run", return_value=(0, "ok")) as run:
            rc, out = self.client.reload()
        self.assertEqual(rc, 0)
        run.assert_called_once_with("reload")

    def test_apply_preset_failure_skips_reload(self):
        # Drive the same closure action_apply_preset builds, without the
        # TrayApp worker machinery (locks/menu) that needs a full app.
        app = mock.Mock()
        app.client = self.client
        captured = {}
        def fake_do(fn, label):
            captured["rc"] = fn()
            captured["label"] = label
        with mock.patch.object(self.client, "_run",
                               side_effect=[(1, "boom"), (0, "reloaded")]) as run:
            bound = tray.TrayApp.action_apply_preset.__get__(app)
            real_do = tray.TrayApp._do.__get__(app)
            # replace _do on the instance for this call
            app._do = fake_do
            bound("school-warp")
        run.assert_called_once_with("setup", "--preset", "school-warp")
        self.assertEqual(captured["rc"], (1, "boom"))
