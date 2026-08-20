"""Unit tests for proxy_tray.py (stdlib only, no GUI deps — the
module's pystray/PIL imports are guarded)."""
import importlib.util
import subprocess
import sys
import tempfile
import threading
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


class QuitActionTests(unittest.TestCase):
    """Quit must stop the engine BEFORE leaving the tray (issue #52):
    a quitting tray that leaves the proxy-router engine running strands
    the user with a live tunnel they can no longer control."""

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

        app = tray.TrayApp(FakeClient(), None)
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

        app = tray.TrayApp(FakeClient(), None)
        app.tray = FakeTray()
        app.action_quit()
        self.assertTrue(tray_stopped.wait(2))


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
        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)
        with mock.patch.object(tray.subprocess, "run", side_effect=fake_run):
            self.assertTrue(tray.open_dashboard(self.root))
        self.assertEqual(calls[0][0], "osascript")
        self.assertIn("setup_tui.py", " ".join(calls[0]))

    def test_macos_terminal_failure_fails_quietly(self):
        failed = subprocess.CompletedProcess(["osascript"], 1)
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch.object(tray.subprocess, "run", return_value=failed):
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


