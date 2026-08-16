"""Unit tests for examples/proxy_tray.py (stdlib only, no GUI deps — the
module's pystray/PIL imports are guarded)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load_tray():
    if "proxy_tray" in sys.modules:
        return sys.modules["proxy_tray"]
    spec = importlib.util.spec_from_file_location(
        "proxy_tray", ROOT / "examples" / "proxy_tray.py")
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
        with mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch("builtins.open", side_effect=PermissionError):
                self.assertTrue(self.client._engine_runs_as_root())

    def test_readable_root_pid_confirmed_by_ps(self):
        self.pid.write_text("4242")
        with mock.patch("os.stat") as st:
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


class RunElevatedFallbackTests(unittest.TestCase):
    """`_run_elevated` falls back to the admin dialog when `sudo -n`
    denies (stale grant missing a command shape added later), but returns
    a real elevated-command failure unchanged (no dialog for an engine
    error)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _probe(self, returncode, stdout="", stderr=""):
        return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()

    def test_sudo_denial_falls_back_to_osascript(self):
        with mock.patch.object(tray, "_sudoers_ok", return_value=True), \
             mock.patch.object(tray.subprocess, "run") as run:
            run.side_effect = [
                self._probe(1, stderr="a password is required"),
                self._probe(0, stdout="stopped"),
            ]
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (0, "stopped"))
        self.assertEqual(run.call_args.args[0][0], "osascript")

    def test_sudoers_denial_token_falls_back_to_osascript(self):
        with mock.patch.object(tray, "_sudoers_ok", return_value=True), \
             mock.patch.object(tray.subprocess, "run") as run:
            run.side_effect = [
                self._probe(1, stderr="kyson is not in the sudoers file"),
                self._probe(0, stdout="stopped"),
            ]
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (0, "stopped"))
        self.assertEqual(run.call_args.args[0][0], "osascript")

    def test_elevated_command_failure_returns_rc_without_osascript(self):
        with mock.patch.object(tray, "_sudoers_ok", return_value=True), \
             mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(3, stderr="router: engine failed to start")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual(rc, 3)
        self.assertEqual(run.call_args.args[0][0], "sudo")
        self.assertEqual(run.call_count, 1)

    def test_success_returns_without_osascript(self):
        with mock.patch.object(tray, "_sudoers_ok", return_value=True), \
             mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(0, stdout="stopped")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (0, "stopped"))
        self.assertEqual(run.call_args.args[0][0], "sudo")
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


if __name__ == "__main__":
    unittest.main()
