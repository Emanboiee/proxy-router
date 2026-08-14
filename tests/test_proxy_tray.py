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


if __name__ == "__main__":
    unittest.main()
