"""Unit tests for the macOS elevation path of router.py (stdlib only)."""
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router


def _relocate(module, root: Path) -> None:
    """Point every module-level runtime path at ``root`` for test isolation."""
    module.ROOT = Path(root).resolve()
    module.CONFIG_FILE = module.ROOT / "router.json"
    module.SING_BOX_CONFIG = module.ROOT / "sing-box.json"
    module.LAST_GOOD_FILE = module.ROOT / "sing-box.json.last-good"
    module.PID_FILE = module.ROOT / "sing-box.pid"
    module.LOG_FILE = module.ROOT / "sing-box.log"
    module.LOCK_FILE = module.ROOT / "state" / "engine.lock"
    module.MODE_FILE = module.ROOT / "state" / "mode"
    module.MANUAL_OFF_FILE = module.ROOT / "state" / "manual-off"


def _root_stat(uid: int) -> os.stat_result:
    """A real stat_result owned by ``uid`` (mode 0600 regular file)."""
    return os.stat_result((0o100600, 1, 1, 1, uid, 0, 10, 0, 0, 0))


def _block_pid_read():
    """Context manager: router.PID_FILE reads raise PermissionError.

    Mirrors the real 0600 root-owned pid file: present and stat-able, but
    its contents are unreadable for a regular user. Patched at the class
    level because Path attributes are read-only on instances.
    """
    real_read = Path.read_text

    def fake_read(self, *args, **kwargs):
        if self == router.PID_FILE:
            raise PermissionError
        return real_read(self, *args, **kwargs)

    return mock.patch.object(Path, "read_text", fake_read)


class SudoersRulesTests(unittest.TestCase):
    def test_rules_cover_start_and_stop(self):
        rules = router._sudoers_rules("alice", "/usr/bin/python3", "/opt/pr/router.py")
        lines = rules.strip().splitlines()
        cmds = [l.split("NOPASSWD: ", 1)[1] for l in lines[1:]]
        self.assertIn("/usr/bin/python3 /opt/pr/router.py start", cmds)
        self.assertIn("/usr/bin/python3 /opt/pr/router.py stop", cmds)
        # Exact grant surface: tray Connect/Disconnect + engine commands only.
        self.assertEqual(len(cmds), 7)
        self.assertTrue(all(" ALL=(root) NOPASSWD: " in l for l in lines[1:]))


class EngineRunsAsRootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        _relocate(router, root)
        self.addCleanup(self.tmp.cleanup)

    def test_missing_pid_file_is_not_root(self):
        self.assertFalse(router._engine_runs_as_root())

    def test_user_owned_pid_file_is_not_root(self):
        router.PID_FILE.write_text("4242")
        with mock.patch("os.stat") as st:
            st.return_value.st_uid = 501
            self.assertFalse(router._engine_runs_as_root())

    def test_unreadable_root_pid_file_counts_as_root(self):
        """Mode-0600 root-owned pid files are unreadable for a regular user —
        that state is exactly what makes plain `stop` fail (issue #12)."""
        router.PID_FILE.write_text("4242")
        with mock.patch("os.stat", return_value=_root_stat(0)), _block_pid_read():
            self.assertTrue(router._engine_runs_as_root())

    def test_readable_root_pid_confirmed_by_ps(self):
        router.PID_FILE.write_text("4242")
        with mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch.object(router.subprocess, "run") as run:
                run.return_value.stdout = "root\n"
                self.assertTrue(router._engine_runs_as_root())
        self.assertEqual(run.call_args.args[0], ["ps", "-o", "user=", "-p", "4242"])

    def test_root_pid_but_recycled_process_is_not_root_engine(self):
        router.PID_FILE.write_text("4242")
        with mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch.object(router.subprocess, "run") as run:
                run.return_value.stdout = "alice\n"
                self.assertFalse(router._engine_runs_as_root())

    def test_never_root_on_windows(self):
        router.PID_FILE.write_text("4242")
        with mock.patch("os.name", "nt"):
            self.assertFalse(router._engine_runs_as_root())


class NeedsElevationTests(unittest.TestCase):
    """Proxy-mode engine commands elevate only while the engine runs as root."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        _relocate(router, root)
        self.addCleanup(self.tmp.cleanup)
        self.platform = mock.patch.object(router.sys, "platform", "darwin")
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.euid = mock.patch.object(router.os, "geteuid", return_value=501)
        self.euid.start()
        self.addCleanup(self.euid.stop)
        self.tty = mock.patch.object(router.sys.stdin, "isatty", return_value=True)
        self.tty.start()
        self.addCleanup(self.tty.stop)
        os.environ.pop("PROXY_ROUTER_ELEVATED", None)
        router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
        router.MODE_FILE.write_text("proxy")

    def _args(self, cmd, action=None):
        return type("A", (), {"cmd": cmd, "action": action})()

    def _root_engine(self):
        router.PID_FILE.write_text("4242")
        patcher = mock.patch("os.stat", return_value=_root_stat(0))
        patcher.start()
        self.addCleanup(patcher.stop)
        blocker = _block_pid_read()
        blocker.start()
        self.addCleanup(blocker.stop)

    def test_proxy_mode_stop_elevates_when_engine_root_owned(self):
        self._root_engine()
        self.assertTrue(router._needs_elevation(self._args("stop")))

    def test_proxy_mode_start_elevates_when_engine_root_owned(self):
        self._root_engine()
        self.assertTrue(router._needs_elevation(self._args("start")))

    def test_proxy_mode_engine_commands_stay_user_level_when_engine_user_owned(self):
        router.PID_FILE.write_text("4242")
        with mock.patch("os.stat", return_value=_root_stat(501)):
            for cmd in ("start", "stop", "ensure", "reload", "rotate", "add", "remove"):
                self.assertFalse(router._needs_elevation(self._args(cmd)), cmd)

    def test_proxy_mode_readonly_commands_never_elevate_even_for_root_engine(self):
        self._root_engine()
        for cmd, action in (("status", None), ("routes", None), ("vpn", "status")):
            self.assertFalse(router._needs_elevation(self._args(cmd, action)), cmd)

    def test_background_tick_never_elevates_without_sudoers_grant(self):
        """keepalive/launchd ticks have no TTY and must never pop the admin
        dialog on every interval, even when the engine runs as root."""
        self._root_engine()
        with mock.patch.object(router.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(router, "_sudoers_installed", return_value=False):
            self.assertFalse(router._needs_elevation(self._args("stop")))
            self.assertFalse(router._needs_elevation(self._args("start")))

    def test_background_tick_lifts_when_sudoers_grant_installed(self):
        self._root_engine()
        with mock.patch.object(router.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(router, "_sudoers_installed", return_value=True):
            self.assertTrue(router._needs_elevation(self._args("stop")))


class EngineStopMessageTests(unittest.TestCase):
    """The root-owned-engine error must name the one-time fix (issue #12)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        _relocate(router, root)
        self.addCleanup(self.tmp.cleanup)

    def test_unreadable_pid_file_message_advises_elevate_install(self):
        router.PID_FILE.write_text("4242")
        with _block_pid_read(), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router.engine_stop()
        self.assertEqual(rc, 1)
        self.assertIn("elevate install", err.getvalue())
        self.assertIn("sudo python3 router.py stop", err.getvalue())
        self.assertTrue(router.PID_FILE.is_file())  # live engine pid kept

    def test_kill_permission_error_message_advises_elevate_install(self):
        router.PID_FILE.write_text("4242")
        with mock.patch.object(router, "_pid_matches", return_value=True), \
             mock.patch.object(router.os, "kill", side_effect=PermissionError), \
             mock.patch.object(router.time, "sleep"), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router.engine_stop()
        self.assertEqual(rc, 1)
        self.assertIn("elevate install", err.getvalue())
        self.assertTrue(router.PID_FILE.is_file())


class ElevateFallbackTests(unittest.TestCase):
    """`_elevate` must fall back to the admin dialog when `sudo -n`
    DENIES (stale grant missing a command shape added later, e.g.
    `start`/`stop`), but return a real elevated-command failure unchanged
    (no dialog for an engine error)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        _relocate(router, root)
        self.addCleanup(self.tmp.cleanup)
        router.sys.argv = ["router.py", "stop"]

    def _probe(self, returncode: int, stderr: str = ""):
        return type("P", (), {"returncode": returncode, "stderr": stderr})()

    def test_sudo_denial_falls_back_to_admin_dialog(self):
        with mock.patch.object(router, "_sudoers_installed", return_value=True), \
             mock.patch.object(router.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run",
                               return_value=self._probe(1, "a password is required")):
            rc = router._elevate()
        self.assertEqual(rc, 42)
        dialog.assert_called_once()

    def test_sudoers_denial_token_falls_back_to_admin_dialog(self):
        with mock.patch.object(router, "_sudoers_installed", return_value=True), \
             mock.patch.object(router.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run",
                               return_value=self._probe(1, "alice is not in the sudoers file")):
            rc = router._elevate()
        self.assertEqual(rc, 42)
        dialog.assert_called_once()

    def test_elevated_command_failure_returns_rc_without_dialog(self):
        with mock.patch.object(router, "_sudoers_installed", return_value=True), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run",
                               return_value=self._probe(3, "router: engine failed to start")):
            rc = router._elevate()
        self.assertEqual(rc, 3)
        dialog.assert_not_called()

    def test_success_returns_zero_without_dialog(self):
        with mock.patch.object(router, "_sudoers_installed", return_value=True), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run", return_value=self._probe(0)):
            rc = router._elevate()
        self.assertEqual(rc, 0)
        dialog.assert_not_called()

    def test_non_tty_denial_never_opens_admin_dialog(self):
        # A stale grant whose probed shape is denied must NOT pop the
        # admin dialog from a keepalive/launchd tick (no TTY).
        with mock.patch.object(router, "_sudoers_installed", return_value=True), \
             mock.patch.object(router.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run",
                               return_value=self._probe(1, "a password is required")):
            rc = router._elevate()
        self.assertEqual(rc, 1)
        dialog.assert_not_called()

    def test_non_tty_without_grant_never_opens_admin_dialog(self):
        with mock.patch.object(router, "_sudoers_installed", return_value=False), \
             mock.patch.object(router.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(router, "_elevate_macos", return_value=42) as dialog:
            rc = router._elevate()
        self.assertEqual(rc, 1)
        dialog.assert_not_called()


if __name__ == "__main__":
    unittest.main()
