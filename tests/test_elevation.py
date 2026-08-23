"""Unit tests for the macOS elevation path of router.py (stdlib only)."""
import io
import json
import os
import subprocess
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
    def test_rules_cover_only_exact_root_helper_operations(self):
        rules = router._sudoers_rules("alice", 501)
        lines = rules.strip().splitlines()
        commands = [line.split("NOPASSWD: ", 1)[1] for line in lines if "NOPASSWD:" in line]
        self.assertEqual(len(commands), 5)
        self.assertTrue(all(str(router.PRIVILEGED_HELPER) in command for command in commands))
        self.assertTrue(all("router.py" not in command and "*" not in command for command in commands))
        self.assertEqual(
            {command.rsplit(" ", 2)[-2] for command in commands},
            {"status", "start", "stop", "reload", "uninstall"},
        )


class PrivilegedHelperCommandTests(unittest.TestCase):
    def test_helper_command_is_exact_and_never_executes_checkout_code(self):
        with mock.patch.object(router.os, "getuid", return_value=501):
            command = router._helper_command("reload")

        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertEqual(
            command[2:],
            [
                "/usr/bin/env", "-i", "HOME=/var/empty",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C",
                "/usr/bin/python3", "-I", "-S",
                "/Library/PrivilegedHelperTools/com.proxy-router/current/privileged_helper.py",
                "reload", "501",
            ],
        )
        self.assertNotIn(str(Path(router.__file__).resolve()), command)
        self.assertNotIn(router.sys.executable, command)

    def test_helper_status_executes_exact_status_and_parses_json(self):
        payload = {"installed": True, "running": True, "pid": 4242, "mode": "tun", "schema_version": 1}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with mock.patch.object(router.os, "getuid", return_value=501), \
             mock.patch.object(router.subprocess, "run", return_value=completed) as run:
            status = router._helper_status()

        self.assertEqual(status, payload)
        self.assertEqual(run.call_args.args[0], router._helper_command("status", 501))

    def test_helper_status_sudo_denial_is_absent_not_checkout_fallback(self):
        denied = subprocess.CompletedProcess([], 1, "", "sudo: a password is required")
        with mock.patch.object(router.subprocess, "run", return_value=denied), \
             mock.patch.object(router, "_elevate_macos") as dialog:
            status = router._helper_status()

        self.assertIsNone(status)
        dialog.assert_not_called()

    def test_engine_liveness_and_mode_use_helper_backend_first(self):
        helper_status = {"installed": True, "running": True, "pid": 4242, "mode": "tun", "schema_version": 1}
        with mock.patch.object(router, "_helper_status", return_value=helper_status):
            self.assertTrue(router.engine_alive())
            with mock.patch.object(router, "current_mode", return_value="tun"):
                self.assertTrue(router.engine_mode_consistent())
            with mock.patch.object(router, "current_mode", return_value="proxy"):
                self.assertFalse(router.engine_mode_consistent())

    def test_tun_engine_start_builds_config_then_uses_helper_not_local_spawn(self):
        config = {
            "log": {"level": "info"}, "inbounds": [], "endpoints": [],
            "outbounds": [], "dns": {}, "route": {},
        }
        with mock.patch.object(router, "resolve_sing_box", return_value="/trusted/sing-box"), \
             mock.patch.object(router, "sing_box_at_least", return_value=True), \
             mock.patch.object(router, "build_singbox_config", return_value=(config, {"p": Path("p.conf")})), \
             mock.patch.object(router, "write_sing_box") as write_config, \
             mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "current_mode", return_value="tun"), \
             mock.patch.object(router, "_helper_status", return_value={"installed": True, "running": False}), \
             mock.patch.object(router, "_helper_run", return_value=0) as helper_run, \
             mock.patch.object(router.subprocess, "Popen") as popen, \
             mock.patch.object(router, "engine_stop") as local_stop:
            rc = router.engine_start()

        self.assertEqual(rc, 0)
        write_config.assert_called_once_with(config)
        helper_run.assert_called_once_with("start")
        popen.assert_not_called()
        local_stop.assert_not_called()

    def test_root_backend_stop_and_reload_use_only_helper_lifecycle(self):
        status = {"installed": True, "running": True, "pid": 4242, "mode": "tun", "schema_version": 1}
        with mock.patch.object(router, "_helper_status", return_value=status), \
             mock.patch.object(router, "_helper_run", return_value=0) as helper_run, \
             mock.patch.object(router.os, "kill") as kill:
            self.assertEqual(router.engine_stop(), 0)
        helper_run.assert_called_once_with("stop")
        kill.assert_not_called()

        config = {
            "log": {"level": "info"}, "inbounds": [], "endpoints": [],
            "outbounds": [], "dns": {}, "route": {},
        }
        with mock.patch.object(router, "_helper_status", return_value=status), \
             mock.patch.object(router, "resolve_sing_box", return_value="/trusted/sing-box"), \
             mock.patch.object(router, "sing_box_at_least", return_value=True), \
             mock.patch.object(router, "build_singbox_config", return_value=(config, {"p": Path("p.conf")})), \
             mock.patch.object(router, "write_sing_box"), \
             mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "_helper_run", return_value=0) as helper_run, \
             mock.patch.object(router.os, "kill") as kill:
            self.assertEqual(router.engine_reload(), 0)
        helper_run.assert_called_once_with("reload")
        kill.assert_not_called()


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

    def test_proxy_mode_stop_stays_user_controller_when_helper_owns_engine(self):
        self._root_engine()
        self.assertFalse(router._needs_elevation(self._args("stop")))

    def test_proxy_mode_start_stays_user_controller_when_helper_owns_engine(self):
        self._root_engine()
        self.assertFalse(router._needs_elevation(self._args("start")))

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

    def test_background_tick_with_helper_never_reexecutes_controller_as_root(self):
        self._root_engine()
        with mock.patch.object(router.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(router, "_sudoers_installed", return_value=True):
            self.assertFalse(router._needs_elevation(self._args("stop")))


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
        self.assertIn("safe root-owned helper", err.getvalue())
        self.assertNotIn("sudo python3 router.py", err.getvalue())
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
    """Whole-controller elevation is permanently fail-closed."""

    def test_elevate_never_calls_sudo_or_admin_dialog(self):
        with mock.patch.object(router, "_elevate_macos", return_value=42) as dialog, \
             mock.patch.object(router.subprocess, "run") as run:
            rc = router._elevate()
        self.assertEqual(rc, 1)
        dialog.assert_not_called()
        run.assert_not_called()


class HelperPermissionUxTests(unittest.TestCase):
    """Issue #76: the launchd-autostarted app has no TTY; when its one-time
    elevation grant is missing every action failed with raw sudo jargon and
    no fix. The failure must name the gap and the exact one-time command."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        _relocate(router, root)
        self.addCleanup(self.tmp.cleanup)

    def _denied(self, stderr="sudo: a password is required\n"):
        return subprocess.CompletedProcess([], 1, "", stderr)

    def test_helper_run_denial_prints_actionable_permission_message(self):
        denied = subprocess.CompletedProcess(
            [], 1, "", "sudo: no tty present and no askpass program specified")
        with mock.patch.object(router.subprocess, "run", return_value=denied), \
             mock.patch.object(router.os, "getuid", return_value=501), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router._helper_run("start")
        self.assertEqual(rc, 1)
        text = err.getvalue()
        self.assertIn("startup permission missing", text.lower())
        self.assertIn("elevate install", text)
        self.assertIn("raw error:", text)

    def test_helper_run_genuine_failure_keeps_helper_prefix(self):
        failed = subprocess.CompletedProcess([], 1, "", "boom: engine exploded")
        with mock.patch.object(router.subprocess, "run", return_value=failed), \
             mock.patch.object(router.os, "getuid", return_value=501), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router._helper_run("stop")
        self.assertEqual(rc, 1)
        text = err.getvalue()
        self.assertIn("privileged helper stop failed", text)
        self.assertIn("boom", text)
        self.assertNotIn("permission missing", text.lower())

    def test_denied_reason_classifier(self):
        self.assertEqual(
            router._helper_denied_reason("sudo: a password is required"),
            "not-granted")
        self.assertEqual(
            router._helper_denied_reason("user is not in the sudoers file"),
            "not-granted")
        self.assertIsNone(router._helper_denied_reason("engine exploded"))

    def test_start_without_helper_uses_actionable_not_installed_message(self):
        """The autostarted tray's first Connect hits exactly this path."""
        config = {
            "log": {"level": "info"}, "inbounds": [], "endpoints": [],
            "outbounds": [], "dns": {}, "route": {},
        }
        platform = mock.patch.object(router.sys, "platform", "darwin")
        euid = mock.patch.object(router.os, "geteuid", return_value=501)
        mode = mock.patch.object(router, "current_mode", return_value="tun")
        status = mock.patch.object(router, "_helper_status", return_value=None)
        # CI runners have no sing-box; the permission gate must fire before
        # any binary/version dependency is consulted.
        sing = mock.patch.object(
            router, "resolve_sing_box", return_value=Path("/usr/bin/false"))
        version = mock.patch.object(router, "sing_box_at_least", return_value=True)
        for patcher in (platform, euid, mode, status, sing, version):
            patcher.start()
            self.addCleanup(patcher.stop)
        with mock.patch.object(router, "_helper_run") as helper_run, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router.engine_start()
        self.assertEqual(rc, 1)
        helper_run.assert_not_called()
        text = err.getvalue()
        self.assertIn("startup permission not set up yet", text.lower())
        self.assertIn("launchd", text.lower())
        self.assertIn("elevate install", text)
        self.assertNotIn("TUN/root engine requires", text)

    def test_reload_without_helper_uses_actionable_message(self):
        platform = mock.patch.object(router.sys, "platform", "darwin")
        euid = mock.patch.object(router.os, "geteuid", return_value=501)
        status = mock.patch.object(router, "_helper_status", return_value=None)
        for patcher in (platform, euid, status):
            patcher.start()
            self.addCleanup(patcher.stop)
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = router._elevated_reload()
        self.assertEqual(rc, 1)
        text = err.getvalue()
        self.assertIn("startup permission not set up yet", text.lower())
        self.assertIn("elevate install", text)

    def test_status_json_exposes_elevation_block(self):
        platform = mock.patch.object(router.sys, "platform", "linux")
        euid = mock.patch.object(router.os, "geteuid", return_value=501)
        root_engine = mock.patch.object(
            router, "_engine_runs_as_root", return_value=False)
        sudoers = mock.patch.object(router, "_sudoers_installed",
                                    return_value=True)
        report = mock.patch.object(
            router, "_status_report", return_value=(0, "up"))
        for patcher in (platform, euid, root_engine, sudoers, report):
            patcher.start()
            self.addCleanup(patcher.stop)
        data = router.status_json()
        elevation = data["elevation"]
        self.assertFalse(elevation["root_engine"])
        self.assertTrue(elevation["sudo_grant"])
        # Non-macOS: helper probe skipped -> installed flag stays False.
        self.assertFalse(elevation["helper_installed"])
        self.assertIn("elevate install", elevation["fix_hint"])

    def test_status_json_darwin_includes_launchd_agents(self):
        platform = mock.patch.object(router.sys, "platform", "darwin")
        euid = mock.patch.object(router.os, "geteuid", return_value=501)
        root_engine = mock.patch.object(
            router, "_engine_runs_as_root", return_value=True)
        sudoers = mock.patch.object(router, "_sudoers_installed",
                                    return_value=False)
        helper = mock.patch.object(
            router, "_helper_status",
            return_value={"installed": False, "error": "denied"})
        listing = subprocess.CompletedProcess(
            [], 0,
            "PID\tStatus\tLabel\n-\t0\tcom.proxy-router.keepalive\n"
            "-\t0\tcom.apple.Finder\n", "")
        probe = mock.patch.object(
            router.subprocess, "run", return_value=listing)
        report = mock.patch.object(
            router, "_status_report", return_value=(0, "up"))
        for patcher in (platform, euid, root_engine, sudoers, helper, probe,
                        report):
            patcher.start()
            self.addCleanup(patcher.stop)
        data = router.status_json()
        elevation = data["elevation"]
        self.assertTrue(elevation["keepalive_agent"])
        self.assertFalse(elevation["tray_agent"])
        self.assertFalse(elevation["helper_installed"])
        self.assertTrue(elevation["root_engine"])

    def test_launchd_agent_state_false_off_darwin(self):
        platform = mock.patch.object(router.sys, "platform", "win32")
        platform.start()
        self.addCleanup(platform.stop)
        self.assertFalse(router._launchd_agent_state("com.proxy-router.tray"))


if __name__ == "__main__":
    unittest.main()
