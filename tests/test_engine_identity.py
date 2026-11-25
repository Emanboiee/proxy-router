"""Pure behavior tests for the engine.py identity leaf (issue #66 E1 PR 1).

Imports engine directly — no router involvement. Every assertion is on
observable behavior with a concrete input, so a corrupted body fails.
"""
import subprocess
import unittest
from unittest import mock

import engine


class ExpectedCommandTests(unittest.TestCase):
    def test_resolver_none_returns_none(self):
        self.assertIsNone(engine.expected_engine_command(lambda: None, "/root/sing-box.json"))

    def test_resolver_path_builds_exact_command(self):
        got = engine.expected_engine_command(lambda: "/opt/homebrew/bin/sing-box", "/root/sing-box.json")
        self.assertEqual(got, "/opt/homebrew/bin/sing-box run -c /root/sing-box.json")


class ArgvCacheTests(unittest.TestCase):
    def setUp(self):
        engine._argv_cache = None
        engine._argv_cache_source = None

    def test_none_command_returns_none(self):
        self.assertIsNone(engine.expected_engine_argv(None))

    def test_split_is_exact(self):
        self.assertEqual(
            engine.expected_engine_argv("/opt/bin/sing-box run -c /root/sing-box.json"),
            ["/opt/bin/sing-box", "run", "-c", "/root/sing-box.json"],
        )

    def test_cache_hit_returns_same_value(self):
        cmd = "/opt/bin/sing-box run -c /root/sing-box.json"
        first = engine.expected_engine_argv(cmd)
        second = engine.expected_engine_argv(cmd)
        self.assertEqual(first, second)

    def test_new_command_invalidates_cache(self):
        a = engine.expected_engine_argv("/a run -c /x")
        b = engine.expected_engine_argv("/b run -c /y")
        self.assertEqual(a, ["/a", "run", "-c", "/x"])
        self.assertEqual(b, ["/b", "run", "-c", "/y"])

    def test_invalid_quote_returns_none_and_keeps_source(self):
        self.assertIsNone(engine.expected_engine_argv('/a "unterminated'))
        # source unchanged after ValueError, so the previous valid cache survives
        self.assertIsNone(engine._argv_cache_source)


class CommandIsOurEngineTests(unittest.TestCase):
    def test_empty_argv_never_matches(self):
        self.assertFalse(engine.command_is_our_engine("/a run -c /x", None))
        self.assertFalse(engine.command_is_our_engine("/a run -c /x", []))

    def test_exact_match(self):
        self.assertTrue(engine.command_is_our_engine(
            "/a run -c /x", ["/a", "run", "-c", "/x"]))

    def test_suffix_attack_does_not_match(self):
        self.assertFalse(engine.command_is_our_engine(
            "/a run -c /x.evil", ["/a", "run", "-c", "/x"]))

    def test_invalid_cmd_returns_false(self):
        self.assertFalse(engine.command_is_our_engine('/a "unterminated', ["/a"]))


class FindPidsTests(unittest.TestCase):
    def test_empty_argv_fails_closed(self):
        with self.assertRaises(engine.EngineIdentityError):
            engine.find_our_engine_pids(None, lambda: "/a", lambda c: True)

    @mock.patch.object(engine.os, "name", "nt")
    def test_windows_raises(self):
        with self.assertRaises(engine.EngineIdentityError):
            engine.find_our_engine_pids(["/a"], lambda: "/a", lambda c: True)

    def test_bad_ps_rc_raises(self):
        with mock.patch.object(engine.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1, "", "")):
            with self.assertRaises(engine.EngineIdentityError):
                engine.find_our_engine_pids(["/a"], lambda: "/a", lambda c: True)

    def test_finds_exact_pid_and_skips_unrelated(self):
        out = "100 0 /a run -c /x\n101 0 python something\n1 0 /a run -c /x\n"
        with mock.patch.object(engine.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, out, "")):
            got = engine.find_our_engine_pids(
                ["/a", "run", "-c", "/x"], lambda: "/a",
                lambda c: c.strip() == "/a run -c /x")
        self.assertEqual(got, [100])


class PidMatchesTests(unittest.TestCase):
    def test_none_command_false(self):
        self.assertFalse(engine.pid_matches(4242, None, lambda c: True))

    def test_string_pid_injection_rejected(self):
        # A str pid must never reach PowerShell interpolation.
        self.assertFalse(engine.pid_matches("1); Write-Output INJECTED; (Get-Process", "/a run -c /x", lambda c: True))

    def test_linux_exact(self):
        with mock.patch.object(engine.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "501 /a run -c /x", "")):
            self.assertTrue(engine.pid_matches(4242, "/a run -c /x",
                                               lambda c: c == "/a run -c /x"))

    def test_non_digit_uid_false(self):
        with mock.patch.object(engine.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "root /a run -c /x", "")):
            self.assertFalse(engine.pid_matches(4242, "/a run -c /x", lambda c: True))


class TerminatePidTests(unittest.TestCase):
    def test_no_match_does_not_kill(self):
        with mock.patch.object(engine.os, "kill") as kill:
            self.assertFalse(engine.terminate_pid(4242, lambda p: False))
        kill.assert_not_called()

    def test_term_then_kill_sequencing(self):
        # A fake clock that advances a fixed step per call drives both grace
        # loops quickly. matches() stays True throughout, so after TERM the
        # full grace elapses and SIGKILL must fire.
        now = [0.0]

        def tick():
            now[0] += 0.1
            return now[0]

        with mock.patch.object(engine.os, "kill") as kill, \
             mock.patch.object(engine.time, "sleep"), \
             mock.patch.object(engine.time, "monotonic", side_effect=tick):
            result = engine.terminate_pid(4242, lambda p: True)
        self.assertTrue(result)
        signals = [c.args[1] for c in kill.call_args_list]
        self.assertEqual(signals[0], 15)  # SIGTERM
        self.assertIn(9, signals)        # SIGKILL after grace

    def test_process_lookup_error_false(self):
        with mock.patch.object(engine.os, "kill", side_effect=ProcessLookupError):
            self.assertFalse(engine.terminate_pid(4242, lambda p: True))


if __name__ == "__main__":
    unittest.main()
