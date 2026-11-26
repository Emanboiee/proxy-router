"""provider_upstream: activation policy, guards, and CLI contract.

All IO is injected, so these exercise the decisions without a socket, a spawn,
or a real provider table.
"""
import json
import tempfile
import types
import unittest
from pathlib import Path

import provider_upstream


class FakeRunner:
    """Records argv and replays a queued returncode/stdout/stderr."""

    def __init__(self, returncode=0, stderr="", stdout=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout

    def __call__(self, argv, *, timeout=None):
        self.calls.append({"argv": list(argv), "timeout": timeout})
        return types.SimpleNamespace(returncode=self.returncode,
                                     stdout=self.stdout, stderr=self.stderr)


class Harness:
    """An Upstreams bound to a temp root, with a scriptable probe and clock."""

    def __init__(self, providers, *, listening=False, runner=None, now=1000,
                 comes_up_after_run=False):
        """...

        ``comes_up_after_run`` models an upstream that is DOWN until activation
        actually works: the probe stays False while no command has run, then
        turns True once one returns 0. Without it the probe is a static flag,
        so flipping ``listen`` before calling ``activate``/``ensure_all`` only
        proves "already listening" and the command is never run.
        """
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = now
        self.listen = listening
        self.runner = runner or FakeRunner()
        self.writes = []

        def write(path, text, mode):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            self.writes.append((str(path), mode))

        def probe(host, port, timeout):
            return self.listen

        def upstream_of(name):
            spec = providers.get(name, {}).get("socks5")
            if not isinstance(spec, dict):
                raise ValueError("not socks5")
            return spec["host"], int(spec["port"])

        if comes_up_after_run:
            inner = self.runner

            def bring_up(argv, *, timeout=None):
                # A successful command is what makes the upstream answer.
                result = inner(argv, timeout=timeout)
                if getattr(result, "returncode", 1) == 0:
                    self.listen = True
                return result
            runner_for_upstreams = bring_up
        else:
            runner_for_upstreams = self.runner

        self.upstreams = provider_upstream.Upstreams(
            providers=providers, root=self.root, write=write,
            is_proxy=lambda name: isinstance(providers.get(name, {}).get("socks5"), dict),
            upstream_of=upstream_of, probe=probe, runner=runner_for_upstreams,
            sleep=lambda _s: None, now=lambda: self.now)

    def close(self):
        self.tmp.cleanup()

    def state(self, name):
        path = self.root / "state" / "upstream" / f"{name}.json"
        return json.loads(path.read_text()) if path.is_file() else {}


CFG = {"cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181},
                      "activate": ["warp-cli", "--accept-tos", "connect"]}}


class ValidArgvTests(unittest.TestCase):
    def test_accepts_argument_list(self):
        self.assertTrue(provider_upstream.valid_argv(["warp-cli", "connect"]))
        self.assertTrue(provider_upstream.valid_argv(["cmd", "--flag=1"]))

    def test_rejects_non_list_empty_and_control_characters(self):
        for value in (None, "warp-cli connect", [], ["cmd", ""], ["cmd\nx"], ["cmd", 7]):
            with self.subTest(value=value):
                self.assertFalse(provider_upstream.valid_argv(value))


class ProviderKeyErrorTests(unittest.TestCase):
    def test_accepts_valid_keys(self):
        self.assertIsNone(provider_upstream.provider_key_error(
            {"activate": ["warp-cli", "connect"], "upstream_required": True,
             "activate_cooldown_seconds": 60}))

    def test_rejects_each_bad_key(self):
        cases = [
            ({"activate": "warp-cli connect"}, "activate"),
            ({"deactivate": []}, "deactivate"),
            ({"upstream_required": "yes"}, "upstream_required"),
            ({"activate_cooldown_seconds": -1}, "activate_cooldown_seconds"),
            ({"activate_max_attempts": "two"}, "activate_max_attempts"),
            ({"upstream_timeout_ms": -5}, "upstream_timeout_ms"),
        ]
        for entry, expected in cases:
            with self.subTest(entry=entry):
                reason = provider_upstream.provider_key_error(entry)
                self.assertIsNotNone(reason)
                self.assertIn(expected, reason)


class GuardTests(unittest.TestCase):
    def test_cooldown_blocks_until_elapsed(self):
        state = {"last_attempt_at": 1000}
        self.assertEqual(
            provider_upstream.guard_reason(state, now=1010, cooldown=120, cap=2, window=600),
            {"reason": "activation cooling down", "retry_in_seconds": 110})
        self.assertIsNone(
            provider_upstream.guard_reason(state, now=1200, cooldown=120, cap=2, window=600))

    def test_attempt_cap_blocks_within_window(self):
        state = {"attempts": [1000, 1100]}
        self.assertEqual(
            provider_upstream.guard_reason(state, now=1150, cooldown=0, cap=2, window=600),
            {"reason": "activation attempt cap reached"})
        self.assertIsNone(
            provider_upstream.guard_reason(state, now=2000, cooldown=0, cap=2, window=600))

    def test_record_attempt_trims_to_window_and_caps_history(self):
        state = {"attempts": [1, 2, 3]}
        recorded = provider_upstream.record_attempt(state, now=5000, error=None, window=600)
        self.assertEqual(recorded["last_attempt_at"], 5000)
        self.assertEqual(recorded["attempts"], [5000])
        self.assertIsNone(recorded["last_error"])


class ActivateTests(unittest.TestCase):
    def test_already_listening_is_a_noop(self):
        h = Harness(CFG, listening=True)
        try:
            result = h.upstreams.activate("cloudflare")
            self.assertFalse(result["attempted"])
            self.assertTrue(result["listening"])
            self.assertEqual(h.runner.calls, [])
        finally:
            h.close()

    def test_no_command_configured(self):
        h = Harness({"cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}})
        try:
            result = h.upstreams.activate("cloudflare")
            self.assertFalse(result["attempted"])
            self.assertIn("no activate command", result["reason"])
        finally:
            h.close()

    def test_not_a_proxy_provider(self):
        h = Harness(CFG)
        try:
            result = h.upstreams.activate("proton")
            self.assertFalse(result["attempted"])
            self.assertIn("not a proxy-backed", result["reason"])
        finally:
            h.close()

    def test_successful_activation_marks_listening_and_persists(self):
        h = Harness(CFG, runner=FakeRunner(returncode=0), comes_up_after_run=True)
        try:
            result = h.upstreams.activate("cloudflare")
            self.assertTrue(result["listening"])
            self.assertEqual(h.runner.calls[0]["argv"],
                             ["warp-cli", "--accept-tos", "connect"])
            state = h.state("cloudflare")
            self.assertEqual(state["activated_at"], h.now)
            self.assertIsNone(state["last_error"])
            self.assertTrue(all(mode == 0o600 for _path, mode in h.writes))
        finally:
            h.close()

    def test_failed_command_does_not_mark_listening(self):
        h = Harness(CFG, runner=FakeRunner(returncode=1, stderr="could not connect"))
        try:
            result = h.upstreams.activate("cloudflare")
            self.assertTrue(result["attempted"])
            self.assertFalse(result["listening"])
            self.assertIn("could not connect", result["error"])
            self.assertIn("could not connect", h.state("cloudflare")["last_error"])
        finally:
            h.close()

    def test_cooldown_skips_second_attempt(self):
        h = Harness(CFG, runner=FakeRunner(returncode=0))
        try:
            h.listen = False
            h.upstreams.activate("cloudflare")
            self.assertEqual(len(h.runner.calls), 1)
            h.now += 5
            skipped = h.upstreams.activate("cloudflare")
            self.assertFalse(skipped["attempted"])
            self.assertIn("cooling down", skipped["reason"])
            self.assertEqual(len(h.runner.calls), 1)
            forced = h.upstreams.activate("cloudflare", force=True)
            self.assertTrue(forced["attempted"])
            self.assertEqual(len(h.runner.calls), 2)
        finally:
            h.close()

    def test_attempt_cap_stops_a_permanently_broken_provider(self):
        cfg = {"cloudflare": dict(CFG["cloudflare"], activate_cooldown_seconds=0,
                                  activate_max_attempts=2, activate_window_seconds=600)}
        h = Harness(cfg, runner=FakeRunner(returncode=1, stderr="nope"))
        try:
            h.listen = False
            self.assertTrue(h.upstreams.activate("cloudflare")["attempted"])
            self.assertTrue(h.upstreams.activate("cloudflare")["attempted"])
            capped = h.upstreams.activate("cloudflare")
            self.assertFalse(capped["attempted"])
            self.assertIn("attempt cap", capped["reason"])
            self.assertEqual(len(h.runner.calls), 2)
        finally:
            h.close()

    def test_runner_failure_is_attempted_not_crash(self):
        def boom(argv, *, timeout=None):
            raise OSError("spawn failed")

        h = Harness(CFG, runner=boom)
        try:
            result = h.upstreams.activate("cloudflare")
            self.assertTrue(result["attempted"])
            self.assertFalse(result["listening"])
            self.assertIn("OSError", result["error"])
        finally:
            h.close()


class ListeningTests(unittest.TestCase):
    def test_probe_exception_is_not_listening(self):
        def boom(_host, _port, _timeout):
            raise RuntimeError("socket blocked")

        h = Harness(CFG)
        try:
            h.upstreams._probe = boom
            self.assertFalse(h.upstreams.listening("cloudflare"))
        finally:
            h.close()

    def test_status_reports_state(self):
        h = Harness(CFG, listening=True)
        try:
            report = h.upstreams.status("cloudflare")
            self.assertEqual((report["host"], report["port"]), ("127.0.0.1", 2181))
            self.assertTrue(report["listening"])
            self.assertFalse(h.upstreams.status("proton")["known"])
        finally:
            h.close()


class EnsureAllTests(unittest.TestCase):
    def test_activates_only_configured_down_providers(self):
        providers = {
            "cloudflare": dict(CFG["cloudflare"]),
            "plain": {"socks5": {"host": "127.0.0.1", "port": 2182}},
        }
        h = Harness(providers, runner=FakeRunner(returncode=0), comes_up_after_run=True)
        try:
            events = h.upstreams.ensure_all()
            self.assertEqual(events, [{"provider": "cloudflare", "state": "activated"}])
            self.assertEqual(len(h.runner.calls), 1)
        finally:
            h.close()

    def test_logged_variant_reports_failures(self):
        cfg = {"cloudflare": dict(CFG["cloudflare"], activate_cooldown_seconds=0)}
        h = Harness(cfg, runner=FakeRunner(returncode=1, stderr="off"))
        try:
            lines = []
            recovered = h.upstreams.ensure_all_logged(lines.append)
            self.assertEqual(recovered, [])
            self.assertEqual(len(lines), 1)
            self.assertIn("still down", lines[0])
        finally:
            h.close()


class CliTests(unittest.TestCase):
    def _args(self, **kw):
        # defaults first, then overrides: callers pass provider_action/json
        # positionally-by-keyword and would otherwise collide with these.
        defaults = dict(provider_action=None, name=None, json=False,
                        force=False, ensure=False)
        defaults.update(kw)
        return types.SimpleNamespace(**defaults)

    def test_activate_exit_codes(self):
        h = Harness(CFG, runner=FakeRunner(returncode=0))
        try:
            h.listen = True
            out = []
            rc = provider_upstream.run_cli(
                self._args(provider_action="activate", name="cloudflare"),
                h.upstreams, is_proxy=lambda n: n == "cloudflare", out=out.append)
            self.assertEqual(rc, 0)
            self.assertIn("listening", out[0])
        finally:
            h.close()

    def test_upstream_rejects_non_proxy_provider(self):
        h = Harness(CFG)
        try:
            err = []
            rc = provider_upstream.run_cli(
                self._args(provider_action="upstream", name="proton"),
                h.upstreams, is_proxy=lambda n: n == "cloudflare", err=err.append)
            self.assertEqual(rc, 1)
            self.assertIn("not proxy-backed", err[0])
        finally:
            h.close()

    def test_upstream_json_reports_every_proxy_provider(self):
        h = Harness(CFG, listening=True)
        try:
            out = []
            rc = provider_upstream.run_cli(
                self._args(provider_action="upstream", json=True),
                h.upstreams, is_proxy=lambda n: n == "cloudflare", out=out.append)
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(out[0])["cloudflare"]["listening"])
        finally:
            h.close()

    def test_unknown_action_errors(self):
        h = Harness(CFG)
        try:
            err = []
            rc = provider_upstream.run_cli(self._args(provider_action="bogus"),
                                           h.upstreams, is_proxy=lambda _n: True,
                                           err=err.append)
            self.assertEqual(rc, 2)
            self.assertTrue(err)
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
