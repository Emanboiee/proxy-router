"""Integration tests for examples/keepalive.sh.

Run the real script against a fake router.py and a fake sleep (both on PATH)
so the loop is fast and deterministic. The fake router is argv-aware (only
`ensure` calls advance the ensure counter) and logs every invocation, so the
tests can assert on:

- exponential backoff (ensure fails on chosen call numbers),
- the periodic egress-check cadence (PROXY_KEEPALIVE_PROBE_EVERY),
- two-strike dead detection + auto-rotation,
- the rotation storm guard (MAX_ROTATIONS per STORM_WINDOW),
- reset-on-success, and the boot self-test.
"""
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KEEPALIVE_SRC = REPO / "examples" / "keepalive.sh"

FAKE_ROUTER = r"""#!/usr/bin/env bash
cmd="${1:-}"
logger="${FAKE_ROUTER_LOG:-}"
if [ -n "$logger" ]; then printf '%s\n' "$*" >> "$logger"; fi
case "$cmd" in
  ensure)
    n=$(cat "${FAKE_ROUTER_ENSURE_COUNT:-/dev/null}" 2>/dev/null || echo 0)
    n=$((n + 1))
    printf '%s\n' "$n" > "${FAKE_ROUTER_ENSURE_COUNT}"
    if [ -n "${FAKE_ROUTER_FAIL_ENSURES:-}" ]; then
      case ",${FAKE_ROUTER_FAIL_ENSURES}," in
        *",$n,"*) exit 1 ;;
      esac
    fi
    exit 0
    ;;
  egress)
    if [ -n "${FAKE_ROUTER_EGRESS_FILE:-}" ] && [ -f "$FAKE_ROUTER_EGRESS_FILE" ]; then
      state=$(cat "$FAKE_ROUTER_EGRESS_FILE")
    else
      state="${FAKE_ROUTER_EGRESS:-alive}"
    fi
    case "$state" in
      dead)
        echo "proton: dead (a; probe connection)"
        echo "dead: proton"
        exit 1
        ;;
      *)
        echo "proton: alive (a)"
        exit 0
        ;;
    esac
    ;;
  rotate)
    if [ -n "${FAKE_ROUTER_ROTATE_FAIL:-}" ]; then exit 1; fi
    exit 0
    ;;
  failover)
    if [ "${3:-}" = "status" ]; then
      configured="${FAKE_ROUTER_FALLBACK_CONFIGURED:-cloudflare}"
      if [ -n "${FAKE_ROUTER_FALLBACK_ACTIVE:-}" ]; then
        echo "fallback proton: configured=$configured active=cloudflare"
      else
        echo "fallback proton: configured=$configured active=none"
      fi
    fi
    exit 0
    ;;
esac
exit 0
"""

FAKE_SLEEP = r"""#!/usr/bin/env bash
printf '%s\n' "$1" >> "${SLEEP_LOG:-/dev/null}"
"""


class KeepaliveHarness:
    """Run the real keepalive.sh against fake router.py/sleep on PATH."""

    def __init__(self, *, interval="1", fail_ensures="", egress="alive",
                 probe_every="4", dead_strikes="2", storm_window="600",
                 max_rotations="2", rotate_fail=False, fallback_active=False,
                 fallback_configured="cloudflare"):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "bin").mkdir()
        sleep_bin = self.root / "bin" / "sleep"
        sleep_bin.write_text(FAKE_SLEEP)
        sleep_bin.chmod(0o755)
        router_bin = self.root / "router.py"
        router_bin.write_text(FAKE_ROUTER)
        router_bin.chmod(0o755)
        target = self.root / "keepalive.sh"
        target.write_text(KEEPALIVE_SRC.read_text())
        target.chmod(0o755)
        self.log = self.root / "router.log"
        self.count = self.root / "count"
        self.sleep_log = self.root / "sleeps.log"
        self.egress_file = self.root / "egress.state"
        self.egress_file.write_text(egress)
        env = dict(os.environ)
        env["PATH"] = f"{self.root / 'bin'}:" + env["PATH"]
        env["PROXY_KEEPALIVE_INTERVAL"] = interval
        env["PROXY_KEEPALIVE_MAX_BACKOFF"] = "8"
        env["PROXY_KEEPALIVE_PROBE_EVERY"] = probe_every
        env["PROXY_KEEPALIVE_DEAD_STRIKES"] = dead_strikes
        env["PROXY_KEEPALIVE_STORM_WINDOW"] = storm_window
        env["PROXY_KEEPALIVE_MAX_ROTATIONS"] = max_rotations
        env["SLEEP_LOG"] = str(self.sleep_log)
        env["FAKE_ROUTER_LOG"] = str(self.log)
        env["FAKE_ROUTER_ENSURE_COUNT"] = str(self.count)
        env["FAKE_ROUTER_EGRESS_FILE"] = str(self.egress_file)
        if rotate_fail:
            env["FAKE_ROUTER_ROTATE_FAIL"] = "1"
        if fallback_active:
            env["FAKE_ROUTER_FALLBACK_ACTIVE"] = "1"
        env["FAKE_ROUTER_FALLBACK_CONFIGURED"] = fallback_configured
        if fail_ensures:
            env["FAKE_ROUTER_FAIL_ENSURES"] = fail_ensures
        self.env = env
        self.proc = subprocess.Popen([str(target)], env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True,
                                     start_new_session=(os.name == "posix"))

    def lines(self) -> list[str]:
        if not self.log.is_file():
            return []
        return [l for l in self.log.read_text().splitlines() if l.strip()]

    def set_egress(self, state: str) -> None:
        self.egress_file.write_text(state)

    def wait_lines(self, count: int, timeout: float = 20.0) -> list[str]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            lines = self.lines()
            if len(lines) >= count:
                return lines
            time.sleep(0.05)
        return self.lines()

    def close(self) -> None:
        if getattr(self, "_closed", False):
            return
        self._closed = True
        if os.name == "posix":
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            self.proc.terminate()
        try:
            self.out, self.err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                self.proc.kill()
            self.out, self.err = self.proc.communicate()
        self._tmp.cleanup()


class KeepaliveBackoffTests(unittest.TestCase):
    def test_backoff_grows_then_recovers_and_caps(self):
        h = KeepaliveHarness(interval="2", fail_ensures="3,4")
        try:
            deadline = time.time() + 20
            while time.time() < deadline:
                if h.sleep_log.is_file() and len(h.sleep_log.read_text().split()) >= 8:
                    break
                time.sleep(0.05)
            durations = [int(x) for x in h.sleep_log.read_text().split()] if h.sleep_log.is_file() else []
            self.assertGreaterEqual(len(durations), 8, f"loop made too few waits: {durations}")
            self.assertIn(4, durations, f"backoff to 4 missing: {durations}")
            self.assertIn(8, durations, f"backoff to 8 (cap) missing: {durations}")
            self.assertIn(2, durations, f"recovery to base missing: {durations}")
            self.assertLessEqual(max(durations), 8, "backoff must respect MAX_BACKOFF")
            last_cap = max(i for i, d in enumerate(durations) if d == 8)
            self.assertTrue(any(d == 2 for d in durations[last_cap + 1:]),
                            f"no recovery after cap: {durations}")
        finally:
            h.close()


class KeepaliveEgressCheckTests(unittest.TestCase):
    def test_boot_self_test_healthy_logs_and_never_rotates(self):
        h = KeepaliveHarness(probe_every="2")
        try:
            lines = h.wait_lines(20)
            h.close()
            self.assertIn("router: boot self-test ok", h.out,
                          f"healthy boot line missing:\nstdout={h.out!r}\nstderr={h.err!r}")
            # The scheduled-rotation check (`rotate --if-due`) runs every
            # healthy tick and self-gates on its interval; the boot self-test
            # must never trigger an EMERGENCY provider rotation.
            rotates = [l for l in lines if l.startswith("rotate proton")]
            self.assertEqual(rotates, [])
            # cadence: periodic checks every PROBE_EVERY(2) ensures after boot.
            # `rotate --if-due` and `egress sweep` entries are tick noise, so
            # measure gaps on the filtered list.
            checks = [l for l in lines if l == "egress check"]
            self.assertGreaterEqual(len(checks), 4, f"too few checks: {lines}")
            ticks = [l for l in lines if l not in {"rotate --if-due", "egress sweep --json"}]
            check_lines = [i for i, l in enumerate(ticks) if l == "egress check"]
            gaps = [b - a for a, b in zip(check_lines, check_lines[1:])]
            # every PROBE_EVERY ensures triggers a check; log distance is
            # PROBE_EVERY + 1 because the ensure line sits between checks
            self.assertTrue(all(g == 3 for g in gaps), f"cadence off: {gaps}")
        finally:
            h.close()

    def test_boot_self_test_dead_rotates_once_then_storm_guard_blocks(self):
        h = KeepaliveHarness(egress="dead", probe_every="1", storm_window="3600",
                             max_rotations="1")
        try:
            lines = h.wait_lines(40)
            h.close()
            rotates = [l for l in lines if l.startswith("rotate proton")]
            self.assertEqual(len(rotates), 1,
                             f"storm guard must cap rotations at 1: {rotates}")
            self.assertIn("boot self-test: active tunnel is dead", h.err,
                          f"boot warning missing: {h.err!r}")
            self.assertIn("storm guard", h.err,
                          f"storm-guard skip message missing: {h.err!r}")
        finally:
            h.close()

    def test_two_strike_dead_rotation(self):
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="2",
                             storm_window="3600", max_rotations="50")
        try:
            h.wait_lines(30)
            lines = h.lines()
            rotates = [l for l in lines if l.startswith("rotate proton")]
            self.assertGreaterEqual(len(rotates), 3, f"expected repeated rotations: {lines}")
            # consecutive rotates must be separated by >= 2 dead checks
            positions = [i for i, l in enumerate(lines) if l.startswith("rotate proton")]
            for a, b in zip(positions, positions[1:]):
                between = lines[a + 1:b]
                self.assertGreaterEqual(between.count("egress check"), 2,
                                        f"rotated before two dead strikes: {lines}")
        finally:
            h.close()

    def test_success_resets_dead_counter(self):
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="2",
                             storm_window="3600", max_rotations="50")
        try:
            h.wait_lines(14)
            lines = h.lines()
            rotates = [l for l in lines if l.startswith("rotate proton")]
            self.assertGreaterEqual(len(rotates), 2, f"expected rotations: {lines}")
            h.set_egress("alive")
            time.sleep(0.3)  # let the loop hit at least one successful check
            before = len(h.lines())
            h.wait_lines(before + 12)
            tail = h.lines()[before:]
            tail_rotates = [l for l in tail if l.startswith("rotate proton")]
            self.assertEqual(tail_rotates, [], f"rotated AFTER a successful check: {tail}")
        finally:
            h.close()

    def test_storm_guard_window_recovers_with_zero_window(self):
        # STORM_WINDOW=0: every rotation_allowed() call sees the window as
        # expired, so the guard must NOT block (tests the reset path).
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="1",
                             storm_window="0", max_rotations="1")
        try:
            h.wait_lines(20)
            rotates = [l for l in h.lines() if l.startswith("rotate proton")]
            self.assertGreaterEqual(len(rotates), 4, f"expected rotation churn: {rotates}")
        finally:
            h.close()


class KeepaliveFallbackTests(unittest.TestCase):
    def test_dead_active_fallback_is_not_reported_as_recovered(self):
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="1",
                             storm_window="3600", max_rotations="50",
                             rotate_fail=True, fallback_active=True)
        try:
            lines = h.wait_lines(20)
            h.close()
            self.assertIn("failover proton status", lines)
            self.assertNotIn("failover proton on --reason timeout", lines)
            self.assertIn("already active; waiting for the next dead check", h.err)
        finally:
            h.close()

    def test_failed_rotation_without_fallback_is_backed_off(self):
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="1",
                             storm_window="3600", max_rotations="1",
                             rotate_fail=True, fallback_configured="none")
        try:
            lines = h.wait_lines(20)
            h.close()
            self.assertEqual([l for l in lines if l.startswith("rotate proton")],
                             ["rotate proton --reason timeout"])
            self.assertNotIn("failover proton on --reason timeout", lines)
            self.assertIn("no configured fallback", h.err)
            self.assertIn("storm guard", h.err)
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
