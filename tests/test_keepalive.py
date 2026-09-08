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
import json
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
  network-status)
    state="${FAKE_ROUTER_NETWORK:-connected}"
    if [ -n "${FAKE_ROUTER_NETWORK_FILE:-}" ] && [ -f "$FAKE_ROUTER_NETWORK_FILE" ]; then
      state=$(cat "$FAKE_ROUTER_NETWORK_FILE")
    fi
    [ "$state" = "disconnected" ] && exit 1
    exit 0
    ;;
  network-disconnect)
    if [ -n "${FAKE_ROUTER_NETWORK_OFF_FILE:-}" ]; then
      mkdir -p "$(dirname "$FAKE_ROUTER_NETWORK_OFF_FILE")"
      : > "$FAKE_ROUTER_NETWORK_OFF_FILE"
    fi
    exit 0
    ;;
  network-reconnect)
    rm -f "${FAKE_ROUTER_NETWORK_OFF_FILE:-/dev/null}"
    exit 0
    ;;
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
    if [ "$3" = "--provider" ]; then
      # per-provider probe used by restore_fallbacks after `failover off`
      if [ -n "${FAKE_ROUTER_EGRESS_FILE:-}" ] && [ -f "$FAKE_ROUTER_EGRESS_FILE" ]; then
        state=$(cat "$FAKE_ROUTER_EGRESS_FILE")
      else
        state="${FAKE_ROUTER_EGRESS:-alive}"
      fi
      case "$state" in
        dead)
          echo "proton: dead (a; probe connection)"
          exit 1
          ;;
        *)
          echo "proton: alive (a)"
          exit 0
          ;;
      esac
    fi
    # While a fallback marker exists the router reports `fallback` instead of
    # probing the primary, so the keepalive never sees a dead primary.
    if [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ] && [ -f "$FAKE_ROUTER_FALLBACK_FILE" ]; then
      echo "proton: fallback (cloudflare)"
      exit 0
    fi
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
  failover)
    if [ "$3" = "off" ]; then
      rm -f "${FAKE_ROUTER_FALLBACK_FILE:-/dev/null}"
    elif [ "$3" = "on" ] && [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ]; then
      printf '%s\n' "$2" > "$FAKE_ROUTER_FALLBACK_FILE"
    fi
    exit 0
    ;;
  rotate)
    exit 0
    ;;
esac
exit 0
"""

FAKE_SLEEP = r"""#!/usr/bin/env bash
printf '%s\n' "$1" >> "${SLEEP_LOG:-/dev/null}"
"""

FAKE_DATE = r"""#!/usr/bin/env bash
if [ "${1:-}" = "+%s" ] && [ -n "${FAKE_DATE_FILE:-}" ] && [ -f "$FAKE_DATE_FILE" ]; then
  cat "$FAKE_DATE_FILE"
  exit 0
fi
exec /bin/date "$@"
"""

# Records every invocation of the PINNED interpreter, then forwards to the
# real target. keepalive.sh must call router.py through this exact path when
# PROXY_ROUTER_PYTHON is set (issue #57).
FAKE_PINNED_PYTHON = r"""#!/usr/bin/env bash
printf '%s\n' "$0 $*" >> "${PINNED_LOG:-/dev/null}"
if [ "${1:-}" = "-" ]; then
  shift
  exec /usr/bin/env python3 - "$@"
fi
exec "$@"
"""


class KeepaliveHarness:
    """Run the real keepalive.sh against fake router.py/sleep on PATH."""

    def __init__(self, *, interval="1", fail_ensures="", egress="alive",
                 probe_every="4", dead_strikes="2", storm_window="600",
                 max_rotations="2", fallback="", root=None, pinned_python="",
                 mode="proxy", network="connected", wake_gap="", clock=None):
        self._tmp = None
        if root is None:
            self._tmp = tempfile.TemporaryDirectory()
            root = Path(self._tmp.name)
        self.root = Path(root)
        self.pinned_python = pinned_python
        (self.root / "bin").mkdir()
        if mode is not None:
            (self.root / "state").mkdir(parents=True, exist_ok=True)
            (self.root / "state" / "mode").write_text(mode)
        if mode == "proxy":
            (self.root / "sing-box.json").write_text(
                json.dumps({"inbounds": [{"type": "mixed"}]})
            )
        sleep_bin = self.root / "bin" / "sleep"
        sleep_bin.write_text(FAKE_SLEEP)
        sleep_bin.chmod(0o755)
        self.clock_file = None
        if clock is not None:
            self.clock_file = self.root / "clock"
            self.clock_file.write_text(str(clock))
            date_bin = self.root / "bin" / "date"
            date_bin.write_text(FAKE_DATE)
            date_bin.chmod(0o755)
        router_bin = self.root / "router.py"
        router_bin.write_text(FAKE_ROUTER)
        router_bin.chmod(0o755)
        self.pinned_log = self.root / "pinned.log"
        if pinned_python:
            pinned_bin = self.root / "bin" / "pinned-python"
            pinned_bin.write_text(FAKE_PINNED_PYTHON)
            pinned_bin.chmod(0o755)
        target = self.root / "keepalive.sh"
        target.write_text(KEEPALIVE_SRC.read_text())
        target.chmod(0o755)
        self.log = self.root / "router.log"
        self.count = self.root / "count"
        self.sleep_log = self.root / "sleeps.log"
        self.egress_file = self.root / "egress.state"
        self.egress_file.write_text(egress)
        self.fallback_file = self.root / "fallback.state"
        if fallback:
            self.fallback_file.write_text(fallback)
        self.network_file = self.root / "network.state"
        self.network_file.write_text(network)
        self.network_off_file = self.root / "state" / "network-off"
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
        env["FAKE_ROUTER_FALLBACK_FILE"] = str(self.fallback_file)
        env["FAKE_ROUTER_NETWORK_FILE"] = str(self.network_file)
        env["FAKE_ROUTER_NETWORK_OFF_FILE"] = str(self.network_off_file)
        if wake_gap:
            env["PROXY_KEEPALIVE_WAKE_GAP"] = wake_gap
        if self.clock_file is not None:
            env["FAKE_DATE_FILE"] = str(self.clock_file)
        if pinned_python:
            pinned_bin = self.root / "bin" / "pinned-python"
            env["PROXY_ROUTER_PYTHON"] = str(pinned_bin)
            env["PINNED_LOG"] = str(self.pinned_log)
        if fail_ensures:
            env["FAKE_ROUTER_FAIL_ENSURES"] = fail_ensures
        self.env = env
        self.proc = subprocess.Popen([str(target)], env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, start_new_session=(os.name == "posix"))

    def lines(self) -> list[str]:
        if not self.log.is_file():
            return []
        return [line for line in self.log.read_text().splitlines() if line.strip()]

    def set_egress(self, state: str) -> None:
        self.egress_file.write_text(state)

    def set_network(self, state: str) -> None:
        self.network_file.write_text(state)

    def advance_clock(self, seconds: int) -> None:
        if self.clock_file is None:
            raise AssertionError("clock simulation is not enabled")
        current = int(self.clock_file.read_text())
        with tempfile.NamedTemporaryFile(
                mode="w", dir=self.clock_file.parent,
                prefix=f".{self.clock_file.name}.", delete=False) as tmp:
            tmp.write(str(current + seconds))
            replacement = Path(tmp.name)
        replacement.replace(self.clock_file)

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
        if os.name == "posix":
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Pinned-interpreter re-exec can leave the child outside the
                # spawned process group; fall back to signalling the direct
                # child (our own process — always permitted).
                self.proc.terminate()
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
                except PermissionError:
                    self.proc.kill()
            else:
                self.proc.kill()
            self.out, self.err = self.proc.communicate()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if self.proc.returncode is None:
            raise RuntimeError("keepalive child did not reach a terminal state")
        from tests.safety import get_session_registry
        get_session_registry().unregister(self.proc.pid)
        if self._tmp is not None:
            self._tmp.cleanup()
        self._closed = True


class KeepaliveHarnessCleanupTests(unittest.TestCase):
    def test_close_reaps_process_closes_pipes_and_unregisters(self):
        from tests.safety import get_session_registry

        h = KeepaliveHarness()
        pid = h.proc.pid
        stdout = h.proc.stdout
        stderr = h.proc.stderr
        h.close()

        self.assertIsNotNone(h.proc.returncode)
        self.assertTrue(stdout is None or stdout.closed)
        self.assertTrue(stderr is None or stderr.closed)
        self.assertFalse(get_session_registry().is_registered(pid))

    def test_close_is_idempotent(self):
        h = KeepaliveHarness()
        h.close()
        first = (h.proc.returncode, h.out, h.err)
        h.close()
        self.assertEqual((h.proc.returncode, h.out, h.err), first)


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

    def test_failed_ensure_logs_timestamped_failure_then_recovery(self):
        h = KeepaliveHarness(interval="1", fail_ensures="1")
        try:
            # Wait for the failed ensure and its first successful retry.
            deadline = time.time() + 5
            while time.time() < deadline and h.lines().count("ensure") < 2:
                time.sleep(0.05)
        finally:
            h.close()
        self.assertRegex(h.err, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} router: ensure failed \(rc=1\)",
                         f"timestamped failure line missing: {h.err!r}")
        self.assertIn("router: ensure ok; backoff reset to 1s", h.err,
                      f"recovery line missing: {h.err!r}")


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
            rotates = [line for line in lines if line.startswith("rotate proton")]
            self.assertEqual(rotates, [])
            # cadence: periodic checks every PROBE_EVERY(2) ensures after boot.
            # `rotate --if-due` entries are tick noise, so measure gaps on the
            # filtered list. restore_fallbacks() probes once right after the
            # sweep, so drop the `egress check` that directly follows a sweep
            # line too (the sweep cadence is measured separately).
            checks = [line for line in lines if line == "egress check"]
            self.assertGreaterEqual(len(checks), 4, f"too few checks: {lines}")
            restore_probes = {
                i + 1 for i, line in enumerate(lines)
                if line == "egress sweep --json" and i + 1 < len(lines)
                and lines[i + 1] == "egress check"
            }
            ticks = [line for i, line in enumerate(lines)
                     if i not in restore_probes
                     and line not in {"network-status", "rotate --if-due", "egress sweep --json"}]
            check_lines = [i for i, line in enumerate(ticks) if line == "egress check"]
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
            rotates = [line for line in lines if line.startswith("rotate proton")]
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
            rotates = [line for line in lines if line.startswith("rotate proton")]
            self.assertGreaterEqual(len(rotates), 3, f"expected repeated rotations: {lines}")
            # consecutive rotates must be separated by >= 2 dead checks
            positions = [i for i, line in enumerate(lines) if line.startswith("rotate proton")]
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
            rotates = [line for line in lines if line.startswith("rotate proton")]
            self.assertGreaterEqual(len(rotates), 2, f"expected rotations: {lines}")
            h.set_egress("alive")
            time.sleep(0.3)  # let the loop hit at least one successful check
            before = len(h.lines())
            h.wait_lines(before + 12)
            tail = h.lines()[before:]
            tail_rotates = [line for line in tail if line.startswith("rotate proton")]
            self.assertEqual(tail_rotates, [], f"rotated AFTER a successful check: {tail}")
        finally:
            h.close()

    def test_storm_guard_window_recovers_with_zero_window(self):
        # STORM_WINDOW=0: every rotation_allowed() call sees the window as
        # expired, so the guard must NOT block (tests the reset path).
        h = KeepaliveHarness(egress="dead", probe_every="1", dead_strikes="1",
                             storm_window="0", max_rotations="1")
        try:
            deadline = time.time() + 5
            rotates = []
            while time.time() < deadline:
                rotates = [line for line in h.lines() if line.startswith("rotate proton")]
                if len(rotates) >= 4:
                    break
                time.sleep(0.05)
            self.assertGreaterEqual(len(rotates), 4, f"expected rotation churn: {rotates}")
        finally:
            h.close()


class KeepaliveSweepStaggerTests(unittest.TestCase):
    """A sweep defers when the newest rotation is inside the stagger window."""

    def test_tun_mode_skips_background_rotation_and_sweep(self):
        h = KeepaliveHarness(interval="1", probe_every="1", mode="tun")
        try:
            lines = h.wait_lines(20)
            self.assertIn("egress check", lines)
            self.assertNotIn("rotate --if-due", lines,
                             f"scheduled rotation ran in TUN mode: {lines}")
            self.assertNotIn("egress sweep --json", lines,
                             f"background sweep ran in TUN mode: {lines}")
        finally:
            h.close()

    def test_tun_mode_skips_automatic_dead_exit_rotation(self):
        h = KeepaliveHarness(interval="1", probe_every="1", dead_strikes="1",
                             egress="dead", mode="tun")
        try:
            lines = h.wait_lines(8)
            self.assertNotIn("rotate proton", lines,
                             f"dead-exit recovery rotated in TUN mode: {lines}")
        finally:
            h.close()

    def test_invalid_mode_fails_safe_and_skips_background_rotation(self):
        h = KeepaliveHarness(interval="1", probe_every="1", mode="corrupt")
        try:
            lines = h.wait_lines(20)
            self.assertNotIn("rotate --if-due", lines,
                             f"invalid mode enabled scheduled rotation: {lines}")
            self.assertNotIn("egress sweep --json", lines,
                             f"invalid mode enabled background sweep: {lines}")
        finally:
            h.close()

    def test_stale_proxy_marker_with_tun_config_skips_background_rotation(self):
        h = KeepaliveHarness(interval="1", probe_every="1", mode="proxy")
        try:
            (h.root / "sing-box.json").write_text(
                json.dumps({"inbounds": [{"type": "tun"}]})
            )
            lines = h.wait_lines(20)
            self.assertNotIn("rotate --if-due", lines,
                             f"stale proxy marker enabled scheduled rotation: {lines}")
            self.assertNotIn("egress sweep --json", lines,
                             f"stale proxy marker enabled background sweep: {lines}")
        finally:
            h.close()

    def test_sweep_defers_right_after_rotation(self):
        import time as _time
        h = KeepaliveHarness(interval="2")
        try:
            rotation = h.root / "state" / "proton.rotation"
            rotation.parent.mkdir(parents=True, exist_ok=True)
            rotation.write_text(json.dumps({"profile": "a", "at": int(_time.time())}))
            h.wait_lines(6)
            lines = h.lines()
            self.assertNotIn("egress sweep --json", lines,
                             f"sweep ran inside the stagger window: {lines}")
            h.close()
            self.assertIn("sweep deferred", h.err, f"defer note missing: {h.err!r}")
        finally:
            h.close()

    def test_sweep_runs_when_rotation_is_old(self):
        import time as _time
        h = KeepaliveHarness(interval="2")
        try:
            rotation = h.root / "state" / "proton.rotation"
            rotation.parent.mkdir(parents=True, exist_ok=True)
            rotation.write_text(json.dumps({"profile": "a", "at": int(_time.time()) - 3600}))
            h.wait_lines(6)
            self.assertIn("egress sweep --json", h.lines())
        finally:
            h.close()


class KeepaliveFallbackRestoreTests(unittest.TestCase):
    """restore_fallbacks(): on the sweep cadence, clear the runtime fallback
    marker and probe the primary; keep it cleared when alive, re-activate it
    when the primary is still dead. The sweep runs on the FIRST successful
    ensure (last_sweep=0), so both tests observe the restore immediately."""

    def test_restore_clears_fallback_when_primary_alive(self):
        h = KeepaliveHarness(egress="alive", fallback="proton")
        try:
            h.wait_lines(7)
            lines = h.lines()
            self.assertTrue(any(line.startswith("failover proton off") for line in lines),
                            f"expected failover off: {lines}")
            self.assertFalse(any(line.startswith("failover proton on") for line in lines),
                             f"re-activated a live primary: {lines}")
            h.close()
            self.assertIn("'proton' primary is alive again; fallback cleared", h.err,
                          f"restore message missing: {h.err!r}")
        finally:
            h.close()

    def test_restore_reactivates_fallback_when_primary_still_dead(self):
        h = KeepaliveHarness(egress="dead", fallback="proton")
        try:
            h.wait_lines(9)
            lines = h.lines()
            self.assertTrue(any(line.startswith("failover proton off") for line in lines),
                            f"expected failover off: {lines}")
            self.assertTrue(any(line.startswith("failover proton on --reason timeout") for line in lines),
                            f"expected fallback re-activation: {lines}")
            h.close()
            self.assertIn("'proton' primary still dead; re-activating fallback", h.err,
                          f"re-activation message missing: {h.err!r}")
        finally:
            h.close()


class KeepaliveNetworkGuardTests(unittest.TestCase):
    def test_wifi_loss_disconnects_and_return_reconnects(self):
        h = KeepaliveHarness(interval="1", network="disconnected")
        try:
            h.wait_lines(4)
            lines = h.lines()
            self.assertIn("network-status", lines)
            self.assertIn("network-disconnect", lines)
            self.assertNotIn("ensure", lines)
            self.assertTrue(h.network_off_file.is_file())

            h.set_network("connected")
            deadline = time.time() + 5
            while time.time() < deadline:
                lines = h.lines()
                if "network-reconnect" in lines and "ensure" in lines:
                    break
                time.sleep(0.05)
            self.assertIn("network-reconnect", lines)
            self.assertIn("ensure", lines)
            self.assertFalse(h.network_off_file.exists())
            h.close()
            self.assertIn("Wi-Fi returned; supervision resumed", h.err)
        finally:
            h.close()

    def test_wake_gap_forces_immediate_network_recovery(self):
        h = KeepaliveHarness(interval="1", probe_every="99", wake_gap="5", clock=1000)
        try:
            baseline = len(h.wait_lines(4))
            h.advance_clock(10)
            deadline = time.time() + 5
            lines = h.lines()
            while time.time() < deadline:
                lines = h.lines()
                if ("network-disconnect" in lines[baseline:] and "network-reconnect" in lines[baseline:]
                        and "ensure" in lines[baseline:] and "egress check" in lines[baseline:]):
                    break
                time.sleep(0.05)
            tail = lines[baseline:]
            self.assertIn("network-disconnect", tail)
            self.assertIn("network-reconnect", tail)
            self.assertIn("ensure", tail)
            self.assertIn("egress check", tail)
            h.close()
            self.assertIn("wake gap detected (10s)", h.err)
        finally:
            h.close()


class KeepalivePinnedInterpreterTests(unittest.TestCase):
    """Issue #57: with PROXY_ROUTER_PYTHON set, keepalive.sh must invoke the
    controller through that exact pinned interpreter -- never bare python3 or
    the router.py shebang (which resolves via an ambient launchd PATH)."""

    def test_controller_runs_through_pinned_interpreter(self):
        h = KeepaliveHarness(interval="1", pinned_python="1")
        try:
            lines = h.wait_lines(4)
            pinned_lines = (h.pinned_log.read_text().splitlines()
                            if h.pinned_log.is_file() else [])
            h.close()
            self.assertIn("ensure", lines, f"loop did not ensure: {lines}")
            self.assertTrue(
                pinned_lines,
                "pinned interpreter was never invoked",
            )
            self.assertTrue(
                any("ensure" in line for line in pinned_lines),
                f"ensure did not run through pinned interpreter: {pinned_lines}",
            )
            # no controller call may bypass the pinned interpreter
            self.assertTrue(
                all("pinned-python" in line for line in pinned_lines),
                f"controller call bypassed pinned interpreter: {pinned_lines}",
            )
        finally:
            h.close()

    def test_config_setting_uses_pinned_interpreter(self):
        # ENABLED/etc read router.json through config_setting() at startup;
        # that python call must also go through the pinned interpreter.
        h = KeepaliveHarness(interval="1", pinned_python="1")
        try:
            h.wait_lines(2)
            pinned_lines = (h.pinned_log.read_text().splitlines()
                            if h.pinned_log.is_file() else [])
            h.close()
            self.assertTrue(
                pinned_lines,
                "pinned interpreter was never invoked for config",
            )
            self.assertTrue(
                any("router.json" in line for line in pinned_lines),
                f"config_setting did not use pinned interpreter: {pinned_lines}",
            )
        finally:
            h.close()


class KeepaliveManualOffTests(unittest.TestCase):
    """AC1/AC2: a manual disconnect marker must quiesce the loop (no maintain
    calls at all), and a runtime config flip of keepalive.enabled must stop
    the agent without a reload."""

    def test_manual_off_suppresses_all_maintenance_and_resumes_after_clear(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "state").mkdir(parents=True)
        (root / "state" / "manual-off").write_text("manual stop\n")
        h = KeepaliveHarness(interval="1", root=root)
        try:
            # Deterministic wait: loop ticks every 1s; quiescence should suppress
            # all router calls within 2.5s.  Poll with short sleeps instead of a
            # single blind sleep so the test is not flaky on slow CI.
            deadline = time.time() + 2.5
            while time.time() < deadline:
                if h.lines():
                    break
                time.sleep(0.1)
            lines = h.lines()
            self.assertEqual(lines, [],
                             f"manual-off must suppress ALL router calls: {lines}")
            h.root.joinpath("state", "manual-off").unlink()
            h.wait_lines(2, timeout=5.0)
            self.assertNotEqual(h.lines(), [],
                                "maintenance must resume after marker clears")
        finally:
            h.close()
        self.assertIn("manual-off present; supervision quiescent", h.err,
                      f"quiescent note missing: {h.err!r}")

    def test_enabled_reread_stops_loop_mid_run(self):
        h = KeepaliveHarness(interval="1")
        try:
            h.wait_lines(2)
            config = h.root / "router.json"
            config.write_text(json.dumps({"keepalive": {"enabled": False}}))
            h.proc.wait(timeout=10)
            self.assertEqual(h.proc.returncode, 0, "agent must exit cleanly")
            count_before = len(h.lines())
            time.sleep(0.5)
            self.assertEqual(len(h.lines()), count_before,
                             "no router calls may happen after disable")
        finally:
            h.close()
        self.assertIn("autocheck disabled by config", h.err,
                      f"disable note missing: {h.err!r}")



if __name__ == "__main__":
    unittest.main()
