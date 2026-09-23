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
      if [ "$2" = "--json" ]; then
      gate="${FAKE_ROUTER_JSON_CAPTURE_GATE_FILE:-}"
      if [ -n "$gate" ] && [ -f "$gate" ]; then
        rm -f "$gate"
        : > "${gate}.waiting"
        attempts=0
        while [ ! -f "${gate}.release" ] && [ "$attempts" -lt 500 ]; do
          /bin/sleep 0.01
          attempts=$((attempts + 1))
        done
        if [ ! -f "${gate}.release" ]; then
          echo "fake router: JSON capture gate timed out" >&2
          exit 75
        fi
        rm -f "${gate}.release"
      fi
      ssid="${FAKE_ROUTER_SSID:-proto}"
      if [ -n "${FAKE_ROUTER_SSID_FILE:-}" ] && [ -f "$FAKE_ROUTER_SSID_FILE" ]; then
        ssid=$(cat "$FAKE_ROUTER_SSID_FILE")
      fi
      if [ -n "${FAKE_ROUTER_HOLD_FILE:-}" ] && [ -f "$FAKE_ROUTER_HOLD_FILE" ]; then
        ssid="${FAKE_ROUTER_SSID:-proto}"
      fi
      if [ "$state" = "disconnected" ]; then
        printf '%s\n' '{"connected": false, "ssid": null}'
        exit 1
      fi
      printf '{"connected": true, "ssid": "%s"}\n' "$ssid"
      exit 0
    fi
    [ "$state" = "disconnected" ] && exit 1
    ssid="${FAKE_ROUTER_SSID:-proto}"
    if [ -n "${FAKE_ROUTER_SSID_FILE:-}" ] && [ -f "$FAKE_ROUTER_SSID_FILE" ]; then
      ssid=$(cat "$FAKE_ROUTER_SSID_FILE")
    fi
    printf 'network: connected (%s)\n' "$ssid"
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
      # Mirror the production fallback marker so restore gating is testable.
      if [ -n "${FAKE_ROUTER_ROOT:-}" ]; then
        rm -f "$FAKE_ROUTER_ROOT"/state/fallback/*.json
      fi
    elif [ "$3" = "on" ] && [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ]; then
      printf '%s\n' "$2" > "$FAKE_ROUTER_FALLBACK_FILE"
      if [ -n "${FAKE_ROUTER_ROOT:-}" ]; then
        mkdir -p "$FAKE_ROUTER_ROOT"/state/fallback
        printf '%s\n' "{\"provider\": \"$2\"}" > "$FAKE_ROUTER_ROOT"/state/fallback/"$2".json
      fi
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
if [ "${1:-}" = "+%s" ] && [ -n "${FAKE_DATE_SAMPLE_GATE_FILE:-}" ] \
   && [ -f "$FAKE_DATE_SAMPLE_GATE_FILE" ]; then
  rm -f "$FAKE_DATE_SAMPLE_GATE_FILE"
  : > "${FAKE_DATE_SAMPLE_GATE_FILE}.waiting"
  attempts=0
  while [ ! -f "${FAKE_DATE_SAMPLE_GATE_FILE}.release" ] && [ "$attempts" -lt 500 ]; do
    /bin/sleep 0.01
    attempts=$((attempts + 1))
  done
  if [ ! -f "${FAKE_DATE_SAMPLE_GATE_FILE}.release" ]; then
    echo "fake date: time sample gate timed out" >&2
    exit 75
  fi
  rm -f "${FAKE_DATE_SAMPLE_GATE_FILE}.release"
fi
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
                 mode="proxy", network="connected", wake_gap="", clock=None,
                 ssid="proto"):
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
            self.park(fallback)
        self.network_file = self.root / "network.state"
        self.network_file.write_text(network)
        self.ssid_file = self.root / "ssid.state"
        self.ssid_file.write_text(ssid)
        self.json_capture_gate = self.root / "network-status-json.gate"
        self.date_sample_gate = self.root / "date-sample.gate"
        self.ssid_flip_file = self.root / "ssid-flip.state"
        self.ssid_flip_at = self.root / "ssid-flip.count"
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
        env["FAKE_ROUTER_ROOT"] = str(self.root)
        env["FAKE_ROUTER_NETWORK_FILE"] = str(self.network_file)
        env["FAKE_ROUTER_NETWORK_FILE"] = str(self.network_file)
        env["FAKE_ROUTER_NETWORK_OFF_FILE"] = str(self.network_off_file)
        env["FAKE_ROUTER_SSID_FILE"] = str(self.ssid_file)
        env["FAKE_ROUTER_HOLD_FILE"] = str(self.root / "ssid-hold.state")
        env["FAKE_ROUTER_JSON_CAPTURE_GATE_FILE"] = str(self.json_capture_gate)
        env["FAKE_DATE_SAMPLE_GATE_FILE"] = str(self.date_sample_gate)
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

    def park(self, provider: str) -> None:
        """Simulate a runtime park in both the fake router and marker state."""
        self.fallback_file.write_text(provider)
        markers = self.root / "state" / "fallback"
        markers.mkdir(parents=True, exist_ok=True)
        (markers / f"{provider}.json").write_text(json.dumps({"provider": provider}))

    def lines(self) -> list[str]:
        if not self.log.is_file():
            return []
        return [line for line in self.log.read_text().splitlines() if line.strip()]

    def set_egress(self, state: str) -> None:
        self.egress_file.write_text(state)

    def set_network(self, state: str) -> None:
        self.network_file.write_text(state)

    def arm_json_capture_gate(self) -> None:
        self.json_capture_gate.with_name(self.json_capture_gate.name + ".waiting").unlink(
            missing_ok=True)
        self.json_capture_gate.with_name(self.json_capture_gate.name + ".release").unlink(
            missing_ok=True)
        self.json_capture_gate.touch()

    def wait_for_json_capture(self, timeout: float = 5.0) -> None:
        waiting = self.json_capture_gate.with_name(self.json_capture_gate.name + ".waiting")
        deadline = time.monotonic() + timeout
        while not waiting.is_file() and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"keepalive exited before capture gate: {self.err!r}")
            time.sleep(0.01)
        if not waiting.is_file():
            raise AssertionError("fake router never reached the gated JSON capture")

    def release_json_capture(self) -> None:
        self.json_capture_gate.with_name(self.json_capture_gate.name + ".release").touch()

    def arm_time_sample_gate(self) -> None:
        self.date_sample_gate.with_name(self.date_sample_gate.name + ".waiting").unlink(
            missing_ok=True)
        self.date_sample_gate.with_name(self.date_sample_gate.name + ".release").unlink(
            missing_ok=True)
        self.date_sample_gate.touch()

    def wait_for_time_sample(self, timeout: float = 5.0) -> None:
        waiting = self.date_sample_gate.with_name(self.date_sample_gate.name + ".waiting")
        deadline = time.monotonic() + timeout
        while not waiting.is_file() and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"keepalive exited before time sample gate: {self.err!r}")
            time.sleep(0.01)
        if not waiting.is_file():
            raise AssertionError("keepalive never reached the gated clock sample")

    def release_time_sample(self) -> None:
        self.date_sample_gate.with_name(self.date_sample_gate.name + ".release").touch()

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
            # Hosted runners can be heavily loaded while the full suite is
            # running; allow the child to reach its first retry before
            # declaring the recovery log missing.
            deadline = time.time() + 20
            # The fake router records an ensure invocation before the shell
            # can emit its recovery message.  Wait for the boot probe that
            # follows that message so close() cannot race the stderr write.
            while time.time() < deadline and "egress check" not in h.lines():
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
            lines = h.wait_lines(30)
            h.close()
            self.assertIn("router: boot self-test ok", h.out,
                          f"healthy boot line missing:\nstdout={h.out!r}\nstderr={h.err!r}")
            # The scheduled-rotation check (`rotate --if-due`) runs every
            # healthy tick and self-gates on its interval; the boot self-test
            # must never trigger an EMERGENCY provider rotation.
            rotates = [line for line in lines if line.startswith("rotate proton")]
            self.assertEqual(rotates, [])
            # Cadence: periodic checks every PROBE_EVERY(2) ensures after boot.
            # With no parked fallback marker, the full-pool sweep must not add
            # a duplicate restore probe; keep only the boot and periodic checks.
            checks = [line for line in lines if line == "egress check"]
            restore_probes = {
                i + 1 for i, line in enumerate(lines)
                if line == "egress sweep --json" and i + 1 < len(lines)
                and lines[i + 1] == "egress check"
            }
            self.assertEqual(restore_probes, set(),
                             f"restore probe ran without a fallback marker: {lines}")
            self.assertGreaterEqual(len(checks), 3, f"too few checks: {lines}")
            ticks = [line for i, line in enumerate(lines)
                     if i not in restore_probes
                     and line not in {"network-status", "network-status --json",
                                      "rotate --if-due", "egress sweep --json"}]
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
            h.wait_lines(21)
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

    def test_sweep_every_zero_disables_sweep_without_defer_noise(self):
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(
                json.dumps({"keepalive": {"sweep_every": 0}}))
            h = KeepaliveHarness(interval="1", root=root)
            try:
                rotation = h.root / "state" / "proton.rotation"
                rotation.write_text(json.dumps({"profile": "a", "at": int(_time.time())}))
                h.wait_lines(6)
                self.assertNotIn("egress sweep --json", h.lines(),
                                 "sweep_every 0 must not run the full-pool sweep")
                self.assertFalse(any(line.startswith("failover ") for line in h.lines()),
                                 "no fallback restore work should run without a marker")
                h.close()
                self.assertNotIn("sweep deferred", h.err,
                                 f"sweep_every 0 must silence the stagger note: {h.err!r}")
            finally:
                h.close()


class KeepaliveFallbackRestoreTests(unittest.TestCase):
    """restore_fallbacks(): on its own cadence, clear the runtime fallback
    marker and probe the primary; keep it cleared when alive, re-activate it
    when the primary is still dead. Both clocks start at zero, so the first
    successful ensure observes the restore immediately."""

    def test_restore_runs_when_full_pool_sweep_is_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({
                "keepalive": {"sweep_every": 0, "fallback_restore_every": 1}
            }))
            h = KeepaliveHarness(interval="1", fallback="proton", root=root)
            try:
                deadline = time.time() + 10
                lines = h.lines()
                while time.time() < deadline and not any(
                        line.startswith("egress check --provider proton") for line in lines):
                    time.sleep(0.05)
                    lines = h.lines()
                self.assertTrue(
                    any(line.startswith("failover proton off") for line in lines),
                    f"restore did not run with sweep_every=0: {lines}",
                )
                self.assertIn("egress check --provider proton", lines)
                self.assertNotIn("egress sweep --json", lines,
                                 "disabled full-pool sweep must remain disabled")
            finally:
                h.close()

    def test_restore_clears_fallback_when_primary_alive(self):
        h = KeepaliveHarness(egress="alive", fallback="proton")
        try:
            deadline = time.time() + 10
            lines = h.lines()
            while time.time() < deadline and not any(
                    line.startswith("failover proton off") for line in lines):
                time.sleep(0.05)
                lines = h.lines()
            deadline = time.time() + 10
            while time.time() < deadline and not any(
                    line.startswith("egress check --provider proton") for line in lines):
                time.sleep(0.05)
                lines = h.lines()
            self.assertTrue(any(line.startswith("failover proton off") for line in lines),
                            f"expected failover off: {lines}")
            self.assertFalse(any(line.startswith("failover proton on") for line in lines),
                             f"re-activated a live primary: {lines}")
            self.assertTrue(any(line.startswith("egress check --provider proton") for line in lines),
                            f"expected post-clear primary probe: {lines}")
            h.close()
        finally:
            h.close()

    def test_restore_reactivates_fallback_when_primary_still_dead(self):
        h = KeepaliveHarness(egress="dead", fallback="proton")
        try:
            deadline = time.time() + 10
            lines = h.lines()
            while time.time() < deadline and not any(
                    line.startswith("failover proton on --reason timeout") for line in lines):
                time.sleep(0.05)
                lines = h.lines()
            deadline = time.time() + 10
            while time.time() < deadline and not any(
                    line.startswith("failover proton on --reason timeout") for line in lines):
                time.sleep(0.05)
                lines = h.lines()
            self.assertTrue(any(line.startswith("failover proton off") for line in lines),
                            f"expected failover off: {lines}")
            self.assertTrue(any(line.startswith("failover proton on --reason timeout") for line in lines),
                            f"expected fallback re-activation: {lines}")
            h.close()
        finally:
            h.close()


def _wait_two_ticks(h, timeout: float = 30.0) -> int:
    """Return the log length once two ticks have logged their first line.

    Tick 1 can still be mid-flight when its first lines appear, so a clock
    jump here would be absorbed by tick 1's top-of-loop sample. Waiting for
    tick 2's 'network-status' guarantees tick 2's sample already happened
    and the jump lands strictly between two samples."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        lines = h.lines()
        if lines.count("network-status") >= 2:
            return len(lines)
        time.sleep(0.05)
    return len(h.lines())


def _trigger_wake(h, seconds: int = 10) -> None:
    """Advance the fake clock between loop samples, not during a tick."""
    h.arm_time_sample_gate()
    h.wait_for_time_sample()
    h.advance_clock(seconds)
    h.release_time_sample()


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
            _wait_two_ticks(h)
            (h.root / "ssid-hold.state").write_text("1")
            h.ssid_file.write_text("new-wifi")
            wake_line = len(h.lines())
            h.arm_time_sample_gate()
            h.wait_for_time_sample()
            h.arm_json_capture_gate()
            h.advance_clock(10)
            h.release_time_sample()
            h.wait_for_json_capture()
            (h.root / "ssid-hold.state").unlink(missing_ok=True)
            h.release_json_capture()

            deadline = time.time() + 20
            lines = h.lines()
            while time.time() < deadline:
                lines = h.lines()
                if "network-disconnect" in lines[wake_line:]:
                    break
                time.sleep(0.05)
            tail = lines[wake_line:]
            # Give the boot self-test one extra tick to log egress check.
            deadline = time.time() + 10
            while time.time() < deadline and "egress check" not in tail:
                time.sleep(0.05)
                tail = h.lines()[wake_line:]
            self.assertIn("network-disconnect", tail)
            self.assertIn("network-reconnect", tail)
            self.assertIn("ensure", tail)
            self.assertIn("egress check", tail)
            h.close()
            self.assertIn("wake gap detected (10s)", h.err)
        finally:
            h.close()

    def test_wake_gap_on_unchanged_network_skips_teardown(self):
        h = KeepaliveHarness(interval="1", probe_every="99", wake_gap="5", clock=1000)
        try:
            baseline = _wait_two_ticks(h)
            _trigger_wake(h)
            deadline = time.time() + 30
            lines = h.lines()
            while time.time() < deadline:
                lines = h.lines()
                if "ensure" in lines[baseline:] and len(lines) >= baseline + 6:
                    break
                time.sleep(0.05)
            tail = lines[baseline:]
            h.close()
            self.assertIn("wake gap on an unchanged network", h.err,
                          f"wake evaluation never ran: {h.err!r}")
            self.assertNotIn("wake recovery failed", h.err)
            self.assertNotIn("network-disconnect", tail,
                             f"unchanged network was torn down: {tail}")
            self.assertNotIn("network-reconnect", tail,
                             f"unchanged network was torn down: {tail}")
            self.assertIn("ensure", tail, f"fast path skipped supervision: {tail}")
        finally:
            h.close()

    def test_wake_gap_after_ssid_change_still_tears_down(self):
        h = KeepaliveHarness(interval="1", probe_every="99", wake_gap="5", clock=1000)
        try:
            # The held baseline stays proto. Pause the next wake capture,
            # release the hold after the fake router acknowledges that exact
            # call, and then let it read school-wifi.
            (h.root / "ssid-hold.state").write_text("1")
            baseline = _wait_two_ticks(h)
            h.ssid_file.write_text("school-wifi")
            wake_line = len(h.lines())
            h.arm_time_sample_gate()
            h.wait_for_time_sample()
            h.arm_json_capture_gate()
            h.advance_clock(10)
            h.release_time_sample()
            h.wait_for_json_capture()
            (h.root / "ssid-hold.state").unlink(missing_ok=True)
            h.release_json_capture()

            deadline = time.time() + 20
            lines = h.lines()
            while time.time() < deadline:
                lines = h.lines()
                if "network-disconnect" in lines[wake_line:]:
                    break
                time.sleep(0.05)
            self.assertIn("network-disconnect", lines[wake_line:])
            tail = lines[baseline:]
            self.assertIn("network-disconnect", tail,
                          f"SSID change did not tear down: {tail}")
            deadline = time.time() + 10
            while time.time() < deadline and "network-reconnect" not in tail:
                time.sleep(0.05)
                tail = h.lines()[baseline:]
            self.assertIn("network-reconnect", tail)
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
