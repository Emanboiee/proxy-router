"""Focused lifecycle tests for examples/keepalive.sh (single-profile WARP case).

Runs the real script against a fake router.py and a fake sleep (both on
PATH) so the loop is fast and deterministic. Covers the bounded lifecycle
fix for the live incident (one WARP profile dead, configured fallback
cloudflare -> proton):

- dead single-profile provider parks once on the fallback and stays sticky
  (exactly one rotation attempt, no per-tick reload/probe/rotate storm);
- an already-active fallback is never re-rotated or re-activated;
- malformed fallback status (none/no/list-valued/whitespace/case variants)
  never mistakes an inactive marker for an active fallback;
- base-route gaps (missing default interface / no route to internet /
  WireGuard is not ready) defer without consuming strike/rotation budget;
- the text status path (no --json) parks the same way as the JSON path.

Deterministic: temporary state only, no live sing-box start or reload.
TUN-mode no-automatic-mutation and the storm guard are untouched paths
covered by tests/test_keepalive.py.
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
    exit 0
    ;;
  network-disconnect)
    exit 0
    ;;
  network-reconnect)
    exit 0
    ;;
  ensure)
    n=$(cat "${FAKE_ROUTER_ENSURE_COUNT:-/dev/null}" 2>/dev/null || echo 0)
    n=$((n + 1))
    printf '%s\n' "$n" > "${FAKE_ROUTER_ENSURE_COUNT}"
    exit 0
    ;;
  egress)
    if [ "${2:-}" = "sweep" ]; then
      echo "cloudflare: sweep done, 1/1 alive (best: warp)"
      exit 0
    fi
    if [ -n "${FAKE_ROUTER_GAP_FILE:-}" ] && [ -f "$FAKE_ROUTER_GAP_FILE" ]; then
      gap=$(cat "$FAKE_ROUTER_GAP_FILE")
      if [ -n "$gap" ]; then
        echo "cloudflare: dead ($gap)"
        echo "dead: cloudflare"
        exit 1
      fi
    fi
    if [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ] && [ -f "$FAKE_ROUTER_FALLBACK_FILE" ]; then
      if [ "${FAKE_FALLBACK_DEAD:-}" = "1" ]; then
        echo "cloudflare: fallback (proton)"
        echo "dead: cloudflare"
        exit 1
      fi
      echo "cloudflare: fallback (proton)"
      exit 0
    fi
    state="alive"
    if [ -n "${FAKE_ROUTER_EGRESS_FILE:-}" ] && [ -f "$FAKE_ROUTER_EGRESS_FILE" ]; then
      state=$(cat "$FAKE_ROUTER_EGRESS_FILE")
    fi
    case "$state" in
      dead)
        echo "cloudflare: dead (probe connection)"
        echo "dead: cloudflare"
        exit 1
        ;;
      *)
        echo "cloudflare: alive (warp)"
        exit 0
        ;;
    esac
    ;;
  failover)
    prov="${2:-}"
    action="${3:-}"
    case "$action" in
      status)
        json=0
        for a in "$@"; do
          if [ "$a" = "--json" ]; then json=1; fi
        done
        if [ "$json" = "1" ]; then
          if [ "${FAKE_FAILOVER_NO_JSON:-}" = "1" ]; then
            exit 1
          fi
          _active="${FAKE_JSON_ACTIVE:-auto}"
          if [ "$_active" = "auto" ]; then
            if [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ] && [ -f "$FAKE_ROUTER_FALLBACK_FILE" ]; then
              _active='"proton"'
            else
              _active='null'
            fi
          fi
          printf '{"configured": %s, "active": %s}\n' "${FAKE_JSON_CONFIGURED}" "$_active"
          exit 0
        fi
        if [ -n "${FAKE_FAILOVER_TEXT:-}" ]; then
          printf '%s\n' "$FAKE_FAILOVER_TEXT"
          exit 0
        fi
        active="none"
        if [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ] && [ -f "$FAKE_ROUTER_FALLBACK_FILE" ]; then
          active="proton"
        fi
        conf="${FAKE_TEXT_CONFIGURED:-['proton']}"
        printf 'fallback %s: configured=%s active=%s\n' "$prov" "$conf" "$active"
        exit 0
        ;;
      on)
        rc="${FAKE_FAILOVER_ON_RC:-0}"
        if [ "$rc" != "0" ]; then
          echo "fallback failed" >&2
          exit "$rc"
        fi
        if [ -n "${FAKE_ROUTER_FALLBACK_FILE:-}" ]; then
          printf '%s\n' "$prov" > "$FAKE_ROUTER_FALLBACK_FILE"
        fi
        echo "fallback active: $prov -> proton (timeout)"
        exit 0
        ;;
      off)
        rm -f "${FAKE_ROUTER_FALLBACK_FILE:-/dev/null}"
        echo "fallback cleared: $prov"
        exit 0
        ;;
    esac
    exit 0
    ;;
  rotate)
    if [ "${2:-}" = "--if-due" ]; then
      exit 3
    fi
    if [ "${FAKE_ROTATE:-ok}" = "fail-cooling" ]; then
      echo "provider 'cloudflare': all profiles cooling down" >&2
      exit 1
    fi
    echo "switched ${2:-unknown} -> warp2"
    exit 0
    ;;
esac
exit 0
"""

FAKE_SLEEP = r"""#!/usr/bin/env bash
printf '%s\n' "$1" >> "${SLEEP_LOG:-/dev/null}"
"""


class LifecycleHarness:
    """Run the real keepalive.sh against fake router.py/sleep on PATH.

    A fresh rotation record pre-seeds the sweep stagger window, so the
    time-based sweep (and its restore off/on pair) never fires during these
    short tests: every observed failover call comes from the dead-exit path
    under test, not from restore_fallbacks.
    """

    def __init__(self, *, interval="1", egress="alive", gap="",
                 probe_every="1", dead_strikes="1", storm_window="3600",
                 max_rotations="50", fallback=False, fallback_dead=False,
                 rotate="fail-cooling", json_configured='["proton"]',
                 json_active="auto", failover_text=None, no_json=False,
                 text_configured=None, failover_on_rc="0"):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "state").mkdir(parents=True, exist_ok=True)
        (self.root / "state" / "mode").write_text("proxy")
        (self.root / "sing-box.json").write_text(
            json.dumps({"inbounds": [{"type": "mixed"}]})
        )
        # Fresh rotation record: keeps the sweep stagger window closed, so
        # the background sweep + restore never run in these tests.
        (self.root / "state" / "cloudflare.rotation").write_text(
            json.dumps({"profile": "warp", "at": int(time.time())})
        )
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
        self.gap_file = self.root / "gap.state"
        self.gap_file.write_text(gap)
        self.fallback_file = self.root / "fallback.state"
        if fallback:
            self.fallback_file.write_text("cloudflare")
        env = dict(os.environ)
        env["PATH"] = f"{self.root / 'bin'}:" + env["PATH"]
        env["PROXY_KEEPALIVE_INTERVAL"] = interval
        env["PROXY_KEEPALIVE_MAX_BACKOFF"] = "8"
        env["PROXY_KEEPALIVE_PROBE_EVERY"] = probe_every
        env["PROXY_KEEPALIVE_DEAD_STRIKES"] = dead_strikes
        env["PROXY_KEEPALIVE_STORM_WINDOW"] = storm_window
        env["PROXY_KEEPALIVE_MAX_ROTATIONS"] = max_rotations
        env["PROXY_KEEPALIVE_SWEEP_EVERY"] = "3600"
        env["SLEEP_LOG"] = str(self.sleep_log)
        env["FAKE_ROUTER_LOG"] = str(self.log)
        env["FAKE_ROUTER_ENSURE_COUNT"] = str(self.count)
        env["FAKE_ROUTER_EGRESS_FILE"] = str(self.egress_file)
        env["FAKE_ROUTER_GAP_FILE"] = str(self.gap_file)
        env["FAKE_ROUTER_FALLBACK_FILE"] = str(self.fallback_file)
        env["FAKE_ROTATE"] = rotate
        env["FAKE_JSON_CONFIGURED"] = json_configured
        env["FAKE_JSON_ACTIVE"] = json_active
        env["FAKE_FAILOVER_ON_RC"] = failover_on_rc
        if fallback_dead:
            env["FAKE_FALLBACK_DEAD"] = "1"
        if failover_text is not None:
            env["FAKE_FAILOVER_TEXT"] = failover_text
        if no_json:
            env["FAKE_FAILOVER_NO_JSON"] = "1"
        if text_configured is not None:
            env["FAKE_TEXT_CONFIGURED"] = text_configured
        self.env = env
        self.proc = subprocess.Popen([str(target)], env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, start_new_session=(os.name == "posix"))

    def lines(self) -> list[str]:
        if not self.log.is_file():
            return []
        return [line for line in self.log.read_text().splitlines() if line.strip()]

    def matching(self, prefix: str) -> list[str]:
        return [line for line in self.lines() if line.startswith(prefix)]

    def set_egress(self, state: str) -> None:
        self.egress_file.write_text(state)

    def set_gap(self, text: str) -> None:
        self.gap_file.write_text(text)

    def wait_for_log(self, prefix: str, timeout: float = 20.0) -> list[str]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = self.matching(prefix)
            if found:
                return found
            time.sleep(0.05)
        return self.matching(prefix)

    def close(self) -> None:
        if getattr(self, "_closed", False):
            return
        if os.name == "posix":
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
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


class SingleProfileFallbackTests(unittest.TestCase):
    """Dead one-profile provider with cloudflare -> proton parks once."""

    def test_dead_single_profile_parks_once_and_stays_parked(self):
        h = LifecycleHarness(egress="dead")
        try:
            ons = h.wait_for_log("failover cloudflare on", timeout=20.0)
            self.assertTrue(ons, "fallback was never activated for dead cloudflare")
            time.sleep(3.0)  # several more probe ticks while parked
            lines = h.lines()
            rotates = [line for line in lines if line.startswith("rotate cloudflare")]
            ons = [line for line in lines if line.startswith("failover cloudflare on")]
            self.assertEqual(len(rotates), 1,
                             f"single-profile pool must rotate exactly once: {lines}")
            self.assertEqual(len(ons), 1,
                             f"fallback must activate exactly once (sticky): {lines}")
            self.assertTrue(h.fallback_file.is_file(),
                            "fallback marker must exist after parking")
            h.close()
            self.assertIn("parked 'cloudflare' on fallback", h.err,
                          f"parked note missing: {h.err!r}")
            self.assertNotIn("all profiles cooling down", h.err.split("parked")[1],
                             f"rotation retried after parking: {h.err!r}")
        finally:
            h.close()

    def test_text_status_path_parks_the_same_way(self):
        # No --json support: the shell text parser must still find the
        # list-valued configured field and the inactive marker.
        h = LifecycleHarness(egress="dead", no_json=True,
                             text_configured="['proton']")
        try:
            ons = h.wait_for_log("failover cloudflare on", timeout=20.0)
            self.assertTrue(ons, f"no parking via text status: {h.lines()}")
            time.sleep(3.0)
            lines = h.lines()
            rotates = [line for line in lines if line.startswith("rotate cloudflare")]
            self.assertEqual(len(rotates), 1,
                             f"text path must rotate exactly once: {lines}")
            h.close()
            self.assertIn("parked 'cloudflare' on fallback", h.err,
                          f"parked note missing: {h.err!r}")
        finally:
            h.close()


class AlreadyActiveFallbackTests(unittest.TestCase):
    def test_healthy_fallback_never_rotates_or_reactivates(self):
        h = LifecycleHarness(egress="alive", fallback=True)
        try:
            time.sleep(4.0)  # several healthy probe ticks while parked
            lines = h.lines()
            self.assertEqual([line for line in lines if line.startswith("rotate cloudflare")], [],
                             f"parked provider must never rotate: {lines}")
            self.assertEqual([line for line in lines if line.startswith("failover cloudflare on")], [],
                             f"active fallback must never re-activate: {lines}")
        finally:
            h.close()

    def test_fallback_path_dead_stays_parked_without_reload(self):
        # Even when the parked path itself probes dead, the loop must not
        # reload or re-rotate the dead primary every tick.
        h = LifecycleHarness(egress="alive", fallback=True, fallback_dead=True)
        try:
            # Wait for several probe ticks while parked-dead, then assert
            # the loop never reached for a reload.
            deadline = time.time() + 20.0
            while time.time() < deadline:
                if len([line for line in h.lines() if line == "egress check"]) >= 4:
                    break
                time.sleep(0.05)
            time.sleep(2.0)
            lines = h.lines()
            self.assertEqual([line for line in lines if line.startswith("rotate cloudflare")], [],
                             f"parked-dead provider must never rotate: {lines}")
            self.assertEqual([line for line in lines if line.startswith("failover cloudflare on")], [],
                             f"parked-dead provider must never re-activate: {lines}")
            h.close()
            self.assertIn("staying parked", h.err,
                          f"sticky note missing: {h.err!r}")
        finally:
            h.close()


class NetworkGapDeferralTests(unittest.TestCase):
    GAP_SIGNALS = (
        "missing default interface",
        "no route to internet",
        "WireGuard is not ready",
    )

    def test_gap_defers_without_budget_then_recovers(self):
        h = LifecycleHarness(egress="dead", gap=self.GAP_SIGNALS[0])
        try:
            # Every incident signal defers: no rotation while any is present.
            for sig in self.GAP_SIGNALS:
                h.set_gap(sig)
                time.sleep(2.0)
                lines = h.lines()
                self.assertEqual([line for line in lines if line.startswith("rotate cloudflare")], [],
                                 f"gap {sig!r} must never rotate: {lines}")
                self.assertEqual([line for line in lines if line.startswith("failover cloudflare on")], [],
                                 f"gap {sig!r} must never fail over: {lines}")
            # Gap clears with the primary still dead: the preserved budget
            # must now drive exactly one rotation + park cycle.
            before = len(h.lines())
            h.set_gap("")
            ons = h.wait_for_log("failover cloudflare on", timeout=20.0)
            self.assertTrue(ons, f"no park after gap cleared: {h.lines()[before:]}")
            h.close()
            self.assertIn("network gap detected", h.err,
                          f"gap deferral note missing: {h.err!r}")
            self.assertIn("parked 'cloudflare' on fallback", h.err,
                          f"parked note missing after recovery: {h.err!r}")
        finally:
            h.close()


def _bash_quote(value: str) -> str:
    if "'" not in value:
        return "'" + value + "'"
    if '"' not in value:
        return '"' + value + '"'
    raise ValueError(f"unquotable test value: {value!r}")


class FallbackStatusParsingTests(unittest.TestCase):
    """Unit-test the exact helpers shipped in keepalive.sh.

    The helper block is extracted verbatim between the lifecycle markers,
    so these assertions always run against the shipped code, covering
    `none` / `no` / list-valued configured fields / whitespace / case
    variants with deterministic, network-free bash.
    """

    GAP_TRUE = (
        "missing default interface",
        "Missing Default Route",
        "no route to internet",
        "WireGuard is not ready",
        "WIREGUARD IS NOT READY",
        "engine not listening on 127.0.0.1:2080",
        "tunnel is down",
        "network unreachable",
        "no internet",
    )
    GAP_FALSE = (
        "cloudflare: dead (probe connection)",
        "proton: alive (warp)",
        "dead: cloudflare",
        "provider 'cloudflare': all profiles cooling down",
        "",
    )
    CONFIGURED_TRUE = (
        "['proton']",
        '["proton"]',
        "['proton', 'direct']",
        "proton",
        "  proton  ",
        "Proton",
        "[proton]",
        "proton,direct",
        "('proton')",
    )
    CONFIGURED_FALSE = (
        "none", "None", "NONE", "no", "No", "NO", "false", "False", "0",
        "off", "OFF", "Off", "[]", "[  ]", "", "null", "NULL", "-",
        "n/a", "N/A", "['none']", "none, none",
    )
    ACTIVE_CASES = (
        ("proton", "proton"),
        (" Proton ", "Proton"),
        ("['proton']", "proton"),
        ('"proton"', "proton"),
        ("[proton]", "proton"),
        ("none", ""),
        ("No", ""),
        ("", ""),
        ("OFF", ""),
        ("false", ""),
        ("0", ""),
        ("[]", ""),
        ("NONE", ""),
        ("null", ""),
    )
    SPLIT_CASES = (
        ("fallback cloudflare: configured=['proton'] active=none",
         "['proton']", "none"),
        ("fallback cloudflare: configured=['proton', 'direct'] active=none",
         "['proton', 'direct']", "none"),
        ("fallback cloudflare: configured=None active=No",
         "None", "No"),
        ("fallback cloudflare: configured=  NONE   active=  OFF",
         "NONE", "OFF"),
        ("fallback cloudflare: CONFIGURED=no ACTIVE=false",
         "no", "false"),
        ("fallback cloudflare: configured=proton active=proton",
         "proton", "proton"),
    )

    def test_shipped_helpers_parse_all_variants(self):
        src = KEEPALIVE_SRC.read_text()
        start = src.index("# LIFECYCLE-HELPERS-START")
        end = src.index("# LIFECYCLE-HELPERS-END") + len("# LIFECYCLE-HELPERS-END")
        helpers = src[start:end]
        self.assertIn("fallback_configured_has_candidate", helpers)
        self.assertIn("is_network_gap", helpers)

        with tempfile.TemporaryDirectory() as tmp:
            helpers_path = Path(tmp) / "helpers.sh"
            helpers_path.write_text(helpers)
            script_path = Path(tmp) / "check.sh"
            chunks = ["#!/usr/bin/env bash", "set -u",
                      '. "$1"', "pass=0", "fail=0",
                      "note() { printf 'FAIL %s\\n' \"$1\"; fail=$((fail + 1)); }",
                      "hit() { pass=$((pass + 1)); }"]
            for sig in self.GAP_TRUE:
                chunks.append(
                    f"is_network_gap {_bash_quote(sig)} >/dev/null 2>&1 && hit || note {_bash_quote('gap-true:' + sig)}")
            for sig in self.GAP_FALSE:
                if sig:
                    chunks.append(
                        f"is_network_gap {_bash_quote(sig)} >/dev/null 2>&1 && note {_bash_quote('gap-false:' + sig)} || hit")
                else:
                    chunks.append("is_network_gap '' >/dev/null 2>&1 && note 'gap-false:empty' || hit")
            for raw in self.CONFIGURED_TRUE:
                chunks.append(
                    f"fallback_configured_has_candidate {_bash_quote(raw)} && hit || note {_bash_quote('conf-true:' + raw)}")
            for raw in self.CONFIGURED_FALSE:
                if raw:
                    chunks.append(
                        f"fallback_configured_has_candidate {_bash_quote(raw)} && note {_bash_quote('conf-false:' + raw)} || hit")
                else:
                    chunks.append("fallback_configured_has_candidate '' && note 'conf-false:empty' || hit")
            for raw, want in self.ACTIVE_CASES:
                if want:
                    chunks.append(
                        f'[ "$(fallback_active_name {_bash_quote(raw)})" = {_bash_quote(want)} ] && hit || note {_bash_quote("act:" + raw)}')
                else:
                    if raw:
                        chunks.append(
                            f'fallback_active_name {_bash_quote(raw)} >/dev/null 2>&1 && note {_bash_quote("act-active:" + raw)} || hit')
                    else:
                        chunks.append("fallback_active_name '' >/dev/null 2>&1 && note 'act-active:empty' || hit")
            for line, want_conf, want_act in self.SPLIT_CASES:
                chunks.append(
                    f"fallback_split_status_text {_bash_quote(line)} || note {_bash_quote('split-rc:' + line)}")
                chunks.append(
                    f'[ "$FB_CONFIGURED" = {_bash_quote(want_conf)} ] && hit || note {_bash_quote("split-conf:" + line)}')
                chunks.append(
                    f'[ "$FB_ACTIVE" = {_bash_quote(want_act)} ] && hit || note {_bash_quote("split-act:" + line)}')
            chunks.append('printf \'pass=%s fail=%s\\n\' "$pass" "$fail"')
            chunks.append('[ "$fail" -eq 0 ]')
            script_path.write_text("\n".join(chunks) + "\n")
            proc = subprocess.run(["bash", str(script_path), str(helpers_path)],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0,
                             f"helper parsing failures:\n{proc.stdout}\n{proc.stderr}")
            self.assertIn("fail=0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
