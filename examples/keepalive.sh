#!/usr/bin/env bash
# Keeps the proxy router's sing-box listener alive on 127.0.0.1:2080.
#
# Runs indefinitely as a launchd agent: every CHECK_INTERVAL seconds it calls
# `router.py ensure`, which starts the engine when the listener is missing.
# This resurrects a silently-died proxy without waiting for the next login or
# for a Hermes process to be restarted.
#
# Backoff: while `ensure` keeps failing (broken config, missing sing-box, ...)
# the wait grows exponentially (INTERVAL, 2x, 4x, ...) up to MAX_BACKOFF
# seconds, so a dead engine is not hammered every INTERVAL; a single
# successful ensure resets the wait back to INTERVAL.
#
# Dead-tunnel self-heal: `ensure` only proves the PROCESS is alive - a
# WireGuard tunnel whose route/handshake is dead still "passes ensure" while
# every request times out upstream. On a slower cadence the loop therefore
# also runs `router.py egress check` (a read-only probe of the ACTIVE exit
# through the running tunnel) and auto-rotates the provider pool when the
# exit is genuinely dead: after PROXY_KEEPALIVE_DEAD_STRIKES consecutive dead
# checks (a single transient blip never rotates), and never more than
# PROXY_KEEPALIVE_MAX_ROTATIONS times per PROXY_KEEPALIVE_STORM_WINDOW
# seconds, so a broken pool cannot storm. A boot self-test runs once on the
# first successful ensure (one early rotation, same storm guard).
#
# Scheduled rotation: when router.json has a "rotation" block, the loop also
# calls `router.py rotate --if-due` on every healthy tick - the CLI reads the
# configured interval/jitter and only rotates once the interval has elapsed
# (exit 3 = not due, nothing logged), so the active exit churns on a cadence
# and upstream rate limits see a fresh egress IP. The verify-then-switch
# rollback path and per-provider cooldowns apply exactly as for a manual
# rotate; `state/<provider>.rotation` tracks the last switch time.
#
# Full-pool egress sweep: nothing above probes the non-active exits, so a pool
# could sit on a stale-but-alive lane forever. Every
# PROXY_KEEPALIVE_SWEEP_EVERY seconds (default 1800 = 30 min) the loop runs
# `router.py egress sweep`, which probes EVERY profile of every provider
# through the tunnel, persists health/cooldown/block markers, and ends on the
# best alive exit (no reload when the current exit already is best).
#
# Manual-off quiescence: when `state/manual-off` exists (user disconnected via
# tray/CLI), the loop performs NO maintenance at all - no ensure, no probe, no
# rotation, no sweep, no fallback restore. Manual disconnect is a deliberate
# state, not an engine failure; the tunnel stays down until `router.py start`
# clears the marker. The agent polls only its own enabled flag while quiescent.
#
# Runtime reconfiguration: the enabled flag is re-read from router.json on
# every tick (env override wins), so `keepalive.enabled: false` stops the
# agent without a launchctl reload, and true resumes it.
#
# Knobs (env vars, defaults):
#   PROXY_KEEPALIVE_INTERVAL       base wait between ensures           (15)
#   PROXY_KEEPALIVE_MAX_BACKOFF    cap for exponential backoff         (300)
#   PROXY_KEEPALIVE_PROBE_EVERY    egress check per N successful ensures (4)
#   PROXY_KEEPALIVE_DEAD_STRIKES   consecutive dead checks before rotate (2)
#   PROXY_KEEPALIVE_STORM_WINDOW   rotation-guard window in seconds    (600)
#   PROXY_KEEPALIVE_MAX_ROTATIONS  max keepalive rotations per window  (2)
#   PROXY_KEEPALIVE_SWEEP_EVERY    full-pool egress sweep every N seconds (1800)
#   PROXY_KEEPALIVE_ENABLED        temporary on/off override               (config)
set -uo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# The scripts ship under examples/ next to router.py; locate the prefix either
# from the examples dir (parent) or from a standalone copy of the script.
if [ ! -f "$ROOT/router.py" ] && [ -f "$(dirname "$ROOT")/router.py" ]; then
  ROOT="$(dirname "$ROOT")"
fi

# Controller invocation. install-launchd.sh pins the exact interpreter that
# elevation authorized into the plist environment (PROXY_ROUTER_PYTHON), so a
# launchd run never resolves python3 through an ambient PATH that differs from
# the authorized identity. Standalone/manual runs without the env var keep
# executing router.py directly through its shebang.
controller() {
  if [ -n "${PROXY_ROUTER_PYTHON:-}" ]; then
    "$PROXY_ROUTER_PYTHON" "$ROOT/router.py" "$@"
  else
    "$ROOT/router.py" "$@"
  fi
}

# Read one validated value from router.json. Environment variables below win,
# so launchd/system operators can make temporary changes without rewriting
# config. Missing or malformed config falls back to the safe defaults.
config_setting() {
  if [ -n "${PROXY_ROUTER_PYTHON:-}" ]; then
    "$PROXY_ROUTER_PYTHON" - "$ROOT/router.json" "$1" "$2" <<'PY' 2>/dev/null || printf '%s\n' "$2"
import json
import sys

path, key, default = sys.argv[1:]
try:
    data = json.loads(open(path, encoding="utf-8").read())
    value = (data.get("keepalive") or {}).get(key, default)
    if key == "enabled":
        print("1" if value not in (False, 0, "0", "false", "off") else "0")
    else:
        value = int(value)
        if value < 1:
            raise ValueError
        print(value)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
  else
    python3 - "$ROOT/router.json" "$1" "$2" <<'PY' 2>/dev/null || printf '%s\n' "$2"
import json
import sys

path, key, default = sys.argv[1:]
try:
    data = json.loads(open(path, encoding="utf-8").read())
    value = (data.get("keepalive") or {}).get(key, default)
    if key == "enabled":
        print("1" if value not in (False, 0, "0", "false", "off") else "0")
    else:
        value = int(value)
        if value < 1:
            raise ValueError
        print(value)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
  fi
}

ENABLED="${PROXY_KEEPALIVE_ENABLED:-$(config_setting enabled 1)}"
case "$ENABLED" in
  0|false|False|off|OFF)
    echo "router: autocheck disabled"
    exit 0
    ;;
esac
INTERVAL="${PROXY_KEEPALIVE_INTERVAL:-$(config_setting interval 15)}"
MAX_BACKOFF="${PROXY_KEEPALIVE_MAX_BACKOFF:-$(config_setting max_backoff 300)}"
PROBE_EVERY="${PROXY_KEEPALIVE_PROBE_EVERY:-$(config_setting probe_every 4)}"
DEAD_STRIKES="${PROXY_KEEPALIVE_DEAD_STRIKES:-$(config_setting dead_strikes 2)}"
STORM_WINDOW="${PROXY_KEEPALIVE_STORM_WINDOW:-$(config_setting storm_window 600)}"
MAX_ROTATIONS="${PROXY_KEEPALIVE_MAX_ROTATIONS:-$(config_setting max_rotations 2)}"
SWEEP_EVERY="${PROXY_KEEPALIVE_SWEEP_EVERY:-$(config_setting sweep_every 1800)}"

backoff="$INTERVAL"
boot=1
checks=0
strikes=0
rotations=0
window_start=0
last_sweep=0

# Allow at most MAX_ROTATIONS keepalive rotations per STORM_WINDOW seconds.
rotation_allowed() {
  now=$(date +%s)
  if [ "$window_start" -eq 0 ] || [ $((now - window_start)) -ge "$STORM_WINDOW" ]; then
    window_start="$now"
    rotations=0
  fi
  [ "$rotations" -lt "$MAX_ROTATIONS" ]
}

# One bounded auto-rotation for the provider `egress check` reported dead.
# `egress check` prints "dead: <provider>" as its last stdout line (and exits
# 1) when an active exit is dead; without that line nothing is rotated.
rotate_dead() {
  provider="$1"
  if [ -z "$provider" ]; then
    # egress check failed before it could name a dead provider (e.g. TUN
    # mode, or the engine itself is down): never rotate on an ambiguous
    # signal - ensure already handles the engine-down case.
    echo "router: egress check dead but no provider identified; skipping rotation" >&2
    strikes=0
    return
  fi
  if ! rotation_allowed; then
    echo "router: rotation skipped (storm guard: $rotations rotations in the last ${STORM_WINDOW}s)" >&2
    strikes=0
    return
  fi
  # Count every recovery attempt, including a failed rotate/fallback attempt.
  # Otherwise an exhausted provider can be retried forever every probe tick.
  rotations=$((rotations + 1))
  strikes=0
  echo "router: rotating '$provider' after dead tunnel checks" >&2
  if controller rotate "$provider" --reason timeout; then
    :
  else
    echo "router: rotate '$provider' failed; checking configured fallback" >&2
    fallback_state=$(controller failover "$provider" status 2>/dev/null || true)
    configured_fallback=$(printf '%s\n' "$fallback_state" | sed -n 's/.* configured=\([^ ]*\).*/\1/p')
    active_fallback=$(printf '%s\n' "$fallback_state" | sed -n 's/.* active=\([^ ]*\).*/\1/p')
    case "$active_fallback" in
      ""|none|no|false|0|off|OFF)
        ;;
      *)
        echo "router: fallback '$active_fallback' already active; waiting for the next dead check" >&2
        return
        ;;
    esac
    case "$configured_fallback" in
      ""|none|no|false|0|off|OFF)
        echo "router: no configured fallback for '$provider'; backing off" >&2
        return
        ;;
    esac
    if ! controller failover "$provider" on --reason timeout >/dev/null 2>&1; then
      echo "router: fallback for '$provider' failed; will retry after the next dead check" >&2
      return
    fi
  fi
}

# One bounded restore attempt per fallback-parked provider, run on the sweep
# cadence: clear the marker, probe the primary live through the tunnel, keep
# the fallback cleared when the primary answers, re-activate it when the
# primary is still dead. The sweep cadence throttles the restore, so a
# genuinely dead primary never causes a failover off/on storm.
restore_fallbacks() {
  out=$(controller egress check 2>&1 || true)
  printf '%s\n' "$out" | sed -n 's/^\([A-Za-z0-9._-]*\): fallback (.*)$/\1/p' | while IFS= read -r provider; do
    [ -n "$provider" ] || continue
    if ! controller failover "$provider" off >/dev/null 2>&1; then
      continue
    fi
    if controller egress check --provider "$provider" >/dev/null 2>&1; then
      echo "router: '$provider' primary is alive again; fallback cleared" >&2
    else
      echo "router: '$provider' primary still dead; re-activating fallback" >&2
      controller failover "$provider" on --reason timeout >/dev/null 2>&1 || true
    fi
  done
}

while true; do
  # Re-read the enabled flag every tick so a runtime config flip takes effect
  # without waiting for an agent restart (env override still wins for
  # temporary ops changes).
  ENABLED="${PROXY_KEEPALIVE_ENABLED:-$(config_setting enabled 1)}"
  case "$ENABLED" in
    0|false|False|off|OFF)
      echo "$(date '+%Y-%m-%d %H:%M:%S') router: autocheck disabled by config; exiting" >&2
      exit 0
      ;;
  esac
  # Manual-off quiescence: the user disconnected deliberately. Do NOTHING
  # until `router.py start` clears the marker - no ensure (which would report
  # "ok" and let maintenance continue), no egress checks, no rotations, no
  # sweeps, no fallback restore. Reset backoff so a reconnect is acted on at
  # the base cadence, and log the transition once instead of every tick.
  if [ -f "$ROOT/state/manual-off" ]; then
    if [ "${manual_quiet:-0}" -ne 1 ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') router: manual-off present; supervision quiescent (ensure/probe/rotate/sweep paused)" >&2
      manual_quiet=1
    fi
    backoff="$INTERVAL"
    sleep "$backoff"
    continue
  fi
  manual_quiet=0
  if ensure_out=$(controller ensure 2>&1); then
    if [ "$backoff" -ne "$INTERVAL" ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') router: ensure ok; backoff reset to ${INTERVAL}s" >&2
    fi
    backoff="$INTERVAL"
    if [ "$boot" -eq 1 ]; then
      boot=0
      # Boot self-test: one live egress check on the first successful ensure.
      # A dead tunnel gets ONE early rotation (storm guard applies); a
      # healthy one is logged and the normal loop continues.
      if out=$(controller egress check 2>&1); then
        echo "router: boot self-test ok"
      else
        echo "router: boot self-test: active tunnel is dead - rotating once ($(printf '%s\n' "$out" | tail -n 1))" >&2
        rotate_dead "$(printf '%s\n' "$out" | sed -n 's/^dead: //p')"
      fi
    else
      checks=$((checks + 1))
      if [ "$checks" -ge "$PROBE_EVERY" ]; then
        checks=0
        if out=$(controller egress check 2>&1); then
          strikes=0
        else
          strikes=$((strikes + 1))
          echo "router: egress check: dead exit ($strikes/$DEAD_STRIKES strikes): $(printf '%s\n' "$out" | tail -n 1)" >&2
          if [ "$strikes" -ge "$DEAD_STRIKES" ]; then
            rotate_dead "$(printf '%s\n' "$out" | sed -n 's/^dead: //p')"
          fi
        fi
      fi
      # Scheduled rotation: `rotate --if-due` self-gates on the configured
      # interval (exit 0 = rotated, 3 = not due); never logs when quiet.
      if controller rotate --if-due >/dev/null 2>&1; then
        echo "router: scheduled rotation: rotated provider(s)" >&2
      fi
    fi
    # Time-based full-pool sweep: on the first successful ensure, and every
    # SWEEP_EVERY seconds after, probe EVERY profile of every provider and
    # end on the best alive exit (each profile hop is a hard server switch;
    # a failed/empty sweep restores the original active profile when possible).
    sweep_now=$(date +%s)
    # Rotation/sweep stagger: a full-pool sweep hard-switches exit to exit;
    # never run it right after a scheduled rotation flipped the active exit
    # (the fresh session is still settling and the sweep would immediately
    # hop away). PROXY_KEEPALIVE_STAGGER seconds after the newest rotation
    # record, the sweep defers to the next tick.
    STAGGER="${PROXY_KEEPALIVE_STAGGER:-300}"
    newest_rotation=0
    for rotation_file in "$ROOT"/state/*.rotation; do
      [ -f "$rotation_file" ] || continue
      rotated_at=$(sed -n 's/.*"at": *\([0-9]*\).*/\1/p' "$rotation_file" 2>/dev/null || echo 0)
      case "$rotated_at" in ''|*[!0-9]*) rotated_at=0 ;; esac
      [ "$rotated_at" -gt "$newest_rotation" ] && newest_rotation="$rotated_at"
    done
    if [ "$newest_rotation" -gt 0 ] && [ $((sweep_now - newest_rotation)) -lt "$STAGGER" ]; then
      echo "router: sweep deferred (rotation ${STAGGER}s stagger window)" >&2
    elif [ "$last_sweep" -eq 0 ] || [ $((sweep_now - last_sweep)) -ge "$SWEEP_EVERY" ]; then
      if controller egress sweep --json >/dev/null 2>&1; then
        echo "router: full-pool egress sweep done"
      else
        echo "router: sweep: some provider has no alive exits" >&2
      fi
      # fallback restore rides the sweep cadence (see restore_fallbacks)
      restore_fallbacks
      last_sweep="$sweep_now"
    fi
  else
    ensure_rc=$?
    if [ "$ensure_rc" -eq 3 ]; then
      # Quiescent: manual-off appeared between our marker check and ensure (or
      # a direct ensure raced us). Not a failure - no backoff, no barf log.
      backoff="$INTERVAL"
      sleep "$backoff"
      continue
    fi
    backoff=$((backoff * 2))
    ((backoff < INTERVAL)) && backoff="$INTERVAL"
    ((backoff > MAX_BACKOFF)) && backoff="$MAX_BACKOFF"
    echo "$(date '+%Y-%m-%d %H:%M:%S') router: ensure failed (rc=$ensure_rc): $(printf '%s\n' "$ensure_out" | tail -n 1); backing off to ${backoff}s" >&2
  fi
  sleep "$backoff"
done
