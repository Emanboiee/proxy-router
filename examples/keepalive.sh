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
# first successful ensure (one early rotation in proxy mode, same storm
# guard). TUN mode still permits read-only checks, but never performs an
# automatic profile or fallback change. A single-profile pool with no viable
# rotation candidate parks once on its configured fallback and stays sticky
# (restore rides the sweep cadence); base-route gaps ("missing default
# interface", "no route to internet", "WireGuard is not ready") defer
# without consuming strike/rotation budget.
#
# Scheduled rotation: when router.json has a "rotation" block, the loop also
# calls `router.py rotate --if-due` on every healthy tick in proxy mode - the
# CLI reads the configured interval/jitter and only rotates once the interval
# has elapsed (exit 3 = not due, nothing logged). TUN mode skips this shared
# engine interruption so long-lived connections such as Discord stay up. The
# verify-then-switch rollback path and per-provider cooldowns apply exactly as
# for a manual rotate; `state/<provider>.rotation` tracks the last switch time.
# TUN mode skips this and all other automatic profile changes.
#
# Full-pool egress sweep: nothing above probes the non-active exits, so a pool
# could sit on a stale-but-alive lane forever. Every
# PROXY_KEEPALIVE_SWEEP_EVERY seconds (default 1800 = 30 min) the loop runs
# `router.py egress sweep`, which probes EVERY profile of every provider
# through the tunnel, persists health/cooldown/block markers, and ends on the
# best alive exit (no reload when the current exit already is best). TUN mode
# skips the background sweep because all providers share one engine. Explicit
# CLI sweep/rotate commands remain operator-controlled interruptions.
#
# Manual-off quiescence: when `state/manual-off` exists (user disconnected via
# tray/CLI), the loop performs NO maintenance at all - no ensure, no probe, no
# rotation, no sweep, no fallback restore. Manual disconnect is a deliberate
# state, not an engine failure; the tunnel stays down until `router.py start`
# clears the marker. The agent polls only its own enabled flag while quiescent.
#
# Network-loss guard: on macOS the loop checks the active Wi-Fi SSID before
# supervision. After NETWORK_GRACE consecutive misses it disables the system
# proxy and stops sing-box, then reconnects only after the SSID returns. The
# network-off latch is separate from manual-off, so an operator disconnect still
# remains quiescent and never gets auto-resurrected.
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
#   PROXY_KEEPALIVE_NETWORK_GRACE consecutive Wi-Fi misses before stop (1)
#   PROXY_KEEPALIVE_WAKE_GAP       sleep/wake gap forcing recovery (2x interval)
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

python_runner() {
  if [ -n "${PROXY_ROUTER_PYTHON:-}" ]; then
    "$PROXY_ROUTER_PYTHON" "$@"
  else
    python3 "$@"
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

# Read one validated top-level autodetection setting. Environment overrides
# remain available for temporary operator changes without rewriting config.
autodetect_setting() {
  if [ -n "${PROXY_ROUTER_PYTHON:-}" ]; then
    "$PROXY_ROUTER_PYTHON" - "$ROOT/router.json" "$1" "$2" <<'PY' 2>/dev/null || printf '%s\n' "$2"
import json
import sys

path, key, default = sys.argv[1:]
try:
    data = json.loads(open(path, encoding="utf-8").read())
    value = (data.get("autodetect") or {}).get(key, default)
    if key == "enabled":
        print("1" if value not in (False, 0, "0", "false", "off") else "0")
    else:
        value = int(value)
        if value < 30:
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
    value = (data.get("autodetect") or {}).get(key, default)
    if key == "enabled":
        print("1" if value not in (False, 0, "0", "false", "off") else "0")
    else:
        value = int(value)
        if value < 30:
            raise ValueError
        print(value)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
  fi
}


# Return every explicit and generated autodetection source for periodic refresh.
autodetect_sources() {
  python_runner - "$ROOT/router.json" <<'PY' 2>/dev/null
import json
import pathlib
import sys

try:
    config_path = pathlib.Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(config_path.parent))
    import router

    data = json.loads(config_path.read_text(encoding="utf-8"))
    routes = data.get("routes") or []
    providers = data.get("providers") or {}
    settings = router._load_autodetect(data, routes, providers)
    if not settings["enabled"]:
        raise SystemExit(0)
    for source in sorted(settings["sources"]):
        print(source)
except (OSError, TypeError, ValueError, json.JSONDecodeError, ImportError, AttributeError):
    raise SystemExit(1)
PY
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
NETWORK_GRACE="${PROXY_KEEPALIVE_NETWORK_GRACE:-$(config_setting network_grace 1)}"
AUTODETECT_ENABLED="${PROXY_AUTODETECT_ENABLED:-$(autodetect_setting enabled 0)}"
AUTODETECT_INTERVAL="${PROXY_AUTODETECT_INTERVAL:-$(autodetect_setting interval_seconds 300)}"
WAKE_GAP="${PROXY_KEEPALIVE_WAKE_GAP:-$((INTERVAL * 2))}"
case "$WAKE_GAP" in
  ''|*[!0-9]*) WAKE_GAP=$((INTERVAL * 2)) ;;
esac
((WAKE_GAP < 1)) && WAKE_GAP=1

backoff="$INTERVAL"
boot=1
checks=0
strikes=0
rotations=0
window_start=0
last_sweep=0
last_autodetect=0
network_lost=0
network_quiet=0
last_tick=0

# Allow at most MAX_ROTATIONS keepalive rotations per STORM_WINDOW seconds.
rotation_allowed() {
  now=$(date +%s)
  if [ "$window_start" -eq 0 ] || [ $((now - window_start)) -ge "$STORM_WINDOW" ]; then
    window_start="$now"
    rotations=0
  fi
  [ "$rotations" -lt "$MAX_ROTATIONS" ]
}

# TUN shares one sing-box process across every provider. Background profile
# changes reload that process and can drop unrelated long-lived connections
# such as Hermes' Discord gateway. Keep the automatic rotation/sweep lane in
# proxy mode; explicit router commands still work in either mode.
is_tun_mode() {
  local marker=""
  local generated="unknown"
  if [ -r "$ROOT/state/mode" ]; then
    marker=$(tr -d '[:space:]' < "$ROOT/state/mode" 2>/dev/null || true)
  fi
  if [ "$marker" = "tun" ]; then
    return 0
  fi

  # A stale marker must not authorize disruptive maintenance. The generated
  # config is the second source of truth: if it contains a TUN inbound, skip
  # maintenance even when state/mode still says proxy. Only a valid proxy
  # marker plus a readable config that contains no TUN is positive proxy proof.
  if [ -r "$ROOT/sing-box.json" ]; then
    generated=$(python_runner - "$ROOT/sing-box.json" 2>/dev/null <<'PY'
import json
import sys

try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError
    inbounds = data.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError
    print("tun" if any(isinstance(item, dict) and item.get("type") == "tun"
                         for item in inbounds) else "proxy")
except (OSError, TypeError, ValueError, json.JSONDecodeError):
    print("unknown")
PY
)
  fi
  if [ "$generated" = "tun" ]; then
    return 0
  fi
  if [ "$marker" = "proxy" ] && [ "$generated" = "proxy" ]; then
    return 1
  fi

  # Unknown or unreadable state is fail-closed: skip disruptive maintenance.
  return 0
}

# LIFECYCLE-HELPERS-START (extracted verbatim by lifecycle unit tests; keep
# these functions side-effect free and free of top-level state).
# Base-route / network-loss signals are a deferral, never rotation budget:
# reloading the engine while the base route is gone only produces "missing
# default interface" / "no route to internet" / "WireGuard is not ready"
# noise and drops long-lived flows (Discord). Case-insensitive.
is_network_gap() {
  printf '%s' "${1:-}" | grep -iq -e 'missing default' -e 'no route to' -e 'wireguard is not ready' -e 'no default route' -e 'network unreachable' -e 'network is down' -e 'no internet' -e 'tunnel is down' -e 'engine not listening'
}

# Lowercase + trim + strip brackets/quotes/parens, for inactive-marker
# comparison only (provider-name spelling is preserved by
# fallback_active_name).
normalize_fallback_token() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -d "[]()\"'" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# True (0) for inactive markers: empty, none, no, false, 0, off, null,
# nil, -, n/a, na, [], etc. Anything else is a candidate name. Never
# mistakes an inactive marker for an active fallback.
fallback_value_is_inactive() {
  _fvi_stripped=$(printf '%s' "${1:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
  case "$_fvi_stripped" in
    ""|"[]"|"["|"]") return 0 ;;
  esac
  _fvi_norm=$(normalize_fallback_token "${1:-}")
  case "$_fvi_norm" in
    ""|none|no|n|false|0|off|null|nil|-|n/a|na) return 0 ;;
  esac
  return 1
}

# True (0) when the raw configured value names at least one candidate:
# plain names, comma lists, and Python list reprs (['proton'],
# ["proton", "direct"]). Inactive markers and empty lists do not count.
fallback_configured_has_candidate() {
  _fcc_cleaned=$(printf '%s' "${1:-}" | tr ',;' ' ' | tr -d "[]()\"'")
  for _fcc_tok in $_fcc_cleaned; do
    if fallback_value_is_inactive "$_fcc_tok"; then
      continue
    fi
    case "$_fcc_tok" in
      *[!A-Za-z0-9._-]* ) continue ;;
      *) return 0 ;;
    esac
  done
  return 1
}

# Echo the active fallback provider name, or nothing when the raw value is
# an inactive marker. Lenient toward sticky (first valid token wins) so a
# malformed status line can never trigger a reload storm; a status that
# reads inactive simply retries within the storm guard.
fallback_active_name() {
  _fan_cleaned=$(printf '%s' "${1:-}" | tr ',;' ' ' | tr -d "[]()\"'")
  for _fan_tok in $_fan_cleaned; do
    _fan_trimmed=$(printf '%s' "$_fan_tok" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$_fan_trimmed" ] || continue
    if fallback_value_is_inactive "$_fan_trimmed"; then
      continue
    fi
    case "$_fan_trimmed" in
      *[!A-Za-z0-9._-]* ) continue ;;
      *) printf '%s\n' "$_fan_trimmed"; return 0 ;;
    esac
  done
  return 1
}

# Split `failover status` text into FB_CONFIGURED / FB_ACTIVE globals.
# Handles extra whitespace, any-case keys, and list-valued configured
# fields containing spaces. Returns 1 when no configured field is found.
fallback_split_status_text() {
  _fst_line=$(printf '%s\n' "${1:-}" | grep -i 'configured[[:space:]]*=' | tail -n 1)
  [ -n "$_fst_line" ] || return 1
  _fst_rest=$(printf '%s\n' "$_fst_line" | sed -n 's/.*[Cc][Oo][Nn][Ff][Ii][Gg][Uu][Rr][Ee][Dd][[:space:]]*=[[:space:]]*//p')
  [ -n "$_fst_rest" ] || return 1
  if printf '%s\n' "$_fst_rest" | grep -iq '[[:space:]]active[[:space:]]*='; then
    FB_ACTIVE=$(printf '%s\n' "$_fst_rest" | sed -n 's/.*[[:space:]][Aa][Cc][Tt][Ii][Vv][Ee][[:space:]]*=[[:space:]]*//p' | sed -e 's/[[:space:]]*$//')
    FB_CONFIGURED=$(printf '%s\n' "$_fst_rest" | sed 's/[[:space:]][Aa][Cc][Tt][Ii][Vv][Ee][[:space:]]*=[[:space:]]*.*$//' | sed -e 's/[[:space:]]*$//')
  else
    FB_CONFIGURED=$(printf '%s' "$_fst_rest" | sed -e 's/[[:space:]]*$//')
    FB_ACTIVE=""
  fi
  return 0
}

# Set FB_CONFIGURED / FB_ACTIVE for a provider. Prefers `status --json`
# (list-safe); falls back to text parsing. Returns 1 when unavailable.
get_fallback_state() {
  FB_CONFIGURED=""; FB_ACTIVE=""
  _gfs_provider="$1"
  if _gfs_json=$(controller failover "$_gfs_provider" status --json 2>/dev/null); then
    if _gfs_parsed=$(python_runner - "$_gfs_json" 2>/dev/null <<'PY'
import json
import sys

try:
    data = json.loads(sys.argv[1])
except Exception:
    raise SystemExit(1)
if not isinstance(data, dict):
    raise SystemExit(1)
conf = data.get("configured", "")
if isinstance(conf, list):
    conf = ",".join(str(x) for x in conf)
elif conf is None:
    conf = ""
else:
    conf = str(conf)
act = data.get("active", "")
if act is None:
    act = ""
else:
    act = str(act)
print(conf)
print(act)
PY
); then
      FB_CONFIGURED=$(printf '%s\n' "$_gfs_parsed" | sed -n '1p')
      FB_ACTIVE=$(printf '%s\n' "$_gfs_parsed" | sed -n '2p')
      return 0
    fi
  fi
  _gfs_state=$(controller failover "$_gfs_provider" status 2>/dev/null || true)
  [ -n "$_gfs_state" ] || return 1
  fallback_split_status_text "$_gfs_state"
}
# LIFECYCLE-HELPERS-END

# One bounded auto-rotation for the provider `egress check` reported dead in
# proxy mode. TUN mode only reports the dead path; it does not reload the
# shared engine automatically.
# `egress check` prints "dead: <provider>" as its last stdout line (and exits
# 1) when an active exit is dead; without that line nothing is rotated.
# Single-profile pools with a configured fallback park once and stay sticky;
# base-route gaps defer without budget. $2 carries the full egress output
# for gap detection.
rotate_dead() {
  provider="$1"
  egress_out="${2:-}"
  if is_tun_mode; then
    echo "router: automatic dead-exit rotation skipped in TUN mode" >&2
    strikes=0
    return
  fi
  if [ -z "$provider" ]; then
    # egress check failed before it could name a dead provider (e.g. TUN
    # mode, or the engine itself is down): never rotate on an ambiguous
    # signal - ensure already handles the engine-down case.
    echo "router: egress check dead but no provider identified; skipping rotation" >&2
    strikes=0
    return
  fi
  # Base-route gap: defer without consuming strike/rotation budget.
  if [ -n "$egress_out" ] && is_network_gap "$egress_out"; then
    echo "router: network gap detected for '$provider'; deferring rotation (no budget consumed)" >&2
    strikes=0
    return
  fi
  # If the egress checker already identifies a fallback path, do not spend
  # a rotation/status round-trip on the parked primary. This keeps normal
  # non-fallback rotation cadence unchanged while making the sticky path
  # completely quiet.
  if printf '%s\n' "$egress_out" | grep -Eiq 'fallback[[:space:]]*\('; then
    parked=$(printf '%s\n' "$egress_out" | sed -n 's/.*fallback[[:space:]]*(\([^)]*\)).*/\1/p' | tail -n 1)
    if [ -n "$parked" ]; then
      echo "router: fallback '$parked' already active for '$provider'; staying parked (no rotation)" >&2
      strikes=0
      return
    fi
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
  if controller rotate "$provider" --reason timeout --automatic; then
    :
  else
    rotate_rc=$?
    if [ "$rotate_rc" -eq 3 ]; then
      echo "router: automatic dead-exit rotation skipped in TUN mode" >&2
      return
    fi
    echo "router: rotate '$provider' failed; checking configured fallback" >&2
    if ! get_fallback_state "$provider"; then
      echo "router: fallback status unavailable for '$provider'; backing off" >&2
      return
    fi
    parked=$(fallback_active_name "$FB_ACTIVE" || true)
    if [ -n "$parked" ]; then
      echo "router: fallback '$parked' already active for '$provider'; staying parked (no rotation)" >&2
      return
    fi
    if ! fallback_configured_has_candidate "$FB_CONFIGURED"; then
      echo "router: no configured fallback for '$provider'; backing off" >&2
      return
    fi
    if ! controller failover "$provider" on --reason timeout --automatic >/dev/null 2>&1; then
      echo "router: fallback for '$provider' failed; will retry after the next dead check" >&2
      return
    fi
    echo "router: parked '$provider' on fallback (sticky; restore rides the sweep cadence)" >&2
  fi
}

# One bounded restore attempt per fallback-parked provider, run on the sweep
# cadence: clear the marker, probe the primary live through the tunnel, keep
# the fallback cleared when the primary answers, re-activate it when the
# primary is still dead. The sweep cadence throttles the restore, so a
# genuinely dead primary never causes a failover off/on storm.
restore_fallbacks() {
  if is_tun_mode; then
    return
  fi
  out=$(controller egress check 2>&1 || true)
  printf '%s\n' "$out" | sed -n 's/^\([A-Za-z0-9._-]*\): fallback (.*)$/\1/p' | while IFS= read -r provider; do
    [ -n "$provider" ] || continue
    if ! controller failover "$provider" off --automatic >/dev/null 2>&1; then
      continue
    fi
    if controller egress check --provider "$provider" >/dev/null 2>&1; then
      echo "router: '$provider' primary is alive again; fallback cleared" >&2
    else
      echo "router: '$provider' primary still dead; re-activating fallback" >&2
      controller failover "$provider" on --reason timeout --automatic >/dev/null 2>&1 || true
    fi
  done
}

while true; do
  tick_now=$(date +%s 2>/dev/null || echo 0)
  case "$tick_now" in ''|*[!0-9]*) tick_now=0 ;; esac
  wake_detected=0
  wake_elapsed=0
  if [ "$last_tick" -gt 0 ] && [ "$tick_now" -ge "$last_tick" ] \
     && [ $((tick_now - last_tick)) -ge "$WAKE_GAP" ]; then
    wake_detected=1
    wake_elapsed=$((tick_now - last_tick))
  fi
  last_tick="$tick_now"
  # Re-read the enabled flag every tick so a runtime config flip takes effect
  # without waiting for an agent restart (env override still wins for
  # temporary ops changes).
  ENABLED="${PROXY_KEEPALIVE_ENABLED:-$(config_setting enabled 1)}"
  AUTODETECT_ENABLED="${PROXY_AUTODETECT_ENABLED:-$(autodetect_setting enabled 0)}"
  AUTODETECT_INTERVAL="${PROXY_AUTODETECT_INTERVAL:-$(autodetect_setting interval_seconds 300)}"
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
  if [ "$wake_detected" -eq 1 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') router: wake gap detected (${wake_elapsed}s); forcing network recovery" >&2
    if controller network-status >/dev/null 2>&1; then
      if controller network-disconnect >/dev/null 2>&1 \
         && controller network-reconnect >/dev/null 2>&1; then
        network_lost=0
        network_quiet=0
        boot=1
        checks=0
        strikes=0
        backoff="$INTERVAL"
      else
        echo "$(date '+%Y-%m-%d %H:%M:%S') router: wake recovery failed; retrying" >&2
        network_quiet=1
        backoff="$INTERVAL"
        sleep "$backoff"
        continue
      fi
    fi
  fi
  # Network guard runs before ensure so a stale proxy cannot strand browsers
  # while Wi-Fi is off. `network-status` is read-only; the controller commands
  # own the durable marker and the teardown/reconnect transaction.
  if controller network-status >/dev/null 2>&1; then
    network_lost=0
    if [ -f "$ROOT/state/network-off" ]; then
      if controller network-reconnect >/dev/null 2>&1; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') router: Wi-Fi returned; supervision resumed" >&2
        network_quiet=0
        boot=1
        checks=0
        strikes=0
        backoff="$INTERVAL"
      else
        echo "$(date '+%Y-%m-%d %H:%M:%S') router: Wi-Fi returned but reconnect failed; retrying" >&2
        backoff="$INTERVAL"
        sleep "$backoff"
        continue
      fi
    fi
  else
    network_lost=$((network_lost + 1))
    if [ "$network_lost" -ge "$NETWORK_GRACE" ]; then
      if controller network-disconnect >/dev/null 2>&1; then
        if [ "$network_quiet" -ne 1 ]; then
          echo "$(date '+%Y-%m-%d %H:%M:%S') router: Wi-Fi unavailable; proxy-router disconnected" >&2
        fi
      elif [ "$network_quiet" -ne 1 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') router: Wi-Fi unavailable; disconnect retry pending" >&2
      fi
      network_quiet=1
    fi
    backoff="$INTERVAL"
    sleep "$backoff"
    continue
  fi
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
      elif is_network_gap "$out"; then
        echo "router: boot self-test: network gap detected - deferring rotation ($(printf '%s\n' "$out" | tail -n 1))" >&2
        strikes=0
      else
        echo "router: boot self-test: active tunnel is dead - rotating once ($(printf '%s\n' "$out" | tail -n 1))" >&2
        rotate_dead "$(printf '%s\n' "$out" | sed -n 's/^dead: //p')" "$out"
      fi
    else
      checks=$((checks + 1))
      if [ "$checks" -ge "$PROBE_EVERY" ]; then
        checks=0
        if out=$(controller egress check 2>&1); then
          strikes=0
        elif is_network_gap "$out"; then
          echo "router: egress check: network gap detected - deferring (no strike, no rotation): $(printf '%s\n' "$out" | tail -n 1)" >&2
          strikes=0
        else
          strikes=$((strikes + 1))
          echo "router: egress check: dead exit ($strikes/$DEAD_STRIKES strikes): $(printf '%s\n' "$out" | tail -n 1)" >&2
          if [ "$strikes" -ge "$DEAD_STRIKES" ]; then
            rotate_dead "$(printf '%s\n' "$out" | sed -n 's/^dead: //p')" "$out"
          fi
        fi
      fi
      # Scheduled rotation: `rotate --if-due` self-gates on the configured
      # interval (exit 0 = rotated, 3 = not due); never logs when quiet.
      # TUN mode skips this shared-engine interruption.
      if ! is_tun_mode; then
        if controller rotate --if-due >/dev/null 2>&1; then
          echo "router: scheduled rotation: rotated provider(s)" >&2
        fi
      fi
    fi
    autodetect_now=$(date +%s)
    if [ "$AUTODETECT_ENABLED" != "0" ] && ! is_tun_mode \
       && { [ "$last_autodetect" -eq 0 ] || [ $((autodetect_now - last_autodetect)) -ge "$AUTODETECT_INTERVAL" ]; }; then
      sources=$(autodetect_sources 2>/dev/null || printf '%s\n' twitch)
      while IFS= read -r source; do
        [ -n "$source" ] || continue
        if controller autodetect "$source" --quiet; then
          :
        else
          echo "router: autodetect $source failed; keeping existing learned routes" >&2
        fi
      done <<< "$sources"
      last_autodetect="$autodetect_now"
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
    if is_tun_mode; then
      :
    elif [ "$newest_rotation" -gt 0 ] && [ $((sweep_now - newest_rotation)) -lt "$STAGGER" ]; then
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
