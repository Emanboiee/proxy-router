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
set -uo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# The scripts ship under examples/ next to router.py; locate the prefix either
# from the examples dir (parent) or from a standalone copy of the script.
if [ ! -f "$ROOT/router.py" ] && [ -f "$(dirname "$ROOT")/router.py" ]; then
  ROOT="$(dirname "$ROOT")"
fi
INTERVAL="${PROXY_KEEPALIVE_INTERVAL:-15}"
MAX_BACKOFF="${PROXY_KEEPALIVE_MAX_BACKOFF:-300}"

backoff="$INTERVAL"
while true; do
  if "$ROOT/router.py" ensure >/dev/null 2>&1; then
    backoff="$INTERVAL"
  else
    backoff=$((backoff * 2))
    ((backoff < INTERVAL)) && backoff="$INTERVAL"
    ((backoff > MAX_BACKOFF)) && backoff="$MAX_BACKOFF"
  fi
  sleep "$backoff"
done