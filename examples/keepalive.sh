#!/usr/bin/env bash
# Keeps the proxy router's sing-box listener alive on 127.0.0.1:2080.
#
# Runs indefinitely as a launchd agent: every CHECK_INTERVAL seconds it calls
# `router.py ensure`, which starts the engine when the listener is missing.
# This resurrects a silently-died proxy without waiting for the next login or
# for a Hermes process to be restarted.
set -uo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INTERVAL="${PROXY_KEEPALIVE_INTERVAL:-15}"

while true; do
  "$ROOT/router.py" ensure >/dev/null || true
  sleep "$INTERVAL"
done