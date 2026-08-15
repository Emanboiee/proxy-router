#!/usr/bin/env bash
# Start the opt-in response-aware proxy; it never installs or trusts a CA.
set -euo pipefail

ACTION="${1:-start}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${PROXY_ROUTER_ROOT:-"$SCRIPT_DIR/.."}
LISTEN_HOST=${RESPONSE_AWARE_LISTEN_HOST:-127.0.0.1}
LISTEN_PORT=${RESPONSE_AWARE_LISTEN_PORT:-2081}
UPSTREAM=${RESPONSE_AWARE_UPSTREAM:-http://127.0.0.1:2080}
MITMDUMP=${MITMDUMP:-mitmdump}
CONFDIR=${RESPONSE_AWARE_CONFDIR:-"$ROOT/state/response-aware/mitmproxy"}
LOG_FILE=${RESPONSE_AWARE_LOG_FILE:-"$ROOT/state/response-aware.log"}
LOG_LINES=${RESPONSE_AWARE_LOG_LINES:-100}

case "$ACTION" in
  logs)
    if [ ! -f "$LOG_FILE" ]; then
      printf 'response-aware: no log yet (%s)\n' "$LOG_FILE"
      exit 0
    fi
    printf '%s\n' "response-aware recent log: $LOG_FILE"
    tail -n "$LOG_LINES" "$LOG_FILE"
    ;;
  start)
    if [ "${RESPONSE_AWARE_ENABLED:-0}" != "1" ]; then
      printf '%s\n' "response-aware: disabled (set RESPONSE_AWARE_ENABLED=1 to start)" >&2
      exit 2
    fi
    if ! command -v "$MITMDUMP" >/dev/null 2>&1; then
      printf '%s\n' "response-aware: mitmdump not found; install mitmproxy first" >&2
      exit 1
    fi
    mkdir -p "$CONFDIR" "$(dirname "$LOG_FILE")"
    # Ignore every TLS host except the configured OpenCode allowlist. The
    # addon receives RESPONSE_AWARE_HOSTS; this default keeps other HTTPS
    # traffic as an opaque upstream tunnel.
    IGNORE_HOSTS=${RESPONSE_AWARE_IGNORE_HOSTS:-'^(?!.*(?:^|\.)opencode\.ai(?::[0-9]+)?$).*'}
    export PROXY_ROUTER_ROOT="$ROOT"
    export RESPONSE_AWARE_LOG_FILE="$LOG_FILE"
    exec "$MITMDUMP" \
      --mode "upstream:$UPSTREAM" \
      --listen-host "$LISTEN_HOST" \
      --listen-port "$LISTEN_PORT" \
      --set "confdir=$CONFDIR" \
      --set "ignore_hosts=$IGNORE_HOSTS" \
      -s "$SCRIPT_DIR/response_aware_mitm.py"
    ;;
  *)
    printf 'usage: %s {start|logs}\n' "$0" >&2
    exit 2
    ;;
esac
