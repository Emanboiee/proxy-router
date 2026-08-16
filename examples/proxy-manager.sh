#!/usr/bin/env bash
# Bridge for the Hermes opencode-server-rotation plugin.
# The plugin calls this machine-level bridge; it forwards provider failures to
# the existing proxy-router CLI. The router remains the only engine mutator.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

router_py() {
  if [ -n "${PROXY_ROUTER_BIN:-}" ] && [ -x "${PROXY_ROUTER_BIN:-}" ]; then
    printf '%s\n' "$PROXY_ROUTER_BIN"
    return 0
  fi
  if [ -n "${PROXY_ROUTER_ROOT:-}" ] && [ -x "${PROXY_ROUTER_ROOT}/router.py" ]; then
    printf '%s\n' "$PROXY_ROUTER_ROOT/router.py"
    return 0
  fi
  if [ -z "${PROXY_ROUTER_ROOT:-}" ] && [ -x "$HOME/proxy-router-fallback-pr/router.py" ] && [ -d "$HOME/proxy-router/providers" ]; then
    export PROXY_ROUTER_ROOT="$HOME/proxy-router"
    printf '%s\n' "$HOME/proxy-router-fallback-pr/router.py"
    return 0
  fi
  local candidate
  for candidate in \
    "$SCRIPT_DIR/router.py" \
    "$(dirname "$SCRIPT_DIR")/router.py" \
    "$HOME/.local/share/proxy-router/router.py" \
    "$HOME/proxy-router/router.py" \
    "$(dirname "$SCRIPT_DIR")/proxy-router/router.py" \
  ; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if command -v proxy-router >/dev/null 2>&1; then
    printf 'proxy-router\n'
    return 0
  fi
  return 1
}

case "${1:-}" in
  rotate)
    ROUTER=$(router_py)
    PROVIDER="${OPENCODE_PROVIDER:-}"
    if [ -z "$PROVIDER" ]; then
      printf 'proxy-manager: OPENCODE_PROVIDER is not set (provider to rotate, see router.py status)\n' >&2
      exit 2
    fi
    REASON="${2:-}"
    case "$REASON" in
      ""|408|425|429|500|502|503|504|1010|403|timeout|tls|connection|rate_limit|upstream_rate_limit|server_error) ;;
      *)
        printf 'proxy-manager: unsupported rotation reason %s\n' "$REASON" >&2
        exit 2
        ;;
    esac
    if [ -n "$REASON" ]; then
      if "$ROUTER" rotate "$PROVIDER" --reason "$REASON"; then
        exit 0
      fi
      "$ROUTER" failover "$PROVIDER" on --reason "$REASON"
    else
      if "$ROUTER" rotate "$PROVIDER"; then
        exit 0
      fi
      "$ROUTER" failover "$PROVIDER" on --reason transport
    fi
    ;;
  help|-h|--help|"")
    printf 'usage: %s rotate [REASON] [PROXY_ROUTER_ROOT=PATH] [OPENCODE_PROVIDER=<name>]\n' "$0" >&2
    exit 0
    ;;
  *)
    printf 'proxy-manager: unknown command %s (supported: rotate)\n' "$1" >&2
    exit 2
    ;;
esac
