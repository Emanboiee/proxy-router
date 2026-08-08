#!/usr/bin/env bash
# Bridge for the Hermes `opencode_server_rotation` plugin.
#
# The plugin invokes `proxy-manager.sh rotate` from the legacy
# tools/opencode-zen-vpn directory (cwd = that directory, 45s timeout). The
# directory was retired and succeeded by proxy-router; install this bridge at
# the plugin's exact expected path and it forwards rotation to the router:
#
#   mkdir -p ~/airi/tools/opencode-zen-vpn   # wherever YOUR prefix lives
#   cp examples/proxy-manager.sh ~/airi/tools/opencode-zen-vpn/proxy-manager.sh
#   chmod +x ~/airi/tools/opencode-zen-vpn/proxy-manager.sh
#
# No plugin edits and no Hermes config changes are required.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Locate the router: explicit override, standalone copy next to this script,
# sibling layout (<prefix>/opencode-zen-vpn + <prefix>/proxy-router), the
# default install prefix, then PATH.
router_py() {
  if [ -n "${PROXY_ROUTER_BIN:-}" ] && [ -x "${PROXY_ROUTER_BIN:-}" ]; then
    printf '%s\n' "$PROXY_ROUTER_BIN"
    return 0
  fi
  local candidate
  for candidate in \
    "$SCRIPT_DIR/router.py" \
    "$(dirname "$SCRIPT_DIR")/proxy-router/router.py" \
    "$HOME/.local/share/proxy-router/router.py" \
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
    PROVIDER="${OPENCODE_PROVIDER:-proton}"
    "$ROUTER" rotate "$PROVIDER"
    ;;
  help|-h|--help|"")
    printf 'usage: %s rotate [OPENCODE_PROVIDER=proton]\n' "$0" >&2
    exit 0
    ;;
  *)
    printf 'proxy-manager: unknown command %s (supported: rotate)\n' "$1" >&2
    exit 2
    ;;
esac
