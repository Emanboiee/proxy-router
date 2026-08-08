#!/usr/bin/env bash
# Bootstraps the macOS launchd keepalive agent for proxy-router.
#
# Fills the placeholders in com.proxy-router.keepalive.plist.template
# (@ROOT@, @LOGIN@, @PATH@, @LOG_DIR@), writes the agent plist into
# ~/Library/LaunchAgents, and loads it with launchctl. Idempotent: rerunning
# re-writes the plist and re-bootstraps. Pass --remove to tear the agent down.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEMPLATE="$SCRIPT_DIR/com.proxy-router.keepalive.plist.template"
LABEL="com.proxy-router.keepalive"
PLIST="$HOME/Library/LaunchAgents/com.proxy-router.keepalive.plist"
LOG_DIR="$HOME/Library/Logs/proxy-router"
# Same default prefix as install.sh; pre-set with PROXY_ROUTER_DIR.
PREFIX="${PROXY_ROUTER_DIR:-${HOME}/.local/share/proxy-router}"
# launchd agents run without a login shell, so give the keepalive script a
# PATH that covers Homebrew, /usr/local and the system tools.
PATH_DEFAULT="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  printf 'removed %s\n' "$PLIST"
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR" "$PREFIX"

sed -e "s|@ROOT@|$PREFIX|g" \
    -e "s|@LOGIN@|$USER|g" \
    -e "s|@PATH@|$PATH_DEFAULT|g" \
    -e "s|@LOG_DIR@|$LOG_DIR|g" \
    "$TEMPLATE" > "$PLIST"

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

printf 'installed and bootstrapped %s\n' "$PLIST"
printf '  prefix: %s\n' "$PREFIX"
printf '  logs:   %s\n' "$LOG_DIR"
printf 'remove with: %s --remove\n' "$0"