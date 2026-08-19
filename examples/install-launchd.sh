#!/usr/bin/env bash
# Bootstraps the macOS launchd keepalive agent for proxy-router.
#
# Fills the placeholders in com.proxy-router.keepalive.plist.template
# (@ROOT@, @HOME@, @PATH@, @LOG_DIR@, @PYTHON@), writes the agent plist into
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
# Resolve the interpreter ONCE here and pin the exact absolute path into the
# plist (ProgramArguments + PROXY_ROUTER_PYTHON). launchd must never resolve
# python3 through an ambient PATH that differs from the interpreter the
# elevation policy authorized. Pre-set with PROXY_ROUTER_PYTHON to pin a
# specific interpreter (e.g. /opt/anaconda3/bin/python3).
PYTHON_BIN="${PROXY_ROUTER_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN=$(command -v python3 || true)
fi
if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
  printf 'error: no executable python3 found; set PROXY_ROUTER_PYTHON to pin one\n' >&2
  exit 1
fi
# Absolute path, no symlink chasing surprises for launchd.
PYTHON_BIN="$(cd "$(dirname "$PYTHON_BIN")" && pwd)/$(basename "$PYTHON_BIN")"

# Legacy agents: an older install (e.g. com.hermes.proxy-router) can coexist
# and resurrect a stale engine. Never delete user files silently -- report
# them and let the operator decide.
LEGACY_LABELS=(com.hermes.proxy-router)
LEGACY_FOUND=0
for legacy in "${LEGACY_LABELS[@]}"; do
  for legacy_plist in "$HOME"/Library/LaunchAgents/"$legacy"*.plist; do
    [ -e "$legacy_plist" ] || continue
    LEGACY_FOUND=1
    printf 'warning: legacy agent found: %s\n' "$legacy_plist" >&2
  done
done
if [ "$LEGACY_FOUND" -eq 1 ]; then
  printf '  migrate with:\n' >&2
  printf '    launchctl bootout "gui/%s" ~/Library/LaunchAgents/com.hermes.proxy-router*.plist\n' "$(id -u)" >&2
  printf '    rm ~/Library/LaunchAgents/com.hermes.proxy-router*.plist\n' >&2
fi

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  printf 'removed %s\n' "$PLIST"
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR" "$PREFIX"

sed -e "s|@ROOT@|$PREFIX|g" \
    -e "s|@HOME@|$HOME|g" \
    -e "s|@PATH@|$PATH_DEFAULT|g" \
    -e "s|@LOG_DIR@|$LOG_DIR|g" \
    -e "s|@PYTHON@|$PYTHON_BIN|g" \
    "$TEMPLATE" > "$PLIST"

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

printf 'installed and bootstrapped %s\n' "$PLIST"
printf '  prefix:     %s\n' "$PREFIX"
printf '  interpreter:%s\n' "$PYTHON_BIN"
printf '  logs:       %s\n' "$LOG_DIR"
printf 'remove with: %s --remove\n' "$0"