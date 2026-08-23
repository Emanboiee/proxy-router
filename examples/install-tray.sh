#!/bin/bash
# install-tray.sh — install the proxy-router menu-bar agent as a login item.
#
# Fills examples/com.proxy-router.tray.plist.template, writes
# ~/Library/LaunchAgents/com.proxy-router.tray.plist, and bootstraps it with
# launchctl. Idempotent: refuses to double-install a live agent.
#
# Usage: install-tray.sh [--remove] [--root PATH]
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT="${PROXY_ROUTER_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PYTHON="${PYTHON:-$(command -v python3 || true)}"
if [ -z "$PYTHON" ]; then
  echo "python3 not found on PATH; set PYTHON=/path/to/python3" >&2
  exit 1
fi
PLIST_SRC="$ROOT/examples/com.proxy-router.tray.plist.template"
PLIST_DST="$HOME/Library/LaunchAgents/com.proxy-router.tray.plist"
LOG_DIR="$HOME/Library/Logs/proxy-router"
LABEL="com.proxy-router.tray"

case "${1:-}" in
  --remove)
    echo "unloading $LABEL..."
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST_DST"
    echo "removed $PLIST_DST"
    exit 0
    ;;
  --root)
    ROOT="${2:?--root needs a path}"
    ;;
esac

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python not found at $PYTHON" >&2
  exit 1
fi

if ! "$PYTHON" -c "import pystray, PIL" 2>/dev/null; then
  echo "missing pystray/pillow for $PYTHON; run: $PYTHON -m pip install pystray pillow" >&2
  exit 1
fi

# Issue #63: an already-loaded job used to make this script exit, preserving
# a STALE root forever until the user removed it by hand. Now: same root ->
# re-render and re-bootstrap (a real upgrade); different root -> unload the
# stale job, keep its plist as *.stale, and tell the operator how to restore.
xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' \
                        -e 's/</\&lt;/g' \
                        -e 's/>/\&gt;/g' \
                        -e "s/'/\&apos;/g" \
                        -e 's/"/\&quot;/g'
}

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"

if [ -f "$PLIST_DST" ]; then
  OLD_ROOT=$(sed -n 's|.*<string>\(.*\)/proxy_tray\.py</string>.*|\1|p' "$PLIST_DST" | head -1 || true)
  LOADED=0
  launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && LOADED=1
  if [ "$LOADED" -eq 1 ] && [ -n "$OLD_ROOT" ] && [ "$OLD_ROOT" != "$ROOT" ]; then
    cp "$PLIST_DST" "$PLIST_DST.stale"
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    echo "warning: loaded $LABEL pointed at stale root: $OLD_ROOT"
    echo "  unloaded it; old plist kept at $PLIST_DST.stale"
    echo "  reversible with:"
    echo "    cp $PLIST_DST.stale $PLIST_DST && launchctl bootstrap \"gui/$(id -u)\" $PLIST_DST"
  fi
fi

if [ ! -f "$PLIST_SRC" ]; then
  echo "missing template: $PLIST_SRC" >&2
  exit 1
fi

ATHOME="$HOME"
ROOT_ESC=$(xml_escape "$ROOT")
PYTHON_ESC=$(xml_escape "$PYTHON")
LOGDIR_ESC=$(xml_escape "$LOG_DIR")
PATH_ESC=$(xml_escape "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
sed -e "s|@ROOT@|$ROOT_ESC|g" \
    -e "s|@PYTHON@|$PYTHON_ESC|g" \
    -e "s|@LOG_DIR@|$LOGDIR_ESC|g" \
    -e "s|@PATH@|$PATH_ESC|g" \
    "$PLIST_SRC" > "$PLIST_DST"

chmod 644 "$PLIST_DST"

# Issue #76: bootstrap used to be trusted blindly; when launchd refused the
# agent (bad interpreter, pystray import crash at startup) the script exited
# 0 and the user's autostart silently never came back. Verify the job is
# actually loaded, and on failure print the exact triage path instead of a
# bare exit code.
bootstrap_ok=0
if launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true; then
  if launchctl bootstrap "gui/$(id -u)" "$PLIST_DST" 2>/dev/null; then
    if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
      bootstrap_ok=1
    fi
  fi
fi
launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true
if [ "$bootstrap_ok" -ne 1 ]; then
  echo "error: launchd did not accept $LABEL — automatic start will NOT work" >&2
  echo "  plist: $PLIST_DST" >&2
  echo "  triage:" >&2
  echo "    plutil -lint $PLIST_DST" >&2
  echo "    launchctl print gui/$(id -u)/$LABEL   # full error" >&2
  echo "    tail -50 $LOG_DIR/proxy-tray.log      # startup crash output" >&2
  echo "  after fixing, re-run this script." >&2
  exit 1
fi
echo "installed $LABEL -> $PLIST_DST (verified loaded)"
echo "menu-bar agent starts at next login; to force start now:"
echo "  launchctl kickstart -k gui/$(id -u)/$LABEL"
echo "startup permission (one-time): open the tray menu -> Setup ->"
echo "  'Fix Startup Permissions (one-time)' or run:"
echo "  $ROOT/router.py elevate install"