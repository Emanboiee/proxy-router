#!/usr/bin/env bash
# Bootstraps the macOS launchd keepalive agent for proxy-router.
#
# Fills the placeholders in com.proxy-router.keepalive.plist.template
# (@ROOT@, @HOME@, @PATH@, @LOG_DIR@, @PYTHON@), writes the agent plist into
# ~/Library/LaunchAgents, and loads it with launchctl. Idempotent: rerunning
# re-writes the plist and re-bootstraps. Pass --remove to tear the agent down.
#
# Issue #63: the agent prefix is DERIVED FROM WHERE THIS SCRIPT IS INSTALLED
# (…/examples/install-launchd.sh inside the proxy-router root) instead of an
# independent hardcoded default — a custom-prefix install used to get a plist
# that silently pointed back at ~/.local/share/proxy-router. Every rendered
# value is XML-escaped so paths containing &, <, >, ' or " produce valid
# plists, and a stale loaded job pointing at a DIFFERENT root is detected and
# migrated (bootout + report) before the new one is trusted.
set -euo pipefail

# Pure-bash dirname: the script must work in stripped-PATH sandboxes
# (tests and minimal launchd contexts) where /usr/bin may be absent.
_self=$0
case $_self in
  */*) SCRIPT_DIR=${_self%/*} ;;
  *) SCRIPT_DIR=. ;;
esac
SCRIPT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR" && pwd)
TEMPLATE="$SCRIPT_DIR/com.proxy-router.keepalive.plist.template"
LABEL="com.proxy-router.keepalive"
PLIST="$HOME/Library/LaunchAgents/com.proxy-router.keepalive.plist"
LOG_DIR="$HOME/Library/Logs/proxy-router"

# XML-escape every value substituted into the plist template. Raw sed
# substitution used to accept any path but produced invalid XML for paths
# containing & < > ' " (launchd then silently refused to load the agent).
xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' \
                        -e 's/</\&lt;/g' \
                        -e 's/>/\&gt;/g' \
                        -e "s/'/\&apos;/g" \
                        -e 's/"/\&quot;/g'
}

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  printf 'removed %s\n' "$PLIST"
  exit 0
fi

# Derive the proxy-router root FROM THIS SCRIPT'S INSTALLED LOCATION. The
# installer lays the script out as <root>/examples/install-launchd.sh, so the
# root is the parent of examples/. An explicit PROXY_ROUTER_DIR still wins;
# a derived root that does not actually contain router.py is an error rather
# than something we silently paper over.
if [ -n "${PROXY_ROUTER_DIR:-}" ]; then
  PREFIX="$PROXY_ROUTER_DIR"
else
  PREFIX=$(cd "$SCRIPT_DIR/.." && pwd)
fi
if [ ! -f "$PREFIX/router.py" ]; then
  printf 'error: %s does not look like a proxy-router root (router.py missing).\n' "$PREFIX" >&2
  printf '       set PROXY_ROUTER_DIR to your install prefix explicitly.\n' >&2
  exit 1
fi

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

# Stale-job migration (issue #63): when an already-loaded keepalive job
# points at a DIFFERENT root than the one being installed now, boot it out
# before switching so two engines can never fight. The move is reversible —
# the previous plist content stays on disk as *.stale and one command
# reloads it.
mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"
if [ -f "$PLIST" ]; then
  OLD_ROOT=$(sed -n 's|.*<string>\(.*\)/examples/keepalive\.sh</string>.*|\1|p' "$PLIST" | head -1 || true)
  OLD_ROOT_UNESCAPED=${OLD_ROOT//&amp;/\&}
  OLD_ROOT_UNESCAPED=${OLD_ROOT_UNESCAPED//&lt;/<}
  OLD_ROOT_UNESCAPED=${OLD_ROOT_UNESCAPED//&gt;/>}
  OLD_ROOT_UNESCAPED=${OLD_ROOT_UNESCAPED//&apos;/\'}
  OLD_ROOT_UNESCAPED=${OLD_ROOT_UNESCAPED//&quot;/\"}
  LOADED=0
  launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && LOADED=1
  if [ "$LOADED" -eq 1 ] && [ -n "$OLD_ROOT" ] && [ "$OLD_ROOT_UNESCAPED" != "$PREFIX" ]; then
    cp "$PLIST" "$PLIST.stale"
    launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
    printf 'warning: loaded keepalive job pointed at stale root: %s\n' "$OLD_ROOT_UNESCAPED" >&2
    printf '  the old job was unloaded and its plist kept at:\n' >&2
    printf '    %s.stale\n' "$PLIST" >&2
    printf '  reversible with:\n' >&2
    printf '    cp %s.stale %s && launchctl bootstrap "gui/%s" %s\n' "$PLIST" "$PLIST" "$(id -u)" "$PLIST" >&2
  fi
fi

PREFIX_ESC=$(xml_escape "$PREFIX")
HOME_ESC=$(xml_escape "$HOME")
LOGDIR_ESC=$(xml_escape "$LOG_DIR")
PYTHON_ESC=$(xml_escape "$PYTHON_BIN")
PATH_ESC=$(xml_escape "$PATH_DEFAULT")

sed -e "s|@ROOT@|$PREFIX_ESC|g" \
    -e "s|@HOME@|$HOME_ESC|g" \
    -e "s|@PATH@|$PATH_ESC|g" \
    -e "s|@LOG_DIR@|$LOGDIR_ESC|g" \
    -e "s|@PYTHON@|$PYTHON_ESC|g" \
    "$TEMPLATE" > "$PLIST"

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

printf 'installed and bootstrapped %s\n' "$PLIST"
printf '  prefix:     %s\n' "$PREFIX"
printf '  interpreter:%s\n' "$PYTHON_BIN"
printf '  logs:       %s\n' "$LOG_DIR"
printf 'remove with: %s --remove\n' "$0"
