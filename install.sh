#!/usr/bin/env bash
# proxy-router installer (macOS + Linux, no sudo required).
#
# Copies router.py, the bundled sing-box engine, the config example, docs and
# the examples/ tree into an unprivileged per-user prefix, then links
# `proxy-router` onto PATH. Idempotent: rerunning never clobbers router.json,
# provider profiles, or any other existing user configuration.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Install prefix. Pre-set with PROXY_ROUTER_DIR (the same variable
# examples/install-launchd.sh reads), or with SING_BOX when it points at a
# directory. Defaults to ~/.local/share/proxy-router.
if [ -n "${PROXY_ROUTER_DIR:-}" ]; then
  PREFIX="$PROXY_ROUTER_DIR"
elif [ -n "${SING_BOX:-}" ] && [ -d "$SING_BOX" ]; then
  PREFIX="$SING_BOX"
else
  PREFIX="${HOME}/.local/share/proxy-router"
fi

# Directory on PATH that will hold the `proxy-router` symlink.
USER_BIN="${USER_BIN:-${HOME}/.local/bin}"

# sing-box binary source: an explicit SING_BOX file wins, otherwise the binary
# bundled in the release archive.
BIN_SOURCE="$SCRIPT_DIR/bin/sing-box"
if [ -n "${SING_BOX:-}" ] && [ -f "$SING_BOX" ]; then
  BIN_SOURCE="$SING_BOX"
fi

mkdir -p "$PREFIX/bin" "$PREFIX/examples" "$PREFIX/providers" "$PREFIX/guides" "$PREFIX/presets" "$PREFIX/rulesets" "$USER_BIN"

for runtime_file in router.py setup_tui.py monitor.py route_watcher.py proxy_tray.py privileged_helper.py privileged_installer.py; do
  cp "$SCRIPT_DIR/$runtime_file" "$PREFIX/$runtime_file"
  chmod 755 "$PREFIX/$runtime_file"
done
cp "$SCRIPT_DIR/sing-box-release.json" "$PREFIX/sing-box-release.json"
chmod 644 "$PREFIX/sing-box-release.json"

if [ -f "$BIN_SOURCE" ] && [ -x "$BIN_SOURCE" ]; then
  cp "$BIN_SOURCE" "$PREFIX/bin/sing-box"
  chmod 755 "$PREFIX/bin/sing-box"
else
  printf 'warning: no bundled sing-box binary at %s;\n' "$BIN_SOURCE" >&2
  printf '         rely on SING_BOX or PATH at runtime.\n' >&2
fi

cp "$SCRIPT_DIR/router.example.json" "$PREFIX/router.example.json"
cp "$SCRIPT_DIR/README.md" "$PREFIX/README.md"
cp "$SCRIPT_DIR/LICENSE" "$PREFIX/LICENSE"
cp -R "$SCRIPT_DIR/examples/." "$PREFIX/examples/"
chmod 755 "$PREFIX/examples/"*.sh 2>/dev/null || true

# Bundled guides and data are defaults, not live configuration. Never replace
# a user's custom preset/ruleset with a later installer run.
copy_missing_tree() {
  local name source target
  name="$1"
  for source in "$SCRIPT_DIR/$name"/*; do
    [ -e "$source" ] || continue
    target="$PREFIX/$name/$(basename "$source")"
    [ -e "$target" ] || cp -R "$source" "$target"
  done
}
copy_missing_tree guides
copy_missing_tree presets
copy_missing_tree rulesets

# Live config: only ever created once; reruns must not clobber it.
if [ ! -f "$PREFIX/router.json" ]; then
  cp "$SCRIPT_DIR/router.example.json" "$PREFIX/router.json"
  printf 'created %s from the example template.\n' "$PREFIX/router.json"
else
  printf 'router.json exists; leaving it untouched.\n'
fi

# The prefix holds WireGuard private keys; keep it private.
chmod 700 "$PREFIX" "$PREFIX/providers"

ln -sf "$PREFIX/router.py" "$USER_BIN/proxy-router"

cat <<EOF

proxy-router installed to:
  $PREFIX
Run it via:
  $USER_BIN/proxy-router

First-time setup:
  proxy-router init      # write router.json from the example
  proxy-router ensure     # start the engine if the listener is down

Add providers:
  drop a WireGuard profile into
    $PREFIX/providers/<provider>/<profile>.conf
  (one file per profile; the active one is rotated automatically)

Docs:
  README.md at $PREFIX/README.md
EOF

if [ "$(uname -s)" = "Darwin" ]; then
  cat <<EOF

macOS keepalive (recommended):
  keepalive.sh + the launchd template are installed under examples/.
  Run
    $PREFIX/examples/install-launchd.sh
  to write the agent plist with your paths and bootstrap it.
EOF
fi