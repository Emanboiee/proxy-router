#!/usr/bin/env bash
# proxy-router installer (macOS + Linux, no sudo required).
#
# Transactional install: everything lands in a versioned staging directory
# first, gets validated, and only then atomically switches into place via a
# `current` symlink — so an interrupted upgrade can never leave a
# mixed-version installation behind (issue #63). Rollback is one command:
#   PROXY_ROUTER_ROLLBACK=1 proxy-router-install.sh --rollback
# or manually: ln -sfn releases/<previous> <prefix>/current
#
# Live configuration (router.json, providers/, presets/, logs) lives OUTSIDE
# the release directories in the prefix root, so it survives every upgrade
# and rollback untouched.
#
# Compatibility: scripts and users that expect the runtime files directly in
# the prefix keep working — the prefix root mirrors the active release's
# runtime modules through the same relative symlinks the layout has always
# had.
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

RELEASE_TAG="${PROXY_ROUTER_RELEASE:-$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo dev)}"

install_runtime() {
  local dest="$1"
  mkdir -p "$dest/bin"
  for runtime_file in router.py setup_tui.py monitor.py route_watcher.py proxy_tray.py privileged_helper.py privileged_installer.py; do
    cp "$SCRIPT_DIR/$runtime_file" "$dest/$runtime_file"
    chmod 755 "$dest/$runtime_file"
  done
  cp "$SCRIPT_DIR/sing-box-release.json" "$dest/sing-box-release.json"
  chmod 644 "$dest/sing-box-release.json"

  if [ -n "${SING_BOX:-}" ] && [ -f "$SING_BOX" ]; then
    BIN_SOURCE="$SING_BOX"
  else
    BIN_SOURCE="$SCRIPT_DIR/bin/sing-box"
  fi
  if [ -f "$BIN_SOURCE" ] && [ -x "$BIN_SOURCE" ]; then
    cp "$BIN_SOURCE" "$dest/bin/sing-box"
    chmod 755 "$dest/bin/sing-box"
  else
    printf 'warning: no bundled sing-box binary at %s;\n' "$BIN_SOURCE" >&2
    printf '         rely on SING_BOX or PATH at runtime.\n' >&2
  fi

  cp "$SCRIPT_DIR/router.example.json" "$dest/router.example.json"
  cp "$SCRIPT_DIR/README.md" "$dest/README.md"
  cp "$SCRIPT_DIR/LICENSE" "$dest/LICENSE"
  cp "$SCRIPT_DIR/examples/keepalive.sh" "$dest/examples/keepalive.sh"
  cp "$SCRIPT_DIR/examples/install-launchd.sh" "$dest/examples/install-launchd.sh"
  cp "$SCRIPT_DIR/examples/com.proxy-router.keepalive.plist.template" \
     "$dest/examples/com.proxy-router.keepalive.plist.template"
}

# --- rollback path -------------------------------------------------------
if [ "${1:-}" = "--rollback" ] || [ "${PROXY_ROUTER_ROLLBACK:-}" = "1" ]; then
  current="$PREFIX/current"
  if [ ! -L "$current" ]; then
    printf 'error: no transactional installation at %s\n' "$PREFIX" >&2
    exit 1
  fi
  previous=$(basename "$(readlink "$current")")
  candidates=()
  for d in "$PREFIX/releases"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    [ "$name" = "$previous" ] || candidates+=("$name")
  done
  if [ "${#candidates[@]}" -eq 0 ]; then
    printf 'error: no previous release to roll back to under %s\n' "$PREFIX/releases" >&2
    exit 1
  fi
  # Highest-sorting remaining release wins; ties are not expected (tags).
  target=${candidates[${#candidates[@]}-1]}
  ln -sfn "releases/$target" "$current"
  printf 'rolled back: current -> releases/%s\n' "$target"
  printf 'restart any running agent to pick it up.\n'
  exit 0
fi

# --- fresh / upgrade install ---------------------------------------------
mkdir -p "$PREFIX" "$USER_BIN"
STAGE_ROOT="$PREFIX/.staging"
STAGE="$STAGE_ROOT/stage.$$"
mkdir -p "$STAGE/examples"
cleanup_stage() { rm -rf "$STAGE"; }
trap cleanup_stage EXIT

install_runtime "$STAGE"
chmod 700 "$PREFIX"

# --- smoke test: the staged tree must actually run ------------------------
# A staged release that cannot print its own status never becomes current.
if [ -z "${PROXY_ROUTER_SKIP_SMOKE:-}" ]; then
  if ! python3 "$STAGE/router.py" status --json >/dev/null 2>&1; then
    printf 'error: staged release failed smoke test (router.py status --json); aborting\n' >&2
    exit 1
  fi
  if ! python3 "$STAGE/router.py" --help >/dev/null 2>&1; then
    printf 'error: staged release failed smoke test (router.py --help); aborting\n' >&2
    exit 1
  fi
fi

# --- validate, then switch atomically -------------------------------------
CURRENT="$PREFIX/current"
OLD_TARGET=""
if [ -L "$CURRENT" ]; then
  OLD_TARGET=$(readlink "$CURRENT" | sed 's|^releases/||')
fi

ln -sfn "releases/$RELEASE_TAG" "$STAGE/final-name"
FINAL="$STAGE_ROOT/release.$$"
mv "$STAGE/final-name" "$FINAL"
trap - EXIT
rmdir "$STAGE_ROOT" 2>/dev/null || true

mkdir -p "$PREFIX/releases"
mv "$FINAL" "$PREFIX/releases/$RELEASE_TAG"
# The rename above is the commit point; everything before it could fail
# without touching the running installation.

ln -sfn "releases/$RELEASE_TAG" "$CURRENT"

# Prefix-root compatibility mirror of the ACTIVE release's runtime files, so
# existing scripts and muscle memory keep working after the layout change.
for f in router.py setup_tui.py monitor.py route_watcher.py proxy_tray.py \
         privileged_helper.py privileged_installer.py \
         router.example.json README.md LICENSE sing-box-release.json; do
  ln -sfn "current/$f" "$PREFIX/$f"
done
ln -sfn "current/bin" "$PREFIX/bin"
mkdir -p "$PREFIX/examples"
for f in keepalive.sh install-launchd.sh com.proxy-router.keepalive.plist.template; do
  ln -sfn "../current/examples/$f" "$PREFIX/examples/$f"
done

# Bundled defaults live per-release; user-customized data stays at the prefix
# root and is created once, never overwritten by an upgrade.
copy_missing_tree() {
  local name source target
  name="$1"
  for source in "$PREFIX/current/$name"/*; do
    [ -e "$source" ] || continue
    target="$PREFIX/$name/$(basename "$source")"
    [ -e "$target" ] || cp -R "$source" "$target"
  done
}
for f in guides rulesets presets; do
  if [ -d "$PREFIX/current/$f" ]; then
    copy_missing_tree "$f"
  else
    mkdir -p "$PREFIX/$f"
  fi
done

# Live config: only ever created once; reruns must not clobber it.
if [ ! -f "$PREFIX/router.json" ]; then
  cp "$SCRIPT_DIR/router.example.json" "$PREFIX/router.json"
  printf 'created %s from the example template.\n' "$PREFIX/router.json"
else
  printf 'router.json exists; leaving it untouched.\n'
fi

# The prefix holds WireGuard private keys; keep it private.
chmod 700 "$PREFIX/providers" 2>/dev/null || mkdir -p "$PREFIX/providers" && chmod 700 "$PREFIX/providers"

ln -sfn "$PREFIX/current/router.py" "$USER_BIN/proxy-router"

cat <<EOF

proxy-router installed to:
  $PREFIX (release: $RELEASE_TAG)
Run it via:
  $USER_BIN/proxy-router

First-time setup:
  proxy-router setup --check   # validate router.json (already created by this installer)
  proxy-router ensure          # start the engine if the listener is down

Add providers:
  drop a WireGuard profile into
    $PREFIX/providers/<provider>/<profile>.conf
  (one file per profile; the active one is rotated automatically)
  or import one:
    proxy-router setup --import-proton <profile.conf>
  then apply a validated preset:
    proxy-router setup --preset-list
    proxy-router setup --preset

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

if [ -n "$OLD_TARGET" ] && [ "$OLD_TARGET" != "$RELEASE_TAG" ]; then
  printf '\nupgraded: releases/%s -> releases/%s\n' "$OLD_TARGET" "$RELEASE_TAG"
  printf 'roll back with: %s --rollback\n' "$0"
fi
