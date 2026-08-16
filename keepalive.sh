#!/usr/bin/env bash
# Compatibility entrypoint. Keep one canonical keepalive implementation.
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/examples/keepalive.sh" "$@"
