#!/usr/bin/env bash
# Bridge for the Hermes opencode-server-rotation plugin.
# The plugin calls this machine-level bridge; it forwards provider failures to
# the existing proxy-router CLI. The router remains the only engine mutator.
#
# Contract (generic, fail-closed):
#   - OPENCODE_PROVIDER, when set, is the explicit override and is used verbatim.
#   - When absent, the bridge infers the egress provider from the router's
#     live config/status (status --json). For opencode.ai it uses the route
#     table's provider for that hostname; if no route matches and the router
#     has exactly one provider, that sole provider is used. Ambiguity (zero or
#     multiple candidates) is a hard error instead of a guess.
#   - Inference respects an active fallback: if the route's primary has a
#     live fallback (status.providers[primary].fallback.active), the effective
#     fallback provider is rotated — mirroring router.py response_event.
#   - No provider name is hardcoded except the target hostname (opencode.ai)
#     that this bridge is bridging. Generic fallback is single-provider inference.
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

# infer_provider <router> -> prints provider name or returns 1
infer_provider() {
  local router="$1"
  local json provider
  if ! json=$("$router" status --json 2>/dev/null); then
    return 1
  fi
  provider=$(printf '%s' "$json" | python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)

routes = data.get("routes") or []
providers = data.get("providers") or {}

def host_matches(host, domain):
    host = str(host or "").strip().lower().rstrip(".")
    domain = str(domain or "").lstrip("*.").strip().lower().rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))

target = "opencode.ai"
candidates = []
for r in routes:
    prov = r.get("provider")
    if not isinstance(prov, str) or not prov:
        continue
    for d in r.get("domains") or []:
        if host_matches(target, d):
            candidates.append(prov)
            break

# de-duplicate while preserving order
seen = set()
uniq = []
for c in candidates:
    if c not in seen:
        seen.add(c)
        uniq.append(c)
candidates = uniq

# Single route provider for opencode.ai -> use it (or its active fallback)
if len(candidates) == 1:
    cand = candidates[0]
    # If the primary has an active fallback, rotate the effective egress
    fb = providers.get(cand, {}).get("fallback", {}).get("active")
    if isinstance(fb, str) and fb and fb in providers:
        print(fb)
    else:
        print(cand)
    sys.exit(0)

# Generic single-provider fallback: when the router has exactly one provider
# and no explicit opencode route, that sole provider is unambiguously the
# egress. This keeps the bridge usable for single-provider deployments without
# hardcoding a provider name.
if not candidates and len(providers) == 1:
    print(list(providers.keys())[0])
    sys.exit(0)

sys.exit(1)
' 2>/dev/null || true)
  if [ -n "${provider:-}" ]; then
    # trim whitespace
    provider=$(printf '%s' "$provider" | tr -d ' \t\r\n')
    if [ -n "$provider" ]; then
      printf '%s\n' "$provider"
      return 0
    fi
  fi
  return 1
}

case "${1:-}" in
  rotate)
    if ! ROUTER=$(router_py); then
      printf 'proxy-manager: router not found (set PROXY_ROUTER_ROOT or PROXY_ROUTER_BIN, or install proxy-router)\n' >&2
      exit 2
    fi
    PROVIDER="${OPENCODE_PROVIDER:-}"
    if [ -z "$PROVIDER" ]; then
      if PROVIDER=$(infer_provider "$ROUTER"); then
        : # inferred
      else
        printf 'proxy-manager: cannot infer provider (no OPENCODE_PROVIDER and router config is ambiguous or has no opencode.ai route); set OPENCODE_PROVIDER or run router.py status --json to inspect\n' >&2
        exit 2
      fi
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
    printf '  OPENCODE_PROVIDER optional; when absent the provider is inferred from router config/status (opencode.ai route or sole provider). Fail-closed on ambiguity.\n' >&2
    exit 0
    ;;
  *)
    printf 'proxy-manager: unknown command %s (supported: rotate)\n' "$1" >&2
    exit 2
    ;;
esac
