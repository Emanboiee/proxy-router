#!/usr/bin/env bash
# verify-proxy-router: one-command, read-only health check for a running
# proxy-router stack. Exits 0 only when every applicable check passes.
# All settings are overridable by environment variable.

set -u

HERE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${PROXY_ROUTER_ROOT:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}"
PY="${PROXY_ROUTER_PYTHON:-python3}"
PORT="${PROXY_ROUTER_PORT:-2080}"
FETCH_URL="${PROXY_ROUTER_FETCH_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
EXPECT_PROVIDERS="${PROXY_ROUTER_EXPECT_PROVIDERS:-cloudflare,proton}"
EXPECT_FALLBACK="${PROXY_ROUTER_EXPECT_FALLBACK:-cloudflare:proton}"
EVIDENCE_ROOT="${PROXY_ROUTER_EVIDENCE:-$ROOT/.verify-evidence}"
SKIP_MACOS="${PROXY_ROUTER_SKIP_MACOS:-0}"

RUN_ID="$(date '+%Y%m%d-%H%M%S')"
EVIDENCE="$EVIDENCE_ROOT/$RUN_ID"
mkdir -p "$EVIDENCE"

PASS=0; FAIL=0; SKIP=0
check() { # name, ok(0 pass / 1 fail), detail
  local name="$1" ok="$2" detail="$3"
  if [ "$ok" -eq 0 ]; then
    echo "PASS  $name :: $detail"; PASS=$((PASS+1))
  else
    echo "FAIL  $name :: $detail"; FAIL=$((FAIL+1))
  fi
  printf '%s | %s | %s\n' "$name" "$([ "$ok" -eq 0 ] && echo PASS || echo FAIL)" "$detail" >> "$EVIDENCE/results.txt"
}
skip() { echo "SKIP  $1 :: $2"; SKIP=$((SKIP+1)); printf '%s | SKIP | %s\n' "$1" "$2" >> "$EVIDENCE/results.txt"; }

echo "=== verify-proxy-router @ $RUN_ID ==="
echo "root: $ROOT"
echo "evidence: $EVIDENCE"

# 1. listener on the proxy port
LISTEN="$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | tail -n +2)"
if [ -n "$LISTEN" ]; then
  check "listener:$PORT" 0 "$(echo "$LISTEN" | awk '{print $1, $2, $9}' | head -1)"
else
  check "listener:$PORT" 1 "no LISTEN on 127.0.0.1:$PORT"
fi
echo "$LISTEN" > "$EVIDENCE/listener.txt"

# 2. live fetch through the proxy
CODE="$(curl -s -m 15 -o "$EVIDENCE/fetch-body.txt" -w '%{http_code}' \
  --proxy "http://127.0.0.1:$PORT" "$FETCH_URL" 2>"$EVIDENCE/fetch-err.txt")"
if [ "$CODE" = "200" ]; then
  check "fetch:$PORT" 0 "HTTP $CODE via 127.0.0.1:$PORT"
else
  check "fetch:$PORT" 1 "HTTP ${CODE:-none}"
fi

# 3. config loads (status --json must parse)
STATUS="$(cd "$ROOT" && "$PY" router.py status --json 2>&1)"
echo "$STATUS" > "$EVIDENCE/status.json"
if echo "$STATUS" | "$PY" -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
  check "config:loads" 0 "router.py status --json parsed"
else
  check "config:loads" 1 "status --json did not parse"
fi

# 4. egress: no dead lanes, at least one alive (respect expected providers)
EGRESS="$(cd "$ROOT" && timeout 25 "$PY" router.py egress check 2>&1)"
echo "$EGRESS" > "$EVIDENCE/egress.txt"
if echo "$EGRESS" | grep -q ': dead'; then
  check "egress:no-dead" 1 "$(echo "$EGRESS" | grep ': dead' | tr '\n' ' ')"
else
  check "egress:no-dead" 0 "no dead providers"
fi
ALIVE=0
IFS=',' read -ra WANTPROVS <<< "$EXPECT_PROVIDERS"
for p in "${WANTPROVS[@]}"; do
  line="$(echo "$EGRESS" | grep "^$p:")"
  if echo "$line" | grep -qE 'alive|fallback'; then ALIVE=$((ALIVE+1)); fi
done
if [ "$ALIVE" -gt 0 ]; then
  check "egress:alive" 0 "$ALIVE of ${#WANTPROVS[@]} expected providers healthy"
else
  check "egress:alive" 1 "none of: $EXPECT_PROVIDERS healthy"
fi

# 5. fallback chain configured (provider:target)
if [ -n "$EXPECT_FALLBACK" ]; then
  FP="${EXPECT_FALLBACK%%:*}"; FT="${EXPECT_FALLBACK##*:}"
  FB="$(cd "$ROOT" && "$PY" router.py failover "$FP" status --json 2>/dev/null)"
  echo "$FB" > "$EVIDENCE/fallback.json"
  if echo "$FB" | grep -q "\"$FT\""; then
    check "fallback:$FP->$FT" 0 "$(echo "$FB" | tr '\n' ' ' | head -c 120)"
  else
    check "fallback:$FP->$FT" 1 "$FT not in configured chain"
  fi
else
  skip "fallback" "PROXY_ROUTER_EXPECT_FALLBACK is empty"
fi

SKIP_MACOS_REASON=""
if [ "$SKIP_MACOS" = "1" ]; then
  SKIP_MACOS_REASON="PROXY_ROUTER_SKIP_MACOS=1"
elif [ "$(uname -s)" != "Darwin" ]; then
  SKIP_MACOS_REASON="not macOS"
fi

if [ -n "$SKIP_MACOS_REASON" ]; then
  skip "tray:root-env" "$SKIP_MACOS_REASON"
  skip "launchd:paths" "$SKIP_MACOS_REASON"
else
  # 6. dashboard env points at this root (if a dashboard job is loaded)
  DASH_PID="$(ps auxww | grep 'proxy-router-dashboard' | grep -v grep | awk '{print $2}' | head -1)"
  if [ -z "$DASH_PID" ]; then
    skip "tray:root-env" "no dashboard process"
  else
    DASH_ENV="$(ps -wwE -p "$DASH_PID" 2>/dev/null | tr ' ' '\n' | grep '^PROXY_ROUTER_ROOT=' | head -1)"
    echo "$DASH_ENV" > "$EVIDENCE/dashboard-env.txt"
    if [ "$DASH_ENV" = "PROXY_ROUTER_ROOT=$ROOT" ]; then
      check "tray:root-env" 0 "$DASH_ENV (pid $DASH_PID)"
    else
      check "tray:root-env" 1 "${DASH_ENV:-unset} (pid $DASH_PID)"
    fi
  fi

  # 7. launchd plists + processes use this root (only jobs that exist)
  LADIR="${HOME}/Library/LaunchAgents"
  PLIST_BAD=""; PLIST_SEEN=0
  for f in "$LADIR"/com.proxy-router.*.plist; do
    [ -f "$f" ] || continue
    grep -q 'ProgramArguments' "$f" || continue
    PLIST_SEEN=$((PLIST_SEEN+1))
    if grep -q "$ROOT" "$f" 2>/dev/null || grep -q '/Applications/' "$f" 2>/dev/null; then :; else
      PLIST_BAD="$PLIST_BAD $(basename "$f")"
    fi
  done
  if [ "$PLIST_SEEN" -eq 0 ]; then
    skip "launchd:plist-paths" "no proxy-router LaunchAgents"
  elif [ -z "$PLIST_BAD" ]; then
    check "launchd:plist-paths" 0 "$PLIST_SEEN jobs reference $ROOT or app bundle"
  else
    check "launchd:plist-paths" 1 "unexpected path in:$PLIST_BAD"
  fi

  PROC="$(ps auxww | grep -E "$ROOT/(router\.py|route_watcher|network_control|network_guard|codex_gateway|sing-box\.json|examples/keepalive)" | grep -v grep)"
  echo "$PROC" > "$EVIDENCE/processes.txt"
  if [ -n "$PROC" ]; then
    check "launchd:process-paths" 0 "$(echo "$PROC" | wc -l | tr -d ' ') procs on root"
  else
    skip "launchd:process-paths" "no matching processes"
  fi
fi

echo "=== RESULT: $PASS passed, $FAIL failed, $SKIP skipped ==="
printf 'RESULT: %s passed, %s failed, %s skipped\n' "$PASS" "$FAIL" "$SKIP" >> "$EVIDENCE/results.txt"
[ "$FAIL" -eq 0 ]
