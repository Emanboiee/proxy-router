#!/usr/bin/env bash
# Disposable bridge contract tests for examples/proxy-manager.sh
# No network, no production port 2080, no live state.
# Each case spins a temp dir with a fake router that answers status --json.
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER="$SCRIPT_DIR/../examples/proxy-manager.sh"

PASS=0; FAIL=0
assert() {
  local desc="$1"; shift
  if "$@"; then
    echo "PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "FAIL: $desc" >&2
    FAIL=$((FAIL+1))
  fi
}
assert_fail() {
  local desc="$1"; shift
  if "$@"; then
    echo "FAIL: $desc (expected failure but succeeded)" >&2
    FAIL=$((FAIL+1))
  else
    echo "PASS: $desc (correctly failed)"
    PASS=$((PASS+1))
  fi
}

# Helpers: create a temp root with a fake router
make_fake_router() {
  local tmp="$1" status_json="$2"
  local fake_router="$tmp/router.py"
  cat > "$fake_router" <<'PYEOF'
#!/usr/bin/env python3
import sys, pathlib
import os
tmp = pathlib.Path(os.environ.get("FAKE_TMP","/tmp"))
status_path = tmp / "status.json"
log_path = tmp / "router.log"
args = sys.argv[1:]
if args[:2] == ["status", "--json"]:
    try:
        print((status_path).read_text())
    except Exception as e:
        print("{}", end="")
    sys.exit(0)
if args and args[0] == "rotate":
    log_path.write_text(" ".join(["rotate"]+args[1:]))
    sys.exit(0)
if args and args[0] == "failover":
    log_path.write_text(" ".join(["failover"]+args[1:]))
    sys.exit(0)
sys.exit(2)
PYEOF
  chmod +x "$fake_router"
  printf '%s' "$status_json" > "$tmp/status.json"
  : > "$tmp/router.log"
  echo "$fake_router"
}

echo "=== proxy-manager bridge disposable tests ==="

# Case 1: explicit OPENCODE_PROVIDER preserved (no inference needed)
tmp=$(mktemp -d)
status='{"providers":{"proton":{},"cloudflare":{}},"routes":[{"id":"opencode-zen","domains":["opencode.ai"],"provider":"proton"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp" OPENCODE_PROVIDER="proton"
result=$(bash "$MANAGER" rotate 429 2>&1 || true)
log=$(cat "$tmp/router.log" 2>/dev/null || echo "")
if grep -q "rotate proton --reason 429" <<<"$log"; then echo "PASS: explicit provider override preserved"; PASS=$((PASS+1)); else echo "FAIL: explicit provider override preserved (log=$log)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"
unset OPENCODE_PROVIDER FAKE_TMP

# Case 2: inferred via opencode.ai route (multi-provider, no explicit)
tmp=$(mktemp -d)
status='{"providers":{"proton":{},"cloudflare":{}},"routes":[{"id":"opencode-zen","domains":["opencode.ai"],"provider":"proton"},{"id":"roblox","domains":["roblox.com"],"provider":"cloudflare"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp"
unset OPENCODE_PROVIDER 2>/dev/null || true
bash "$MANAGER" rotate 429 >/dev/null 2>&1
log=$(cat "$tmp/router.log" 2>/dev/null || echo "")
if grep -q "rotate proton --reason 429" <<<"$log"; then echo "PASS: inferred proton via opencode.ai route"; PASS=$((PASS+1)); else echo "FAIL: inferred proton via opencode.ai route (log=$log)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"

# Case 3: active fallback -> effective provider rotated
tmp=$(mktemp -d)
status='{"providers":{"proton":{"fallback":{"active":"cloudflare"}},"cloudflare":{}},"routes":[{"id":"opencode-zen","domains":["opencode.ai"],"provider":"proton"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp"
unset OPENCODE_PROVIDER || true
bash "$MANAGER" rotate 429 >/dev/null 2>&1
log=$(cat "$tmp/router.log" 2>/dev/null || echo "")
if grep -q "rotate cloudflare --reason 429" <<<"$log"; then echo "PASS: inferred effective fallback (cloudflare) when primary has active fallback"; PASS=$((PASS+1)); else echo "FAIL: effective fallback inference (log=$log)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"

# Case 4: single-provider generic fallback (no opencode route)
tmp=$(mktemp -d)
status='{"providers":{"myvpn":{}},"routes":[]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp"
unset OPENCODE_PROVIDER || true
bash "$MANAGER" rotate 429 >/dev/null 2>&1
log=$(cat "$tmp/router.log" 2>/dev/null || echo "")
if grep -q "rotate myvpn --reason 429" <<<"$log"; then echo "PASS: single-provider generic inference"; PASS=$((PASS+1)); else echo "FAIL: single-provider generic inference (log=$log)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"

# Case 5: ambiguous multi-provider with no opencode route -> fail closed exit 2
tmp=$(mktemp -d)
status='{"providers":{"proton":{},"cloudflare":{}},"routes":[{"id":"roblox","domains":["roblox.com"],"provider":"cloudflare"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp"
unset OPENCODE_PROVIDER || true
set +e
out=$(bash "$MANAGER" rotate 429 2>&1); rc=$?
set -e
if [ "$rc" -eq 2 ] && grep -q "cannot infer provider" <<<"$out"; then echo "PASS: fail-closed on ambiguous (no opencode route, multi-provider)"; PASS=$((PASS+1)); else echo "FAIL: ambiguous should fail-closed (rc=$rc out=$out)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"

# Case 6: unsupported reason -> exit 2 regardless of inference
tmp=$(mktemp -d)
status='{"providers":{"proton":{}},"routes":[{"id":"opencode-zen","domains":["opencode.ai"],"provider":"proton"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp"
unset OPENCODE_PROVIDER || true
set +e
out=$(bash "$MANAGER" rotate 999 2>&1); rc=$?
set -e
if [ "$rc" -eq 2 ] && grep -q "unsupported rotation reason" <<<"$out"; then echo "PASS: unsupported reason rejected"; PASS=$((PASS+1)); else echo "FAIL: unsupported reason (rc=$rc out=$out)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"

# Case 7: explicit provider still triggers unsupported-reason check
tmp=$(mktemp -d)
status='{"providers":{"proton":{}},"routes":[{"id":"opencode-zen","domains":["opencode.ai"],"provider":"proton"}]}'
make_fake_router "$tmp" "$status" >/dev/null
export PROXY_ROUTER_ROOT="$tmp" FAKE_TMP="$tmp" OPENCODE_PROVIDER="proton"
set +e
out=$(bash "$MANAGER" rotate badreason 2>&1); rc=$?
set -e
if [ "$rc" -eq 2 ] && grep -q "unsupported rotation reason" <<<"$out"; then echo "PASS: explicit provider + bad reason -> rejected"; PASS=$((PASS+1)); else echo "FAIL: explicit+bad reason (rc=$rc out=$out)"; FAIL=$((FAIL+1)); fi
rm -rf "$tmp"
unset OPENCODE_PROVIDER

# Case 8: rotate without PROXY_ROUTER_ROOT still finds router via SCRIPT_DIR candidates (simulate by using real manager location)
# Already covered by router_py fallback; skip heavy.

echo "---"
echo "PASSED: $PASS  FAILED: $FAIL"
if [ "$FAIL" -ne 0 ]; then exit 1; fi
