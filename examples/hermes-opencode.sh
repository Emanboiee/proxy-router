#!/usr/bin/env bash
# Bounded one-shot Hermes runner over the proxy router: on rate-limit/transient
# signals it rotates the Proton pool, waits 15s, then retries the same command.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROUTER="$ROOT/router.py"
HERMES_BIN="${HERMES_BIN:-hermes}"
MAX_ATTEMPTS="${OPENCODE_MAX_ATTEMPTS:-}"
RETRY_DELAY="${OPENCODE_RETRY_DELAY_SECONDS:-15}"
PROVIDER="${OPENCODE_PROVIDER:-proton}"
TMP_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/hermes-opencode.XXXXXX")
trap 'rm -f "$TMP_OUTPUT"' EXIT

"$ROUTER" ensure >/dev/null
profile_count=$("$ROUTER" provider-count "$PROVIDER" 2>/dev/null || echo 2)
[[ "$MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || MAX_ATTEMPTS="$profile_count"
((MAX_ATTEMPTS < 1)) && MAX_ATTEMPTS=1

retry_kind() {
  local file="$1"
  if grep -Eiq 'rate[[:space:]]*-limit|too many requests|quota[^[:alnum:]]*(exceeded|exhausted)' "$file"; then
    printf '%s\n' "rate-limit"
    return 0
  fi
  if grep -Eiq 'HTTP[[:space:]/:-]+(408|425|429|500|502|503|504)([^0-9]|$)|(status|status_code|response_code|http_code)[[:space:]]*[=:][[:space:]]*(408|425|429|500|502|503|504)([^0-9]|$)|(408|425|429|500|502|503|504)[[:space:]]-+(request timeout|too early|too many requests|internal server error|bad gateway|service unavailable|gateway timeout)' "$file"; then
    printf '%s\n' "transient-http"
    return 0
  fi
  if grep -Eiq 'timed[[:space:]]+out|timeout|connection[[:space:]]+(reset|refused|closed)|broken pipe|network[[:space:]]+error|temporary failure|ECONNRESET|ECONNREFUSED' "$file"; then
    printf '%s\n' "transport"
    return 0
  fi
  return 1
}

summaries=()
attempt=0
while ((attempt < MAX_ATTEMPTS)); do
  : > "$TMP_OUTPUT"

  set +e
  "$HERMES_BIN" "$@" >"$TMP_OUTPUT" 2>&1
  rc=$?
  set -e

  if ((rc == 0)) && ! retry_kind "$TMP_OUTPUT" >/dev/null 2>&1; then
    cat "$TMP_OUTPUT"
    exit 0
  fi

  if ! kind=$(retry_kind "$TMP_OUTPUT"); then
    printf '[opencode] request failed; no failover signal (exit=%s)\n' "$rc" >&2
    exit "${rc:-1}"
  fi

  summaries+=("$kind")
  ((attempt += 1))
  if ((attempt >= MAX_ATTEMPTS)); then
    printf '[opencode] failover exhausted after %s attempt(s): %s\n' "$attempt" "${summaries[*]}" >&2
    ((rc != 0)) && exit "$rc"
    exit 75
  fi

  printf '[opencode] %s; rotating %s provider (%s/%s)\n' "$kind" "$PROVIDER" "$attempt" "$MAX_ATTEMPTS" >&2
  if ! "$ROUTER" rotate "$PROVIDER" >/dev/null 2>&1; then
    printf '[opencode] failover exhausted: no eligible alternate profile\n' >&2
    ((rc != 0)) && exit "$rc"
    exit 75
  fi

  # Wait a fixed 15s (override with OPENCODE_RETRY_DELAY_SECONDS) before
  # retrying the exact same model command on the freshly rotated server.
  printf '[opencode] waiting %ss before retrying %s on the rotated server\n' "$RETRY_DELAY" "$*" >&2
  sleep "$RETRY_DELAY"
done

printf '[opencode] failover exhausted\n' >&2
exit 75