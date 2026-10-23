"""Pure egress-result classification and transport-recovery policy helpers.

This module is intentionally dependency-free and has no router state.  It is
the first egress seam for issue #66: probe transport/HTTP results can be
classified and tested independently while ``router.py`` keeps its public
compatibility helpers during the staged migration. Primary-first recovery takes
the controller module explicitly instead of importing it, so the seam stays
downward-only.
"""

from __future__ import annotations

import datetime
import json
import re
import time


_DNS_ERROR_RE = re.compile(
    r"(getaddrinfo|no such host|nodename nor servname|name or service not known|"
    r"temporary failure in name resolution|could not resolve|servfail)",
    re.IGNORECASE,
)


def transport_reason(error_text: object) -> str:
    """Classify a transport failure as TLS-related or connection-related."""
    text = str(error_text or "").lower()
    if any(token in text for token in (
        "tls", "ssl", "handshake", "certificate", "eof", "alert",
    )):
        return "tls"
    return "connection"


def should_cool_connection(record: dict, fail_threshold: int) -> bool:
    """Require current positive DNS evidence for repeated connection failures."""
    return (not record.get("ok") and record.get("status") is None
            and record.get("dns_ok") is True
            and transport_reason(record.get("error")) != "tls"
            and int(record.get("fails") or 0) >= fail_threshold)


def is_http_policy_outcome(record: dict | None) -> bool:
    """HTTP policy ends warmup; a truncated curl response remains retryable."""
    return (record is not None and record.get("status") is not None
            and not str(record.get("error") or "").startswith("curl("))


def classify_probe_body(status: int, text: str) -> str | None:
    """Return a reputation-block reason for an HTTP response body, if any."""
    if re.search(
        r"error\s*code\s*[:=]?\s*1010|cloudflare.{0,20}1010",
        text,
        re.IGNORECASE,
    ):
        return "cloudflare-1010"
    if (status in (403, 1010)) and "cloudflare" in text.lower():
        return "cloudflare-403"
    return None


def probe_failure_reason(status: int, text: str) -> tuple[str | None, str | None]:
    """Return ``(error, block_reason)`` for one HTTP probe response."""
    reason = classify_probe_body(status, text)
    if reason is not None:
        return reason, reason
    if status == 429:
        return "rate-limit-429", None
    return None, None


def dns_error_markers(text: str) -> bool:
    """Return whether an error describes failed DNS resolution."""
    return bool(text) and bool(_DNS_ERROR_RE.search(text))


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def egress_rank(record: dict, *, now: int, ok_window: int, slow_latency_ms: float,
                fail_threshold: int) -> tuple[int, float]:
    """Rotation preference: lower is better. Recently-OK profiles rank by
    latency (fastest first); known-slow-but-OK and unknown profiles rank
    second; profiles with RECENT repeated failures rank last.

    Failure streaks expire with the ok window: a record whose last probe is
    older than that window carries no signal (it was typically written by
    an era of dishonest probes or long-gone network conditions), so it
    ranks as unknown instead of poisoning the exit forever."""
    if not record:
        return (1, float("inf"))
    ok = record.get("ok")
    last_ok = _int_or_none(record.get("last_ok_at") or record.get("checked_at"))
    checked_at = _int_or_none(record.get("checked_at"))
    fails = _int_or_none(record.get("fails") or 0) or 0
    window = int(ok_window)
    fresh = checked_at is not None and now - checked_at < window
    if ok and last_ok is not None and now - last_ok < window:
        latency = float(record.get("latency_ms") or float("inf"))
        if latency < float(slow_latency_ms):
            return (0, latency)
        return (2, latency)
    if fails >= int(fail_threshold) and fresh:
        return (3, float("inf"))
    return (1, float("inf"))


def lru_key(record: dict) -> int:
    """Autoroute key: epoch of the exit's last verified OK probe (older =
    preferred; 0 = never used = preferred first)."""
    try:
        return int(record.get("last_ok_at") or record.get("checked_at") or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# primary-first transport recovery
# ---------------------------------------------------------------------------

RECOVERY_PRIMARY_ATTEMPTS = 3
RECOVERY_PRIMARY_BUDGET_SECONDS = 30.0

# Reasons that mark a fallback as owned by automatic transport recovery. A
# supervisor may clear these; an operator-selected fallback (default reason
# "transport") must stay selected until the operator says otherwise.
AUTOMATIC_FALLBACK_REASONS = frozenset({
    "429", "confirmed-stall", "timeout", "tls", "connection",
    "restore-pending", "primary-unhealthy",
})


def quota_active(record: dict | None, now: int) -> bool:
    """True while one egress record carries an unexpired quota marker.

    Deadline-derived, never latched: an expired marker reads eligible again
    without anything having to clear it. A marker with no usable deadline stays
    active until cleared, so one malformed record cannot hand a quota-blocked
    exit back to the selector.
    """
    if not isinstance(record, dict) or not record.get("exhausted"):
        return False
    for key in ("quota_until", "exhausted_until"):
        raw = record.get(key)
        if raw is None:
            continue
        try:
            deadline = datetime.datetime.fromisoformat(str(raw)).timestamp()
        except (TypeError, ValueError, OverflowError):
            return True
        return int(now) < deadline
    return True


def restorable_fallback(router, name: str, *, automatic: bool) -> str | None:
    """Return the serving fallback when a restore may proceed, else ``None``.

    A ``confirmed-stall`` park may sit on another configured provider, not only
    on ``direct``. That is router-owned transport recovery, so it is restorable;
    an operator-selected provider fallback (default reason ``transport``) is
    not, and a supervisor-driven call never clears one.
    """
    serving = router.active_fallback(name)
    if serving is None:
        return None
    try:
        loaded = json.loads(router._fallback_state_path(name).read_text())
    except (OSError, ValueError, TypeError):
        loaded = {}
    marker = loaded if isinstance(loaded, dict) else {}
    if automatic and marker.get("reason") not in AUTOMATIC_FALLBACK_REASONS:
        return None
    if serving != "direct" and marker.get("reason") != "confirmed-stall":
        return None
    return serving


def recover_primary_route(router, name: str, reachable) -> int:
    """Try distinct eligible primary exits; retain the original on exhaustion.

    The budget limits starting new attempts, not engine reload duration.
    Return 2 if rollback fails, so callers cannot continue from uncertain state.
    """
    if router.active_fallback(name) or router.is_proxy_provider(name):
        return 1
    original = router.persisted_active(name) or router.resolve_active(name)
    if original is None:
        return 1
    attempted = {original}
    deadline = time.monotonic() + RECOVERY_PRIMARY_BUDGET_SECONDS
    for _ in range(RECOVERY_PRIMARY_ATTEMPTS):
        if router.MANUAL_OFF_FILE.exists() or not router._automatic_proxy_mode():
            return 3
        if time.monotonic() >= deadline:
            break
        available = [p for p in router.provider_files(name)
                     if p not in attempted and router._profile_error(p) is None
                     and not router.is_cooled_down(name, p)
                     and not router.egress_is_blocked(name, p)
                     and not router.egress_is_exhausted(name, p)]
        if not available:
            break
        if router.rotation_policy() == "least-recent":
            available = [p for p in available
                         if router._egress_rank(router.read_egress(name, p))[0] < 3] or available
            chosen = min(available, key=lambda p: (
                router._lru_key(router.read_egress(name, p)), p.stem))
        else:
            chosen = min(available,
                         key=lambda p: router._egress_rank(router.read_egress(name, p)))
        attempted.add(chosen)
        # Probe the stalled destination through this exit instead of spending a
        # full generic readiness window on every candidate.
        rc = router.rotate(name, to=chosen.stem, reason="timeout",
                           probe=False, automatic=True)
        if rc == 3 or router.MANUAL_OFF_FILE.exists() or not router._automatic_proxy_mode():
            return 3
        if rc == 0:
            if reachable():
                print(f"route recovered: {name} -> {chosen.stem}")
                return 0
            router._apply_upstream_failure(
                name, chosen, "timeout",
                int(router._providers.get(name, {}).get("cooldown_seconds", 60)))
    current = router.persisted_active(name) or router.resolve_active(name)
    if current != original:
        if router.MANUAL_OFF_FILE.exists() or not router._automatic_proxy_mode():
            return 3
        if router.engine_reload({name: original}) != 0:
            return 2
        router.set_active(name, original)
        router.record_rotation(name, original)
    return 1
