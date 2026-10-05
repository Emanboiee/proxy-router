"""Pure egress-result classification helpers.

This module is intentionally dependency-free and has no router state.  It is
the first egress seam for issue #66: probe transport/HTTP results can be
classified and tested independently while ``router.py`` keeps its public
compatibility helpers during the staged migration.
"""

from __future__ import annotations

import re


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
