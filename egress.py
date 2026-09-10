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

