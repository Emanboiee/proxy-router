"""Small, bounded hostname discovery helpers for routed web applications.

Discovery deliberately works from URLs exposed by a normal HTTPS response.  It
does not decrypt TLS or infer ownership from arbitrary third-party CDN names;
callers provide the trusted suffixes that may be learned and persist exact
hostnames with an expiry time.
"""

from __future__ import annotations

import html
import re
import time
import urllib.parse
from typing import Iterable


_URL_RE = re.compile(r"(?:(?:https?:)?//)[^\s\"'<>]+", re.IGNORECASE)


def normalize_host(value: object) -> str | None:
    """Return a safe lower-case DNS hostname, or ``None``."""
    if not isinstance(value, str):
        return None
    value = value.strip().strip(".\\/\"'").lower()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return value


def host_matches_root(host: str, root: str) -> bool:
    """Match a root and its subdomains without allowing suffix collisions."""
    return host == root or host.endswith("." + root)


def extract_related_hosts(document: str, roots: Iterable[str], *,
                          extra_roots: Iterable[str] = ()) -> list[str]:
    """Extract exact hosts under trusted route roots and optional asset roots.

    ``extra_roots`` is explicit because shared CDNs can serve unrelated sites;
    callers must opt in to each cross-origin dependency suffix they trust.
    """
    try:
        candidates = (*(roots or ()), *(extra_roots or ()))
    except TypeError:
        return []
    allowed = {
        normalized
        for root in candidates
        if (normalized := normalize_host(root)) is not None
    }
    if not allowed or not isinstance(document, str):
        return []
    found: set[str] = set()
    for token in _URL_RE.findall(html.unescape(document).replace(r"\/", "/")):
        url = token if token.startswith(("http://", "https://")) else "https:" + token
        try:
            host = normalize_host(urllib.parse.urlsplit(url).hostname)
        except ValueError:
            host = None
        if host and any(host_matches_root(host, root) for root in allowed):
            found.add(host)
    return sorted(found)


def merge_state(state: object, hosts: Iterable[str], *, now: int | None = None,
                ttl_seconds: int = 1800) -> tuple[dict, bool]:
    """Merge hosts into an expiry-based state record and prune expired entries."""
    now = int(time.time() if now is None else now)
    ttl = max(60, int(ttl_seconds))
    current = state if isinstance(state, dict) else {}
    raw_domains = current.get("domains") if isinstance(current.get("domains"), dict) else {}
    domains: dict[str, dict] = {}
    for raw_host, raw_entry in raw_domains.items():
        host = normalize_host(raw_host)
        if host is None or not isinstance(raw_entry, dict):
            continue
        try:
            expires_at = int(raw_entry.get("expires_at", 0))
            first_seen = int(raw_entry.get("first_seen", now))
            last_seen = int(raw_entry.get("last_seen", first_seen))
        except (TypeError, ValueError):
            continue
        if expires_at > now:
            domains[host] = {
                "first_seen": first_seen,
                "last_seen": last_seen,
                "expires_at": expires_at,
            }
    for raw_host in hosts:
        host = normalize_host(raw_host)
        if host is None:
            continue
        entry = domains.get(host)
        if entry is None:
            domains[host] = {"first_seen": now, "last_seen": now, "expires_at": now + ttl}
        else:
            entry["last_seen"] = now
            entry["expires_at"] = now + ttl
    result = dict(current)
    result["updated_at"] = now
    result["domains"] = dict(sorted(domains.items()))
    changed = result != current
    return result, changed


def active_domains(state: object, *, now: int | None = None) -> list[str]:
    """Return non-expired exact hostnames from a discovery state record."""
    now = int(time.time() if now is None else now)
    if not isinstance(state, dict) or not isinstance(state.get("domains"), dict):
        return []
    result = []
    for raw_host, entry in state["domains"].items():
        host = normalize_host(raw_host)
        if host is None or not isinstance(entry, dict):
            continue
        try:
            if int(entry.get("expires_at", 0)) > now:
                result.append(host)
        except (TypeError, ValueError):
            continue
    return sorted(set(result))
