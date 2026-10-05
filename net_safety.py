"""Shared probe-target safety policy (leaf module).

``router.py`` and ``monitor.py`` must apply an identical trust model when a
configured probe target is validated (issue #64): a hostile config must not
aim a probe at loopback, LAN, link-local, or cloud-metadata endpoints. That
policy used to be mirrored by hand in both files behind a comment promising
they stay in sync; this leaf makes the guarantee structural instead of
optimistic.

Must stay a leaf: no imports from router/monitor or any other top-level
module (enforced by tests/test_architecture_guards.py).
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse

PRIVATE_TARGET_BYPASS_ENV = "PROXY_ROUTER_ALLOW_PRIVATE_TARGETS"
METADATA_HOSTNAMES = frozenset({"metadata", "metadata.google.internal"})
METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})


def addr_is_private(addr) -> bool:
    """True for loopback / private / link-local / reserved / multicast /
    unspecified addresses. Unparseable input fails closed."""
    try:
        parsed = ipaddress.ip_address(str(addr))
    except ValueError:
        return True
    return (
        parsed.is_private or parsed.is_loopback or parsed.is_link_local
        or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified
    )


def resolve_target_addresses(url) -> list[str]:
    """Best-effort DNS resolution of ``url``'s hostname (empty list on error).

    Connection-time companion to the private-address check: validating what a
    name resolves to right before dialing closes the DNS-rebinding window a
    config-time-only check leaves open. Every resolved address is returned (no
    truncation) so callers can check all of them. Any failure yields an empty
    list; the caller then relies on the pre-connect check and its transport's
    own error handling.
    """
    try:
        host = urllib.parse.urlsplit(str(url)).hostname
        if not host:
            return []
        addresses: list[str] = []
        for info in socket.getaddrinfo(host, None):
            address = str(info[4][0]).strip("[]")
            if address not in addresses:
                addresses.append(address)
        return addresses
    except Exception:  # noqa: BLE001 - best-effort: no addresses on any failure
        return []
