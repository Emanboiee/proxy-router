"""Pure WireGuard endpoint/DNS parsing helpers extracted from router.py.

Leaf module: imports only the standard library, so it never imports upward
into router.py or any top-level module (enforced by
tests/test_architecture_guards.py). router.py re-exports these names by import
so `import router` callers keep working during the #66 migration.
"""
from __future__ import annotations

import configparser
import socket
import threading
import re
from pathlib import Path


def _bad_endpoint(endpoint: str) -> None:
    raise SystemExit(f"bad Endpoint '{endpoint}' (expected host:port or [v6]:port)")


def parse_endpoint(endpoint: str) -> tuple[str, str]:
    """Split a WireGuard ``host:port`` (or ``[v6]:port``) Endpoint into
    (host, port) without breaking on IPv6 colons."""
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        host, _, rest = endpoint[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, sep, port = endpoint.rpartition(":")
        if not sep:
            _bad_endpoint(endpoint)
    if not host or not port:
        _bad_endpoint(endpoint)
    port_number = 0
    try:
        port_number = int(port)
    except ValueError:
        _bad_endpoint(endpoint)
    if not 1 <= port_number <= 65535:
        _bad_endpoint(endpoint)
    return host, str(port_number)


def dns_server_for(profile: Path) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profile)
    dns = parser.get("Interface", "DNS", fallback="").strip()
    if dns:
        dns = re.split(r"[,\s]+", dns)[0]
    # Proton's private tunnel resolver intermittently blackholes DNS on macOS
    # (10.2.0.1 / 2a07:b944::). Resolve through Cloudflare DNS over the same
    # WireGuard endpoint instead; the destination traffic remains provider-routed.
    if dns.startswith("10.") or dns.lower().startswith("2a07:b944:"):
        return "1.1.1.1"
    return dns or "1.1.1.1"


def _capture_domain_name(value: object) -> str | None:
    """Normalize one route target for destination-IP capture."""
    if not isinstance(value, str):
        return None
    domain = value.strip().lower().rstrip(".")
    while domain.startswith("*."):
        domain = domain[2:]
    return domain or None


def _bounded_getaddrinfo(host: str, port: int, timeout: float) -> list[str] | None:
    """Resolve ``host`` on a daemon worker so a broken resolver can never
    stall the check (mirrors resolve_host's bounded pattern). None on
    failure/timeout."""
    resolved: list[str] = []

    def _resolve() -> None:
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC)
        except (socket.gaierror, OSError, RuntimeError):
            return
        for info in infos:
            resolved.append(info[4][0])

    worker = threading.Thread(target=_resolve, name=f"dnscheck-{host}", daemon=True)
    worker.start()
    worker.join(timeout=timeout)
    return resolved or None


def _vpn_list_intersection(domains, vpn_domains) -> list[str]:
    """Route domains narrowed to the vpn-list intersection, narrowest wins.

    A route domain already inside the list keeps itself; a list entry that is
    a subdomain of the route domain is emitted instead. Disjoint pairs drop.
    """
    out: list[str] = []
    for domain in domains:
        for vpn in sorted(vpn_domains):
            if domain == vpn or domain.endswith("." + vpn):
                candidate = domain
            elif vpn.endswith("." + domain):
                candidate = vpn
            else:
                continue
            if candidate not in out:
                out.append(candidate)
    return out
