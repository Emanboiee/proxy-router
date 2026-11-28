"""Pure sing-box object shapes for attributed probe paths (issue #282).

The controller owns provider state and fallback markers. This leaf owns only
deterministic formatting: tag, port, inbound, route rule, and outbound objects
so generation and restore use identical identities without importing router.
"""
from __future__ import annotations

import os


PROBE_PORT_BASE = 2081


def effective_uid() -> int:
    """Return the effective uid where the platform exposes POSIX ids."""
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter is not None else -1


def probe_tag(name: str) -> str:
    return f"probe-{name}"


def probe_port(providers: dict, name: str, listen_port: int) -> int | None:
    """Return a stable probe port, or None on a listener collision or overflow."""
    if name not in providers:
        return None
    port = PROBE_PORT_BASE + list(providers).index(name) + 1
    return None if port == listen_port or port > 65535 else port


def probe_inbound(name: str, port: int) -> dict:
    return {"type": "mixed", "tag": probe_tag(name),
            "listen": "127.0.0.1", "listen_port": port}


def probe_socks_outbound(name: str, host: str, port: int) -> dict:
    return {"type": "socks", "tag": probe_tag(name),
            "server": host, "server_port": port, "version": "5"}


def probe_rule(name: str) -> dict:
    tag = probe_tag(name)
    return {"inbound": [tag], "outbound": tag}


def build_probe_objects(providers: dict, listen_port: int, *, is_tun: bool,
                        is_parked, is_proxy, proxy_upstream, usable_profile, parse_wg,
                        active: dict, proxy_outbounds: list) -> tuple[list, list]:
    """Append probe-only objects for parked providers and return inbounds/rules."""
    inbounds: list[dict] = []
    rules: list[dict] = []
    if is_tun:
        return inbounds, rules
    for name in providers:
        if not is_parked(name):
            continue
        port = probe_port(providers, name, listen_port)
        if port is None:
            continue
        if is_proxy(name):
            host, upstream = proxy_upstream(name)
            proxy_outbounds.append(probe_socks_outbound(name, host, upstream))
        else:
            profile = usable_profile(name)
            if profile is None:
                continue
            try:
                endpoint = parse_wg(profile)
            except (SystemExit, KeyError, ValueError, OSError):
                continue
            endpoint["tag"] = probe_tag(name)
            active[endpoint["tag"]] = endpoint
        inbounds.append(probe_inbound(name, port))
        rules.append(probe_rule(name))
    return inbounds, rules
