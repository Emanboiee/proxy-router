"""Pure helpers for selective TUN capture scope and destination rulesets.

Kept dependency-free: every filesystem/config/runtime dependency is passed in
at call time so this module can be tested without importing ``router``. A
ruleset is a ``rulesets/<name>.json`` file listing destination CIDRs and the
provider that should carry them; names are validated so they can never escape
the rulesets directory.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Callable

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class RulesetError(ValueError):
    """A ruleset name or file is invalid; message is user-facing."""


def describe(
    rulesets_dir: Path,
    name: str,
    *,
    default_provider: str,
    resolve_provider: Callable[[str], str],
    active_providers: set[str] | None = None,
) -> dict[str, Any]:
    """Describe one ruleset, including whether its provider is usable."""
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise RulesetError(
            "name must contain only letters, digits, dots, underscores, or hyphens"
        )
    path = rulesets_dir / f"{name}.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        raise RulesetError(f"missing ruleset {path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise RulesetError(f"could not read {path}: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("ip_cidr"), list):
        raise RulesetError(f"{path} needs an ip_cidr string list")
    cidrs = data["ip_cidr"]
    if not cidrs or not all(isinstance(cidr, str) and cidr for cidr in cidrs):
        raise RulesetError(f"{path} has no valid ip_cidr entries")
    provider = data.get("provider", default_provider)
    effective = resolve_provider(provider)
    return {
        "name": name,
        "provider": provider,
        "effective_provider": effective,
        "cidrs": list(cidrs),
        "cidr_count": len(cidrs),
        "description": data.get("description", ""),
        "usable": active_providers is None or effective in active_providers,
    }


def listing(
    rulesets_dir: Path,
    configured_vpn: dict,
    *,
    default_provider: str,
    resolve_provider: Callable[[str], str],
    active_providers: set[str],
) -> dict[str, Any]:
    """Build the machine-readable ``vpn rulesets`` payload."""
    rulesets: list[dict] = []
    if rulesets_dir.is_dir():
        for path in sorted(rulesets_dir.glob("*.json")):
            try:
                rulesets.append(
                    describe(
                        rulesets_dir,
                        path.stem,
                        default_provider=default_provider,
                        resolve_provider=resolve_provider,
                        active_providers=active_providers,
                    )
                )
            except RulesetError:
                # A malformed ruleset must not break the whole listing.
                continue
    return {
        "capture": configured_vpn.get("capture"),
        "selected": configured_vpn.get("selective"),
        "rulesets": rulesets,
    }


def select_config(
    configured: dict,
    name: str,
    rulesets_dir: Path,
    *,
    default_provider: str,
    resolve_provider: Callable[[str], str],
) -> dict[str, Any]:
    """Return the updated config dict after validating a ruleset selection."""
    vpn = configured.get("vpn", {})
    providers = configured.get("providers", {})
    active_providers = set(providers)
    info = describe(
        rulesets_dir,
        name,
        default_provider=default_provider,
        resolve_provider=resolve_provider,
        active_providers=active_providers,
    )
    if not info["usable"]:
        raise RulesetError(f"provider '{info['provider']}' has no active profile")
    vpn["selective"] = name
    vpn["selective_provider"] = info["provider"]
    vpn["capture"] = "ruleset"
    configured["vpn"] = vpn
    return info


def capture_config(configured: dict, scope: str) -> None:
    """Set ``vpn.capture`` in-place on a parsed config dict."""
    if scope not in ("ruleset", "routes"):
        raise RulesetError("vpn capture scope must be 'ruleset' or 'routes'")
    vpn = configured.get("vpn", {})
    vpn["capture"] = scope
    configured["vpn"] = vpn


def route_capture_cidrs(
    routes: list[dict],
    routing: dict,
    active: dict[str, dict],
    *,
    vpn_domains: set[str],
    direct_domains: set[str],
    resolve_provider: Callable[[str], str],
    domain_name: Callable[[object], str | None],
    getaddrinfo: Callable[[str, int, float], list[str] | None],
) -> list[str]:
    """Resolve tunneled route targets into TUN destination CIDRs.

    A TUN inbound installs destination IP routes, not hostname routes, so
    route-based capture snapshots the resolved IPs of configured domains.
    Router-owned resolution and provider mapping are injected as callbacks;
    this module stays dependency-free and importable without ``router``.
    """
    routing_mode = routing.get("mode", "default")
    target_domains: set[str] = set()
    raw_cidrs: list[str] = []

    for route in routes:
        route_provider = resolve_provider(route.get("provider", ""))
        if route_provider not in active and route.get("on_unavailable") != "block":
            continue
        for value in (route.get("domains") or []):
            domain = domain_name(value)
            if domain is None:
                continue
            if routing_mode == "vpn-list" and not any(
                domain == vpn or domain.endswith("." + vpn) for vpn in vpn_domains
            ):
                continue
            if routing_mode == "safe-list" and any(
                domain == direct or domain.endswith("." + direct) for direct in direct_domains
            ):
                continue
            try:
                address = ipaddress.ip_address(domain)
            except ValueError:
                target_domains.add(domain)
            else:
                raw_cidrs.append(f"{address}/{address.max_prefixlen}")
        # The vpn-list allow-list does not activate arbitrary IP routes.
        if routing_mode != "vpn-list":
            raw_cidrs.extend(route.get("ip_cidr") or [])

    unresolved: list[str] = []
    for domain in sorted(target_domains):
        answers = getaddrinfo(domain, 443, 3.0) or []
        resolved_domain = False
        for host in answers:
            try:
                address = ipaddress.ip_address(str(host).split("%", 1)[0])
            except (IndexError, TypeError, ValueError):
                continue
            raw_cidrs.append(f"{address}/{address.max_prefixlen}")
            resolved_domain = True
        if not resolved_domain:
            unresolved.append(domain)
    if unresolved:
        raise RulesetError("could not resolve route domains: " + ", ".join(unresolved))

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in raw_cidrs:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    collapsed = list(ipaddress.collapse_addresses(
        n for n in networks if n.version == 4
    )) + list(ipaddress.collapse_addresses(
        n for n in networks if n.version == 6
    ))
    return [
        str(n) for n in sorted(
            collapsed,
            key=lambda n: (n.version, int(n.network_address), n.prefixlen),
        )
    ]
