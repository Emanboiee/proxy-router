"""Canonical runtime configuration defaults and migrations.

This leaf module deliberately has no router or platform imports.  The
controller still owns policy validation during the migration, but all default
values and the schema version now have one source of truth.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import ipaddress
import os
import re
import urllib.parse


SCHEMA_VERSION = 1
DEFAULT_PORT = 2080
DEFAULT_TUN_ADDRESS = ["172.19.0.1/30"]
DEFAULT_TUN_MTU = 1500
DEFAULT_ENDPOINT_MTU = 1280
DEFAULT_TUN_STACK = "system"
DEFAULT_PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_DIRECT_PROBE_URL = "https://example.com/"
DEFAULT_EGRESS_SETTINGS = {
    "probe_url": DEFAULT_PROBE_URL,
    "probe_timeout": 8.0,
    "probe_user_agent": "proxy-router-egress/1.0",
    "block_seconds": 3600,
    "upstream_cooldown_seconds": 300,
    "fail_threshold": 2,
    "slow_latency_ms": 1200.0,
    "ok_window": 86400,
    "probe_settle_seconds": 20.0,
}
DEFAULT_ROTATION_SETTINGS = {
    "interval_seconds": 0,
    "jitter_seconds": 300,
    "policy": "latency",
}
DEFAULT_ERROR_POLICY = {
    "default": {"action": "cooldown", "seconds": 300},
    "429": {"action": "exhaust", "seconds": 900},
    "503": {"action": "cooldown", "seconds": 120},
    "timeout": {"action": "cooldown", "seconds": 60},
    "tls": {"action": "cooldown", "seconds": 300},
    "connection": {"action": "cooldown", "seconds": 300},
    "1010": {"action": "block", "seconds": 3600},
    "403": {"action": "block", "seconds": 3600},
}


def migrate(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a config upgraded to the current schema version.

    Version one is the pre-existing file shape, so migration is intentionally
    a no-op today.  Keeping the version in one leaf module gives future
    changes a single, testable registration point without mutating input.
    """
    if not isinstance(data, dict):
        raise TypeError("configuration must be an object")
    version = data.get("schema_version", SCHEMA_VERSION)
    if version not in (0, 1):
        raise ValueError(f"unsupported config schema version: {version!r}")
    migrated = deepcopy(data)
    migrated["schema_version"] = SCHEMA_VERSION
    return migrated


def runtime_root(source: Path) -> Path:
    """#230: installed launchers resolve to ``releases/<tag>``, but mutable
    state lives at the prefix root (which has ``current/`` + ``router.json``).
    """
    if "PROXY_ROUTER_ROOT" in os.environ:
        return Path(os.environ["PROXY_ROUTER_ROOT"]).resolve()
    prefix = source.parent.parent
    if len(source.parts) >= 2 and source.parts[-2] == "releases" \
            and (prefix / "current").is_symlink() and (prefix / "router.json").is_file():
        return prefix.resolve()
    return source


def parse_error_policy(supplied) -> dict:
    """Validate one error-policy table: {reason: {action, seconds}}. Returns
    the cleaned table ({} when absent). Raises ValueError with a precise
    message on malformed input so load_config rejects the config instead of
    silently guessing."""
    if supplied is None:
        return {}
    if not isinstance(supplied, dict):
        raise ValueError("'error_policy' must be an object of reason -> {\"action\", \"seconds\"}")
    cleaned: dict[str, dict] = {}
    for key, entry in supplied.items():
        if not isinstance(entry, dict):
            raise ValueError(f"'error_policy.{key}' must be an object with 'action' and 'seconds'")
        action = entry.get("action", "cooldown")
        if action not in ("cooldown", "exhaust", "block"):
            raise ValueError(f"'error_policy.{key}.action' must be 'cooldown'|'exhaust'|'block' (got {action!r})")
        try:
            seconds = max(0, int(entry.get("seconds", 300)))
        except (TypeError, ValueError):
            raise ValueError(f"'error_policy.{key}.seconds' must be a non-negative integer") from None
        cleaned[str(key)] = {"action": action, "seconds": seconds}
    return cleaned


def routing_error(routing: dict, known_providers: set) -> str | None:
    """Precise error for a malformed routing section, else None.

    Shared by ``load_config`` and the ``routing`` CLI writer so both paths
    enforce exactly the same schema - malformed config fails loudly, never a
    silent guess. ``mode`` "default" is the explicit spelling of the absent
    (pre-existing) behavior; ``default_provider`` is only meaningful (and only
    required/validated against known providers) in safe-list mode.
    """
    mode = routing.get("mode", "default")
    if mode not in ("default", "safe-list", "vpn-list"):
        return f"routing.mode must be 'safe-list', 'vpn-list', or absent (default); got '{mode}'"
    for key in ("direct_domains", "vpn_domains"):
        value = routing.get(key)
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
            return f"routing.{key} must be a string list"
    default_provider = routing.get("default_provider")
    if default_provider is not None and not isinstance(default_provider, str):
        return "routing.default_provider must be a provider name string"
    health_order = routing.get("health_order")
    if health_order is not None and not isinstance(health_order, bool):
        return "routing.health_order must be a boolean"
    if mode == "safe-list":
        if not default_provider:
            return "routing mode 'safe-list' needs 'default_provider' (everything not on the direct list goes through it)"
        if default_provider not in known_providers:
            return (f"routing.default_provider '{default_provider}' is not a known provider "
                    f"(have {', '.join(sorted(known_providers))})")
    return None


def parse_egress_settings(data: dict) -> dict:
    """Merge router.json's optional ``egress`` dict over DEFAULT_EGRESS_SETTINGS
    with bounded leniency. Pure: returns the settings dict, mutates no globals."""
    settings = dict(DEFAULT_EGRESS_SETTINGS)
    supplied = data.get("egress") if isinstance(data, dict) else None
    if isinstance(supplied, dict):
        for key in DEFAULT_EGRESS_SETTINGS:
            if key in supplied:
                settings[key] = supplied[key]
    try:
        settings["probe_timeout"] = min(max(1.0, float(settings["probe_timeout"])), 60.0)
    except (TypeError, ValueError):
        settings["probe_timeout"] = DEFAULT_EGRESS_SETTINGS["probe_timeout"]
    for key in ("block_seconds", "upstream_cooldown_seconds", "ok_window"):
        try:
            settings[key] = max(0, int(settings[key]))
        except (TypeError, ValueError):
            settings[key] = DEFAULT_EGRESS_SETTINGS[key]
    try:
        settings["fail_threshold"] = min(max(1, int(settings["fail_threshold"])), 20)
    except (TypeError, ValueError):
        settings["fail_threshold"] = DEFAULT_EGRESS_SETTINGS["fail_threshold"]
    try:
        settings["slow_latency_ms"] = max(0.0, float(settings["slow_latency_ms"]))
    except (TypeError, ValueError):
        settings["slow_latency_ms"] = DEFAULT_EGRESS_SETTINGS["slow_latency_ms"]
    url = settings["probe_url"]
    try:
        parsed = urllib.parse.urlsplit(str(url))
        sane = parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except (TypeError, ValueError):
        sane = False
    if not sane:
        settings["probe_url"] = DEFAULT_EGRESS_SETTINGS["probe_url"]
    return settings


def public_dns_error(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return "vpn.public_dns must be an object"
    if not isinstance(value.get("server"), str):
        return "vpn.public_dns.server must be an IP address (no bootstrap DNS)"
    try:
        address = ipaddress.ip_address(value.get("server", ""))
    except ValueError:
        return "vpn.public_dns.server must be an IP address (no bootstrap DNS)"
    if address.is_unspecified or address.is_multicast:
        return "vpn.public_dns.server must be a unicast address"
    if value.get("transport", "https") not in ("https", "udp", "tcp", "tls"):
        return "vpn.public_dns.transport must be 'https', 'udp', 'tcp', or 'tls'"
    domains = value.get("private_domains", ["local", "ts.net"])
    if (not isinstance(domains, list)
            or any(not isinstance(domain, str)
                   or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", domain)
                   for domain in domains)):
        return "vpn.public_dns.private_domains must be a list of domain suffixes"
    return None



@dataclass(frozen=True)
class Config:
    """Immutable snapshot of one validated router.json load.

    The canonical shape for a parsed config (issue #66 C1). ``from_loaded``
    deep-copies every section so two instances never alias mutable state, and
    ``to_dict`` returns another fresh copy as the foundation of the save path.
    Router's module globals remain the mutable runtime table, seeded from this
    snapshot at load time; this object is never treated as live truth.
    """
    port: int
    providers: dict[str, Any]
    routes: list[dict[str, Any]]
    vpn: dict[str, Any]
    routing: dict[str, Any]
    autodetect: dict[str, Any]
    egress_settings: dict[str, Any]
    rotation: dict[str, Any]
    error_policy: dict[str, Any]
    proxy_bypass_domains: list[str]

    @classmethod
    def from_loaded(cls, *, port: int, providers: dict, routes: list, vpn: dict,
                    routing: dict, autodetect: dict, egress_settings: dict,
                    rotation: dict, error_policy: dict,
                    proxy_bypass_domains: list) -> "Config":
        return cls(
            port=port,
            providers=deepcopy(providers),
            routes=deepcopy(routes),
            vpn=deepcopy(vpn),
            routing=deepcopy(routing),
            autodetect=deepcopy(autodetect),
            egress_settings=deepcopy(egress_settings),
            rotation=deepcopy(rotation),
            error_policy=deepcopy(error_policy),
            proxy_bypass_domains=deepcopy(proxy_bypass_domains),
        )

    def runtime_view(self) -> tuple:
        """Fresh deep copies for router's mutable runtime globals, so later
        in-place writes never reach this snapshot."""
        return (
            self.port, deepcopy(self.providers), deepcopy(self.routes),
            deepcopy(self.vpn), deepcopy(self.routing),
            deepcopy(self.autodetect), list(self.proxy_bypass_domains),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a fresh deep copy as a canonical serializable snapshot."""
        return {
            "port": self.port,
            "providers": deepcopy(self.providers),
            "routes": deepcopy(self.routes),
            "vpn": deepcopy(self.vpn),
            "routing": deepcopy(self.routing),
            "autodetect": deepcopy(self.autodetect),
            "egress_settings": deepcopy(self.egress_settings),
            "rotation": deepcopy(self.rotation),
            "error_policy": deepcopy(self.error_policy),
            "proxy_bypass_domains": deepcopy(self.proxy_bypass_domains),
        }
