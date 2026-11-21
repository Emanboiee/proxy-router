"""Canonical runtime configuration defaults and migrations.

This leaf module deliberately has no router or platform imports.  The
controller still owns policy validation during the migration, but all default
values and the schema version now have one source of truth.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import os


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
