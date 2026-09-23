"""Canonical runtime configuration defaults and migrations.

This leaf module deliberately has no router or platform imports.  The
controller still owns policy validation during the migration, but all default
values and the schema version now have one source of truth.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


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
