"""Attributed primary-restore policy for issue #282.

This leaf owns marker/evidence rules and fail-closed promotion. The controller
supplies file paths and callbacks, so no upward import is needed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import probe_paths


def read_marker(marker: Path) -> dict:
    try:
        loaded = json.loads(marker.read_text())
    except (OSError, ValueError, TypeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def cooling_down(previous: dict, now: float, cooldown: float) -> bool:
    try:
        return now - float(previous.get("attempted_at", 0)) < cooldown
    except (TypeError, ValueError):
        return False


def success_count(previous: dict) -> int:
    try:
        return max(0, int(previous.get("successes", 0) or 0))
    except (TypeError, ValueError):
        return 0


def reset_marker(marker: Path, host: str, now: float, write) -> None:
    write(marker, json.dumps({"attempted_at": now, "host": host,
                              "successes": 0}, sort_keys=True) + "\n", 0o600)


def route_probe_port(name: str, port: int | None, config_path: Path) -> int | None:
    """Port of a loaded probe inbound pinned to exactly one probe object."""
    if port is None:
        return None
    try:
        config = json.loads(config_path.read_text())
    except (OSError, ValueError, TypeError):
        return None
    tag = probe_paths.probe_tag(name)
    inbounds = [item for item in config.get("inbounds", [])
                if isinstance(item, dict)]
    if not any(item.get("tag") == tag and item.get("listen_port") == port
               for item in inbounds):
        return None
    tagged = [item for key in ("endpoints", "outbounds")
              for item in config.get(key, []) if isinstance(item, dict)
              and item.get("tag") == tag]
    return port if len(tagged) == 1 else None


def _dial_identity(obj: dict) -> dict:
    identity = dict(obj)
    identity.pop("tag", None)
    identity.pop("domain_resolver", None)
    return identity


def identity_from(config: dict, tag: str) -> dict | None:
    for outbound in config.get("outbounds", []):
        if isinstance(outbound, dict) and outbound.get("tag") == tag:
            return {key: value for key, value in outbound.items() if key != "tag"}
    for endpoint in config.get("endpoints", []):
        if isinstance(endpoint, dict) and endpoint.get("tag") == tag:
            return _dial_identity(endpoint)
    return None


def endpoint_identity(profile: Path, parse_wireguard) -> dict | None:
    try:
        return _dial_identity(parse_wireguard(profile))
    except (SystemExit, ValueError, KeyError, OSError):
        return None


def outbound_identity(name: str, config_path: Path) -> dict | None:
    try:
        return identity_from(json.loads(config_path.read_text()),
                             probe_paths.probe_tag(name))
    except (OSError, ValueError, TypeError):
        return None


def loaded_identity(name: str, config_path: Path, is_proxy: bool,
                    provider_files, parse_wireguard):
    """Return the loaded dial identity and its profile handle, if any."""
    try:
        identity = identity_from(json.loads(config_path.read_text()),
                                 probe_paths.probe_tag(name))
    except (OSError, ValueError, TypeError):
        return None
    if identity is None:
        return None
    profile = None
    if not is_proxy:
        try:
            profile = next((p for p in provider_files(name)
                            if endpoint_identity(p, parse_wireguard) == identity), None)
        except (ValueError, OSError):
            profile = None
    return identity, profile


def commit(name: str, marker: Path, evidence, ctx: dict) -> bool:
    """Pin the measured exit before clearing the serving fallback."""
    fallback_path = ctx["fallback_path"]
    state_path = ctx["state_path"]
    previous_bytes = fallback_path.read_bytes() if fallback_path.is_file() else None
    previous_active = state_path.read_text() if state_path.is_file() else None
    identity, profile = evidence
    ok = False
    try:
        if ctx["proxy"] and (
                identity.get("server") != ctx["upstream"][0]
                or identity.get("server_port") != ctx["upstream"][1]):
            return False
        if not ctx["proxy"]:
            if profile is None:
                return False
            ctx["set_active"](name, profile)
        fallback_path.unlink(missing_ok=True)
        overrides = {name: profile} if profile is not None else None
        config, selected = ctx["build"](overrides)
        if selected.get(name) != profile:
            return False
        if ctx["reload"]() != 0:
            return False
        marker.unlink(missing_ok=True)
        ok = True
        return True
    except (OSError, ValueError, KeyError, TypeError, SystemExit):
        return False
    finally:
        if not ok:
            if previous_bytes is not None:
                ctx["write"](fallback_path, previous_bytes.decode("utf-8"), 0o600)
            elif fallback_path.exists():
                fallback_path.unlink(missing_ok=True)
            if previous_active is None:
                if state_path.is_file():
                    state_path.unlink(missing_ok=True)
            elif not state_path.is_file() or state_path.read_text() != previous_active:
                ctx["write"](state_path, previous_active, 0o600)


def attributed_restore(name: str, host: str, url: str, marker: Path, port: int,
                       *, ctx: dict) -> int:
    """Measure the parked primary while its fallback keeps serving."""
    now = ctx["now"]()
    previous = read_marker(marker)
    if cooling_down(previous, now, ctx["cooldown"]):
        return 3
    successes = success_count(previous)
    evidence = previous.get("probe") if successes else None
    before = loaded_identity(name, ctx["config_path"], ctx["proxy"],
                             ctx["provider_files"], ctx["parse_wireguard"])
    result = ctx["probe"](url=url, port=port, timeout=3.0)
    status = result.get("status") if isinstance(result, dict) else None
    healthy = isinstance(status, int) and 100 <= status < 600
    after = loaded_identity(name, ctx["config_path"], ctx["proxy"],
                            ctx["provider_files"], ctx["parse_wireguard"])
    if before is None or after is None or before[0] != after[0]:
        healthy = False
    if healthy:
        identity = after[0]
        if evidence is not None and evidence != identity:
            successes = 1
        successes += 1
        evidence = identity
    else:
        successes = 0
        evidence = None
    if healthy and successes >= ctx["threshold"]:
        payload = {"attempted_at": now, "host": host,
                   "successes": successes, "probe": evidence}
        ctx["write"](marker, json.dumps(payload, sort_keys=True) + "\n", 0o600)
        if commit(name, marker, after, ctx):
            print(f"primary restored: {name} after {successes} successful checks")
            ctx["event"](name, successes)
            return 0
        reset_marker(marker, host, now, ctx["write"])
        return 1
    payload = {"attempted_at": now, "host": host, "successes": successes}
    if evidence is not None:
        payload["probe"] = evidence
    ctx["write"](marker, json.dumps(payload, sort_keys=True) + "\n", 0o600)
    return 1


def legacy_restore(name: str, host: str, url: str, serving: str, marker: Path,
                   *, ctx: dict) -> int:
    """Destructive measurement path for engines without a probe-only inbound."""
    now = ctx["now"]()
    previous = read_marker(marker)
    if cooling_down(previous, now, ctx["cooldown"]):
        return 3
    successes = success_count(previous)
    if ctx["deactivate"](name, automatic=True) != 0:
        return ctx["rc"]("deactivate failed")
    result = ctx["probe"](url=url, timeout=3.0)
    status = result.get("status") if isinstance(result, dict) else None
    healthy = isinstance(status, int) and 100 <= status < 600
    if healthy:
        successes += 1
        if successes >= ctx["threshold"]:
            marker.unlink(missing_ok=True)
            print(f"primary restored: {name} after {successes} successful checks")
            ctx["event"](name, successes)
            return 0
        ctx["write"](marker, json.dumps({"attempted_at": now, "host": host,
                                        "successes": successes}, sort_keys=True) + "\n", 0o600)
        if ctx["activate"](name, target=serving, reason="restore-pending",
                           automatic=True) == 0:
            print(f"primary check passed for {name}; awaiting one more check")
            return 1
        return ctx["rc"](f"provider '{name}' restore pending but fallback "
                         f"'{serving}' could not be reinstated")
    reset_marker(marker, host, now, ctx["write"])
    if ctx["activate"](name, target=serving, reason="primary-unhealthy",
                       automatic=True) != 0:
        return ctx["rc"](f"provider '{name}' primary is still unhealthy and "
                         f"fallback '{serving}' failed")
    print(f"primary still unhealthy: {name}; fallback '{serving}' retained")
    return 1
