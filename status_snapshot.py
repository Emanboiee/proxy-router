"""Read-only status assembly shared by controller pollers."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace


def build_status_snapshot(namespace: dict, *, fast: bool = False) -> dict:
    router = SimpleNamespace(**namespace)
    rc, line = router._status_report(fast=fast)
    data = {"up": rc == 0, "state": line, "mode": router.current_mode(), "port": router._port,
            "sing_box": router.resolve_sing_box(), "schema_version": router.SCHEMA_VERSION}
    # Local settings inspection is read-only and does not perform a network
    # probe. Keep engine liveness separate from proxy readiness so a listener
    # alone cannot make the tray claim that GUI traffic is connected.
    proxy_status, effective = router._system_proxy_status_readonly()
    data["system_proxy"] = {"status": proxy_status, "effective": effective}
    cached = router._cached_network_diagnostic()
    if cached is not None:
        data["network"] = cached
    try:
        if router.PID_FILE.is_file():
            data["pid"] = int(router.PID_FILE.read_text().strip())
    except (ValueError, OSError):
        pass
    data["providers"] = {name: router._provider_status(name) for name in router._providers}
    data["degraded_lanes"] = router._degraded_lanes()
    data["error_policy"] = {name: router.error_policy_for(name) for name in router._providers}
    data["routes"] = [{
        "id": route.get("id"),
        "provider": route.get("provider"),
        "domains": route.get("domains", []),
        "ip_cidr": route.get("ip_cidr", []),
    } for route in router._routes]
    data["autodetect"] = router.autodetect_status()
    data["routing"] = router.routing_state()
    try:
        cfg = json.loads(router.CONFIG_FILE.read_text())
        data["preset"] = cfg.get("preset")
    except (OSError, json.JSONDecodeError):
        data["preset"] = None
    try:
        import route_watcher

        data["watcher"] = route_watcher.status(router.ROOT)
    except Exception:
        data["watcher"] = {"running": False, "enabled": False, "scope": "proxy-observable only"}
    try:
        data["legacy_agents"] = router._legacy_launch_agents()
    except Exception:
        data["legacy_agents"] = []
    # Issue #76: expose the startup-permission state so the tray (and any
    # dashboard) can tell a permission gap apart from a broken engine and
    # offer the one-click repair instead of a generic failure.
    if fast:
        data["elevation"] = {"platform": sys.platform, "skipped": "fast"}
    else:
        helper = None
        if sys.platform == "darwin" and router._effective_uid() != 0:
            try:
                helper = router._helper_status()
            except Exception:
                helper = {"installed": False, "error": "helper status probe crashed"}
        data["elevation"] = {
            "platform": sys.platform,
            "root_engine": router._engine_runs_as_root(),
            "helper_installed": bool(helper and helper.get("installed")),
            "sudo_grant": router._sudoers_installed(),
            # The one-time fix every consumer should point at when any of the
            # flags above shows the grant missing.
            "fix_hint": router._HELPER_FIX,
        }
        if sys.platform == "darwin":
            data["elevation"]["tray_agent"] = router._launchd_agent_state("com.proxy-router.tray")
            data["elevation"]["keepalive_agent"] = router._launchd_agent_state(
                "com.proxy-router.keepalive")
    rotation = {
        "interval_seconds": router.scheduled_interval(),
        "jitter_seconds": int(router._rotation.get("jitter_seconds", router.DEFAULT_ROTATION_SETTINGS["jitter_seconds"]) or 0),
        "policy": router.rotation_policy(),
    }
    if rotation["interval_seconds"] > 0:
        next_times = [n for n in (router.next_rotation_at(name) for name in router._rotation_candidates())
                      if n is not None]
        if next_times:
            rotation["next_at"] = min(next_times)
    data["rotation"] = rotation
    return data


def build_provider_status(namespace: dict, name: str) -> dict:
    """Machine-readable view of one provider: profiles, active, cooldowns,
    last rotation, and persisted egress records."""
    router = SimpleNamespace(**namespace)
    proxy_backed = router.is_proxy_provider(name)
    profiles = [] if proxy_backed else [p.stem for p in router.provider_files(name)]
    # Report the PERSISTED active profile (what the engine is configured with)
    # rather than resolve_active(), which skips a cooled-down active when
    # picking the next candidate. Proxy-backed providers have one synthetic
    # SOCKS lane; stale WireGuard markers/files must not shadow its status.
    if proxy_backed:
        active_stem = router._PROXY_PROFILE_STEM
    else:
        active_profile = router.persisted_active(name)
        active_stem = active_profile.stem if active_profile is not None else None
    entry = {"profiles": profiles, "active": active_stem}
    if proxy_backed:
        try:
            upstream_host, upstream_port = router.proxy_upstream(name)
        except ValueError as exc:
            entry["upstream_error"] = str(exc)
        else:
            entry["upstream"] = f"{upstream_host}:{upstream_port}"
        proxy_record = router.read_egress(name, router.proxy_profile_key(name))
        if proxy_record:
            entry["egress"] = {router._PROXY_PROFILE_STEM: proxy_record}
    fallback = router.fallback_status(name)
    if fallback["configured"] or fallback["active"]:
        entry["fallback"] = fallback
    if not proxy_backed:
        cooldowns = {}
        for stem in profiles:
            path = router.ROOT / "state" / "cooldowns" / name / f"{stem}.until"
            try:
                if path.is_file():
                    cooldowns[stem] = int(path.read_text().strip())
            except (ValueError, OSError):
                pass
        if cooldowns:
            entry["cooldown_until"] = cooldowns
    if not proxy_backed:
        rotation = router.ROOT / "state" / f"{name}.rotation"
        try:
            if rotation.is_file():
                entry["last_rotation"] = json.loads(rotation.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    if not proxy_backed:
        egress = {}
        for stem in profiles:
            record = router.read_egress(name, Path(stem + ".conf"))
            if record:
                egress[stem] = record
        if egress:
            entry["egress"] = egress
    return entry
