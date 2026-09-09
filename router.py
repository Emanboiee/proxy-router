#!/usr/bin/env python3
"""Proxy router: domain/IP -> provider (WireGuard) selective routing.

Reads ``router.json`` (routes + providers), generates a sing-box config with one
WireGuard endpoint per provider, and hot-reloads it via SIGHUP so route changes
do not drop existing connections. Providers are pools of ``*.conf`` WireGuard
profiles (Proton, Cloudflare WARP, ...) with per-profile cooldown and rotation.

The generated ``sing-box.json`` contains the private keys of every active
profile, so it is written mode 0600 alongside the input profiles.
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
import platform
try:
    import pwd
except ImportError:  # Windows has no POSIX account database module.
    pwd = None
import random
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import domain_autodetect
from config_schema import (
    DEFAULT_DIRECT_PROBE_URL,
    DEFAULT_EGRESS_SETTINGS,
    DEFAULT_ENDPOINT_MTU,
    DEFAULT_ERROR_POLICY,
    DEFAULT_PORT,
    DEFAULT_PROBE_URL,
    DEFAULT_ROTATION_SETTINGS,
    DEFAULT_TUN_ADDRESS,
    DEFAULT_TUN_MTU,
    DEFAULT_TUN_STACK,
    SCHEMA_VERSION,
    migrate as migrate_config,
)


def _effective_uid() -> int:
    """Return the effective uid where the platform exposes POSIX ids."""
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter is not None else -1

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
CONFIG_FILE = ROOT / "router.json"
SING_BOX_CONFIG = ROOT / "sing-box.json"
LAST_GOOD_FILE = ROOT / "sing-box.json.last-good"
PID_FILE = ROOT / "sing-box.pid"
LOG_DIR = ROOT / "logs"
LOG_FILE = LOG_DIR / "sing-box.log"
LOCK_FILE = ROOT / "state" / "engine.lock"
MODE_FILE = ROOT / "state" / "mode"
# Written by `router.py stop` (and the tray Disconnect); respected by
# keepalive.sh so a manual disconnect is NOT resurrected on the next
# ensure tick. Removed by `router.py start` / tray Connect.
MANUAL_OFF_FILE = ROOT / "state" / "manual-off"
# Written automatically when Wi-Fi disappears; unlike manual-off, keepalive
# clears it and reconnects after the network returns.
NETWORK_OFF_FILE = ROOT / "state" / "network-off"
# Versioned ownership record for system proxy changes.  It records only the
# endpoint proxy-router installed (never proxy credentials or full settings),
# so Disconnect can clear stale copies after a network/VPN handoff without
# disabling a foreign proxy.
SYSTEM_PROXY_STATE_FILE = ROOT / "state" / "system-proxy.json"
# Cached result written only by the explicit ``doctor --network`` command.
# ``status --json`` reads this file but never starts a fresh network probe.
NETWORK_DIAGNOSTIC_FILE = ROOT / "state" / "network-diagnostic.json"
# Pending per-provider overrides handed to an elevated `reload` when the
# engine runs as root and the invoking process cannot SIGHUP it directly.
RELOAD_OVERRIDE_FILE = ROOT / "state" / "reload-override.json"
_rotation: dict = {}
# Rotate logs/sing-box.log once it outgrows this (mirrors monitor.py sample
# rotation); the live log grows a line per connection and is unbounded.
LOG_MAX_BYTES = 10_000_000
# Confirmed direct fallbacks are retried on a slow cadence to avoid flapping.
RECOVERY_COOLDOWN_SECONDS = 120.0
RESTORE_COOLDOWN_SECONDS = 300.0
RESTORE_SUCCESS_THRESHOLD = 2

_sing_box_cache: str | None = None
_sing_box_resolved = False


def resolve_sing_box() -> str | None:
    """Resolve the sing-box executable, cached.

    Priority: ``SING_BOX`` env var, then ``<root>/bin/sing-box(.exe)`` (bundled
    releases), then ``sing-box`` on ``PATH``. Returns None when not found.
    """
    global _sing_box_cache, _sing_box_resolved
    if _sing_box_resolved:
        return _sing_box_cache
    bundled = ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    candidates = [os.environ.get("SING_BOX"), str(bundled)]
    if sys.platform == "darwin" and os.name != "nt":
        # launchd does not inherit the login shell's PATH. Keep Homebrew's
        # canonical locations as an explicit fallback so a GUI/keepalive
        # process does not randomly report a perfectly installed engine as
        # missing when PATH is incomplete.
        candidates.extend(("/opt/homebrew/bin/sing-box", "/usr/local/bin/sing-box"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _sing_box_cache = candidate
            _sing_box_resolved = True
            return candidate
    _sing_box_cache = shutil.which("sing-box")
    _sing_box_resolved = True
    return _sing_box_cache


def _sing_box_missing_message() -> str:
    """Actionable one-line message naming every location the resolver checked.

    Tray Connect shows the CLI's last line, so the real candidates (env,
    bundled path, Homebrew locations, PATH) plus the minimum version and
    download URL turn a bare "Sing-box not found" into a next step (issue
    #11: the tray reported an unexplained "Connect: Failed").
    """
    bundled = ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    env_value = os.environ.get("SING_BOX")
    tried = ["env SING_BOX (set, missing)" if env_value else "env SING_BOX=(unset)",
             f"{bundled} (missing)"]
    if sys.platform == "darwin" and os.name != "nt":
        tried.extend(("/opt/homebrew/bin/sing-box (missing)",
                      "/usr/local/bin/sing-box (missing)"))
    tried.append("PATH (no 'sing-box')")
    version = ".".join(map(str, MIN_SING_BOX_VERSION))
    return (f"sing-box not found (tried: {', '.join(tried)}); "
            f"install {version}+ from https://github.com/SagerNet/sing-box/releases "
            f"at {bundled}, or set SING_BOX=/path/to/sing-box")


# The generated sing-box.json uses features that do not exist before sing-box
# 1.12.0 (dialer `domain_resolver`, route `default_domain_resolver`, and the
# dns `hijack-dns` rule action - verified against the 1.12 and 1.11 release
# binaries). An older binary fails `check` with a cryptic "unknown field"
# error, so we reject it up front with a clear message (M8).
MIN_SING_BOX_VERSION = (1, 12, 0)

_sing_box_version_cache: tuple[int, int, int] | None = None
_sing_box_version_resolved = False


def sing_box_version() -> tuple[int, int, int] | None:
    """Parse `sing-box version` output into a (major, minor, patch) tuple.

    Returns None when the binary cannot be run or the banner does not contain
    a parseable version (callers then fall back to `sing-box check`, which
    still reports the concrete schema error instead of guessing)."""
    global _sing_box_version_cache, _sing_box_version_resolved
    if _sing_box_version_resolved:
        return _sing_box_version_cache
    version = None
    sing_box = resolve_sing_box()
    if sing_box is not None:
        try:
            result = subprocess.run(
                [sing_box, "version"], capture_output=True, text=True, timeout=10
            )
            match = re.search(r"version\s+[vV]?(\d+)\.(\d+)\.(\d+)", result.stdout)
            if match:
                version = tuple(int(g) for g in match.groups())
        except (OSError, subprocess.TimeoutExpired):
            pass
    _sing_box_version_cache = version
    _sing_box_version_resolved = True
    return version


def sing_box_at_least(minimum: tuple[int, int, int]) -> bool:
    """True when sing-box satisfies ``minimum``; an unknown version is not
    rejected here (the generated config's `check` still catches real schema
    problems, and refusing on a parse failure could lock out beta builds)."""
    version = sing_box_version()
    return version is None or version >= minimum


def _sing_box_version_message(required: tuple[int, int, int]) -> str:
    version = sing_box_version()
    if version is None:
        return f"cannot determine sing-box version; need >= {'.'.join(map(str, required))}"
    return f"sing-box {'.'.join(map(str, version))} is too old (need >= {'.'.join(map(str, required))}); install a newer sing-box or point SING_BOX at one"

_providers: dict = {}
_routes: list = []
_port: int = DEFAULT_PORT
_vpn: dict = {}
_routing: dict = {}
_autodetect: dict = {}
_egress_settings: dict = {}
_error_policy: dict | None = None
_PROVIDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


# ---------------------------------------------------------------------------
# proxy-backed providers (local SOCKS5 upstream, e.g. `warp-cli mode proxy`)
# ---------------------------------------------------------------------------
# A proxy-backed provider routes its assigned domains through a local SOCKS5
# upstream instead of a WireGuard endpoint in the shared engine:
#   "providers": {"warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 40000}}}
# Only loopback upstreams are accepted: a remote proxy would silently move
# trust to a third party, and any other hostname is ambiguous (DNS may mix
# loopback and public answers over time). The upstream port must never equal
# the router's own listener port (proxy loop).
_PROXY_PROFILE_STEM = "socks"


def is_proxy_provider(name: str) -> bool:
    """True when ``name`` is a proxy-backed (SOCKS5) provider, not a WireGuard pool."""
    entry = _providers.get(name)
    return isinstance(entry, dict) and isinstance(entry.get("socks5"), dict)


def _normalize_proxy_host(host: object) -> str:
    return str(host or "").strip().strip("[]").lower().replace("localhost", "127.0.0.1")


def proxy_upstream(name: str) -> tuple[str, int]:
    """Validated (host, port) for a proxy-backed provider. Raises ValueError."""
    entry = _providers.get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("socks5"), dict):
        raise ValueError(f"provider '{name}' is not a proxy-backed (socks5) provider")
    spec = entry["socks5"]
    host = _normalize_proxy_host(spec.get("host"))
    if host not in ("127.0.0.1", "::1"):
        raise ValueError(
            f"provider '{name}' socks5.host must be a local loopback "
            f"('127.0.0.1', '::1', or 'localhost'); got {spec.get('host')!r}"
        )
    try:
        port = int(spec.get("port"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError(f"provider '{name}' socks5.port must be an integer 1-65535") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"provider '{name}' socks5.port must be between 1 and 65535")
    if port == _port:
        raise ValueError(
            f"provider '{name}' socks5 upstream {host}:{port} is the router's own "
            "listener (proxy loop)"
        )
    return host, port


def proxy_profile_key(name: str) -> Path:
    """Synthetic egress/cooldown key for a proxy-backed provider.

    The health machinery (records, cooldowns, blocks) is keyed by profile
    stem; a SOCKS5 upstream has no *.conf, so it reuses one fixed stem that
    satisfies the _PROVIDER_NAME traversal guard."""
    return Path(f"{_PROXY_PROFILE_STEM}.conf")


def provider_has_valid_exit(name: str) -> bool:
    """True when ``name`` can carry traffic right now (static, no probes)."""
    if is_proxy_provider(name):
        try:
            proxy_upstream(name)
        except ValueError:
            return False
        return True
    try:
        profiles = provider_files(name)
    except ValueError:
        return False
    return any(_profile_error(profile) is None for profile in profiles)


def active_proxy_providers() -> dict[str, tuple[str, int]]:
    """Validated proxy-backed providers that are live in the current build.

    A provider under an active fallback is parked (its routes follow the
    fallback target), mirroring the WireGuard path in build_singbox_config."""
    live: dict[str, tuple[str, int]] = {}
    for name in _providers:
        if not is_proxy_provider(name) or active_fallback(name):
            continue
        try:
            live[name] = proxy_upstream(name)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    return live


def _tun_proxy_blockers(build_routes: list[dict], routing: dict,
                         proxy_live: dict[str, tuple[str, int]]) -> list[str]:
    """Proxy-backed providers that a TUN build would have to carry.

    A local SOCKS5 hop speaks TCP; it cannot serve the arbitrary UDP/IP
    flows a TUN captures. Callers fail the build naming these instead of
    silently half-routing UDP around the proxy."""
    if not proxy_live:
        return []
    blockers: list[str] = []
    for route in build_routes:
        effective = _effective_route_provider(route.get("provider", ""))
        if effective in proxy_live and effective not in blockers:
            blockers.append(effective)
    selective = _vpn.get("selective")
    if isinstance(selective, str):
        effective = _effective_route_provider(selective)
        if effective in proxy_live and effective not in blockers:
            blockers.append(effective)
    if routing.get("mode") == "safe-list":
        default = routing.get("default_provider")
        if isinstance(default, str):
            effective = _effective_route_provider(default)
            if effective in proxy_live and effective not in blockers:
                blockers.append(effective)
    return blockers


def fail(message: str) -> int:
    print(f"router: {message}", file=sys.stderr)
    return 1


def current_mode() -> str:
    """'proxy' or 'tun'. Persisted in state/mode so ensure/reload keep
    running whatever the user last selected; falls back to the configured
    vpn.default_mode ('proxy' unless router.json says otherwise) when no
    mode has been selected yet (fresh install)."""
    try:
        if MODE_FILE.is_file():
            mode = MODE_FILE.read_text().strip()
            if mode in ("proxy", "tun"):
                return mode
    except OSError:
        # Root-owned mode file (written by a sudo run whose ownership was
        # not handed back) must not crash the regular-user CLI/keepalive.
        pass
    return _vpn.get("default_mode", "proxy")


def _generated_config_mode() -> str | None:
    """Return the mode represented by ``sing-box.json`` when readable.

    ``None`` means no generated config exists yet. ``unknown`` is deliberately
    distinct from a proxy config so automatic maintenance can fail closed
    instead of treating a broken/stale file as permission to reload.
    """
    if not SING_BOX_CONFIG.is_file():
        return None
    try:
        data = json.loads(SING_BOX_CONFIG.read_text())
        if not isinstance(data, dict):
            return "unknown"
        inbounds = data.get("inbounds")
        if not isinstance(inbounds, list):
            return "unknown"
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return "unknown"
    return "tun" if any(
        isinstance(item, dict) and item.get("type") == "tun"
        for item in inbounds
    ) else "proxy"


def _automatic_proxy_mode() -> bool:
    """Return whether automatic maintenance has positive proxy proof."""
    try:
        marker = MODE_FILE.read_text().strip()
    except (OSError, UnicodeError):
        return False
    return marker == "proxy" and _generated_config_mode() == "proxy"


def _hand_back_ownership(path: Path) -> None:
    """Chown a state file back to the user who invoked sudo.

    tun mode needs root, so `sudo vpn on` writes state files as root with
    0600; the regular-user keepalive/CLI then cannot read them and treats
    a live engine as dead (garbage pid file H6, unreadable mode/config),
    churning restarts. SUDO_UID/SUDO_GID identify who to hand back to.
    Failures are reported, not swallowed: an unhanded-back file locks the
    regular-user keepalive out and silently resurrects the churn loop."""
    if _effective_uid() != 0:
        return
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or not gid:
        print(f"router: root run without SUDO_UID/SUDO_GID; {path} stays root-owned",
              file=sys.stderr)
        return
    try:
        os.chown(path, int(uid), int(gid))
    except (OSError, ValueError) as exc:
        print(f"router: ownership hand-back failed for {path}: {exc}",
              file=sys.stderr)


def set_mode(mode: str) -> None:
    MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    MODE_FILE.write_text(mode)
    os.chmod(MODE_FILE, 0o600)
    _hand_back_ownership(MODE_FILE)


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write ``text`` to ``path`` atomically (temp file + os.replace) with
    ``mode`` permissions, so a crash mid-write never leaves a truncated
    config and the file is never world-readable (F5)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
        _hand_back_ownership(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)



def _autodetect_route_sources(routes: list[dict], providers: dict,
                              sources: dict[str, dict]) -> dict[str, dict]:
    """Create bounded discovery sources for routes without explicit sources."""
    covered_routes = {
        settings.get("route_id")
        for settings in sources.values()
        if isinstance(settings, dict)
    }
    generated = dict(sources)
    for route in routes:
        if not isinstance(route, dict):
            continue
        route_id = route.get("id")
        provider = route.get("provider")
        if (
            not isinstance(route_id, str)
            or not _PROVIDER_NAME.fullmatch(route_id)
            or not isinstance(provider, str)
            or provider not in providers
            or route_id in covered_routes
        ):
            continue
        roots: list[str] = []
        seed_host: str | None = None
        raw_domains = route.get("domains")
        if not isinstance(raw_domains, list):
            continue
        for raw_domain in raw_domains:
            if not isinstance(raw_domain, str):
                continue
            host = domain_autodetect.normalize_host(raw_domain.lstrip("*."))
            if host is None:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError:
                roots.append(host)
                seed_host = seed_host or host
        roots = sorted(set(roots))
        if not roots or seed_host is None:
            continue
        source = f"route-{route_id}"
        if source in generated:
            existing = generated[source]
            if existing.get("route_id") != route_id:
                raise ValueError(
                    f"autodetect source '{source}' collides with generated route source"
                )
            continue
        generated[source] = {
            "seed": f"https://{seed_host}/",
            "route_id": route_id,
            "provider": provider,
            "roots": roots,
            "ttl_seconds": 1800,
        }
    return generated

def _load_autodetect(data: dict, routes: list, providers: dict) -> dict:
    """Validate bounded hostname autodetection settings."""
    raw = data.get("autodetect", {}) if isinstance(data, dict) else {}
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("'autodetect' must be an object")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("'autodetect.enabled' must be a boolean")
    auto_sources = raw.get("auto_sources", True)
    if not isinstance(auto_sources, bool):
        raise ValueError("'autodetect.auto_sources' must be a boolean")
    try:
        interval = int(raw.get("interval_seconds", 300))
        timeout = int(raw.get("timeout_seconds", 12))
    except (TypeError, ValueError):
        raise ValueError("'autodetect' interval/timeout must be integers") from None
    if interval < 30:
        raise ValueError("'autodetect.interval_seconds' must be at least 30")
    if not 3 <= timeout <= 60:
        raise ValueError("'autodetect.timeout_seconds' must be between 3 and 60")
    sources = raw.get("sources", {})
    if not isinstance(sources, dict):
        raise ValueError("'autodetect.sources' must be an object")
    route_ids = {route.get("id") for route in routes if isinstance(route.get("id"), str)}
    cleaned_sources: dict[str, dict] = {}
    for source, supplied in sources.items():
        if not isinstance(source, str) or not _PROVIDER_NAME.fullmatch(source):
            raise ValueError("'autodetect.sources' names must be valid identifiers")
        if not isinstance(supplied, dict):
            raise ValueError(f"'autodetect.sources.{source}' must be an object")
        seed = supplied.get("seed")
        if not isinstance(seed, str) or not seed.startswith("https://"):
            raise ValueError(f"'autodetect.sources.{source}.seed' must be an https URL")
        seed_host = domain_autodetect.normalize_host(urllib.parse.urlsplit(seed).hostname)
        if seed_host is None:
            raise ValueError(f"'autodetect.sources.{source}.seed' has no valid hostname")
        route_id = supplied.get("route_id")
        provider = supplied.get("provider")
        if not isinstance(route_id, str) or route_id not in route_ids:
            raise ValueError(f"'autodetect.sources.{source}.route_id' must name a configured route")
        if not isinstance(provider, str) or provider not in providers:
            raise ValueError(f"'autodetect.sources.{source}.provider' must name a configured provider")
        try:
            ttl = int(supplied.get("ttl_seconds", 1800))
        except (TypeError, ValueError):
            raise ValueError(f"'autodetect.sources.{source}.ttl_seconds' must be an integer") from None
        if not 60 <= ttl <= 7 * 24 * 60 * 60:
            raise ValueError(f"'autodetect.sources.{source}.ttl_seconds' must be between 60 and 604800")
        roots = supplied.get("roots", [])
        if not isinstance(roots, list) or not roots:
            raise ValueError(f"'autodetect.sources.{source}.roots' must be a non-empty string list")
        normalized_roots = []
        for root in roots:
            normalized = domain_autodetect.normalize_host(root)
            if normalized is None:
                raise ValueError(f"'autodetect.sources.{source}.roots' contains an invalid hostname")
            normalized_roots.append(normalized)
        if not any(domain_autodetect.host_matches_root(seed_host, root) for root in normalized_roots):
            raise ValueError(f"'autodetect.sources.{source}.seed' must be under one of its roots")
        cleaned_sources[source] = {
            "seed": seed,
            "route_id": route_id,
            "provider": provider,
            "roots": sorted(set(normalized_roots)),
            "ttl_seconds": ttl,
        }
    if auto_sources and enabled:
        cleaned_sources = _autodetect_route_sources(routes, providers, cleaned_sources)
    return {
        "enabled": enabled,
        "interval_seconds": interval,
        "timeout_seconds": timeout,
        "sources": cleaned_sources,
        "auto_sources": auto_sources
    }


def load_config() -> int:
    global _providers, _routes, _port, _vpn, _routing, _autodetect
    if not CONFIG_FILE.is_file():
        return fail(f"missing {CONFIG_FILE.name}; run 'router.py init' first")
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict):
            return fail(f"bad {CONFIG_FILE.name}: top level must be an object")
        data = migrate_config(data)
        port = int(data.get("port", DEFAULT_PORT))
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        return fail(f"bad {CONFIG_FILE.name}: {exc}")
    if not 1 <= port <= 65535:
        return fail(f"bad {CONFIG_FILE.name}: port must be between 1 and 65535")
    providers = data.get("providers", {})
    routes = data.get("routes", [])
    vpn = data.get("vpn", {})
    if not isinstance(providers, dict) or not providers:
        return fail("no providers configured")
    if not isinstance(vpn, dict):
        return fail(f"bad {CONFIG_FILE.name}: vpn must be an object")
    capture = vpn.get("capture")
    if capture is not None and capture not in ("ruleset", "routes"):
        return fail(f"bad {CONFIG_FILE.name}: vpn.capture must be 'ruleset' or 'routes'")
    exclude_cidr = vpn.get("exclude_cidr")
    if exclude_cidr is not None and (
        not isinstance(exclude_cidr, list)
        or any(not isinstance(cidr, str) or not cidr.strip() for cidr in exclude_cidr)
    ):
        return fail(f"bad {CONFIG_FILE.name}: vpn.exclude_cidr must be a list of CIDR strings")
    default_mode = vpn.get("default_mode")
    if default_mode is not None and default_mode not in ("proxy", "tun"):
        return fail(f"bad {CONFIG_FILE.name}: vpn.default_mode must be 'proxy' or 'tun'")
    if not all(isinstance(name, str) and _PROVIDER_NAME.fullmatch(name) and isinstance(entry, dict)
               for name, entry in providers.items()):
        return fail(f"bad {CONFIG_FILE.name}: provider names/entries are invalid")
    for name, entry in providers.items():
        if "fail_open_direct" in entry and not isinstance(entry["fail_open_direct"], bool):
            return fail(f"bad {CONFIG_FILE.name}: fail_open_direct must be a boolean")
        directory = entry.get("directory", f"providers/{name}")
        if not isinstance(directory, str):
            return fail(f"bad {CONFIG_FILE.name}: provider '{name}' directory must be a string")
        socks_spec = entry.get("socks5")
        if socks_spec is not None:
            # Proxy-backed provider (local SOCKS5 upstream): an explicit lane
            # with no WireGuard pool. Reject anything ambiguous at load so a
            # bad upstream can never reach the generated config at runtime.
            if not isinstance(socks_spec, dict):
                return fail(f"bad {CONFIG_FILE.name}: provider '{name}' socks5 must be an object with host/port")
            if "directory" in entry:
                return fail(f"bad {CONFIG_FILE.name}: provider '{name}' cannot define both directory and socks5")
            socks_host = _normalize_proxy_host(socks_spec.get("host"))
            if socks_host not in ("127.0.0.1", "::1"):
                return fail(
                    f"bad {CONFIG_FILE.name}: provider '{name}' socks5.host must be a local "
                    f"loopback ('127.0.0.1', '::1', or 'localhost'); got {socks_spec.get('host')!r}"
                )
            try:
                socks_port = int(socks_spec.get("port"))
            except (TypeError, ValueError):
                return fail(f"bad {CONFIG_FILE.name}: provider '{name}' socks5.port must be an integer 1-65535")
            if not 1 <= socks_port <= 65535:
                return fail(f"bad {CONFIG_FILE.name}: provider '{name}' socks5.port must be between 1 and 65535")
            if socks_port == port:
                return fail(
                    f"bad {CONFIG_FILE.name}: provider '{name}' socks5 upstream {socks_host}:{socks_port} "
                    "is the router's own listener (proxy loop)"
                )
        legacy_fallback = entry.get("fallback_provider")
        fallback_list = entry.get("fallback_providers")
        if fallback_list is not None and legacy_fallback is not None:
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' cannot define both fallback_provider and fallback_providers"
            )
        raw_fallbacks = fallback_list if fallback_list is not None else legacy_fallback
        if raw_fallbacks is None:
            fallbacks: list[str] = []
        elif isinstance(raw_fallbacks, str):
            fallbacks = [raw_fallbacks]
        elif isinstance(raw_fallbacks, list) and all(isinstance(t, str) for t in raw_fallbacks):
            fallbacks = list(raw_fallbacks)
        else:
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' fallback_providers must be a provider name or a string list"
            )
        if len(set(fallbacks)) != len(fallbacks):
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' fallback_providers must not contain duplicates"
            )
        if any(target == name or target not in providers for target in fallbacks):
            field = "fallback_providers" if fallback_list is not None else "fallback_provider"
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' {field} must name another configured provider"
            )
        try:
            (ROOT / directory).resolve().relative_to(ROOT)
        except ValueError:
            return fail(f"bad {CONFIG_FILE.name}: provider '{name}' directory escapes the router root")
    def fallback_targets(provider: str) -> list[str]:
        entry = providers[provider]
        targets = entry.get("fallback_providers")
        if isinstance(targets, list):
            return targets
        target = entry.get("fallback_provider")
        return [target] if isinstance(target, str) else []

    def check_fallback_path(provider: str, path: tuple[str, ...] = ()) -> str | None:
        if provider in path:
            return provider
        next_path = path + (provider,)
        for target in fallback_targets(provider):
            cycle = check_fallback_path(target, next_path)
            if cycle is not None:
                return cycle
        return None

    for name in providers:
        cycle = check_fallback_path(name)
        if cycle is not None:
            return fail(f"bad {CONFIG_FILE.name}: fallback chain cycle includes '{cycle}'")
    if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes) or not isinstance(vpn, dict):
        return fail(f"bad {CONFIG_FILE.name}: providers/routes/vpn have invalid types")
    routing = data.get("routing", {})
    if routing is None:
        routing = {}
    if not isinstance(routing, dict):
        return fail(f"bad {CONFIG_FILE.name}: routing must be an object")
    known_providers = set(providers)
    for route in routes:
        if not isinstance(route.get("provider"), str):
            return fail(f"bad {CONFIG_FILE.name}: every route needs a provider")
        # F3: an unknown provider must be rejected at load, never silently
        # dropped, or matching domains would fall through to direct.
        if route["provider"] not in known_providers:
            return fail(
                f"bad {CONFIG_FILE.name}: route '{route.get('id', '<unnamed>')}' "
                f"references unknown provider '{route['provider']}'"
            )
        for key in ("domains", "ip_cidr"):
            if key in route and (not isinstance(route[key], list) or not all(isinstance(v, str) for v in route[key])):
                return fail(f"bad {CONFIG_FILE.name}: route '{route.get('id', '<unnamed>')}' {key} must be a string list")
    for name, entry in providers.items():
        probe_route_id = entry.get("probe_route_id")
        if probe_route_id is None:
            continue
        if not isinstance(probe_route_id, str) or not probe_route_id.strip():
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' probe_route_id must be a non-empty route id"
            )
        matches = [route for route in routes if route.get("id") == probe_route_id]
        if len(matches) != 1:
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' probe_route_id '{probe_route_id}' "
                "must name exactly one route"
            )
        probe_route = matches[0]
        if probe_route.get("provider") != name:
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' probe_route_id '{probe_route_id}' "
                "must reference a route owned by that provider"
            )
        if not probe_route.get("domains"):
            return fail(
                f"bad {CONFIG_FILE.name}: provider '{name}' probe_route_id '{probe_route_id}' "
                "must reference a route with domains"
            )
    # Routing modes (safe-list / vpn-list): validated eagerly so a malformed
    # section fails load with a precise message, never a silent guess. Shared
    # with the `routing` CLI writer so both paths enforce the same rules.
    routing_error = _routing_error(routing, known_providers)
    if routing_error is not None:
        return fail(f"bad {CONFIG_FILE.name}: {routing_error}")
    try:
        _load_error_policy(data, providers)
        _load_rotation_settings(data)
        autodetect = _load_autodetect(data, routes, providers)
    except ValueError as exc:
        return fail(f"bad {CONFIG_FILE.name}: {exc}")
    _load_egress_settings(data)
    _port = port
    _providers = providers
    _routes = routes
    _vpn = vpn
    _routing = dict(routing)
    _autodetect = autodetect
    return 0


def write_default_config(force: bool = False) -> int:
    if CONFIG_FILE.is_file() and not force:
        return fail(f"{CONFIG_FILE.name} already exists; use 'init --force' to overwrite")
    example = ROOT / "router.example.json"
    if example.is_file():
        data = json.loads(example.read_text())
    else:
        data = {
            "port": DEFAULT_PORT,
            "providers": {
                "primary-vpn": {"directory": "providers/primary-vpn", "cooldown_seconds": 60,
                                "fallback_providers": ["fallback-vpn"],
                                "probe_route_id": "opencode-zen"},
                "fallback-vpn": {"directory": "providers/fallback-vpn", "cooldown_seconds": 60,
                                 "error_policy": {"429": {"action": "cooldown", "seconds": 300}}},
            },
            "routes": [
                {
                    "id": "opencode-zen",
                    "domains": ["opencode.ai"],
                    "provider": "primary-vpn",
                },
                {
                    "id": "egress-ip-check",
                    "domains": ["whatismyip.com"],
                    "provider": "primary-vpn",
                },
                {
                    "id": "roblox",
                    "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"],
                    "provider": "fallback-vpn",
                },
            ],
            # vpn-list activates the domains represented by the bundled route
            # table; anything outside this list remains direct.
            "routing": {
                "mode": "vpn-list",
                "vpn_domains": [
                    "opencode.ai", "whatismyip.com",
                    "roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com",
                ],
            },
            "vpn": {
                "default_mode": "tun",
                # Domain-based selective TUN is the default so ordinary apps
                # (including Hermes) use the configured route table directly.
                "capture": "routes",
                "address": DEFAULT_TUN_ADDRESS,
                "mtu": DEFAULT_TUN_MTU,
                "stack": DEFAULT_TUN_STACK,
                "dns_transport": "udp",
                "selective": "roblox",
                "network_auto": False,
                "network_presets": {
                    "MySchoolWiFi": "school-warp",
                    "MyHomeWiFi": "default",
                },
            },
            "egress": {
                "probe_url": DEFAULT_PROBE_URL,
                "probe_timeout": 8,
                "probe_user_agent": "opencode/1.18.18",
                "probe_settle_seconds": 60,
                "block_seconds": 3600,
                "upstream_cooldown_seconds": 300,
                "fail_threshold": 2,
                "slow_latency_ms": 1200,
                "ok_window": 86400,
            },
            "autodetect": {
                "enabled": False,
                "interval_seconds": 300,
                "timeout_seconds": 12,
                "sources": {},
            },
            # Scheduled rotation: churn the active exits every 2h (with
            # ±150s jitter) so upstream rate limits see a fresh egress IP.
            "rotation": {"interval_seconds": 7200, "jitter_seconds": 300, "policy": "latency"},
            "keepalive": {
                "preset": "balanced",
                "enabled": True,
                "interval": 15,
                "max_backoff": 300,
                "probe_every": 4,
                "dead_strikes": 2,
                "storm_window": 600,
                "max_rotations": 2,
                "sweep_every": 1800,
            },
            "error_policy": {
                "default": {"action": "cooldown", "seconds": 300},
                "429": {"action": "exhaust", "seconds": 900},
                "503": {"action": "cooldown", "seconds": 120},
                "timeout": {"action": "cooldown", "seconds": 60},
                "tls": {"action": "cooldown", "seconds": 300},
                "connection": {"action": "cooldown", "seconds": 300},
                "1010": {"action": "block", "seconds": 3600},
                "403": {"action": "block", "seconds": 3600},
            },
        }
    _atomic_write(CONFIG_FILE, json.dumps(data, indent=2) + "\n", 0o600)
    print(f"wrote {CONFIG_FILE}")
    return 0


# ---------------------------------------------------------------------------
# provider pools
# ---------------------------------------------------------------------------

def provider_dir(name: str) -> Path:
    entry = _providers.get(name, {})
    if not isinstance(entry, dict):
        raise ValueError(f"provider '{name}' entry must be an object")
    configured = entry.get("directory", f"providers/{name}")
    if not isinstance(configured, str):
        raise ValueError(f"provider '{name}' directory must be a string")
    path = (ROOT / configured).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"provider '{name}' directory escapes the router root") from exc
    return path


def provider_files(name: str) -> list[Path]:
    return sorted(provider_dir(name).glob("*.conf"))


def is_cooled_down(name: str, profile: Path) -> bool:
    path = ROOT / "state" / "cooldowns" / name / f"{profile.stem}.until"
    if not path.is_file():
        return False
    try:
        return int(path.read_text().strip()) > int(time.time())
    except ValueError:
        return False
    except OSError:
        # An unreadable marker (root keepalive wrote it 0600 without a
        # SUDO_UID hand-back) must not crash the user-level CLI: with no
        # readable marker the lane is treated as not cooled.
        return False


def mark_cooldown(name: str, profile: Path, seconds: int) -> None:
    path = ROOT / "state" / "cooldowns" / name / f"{profile.stem}.until"
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, f"{int(time.time()) + seconds}\n", 0o600)
    # Elevated (root) rotations write these markers; the user-level
    # keepalive/CLI must stay able to read and re-write them.
    _hand_back_ownership(path.parent)


# ---------------------------------------------------------------------------
# egress health per profile
# ---------------------------------------------------------------------------

def egress_settings() -> dict:
    """Effective egress-tuning settings (router.json top-level ``egress``
    merged over module defaults). Rotation consults these to avoid
    known-blocked/slow exits without hardcoding thresholds."""
    return _egress_settings or DEFAULT_EGRESS_SETTINGS


def _parse_error_policy(supplied) -> dict:
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


def _load_error_policy(data: dict, providers: dict) -> None:
    """Store the validated top-level ``error_policy`` table and each provider's
    ``providers.<name>.error_policy`` override. Raises ValueError on malformed
    entries; load_config turns that into a hard config failure so a policy
    mistake can never silently change rotation behavior."""
    global _error_policy
    _error_policy = _parse_error_policy(data.get("error_policy") if isinstance(data, dict) else None)
    for name, entry in providers.items():
        if isinstance(entry, dict) and "error_policy" in entry:
            entry["error_policy"] = _parse_error_policy(entry["error_policy"])


def error_policy_for(name: str) -> dict:
    """Effective error-policy table for provider ``name``.

    Merge precedence (closest scope wins): ``providers.<name>.error_policy``
    beats the top-level ``error_policy`` beats the built-in defaults in
    DEFAULT_ERROR_POLICY. Returns a fresh independent table each call so
    callers can never mutate module state."""
    policy = {key: dict(entry) for key, entry in DEFAULT_ERROR_POLICY.items()}
    for scope in (_error_policy, _provider_error_policy(name)):
        if not isinstance(scope, dict):
            continue
        for key, entry in scope.items():
            if isinstance(entry, dict):
                policy[key] = dict(entry)
    return policy


def _provider_error_policy(name: str) -> dict | None:
    """Per-provider ``error_policy`` override (None when unset)."""
    entry = _providers.get(name) if isinstance(_providers, dict) else None
    if not isinstance(entry, dict):
        return None
    supplied = entry.get("error_policy")
    return supplied if isinstance(supplied, dict) else None


def _normalize_reason(reason) -> str:
    """Map a failure reason string to the policy key it governs: HTTP status
    codes (1010/403/429/503) and transport classes (tls/connection/timeout).
    Unrecognized reasons keep their slugified text so exact-match overrides
    still work; empty/unknown reasons fall back to ``default``."""
    text = str(reason or "").lower()
    for code in ("1010", "403", "429", "503"):
        if re.search(rf"\b{code}\b", text):
            return code
    if any(token in text for token in ("tls", "ssl", "handshake", "certificate")):
        return "tls"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if any(token in text for token in ("connection", "refused", "reset", "unreachable", "eof")):
        return "connection"
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return slug or "default"


def policy_action(name: str, reason) -> tuple[str, int]:
    """(action, seconds) for a failure ``reason`` under provider ``name``'s
    effective policy: normalized reason key, then ``default``, then the
    built-in cooldown 300s fallback."""
    policy = error_policy_for(name)
    entry = policy.get(_normalize_reason(reason))
    if entry is None:
        entry = policy.get("default") or dict(DEFAULT_ERROR_POLICY["default"])
    return entry["action"], int(entry["seconds"])


def _iso_ts(epoch: int) -> str:
    """ISO-8601 UTC timestamp for machine-readable egress markers."""
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


# --- Issue #64: validated probe/monitor targets ------------------------------
# The egress probe rides the local proxy by design, but its target URL is still
# configuration, and a hostile router.json (imported config, tampered state)
# must not aim probes at loopback/LAN/link-local/metadata endpoints. These
# checks mirror monitor.py so both files share one trust model; the explicit
# opt-out environment variable is honored identically.
PRIVATE_TARGET_BYPASS_ENV = "PROXY_ROUTER_ALLOW_PRIVATE_TARGETS"
_METADATA_HOSTNAMES = {"metadata", "metadata.google.internal"}
_METADATA_ADDRESSES = {"169.254.169.254", "fd00:ec2::254"}


def _probe_addr_is_private(addr: str) -> bool:
    """True for loopback / private / link-local / reserved / multicast IPs."""
    try:
        parsed_ip = ipaddress.ip_address(str(addr))
    except ValueError:
        return True  # cannot prove it public -> treat as private (fail closed)
    return (
        parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local
        or parsed_ip.is_reserved or parsed_ip.is_multicast or parsed_ip.is_unspecified
    )


def unsafe_probe_target(url, *, resolved_addresses=None) -> str | None:
    """Return why ``url`` is an unsafe probe target, or None when allowed.

    http/https only, no credentials, no literal or resolved loopback/LAN/
    link-local/metadata targets unless PROXY_ROUTER_ALLOW_PRIVATE_TARGETS is
    set to 1/true/yes (the documented explicit opt-in). ``resolved_addresses``
    carries connection-time DNS answers so a rebinding resolution that turns a
    public name into 127.0.0.1/169.254.169.254 is still caught.
    """
    if os.environ.get(PRIVATE_TARGET_BYPASS_ENV, "").strip().lower() in {"1", "true", "yes"}:
        if isinstance(url, str):
            try:
                parsed_env = urllib.parse.urlsplit(url)
                if parsed_env.scheme in ("http", "https") and parsed_env.hostname:
                    return None
            except ValueError:
                pass
        return "scheme must be http/https with a hostname"
    if not isinstance(url, str):
        return "target must be a string URL"
    try:
        parsed_url = urllib.parse.urlsplit(url)
    except ValueError:
        return "unparseable URL"
    if parsed_url.scheme not in ("http", "https"):
        return f"scheme {parsed_url.scheme!r} must be http/https"
    host = parsed_url.hostname
    if not host:
        return "missing hostname"
    if parsed_url.username is not None or parsed_url.password is not None:
        return "credentials in URL are not allowed"
    bare = host.rstrip(".").lower()
    if bare in _METADATA_HOSTNAMES:
        return f"{bare} is a metadata endpoint"
    if bare == "localhost" or bare.endswith(".localhost") or bare.endswith(".local"):
        # Names that can only ever mean this machine / the LAN segment.
        return f"{bare} is a private/loopback/metadata target"
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        if _probe_addr_is_private(bare):
            return f"{bare} is a private/loopback/metadata target"
    for addr in resolved_addresses or ():
        text = str(addr).strip("[]").lower()
        if text in _METADATA_ADDRESSES:
            return "resolved to a metadata endpoint"
        if _probe_addr_is_private(text):
            return f"resolved to private/loopback address {addr}"
    return None


def resolve_target_addresses(url: str) -> list[str]:
    """Best-effort resolution of ``url``'s hostname (empty list on any error).

    Connection-time companion to :func:`unsafe_probe_target`: validating what
    the name resolves to right before dialing closes the DNS-rebinding window
    a config-time-only check leaves open.
    """
    try:
        host = urllib.parse.urlsplit(str(url)).hostname
        if not host:
            return []
        infos = socket.getaddrinfo(host, None)
        addresses: list[str] = []
        for info in infos:
            addr = str(info[4][0]).strip("[]")
            if addr not in addresses:
                addresses.append(addr)
        return addresses[:8]
    except Exception:  # noqa: BLE001 - best-effort: no addresses on any failure
        return []


def _transport_reason(error_text) -> str:
    """Classify a transport-level probe failure (no HTTP status) into a policy
    reason: TLS/SSL/handshake/certificate errors are ``tls``, everything else
    (dial/connect/reset/read) is ``connection``."""
    text = str(error_text or "").lower()
    if any(token in text for token in ("tls", "ssl", "handshake", "certificate", "eof", "alert")):
        return "tls"
    return "connection"


def _load_egress_settings(data: dict) -> None:
    """Merge router.json's optional top-level ``egress`` dict over defaults
    with the same bounded leniency monitor.py applies to its settings."""
    global _egress_settings
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
    _egress_settings = settings


def _load_rotation_settings(data: dict) -> None:
    """Merge router.json's optional top-level ``rotation`` dict; raises
    ValueError on invalid values so load_config rejects the config."""
    global _rotation
    supplied = data.get("rotation") if isinstance(data, dict) else None
    interval = DEFAULT_ROTATION_SETTINGS["interval_seconds"]
    jitter = DEFAULT_ROTATION_SETTINGS["jitter_seconds"]
    policy = DEFAULT_ROTATION_SETTINGS["policy"]
    if isinstance(supplied, dict):
        interval = int(supplied.get("interval_seconds", interval))
        jitter = int(supplied.get("jitter_seconds", jitter))
        policy = supplied.get("policy", policy)
    if interval < 0 or jitter < 0:
        raise ValueError("rotation interval_seconds/jitter_seconds must be >= 0")
    if policy not in ("latency", "least-recent"):
        raise ValueError("rotation policy must be 'latency' or 'least-recent'")
    _rotation = {"interval_seconds": interval, "jitter_seconds": jitter, "policy": policy}


def egress_record_path(name: str, profile: Path) -> Path:
    """state/egress/<provider>/<profile>.json with a path-traversal guard."""
    stem = profile.stem
    if not _PROVIDER_NAME.fullmatch(stem):
        raise ValueError(f"profile name '{stem}' is invalid")
    return ROOT / "state" / "egress" / name / f"{stem}.json"


def read_egress(name: str, profile: Path) -> dict:
    path = egress_record_path(name, profile)
    if not path.is_file():
        return {}
    try:
        record = json.loads(path.read_text())
        return record if isinstance(record, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def write_egress(name: str, profile: Path, record: dict) -> None:
    path = egress_record_path(name, profile)
    _atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + "\n", 0o600)
    _hand_back_ownership(path)
    _hand_back_ownership(path.parent)


def record_egress(name: str, profile: Path, *, ok: bool, latency_ms: float | None = None,
                  status: int | None = None, error: str | None = None,
                  dns_ok: bool | None = None, target: str | None = None) -> dict:
    """Merge one probe outcome into the profile's egress record. A passing
    probe clears the fail streak and any blocked marker; a failure bumps the
    streak so rotation deprioritizes the exit. ``dns_ok`` (True/False from the
    tunnel-DNS companion check) is persisted when it could be determined."""
    record = read_egress(name, profile)
    now = int(time.time())
    # Keep TLS evidence separate from generic failures: a profile can have
    # historical HTTP errors without those counting as transport death. Scope
    # the streak to the exact target so different routed services cannot poison
    # one another. Store only a digest; probe URLs may contain sensitive paths.
    target_key = hashlib.sha256(target.encode()).hexdigest() if target else None
    tls_failure = not ok and status is None and _transport_reason(error) == "tls"
    record["tls_fails"] = (
        (int(record.get("tls_fails") or 0)
         if record.get("tls_target") == target_key else 0) + 1
        if tls_failure and target_key else 0
    )
    record["tls_target"] = target_key
    record["ok"] = bool(ok)
    record["checked_at"] = now
    if ok:
        record["fails"] = 0
        record["last_ok_at"] = now
        record["latency_ms"] = round(float(latency_ms), 2) if latency_ms is not None else None
        record["status"] = status
        record["error"] = None
        record["blocked"] = False
        record["block_reason"] = None
        record["blocked_at"] = None
        record["blocked_until"] = None
        record["exhausted"] = False
        record["exhausted_at"] = None
        record["exhausted_until"] = None
        # A passing probe heals a stale upstream_error marker (e.g. a 429
        # from `rotate --reason` hours ago): the exit recovered, so the
        # tray must stop warning/disable it.
        record["upstream_error"] = None
        record["upstream_error_at"] = None
    else:
        record["fails"] = int(record.get("fails") or 0) + 1
        record["latency_ms"] = None
        record["status"] = status
        record["error"] = error or record.get("error")
    if dns_ok is not None:
        record["dns_ok"] = bool(dns_ok)
    write_egress(name, profile, record)
    return record


def clear_blocked(name: str, profile: Path) -> None:
    """Drop a blocked marker (rotate --force, or a fresh passing probe)."""
    record = read_egress(name, profile)
    if not record:
        return
    record["blocked"] = False
    record["block_reason"] = None
    record["blocked_at"] = None
    record["blocked_until"] = None
    write_egress(name, profile, record)


def mark_blocked(name: str, profile: Path, reason: str, seconds: int | None = None) -> dict:
    """Persist a blocked-exit marker (Cloudflare 1010/403 egress-IP
    reputation block) so rotation skips the profile until the marker expires
    or an explicit rotate --force."""
    seconds = int(seconds) if seconds is not None else int(egress_settings()["block_seconds"])
    now = int(time.time())
    record = read_egress(name, profile)
    record["blocked"] = True
    record["block_reason"] = str(reason)
    record["blocked_at"] = now
    record["blocked_until"] = now + max(0, seconds)
    write_egress(name, profile, record)
    return record


def egress_is_blocked(name: str, profile: Path, now: int | None = None) -> bool:
    record = read_egress(name, profile)
    if not record.get("blocked"):
        return False
    until = record.get("blocked_until")
    if until is None:
        return True  # no expiry recorded: blocked until cleared
    return (now if now is not None else int(time.time())) < int(until)


def _is_block_reason(reason: str) -> bool:
    """True when an upstream failure reason describes an egress-IP reputation
    block (Cloudflare 1010/403) rather than a transient error."""
    text = str(reason).lower()
    return "1010" in text or "403" in text or "blocked" in text or "cloudflare" in text


def _egress_error_text(exc: Exception) -> str:
    text = str(exc)
    text = re.sub(r"https?://[^\s'\"]+", "[REDACTED_URL]", text)
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _fallback_state_path(name: str) -> Path:
    """Return the private runtime marker for a provider failover."""
    return ROOT / "state" / "fallback" / f"{name}.json"


def fallback_chain(name: str) -> list[str]:
    """Return the normalized ordered fallback chain for ``name``.

    Accepts the legacy ``fallback_provider`` (a single name or an ordered
    list) and the ``fallback_providers`` list, drops self-references,
    unknown providers, and duplicate names (first occurrence wins).
    """
    entry = _providers.get(name)
    if not isinstance(entry, dict):
        return []
    raw = entry.get("fallback_providers")
    if raw is None:
        raw = entry.get("fallback_provider")
    if raw is None:
        raw = []
    items = raw if isinstance(raw, list) else [raw]
    seen: set[str] = set()
    chain: list[str] = []
    for target in items:
        if not isinstance(target, str) or target == name or target not in _providers or target in seen:
            continue
        seen.add(target)
        chain.append(target)
    if entry.get("fail_open_direct") is True:
        chain.append("direct")
    return chain


def configured_fallbacks(name: str) -> list[str]:
    """Return the ordered configured fallback providers for ``name``.

    ``fallback_provider`` is retained as a compatibility alias for existing
    router.json files; new configurations should use ``fallback_providers``.
    """
    return fallback_chain(name)


def configured_fallback(name: str) -> str | None:
    """Return the first configured fallback provider for ``name``."""
    targets = configured_fallbacks(name)
    return targets[0] if targets else None


def active_fallback(name: str) -> str | None:
    """Return the active runtime fallback, ignoring stale/invalid markers."""
    targets = configured_fallbacks(name)
    if not targets:
        return None
    try:
        data = json.loads(_fallback_state_path(name).read_text())
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    active = data.get("provider") if isinstance(data, dict) else None
    if active == "direct" and current_mode() != "proxy":
        return None
    return active if active in targets else None


def _effective_route_provider(name: str) -> str:
    """Map a route through every active fallback until the live provider."""
    current = name
    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        target = active_fallback(current)
        if target is None:
            return current
        current = target
    # Validation rejects cycles, but fail closed if a stale runtime marker
    # somehow creates one instead of looping or silently routing direct.
    return current


def activate_fallback(name: str, *, target: str | None = None, reason: str = "transport",
                      automatic: bool = False) -> int:
    """Activate one provider from ``name``'s ordered fallback chain.

    With no explicit target, candidates are attempted in configured order. A
    candidate with no valid profiles is skipped; a failed hard switch rolls its
    marker/configuration back before the next candidate is tried.
    """
    if automatic and not _automatic_proxy_mode():
        return 3
    if name not in _providers:
        return fail(f"unknown provider '{name}'")
    configured = configured_fallbacks(name)
    if target is not None and target not in configured:
        return fail(
            f"provider '{name}' fallback target '{target}' is not configured "
            f"(choose one of: {', '.join(configured) or 'none'})"
        )
    active = active_fallback(name)
    if active is not None and (target is None or target == active):
        print(f"fallback already active: {name} -> {active}")
        return 0
    candidates = [target] if target is not None else configured
    if not candidates:
        return fail(f"provider '{name}' has no configured fallback providers")
    path = _fallback_state_path(name)
    previous = path.read_text() if path.is_file() else None
    last_error = "no fallback candidate has a valid profile"
    for candidate in candidates:
        if candidate == "direct" and current_mode() != "proxy":
            continue
        # Proxy-backed candidates have a SOCKS5 upstream instead of *.conf
        # files; WireGuard candidates need at least one parseable profile.
        if candidate != "direct" and not provider_has_valid_exit(candidate):
            print(f"router: skipping fallback '{candidate}': no valid exit "
                  "(no parseable profile or bad socks5 upstream)", file=sys.stderr)
            continue
        _atomic_write(path, json.dumps({
            "provider": candidate,
            "reason": str(reason),
            "activated_at": int(time.time()),
        }, sort_keys=True) + "\n", 0o600)
        rc = engine_reload()
        if rc == 0:
            print(f"fallback active: {name} -> {candidate} ({reason})")
            return 0
        last_error = f"fallback '{candidate}' failed to start"
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, previous, 0o600)
    return fail(f"provider '{name}': {last_error}")


def recover_route(name: str, host: str) -> int:
    """Confirm a stalled route, then try configured alternatives and opt-in direct."""
    if MANUAL_OFF_FILE.exists() or not _automatic_proxy_mode():
        return 3
    if name not in _providers or response_provider_for_host(host) != name:
        return fail("recovery target does not belong to the configured provider")
    if not _diagnostic_host_is_routed(host):
        return 3
    routing = routing_state()
    if routing["mode"] == "vpn-list" and not any(
            _response_host_matches(host, domain) for domain in routing["vpn_domains"]):
        return 3
    url = f"https://{host}/"
    if urllib.parse.urlsplit(url).hostname != host or unsafe_probe_target(url):
        return fail("unsafe recovery target")
    # Ignore old log bursts after a recent recovery; one provider owns the budget.
    marker = ROOT / "state" / "recovery" / f"{name}.json"
    now = time.time()
    try:
        if now - float(json.loads(marker.read_text())["attempted_at"]) < RECOVERY_COOLDOWN_SECONDS:
            return 3
    except (OSError, ValueError, KeyError, TypeError):
        pass
    def reachable() -> bool:
        result = probe_egress(url=url, timeout=3.0)
        status = result.get("status")
        return isinstance(status, int) and 100 <= status < 600
    # Require a fresh confirmation and positive DNS, not merely old error lines.
    if reachable():
        return 0
    if egress_dns_probe(host, timeout=2.0) is not True:
        return fail("recovery deferred: direct DNS is unavailable or unknown")
    _atomic_write(marker, json.dumps({"attempted_at": now}) + "\n", 0o600)
    original = _fallback_state_path(name)
    previous = original.read_text() if original.is_file() else None
    active = active_fallback(name)
    # Try at most two VPN alternatives per attempt, keeping direct last.
    configured = configured_fallbacks(name)
    candidates = [item for item in configured if item != "direct" and item != active][:2]
    if not configured:
        rc = rotate(name, reason="timeout", automatic=True)
        return 0 if rc == 0 and reachable() else 1
    if "direct" in configured and active != "direct":
        candidates.append("direct")
    for candidate in candidates:
        if MANUAL_OFF_FILE.exists() or not _automatic_proxy_mode():
            return 3
        rc = activate_fallback(name, target=candidate, reason="confirmed-stall", automatic=True)
        if rc == 0 and reachable():
            print(f"route recovered: {name} -> {candidate}")
            return 0
        if rc == 0 and candidate == "direct":
            print(f"direct fallback active for {name}; {host} remains unreachable", file=sys.stderr)
            return 1
    # No working replacement: restore the previous policy rather than leave a
    # failed candidate selected while reporting an unsuccessful recovery.
    if previous is None:
        original.unlink(missing_ok=True)
    else:
        _atomic_write(original, previous, 0o600)
    if candidates and not MANUAL_OFF_FILE.exists():
        engine_reload()
    return fail(f"no working fallback for '{name}'")


def restore_fallback(name: str, host: str) -> int:
    """Probe a primary provider and remove a direct fallback after two wins.

    Direct fallback remains the serving path while the primary is checked. A
    failed check immediately reinstates direct routing; a single successful
    check is retained as evidence and the second consecutive success commits
    the return to the VPN. Attempts are cooldown-limited to prevent flapping.
    """
    if MANUAL_OFF_FILE.exists() or not _automatic_proxy_mode():
        return 3
    if name not in _providers or response_provider_for_host(host) != name:
        return 3
    if not _diagnostic_host_is_routed(host):
        return 3
    routing = routing_state()
    if routing["mode"] == "vpn-list" and not any(
            _response_host_matches(host, domain) for domain in routing["vpn_domains"]):
        return 3
    url = f"https://{host}/"
    if urllib.parse.urlsplit(url).hostname != host or unsafe_probe_target(url):
        return fail("unsafe restore target")
    if active_fallback(name) != "direct":
        return 3
    marker = ROOT / "state" / "recovery" / f"{name}-restore.json"
    now = time.time()
    previous: dict = {}
    try:
        loaded = json.loads(marker.read_text())
        if isinstance(loaded, dict):
            previous = loaded
        if now - float(previous.get("attempted_at", 0)) < RESTORE_COOLDOWN_SECONDS:
            return 3
    except (OSError, ValueError, TypeError):
        previous = {}
    try:
        successes = max(0, int(previous.get("successes", 0) or 0))
    except (TypeError, ValueError):
        successes = 0
    # Temporarily restore the primary so this probe cannot accidentally measure
    # the already-selected direct path.
    rc = deactivate_fallback(name, automatic=True)
    if rc != 0:
        return rc
    result = probe_egress(url=url, timeout=3.0)
    status = result.get("status") if isinstance(result, dict) else None
    healthy = isinstance(status, int) and 100 <= status < 600
    if healthy:
        successes += 1
        if successes >= RESTORE_SUCCESS_THRESHOLD:
            marker.unlink(missing_ok=True)
            print(f"primary restored: {name} after {successes} successful checks")
            return 0
        _atomic_write(marker, json.dumps({
            "attempted_at": now, "host": host, "successes": successes,
        }, sort_keys=True) + "\n", 0o600)
        if activate_fallback(name, target="direct", reason="restore-pending", automatic=True) == 0:
            print(f"primary check passed for {name}; awaiting one more check")
            return 1
        return fail(f"provider '{name}' restore pending but direct fallback could not be reinstated")
    # Keep service available through direct while the VPN is still unhealthy.
    _atomic_write(marker, json.dumps({
        "attempted_at": now, "host": host, "successes": 0,
    }, sort_keys=True) + "\n", 0o600)
    if activate_fallback(name, target="direct", reason="primary-unhealthy", automatic=True) != 0:
        return fail(f"provider '{name}' primary is still unhealthy and direct fallback failed")
    print(f"primary still unhealthy: {name}; direct fallback retained", file=sys.stderr)
    return 1


def deactivate_fallback(name: str, *, automatic: bool = False) -> int:
    """Restore primary routing for ``name`` with one in-place reload."""
    if automatic and not _automatic_proxy_mode():
        return 3
    if name not in _providers:
        return fail(f"unknown provider '{name}'")
    path = _fallback_state_path(name)
    if not path.is_file():
        print(f"fallback inactive: {name}")
        return 0
    previous = path.read_text()
    path.unlink(missing_ok=True)
    rc = engine_reload()
    if rc != 0:
        _atomic_write(path, previous, 0o600)
        return rc
    print(f"fallback cleared: {name}")
    return 0


def fallback_status(name: str) -> dict:
    """Return configured and active fallback state for status/CLI consumers."""
    return {
        "configured": configured_fallbacks(name),
        "active": active_fallback(name),
    }


def _response_host_matches(host: str, domain: str) -> bool:
    """Match a response-observer host without allowing suffix lookalikes."""
    host = str(host or "").strip().lower().rstrip(".")
    domain = str(domain or "").lstrip("*.").strip().lower().rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


def response_provider_for_host(host: str) -> str | None:
    """Return the configured route provider responsible for ``host``."""
    for route in _routes:
        provider = route.get("provider")
        if not isinstance(provider, str):
            continue
        for domain in route.get("domains", []):
            if _response_host_matches(host, domain):
                return provider
    return None


def _response_event_marker(provider: str) -> Path:
    return ROOT / "state" / "response-events" / f"{provider}.json"


# Real-traffic stall reasons accepted by response-event --reason. These are
# the failures small egress probes cannot see: an exit that answers probes
# yet throttles long streams. Each flows through the error-policy table
# (_normalize_reason) into cooldown/rotate/fallback like 429 does.
STALL_REASONS = ("timeout", "tls", "connection")


def response_event(host: str, status: int, *, provider: str | None = None,
                   reason: str | None = None,
                   dedupe_seconds: int = 5) -> int:
    """Handle a response-aware proxy event and rotate the effective route.

    Two event kinds can mutate provider state for a configured routed host:
    HTTP 429 responses, and explicit stall reports (``--reason
    timeout|tls|connection``) for traffic that connected but never produced
    a usable response. The caller owns request replay; this command only
    performs the hard switch/fallback transaction.
    """
    try:
        status = int(status)
    except (TypeError, ValueError):
        return fail("response-event: status must be an integer")
    label: str | None = None
    if status == 429:
        label, reason = "HTTP 429", "429"
    elif reason is not None:
        reason = str(reason).strip().lower()
        if reason not in STALL_REASONS:
            return fail(
                "response-event: unknown reason "
                f"'{reason}' (expected HTTP 429 status or --reason "
                f"{'|'.join(STALL_REASONS)})"
            )
        label = reason
    else:
        print(f"response-event: ignored HTTP {status} for {host}")
        return 0
    route_provider = response_provider_for_host(host)
    if route_provider is None:
        return fail(f"response-event: host '{host}' is not routed")
    if provider is not None and provider != route_provider:
        return fail(f"response-event: host '{host}' routes through '{route_provider}', not '{provider}'")

    marker = _response_event_marker(route_provider)
    now = int(time.time())
    try:
        previous = json.loads(marker.read_text()) if marker.exists() else {}
        last_at = int(previous.get("at", 0))
    except (OSError, ValueError, TypeError):
        last_at = 0
    if dedupe_seconds > 0 and now - last_at < dedupe_seconds:
        print(f"response-event: suppressed duplicate {label} for {host}")
        return 0
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"at": now, "host": str(host).lower(), "status": status, "reason": reason}) + "\n")
    try:
        marker.chmod(0o600)
    except OSError:
        pass

    effective = active_fallback(route_provider) or route_provider
    print(f"response-event: {label} for {host}; rotating {effective}")
    rc = rotate(effective, reason=reason)
    if rc == 0:
        return 0
    if effective != route_provider:
        return rc
    return activate_fallback(route_provider, reason=reason)


def autodetect_source(source: str = "twitch", *, reload: bool = True,
                      quiet: bool = False) -> int:
    """Discover routed dependency hosts from one configured HTTPS seed page."""
    if not _autodetect.get("enabled"):
        return 0 if quiet else fail("autodetection is disabled")
    settings = (_autodetect.get("sources") or {}).get(source)
    if not isinstance(settings, dict):
        return 0 if quiet else fail(f"autodetection source '{source}' is not configured")
    proxy = f"http://127.0.0.1:{_port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    request = urllib.request.Request(
        settings["seed"],
        headers={"Accept-Encoding": "identity", "User-Agent": "proxy-router-autodetect/1.0"},
    )
    try:
        with opener.open(request, timeout=float(_autodetect.get("timeout_seconds", 12))) as response:
            document = response.read(4 * 1024 * 1024 + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        if not quiet:
            print(f"router: autodetect {source}: seed fetch failed: {exc}", file=sys.stderr)
        return 1
    if len(document) > 4 * 1024 * 1024:
        if not quiet:
            print(f"router: autodetect {source}: seed response is too large", file=sys.stderr)
        return 1
    text = document.decode("utf-8", "replace")
    hosts = domain_autodetect.extract_related_hosts(text, settings["roots"])
    if not hosts:
        if not quiet:
            print(f"router: autodetect {source}: no trusted dependency hosts found", file=sys.stderr)
        return 1
    before = _read_autodetect_state(source)
    now = int(time.time())
    before_domains = set(domain_autodetect.active_domains(before, now=now))
    state, _ = domain_autodetect.merge_state(
        before, hosts, now=now, ttl_seconds=settings["ttl_seconds"]
    )
    state.update({
        "source": source,
        "route_id": settings["route_id"],
        "provider": settings["provider"],
        "seed": settings["seed"],
        "roots": settings["roots"],
        "ttl_seconds": settings["ttl_seconds"],
    })
    state_changed = state != before
    route_changed = before_domains != set(domain_autodetect.active_domains(state, now=now))
    if state_changed:
        _atomic_write(_autodetect_state_path(source), json.dumps(state, indent=2) + "\n", 0o600)
    reload_rc = 0
    if route_changed and reload:
        reload_rc = engine_reload()
    result = {
        "source": source,
        "changed": route_changed,
        "state_changed": state_changed,
        "domains": domain_autodetect.active_domains(state, now=now),
        "reload_rc": reload_rc,
        "updated_at": state.get("updated_at"),
    }
    if not quiet:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if reload_rc == 0 else 1


def _open_probe(opener, request, timeout: float):
    """Open ``request`` through an opener that may be a urllib OpenerDirector
    (use .open) or a plain callable injected by tests, mirroring monitor.py."""
    open_method = getattr(opener, "open", None)
    if callable(open_method):
        return open_method(request, timeout=timeout)
    return opener(request, timeout=timeout)


# Landing pages behind Cloudflare bot management (opencode.ai) intermittently
# reset non-browser probe clients, which false-marks healthy exits dead (seen
# live: `egress check` reported "probe connection" on an exit that was serving
# real traffic at that moment). These hosts have a light, public, bot-lenient
# path the probe uses instead of the bare landing page.
_PROBE_DOMAIN_PATHS = {"opencode.ai": "/zen/v1/models"}


def probe_url_for(name: str) -> str | None:
    """Return a probe target whose host is actually routed through ``name``.

    Provider pins are convenience overrides, not proof of routing: an unrouted
    pin would measure direct egress. Safe-list direct-domain suffixes are also
    excluded, including subdomains.
    """
    routing = routing_state()
    direct = frozenset(routing.get("direct_domains") or []) \
        if routing.get("mode") == "safe-list" else frozenset()

    def matches_domain(host: str, domain: str) -> bool:
        domain = domain.lstrip("*.").strip().lower()
        return bool(domain) and (host == domain or host.endswith("." + domain))

    def is_direct(host: str) -> bool:
        return any(matches_domain(host, domain) for domain in direct)

    def is_tunneled(host: str) -> bool:
        if not host or is_direct(host):
            return False
        if routing.get("mode") == "safe-list":
            default_provider = routing.get("default_provider")
            if isinstance(default_provider, str) and _effective_route_provider(default_provider) == name:
                return True
        for route in _routes:
            if route.get("provider") != name:
                continue
            for domain in route.get("domains", []):
                route_host = domain.lstrip("*.").strip().lower()
                if not matches_domain(host, route_host):
                    continue
                if routing.get("mode") == "vpn-list":
                    vpn_domains = routing.get("vpn_domains") or []
                    if not any(matches_domain(route_host, vpn) for vpn in vpn_domains):
                        continue
                return True
        return False

    def route_probe_url(route: dict) -> str | None:
        for raw_host in route.get("domains", []):
            host = str(raw_host).lstrip("*.").strip().lower()
            if not host or "." not in host or host.startswith(".") or is_direct(host):
                continue
            if is_tunneled(host):
                return f"https://{host}{_PROBE_DOMAIN_PATHS.get(host, '')}"
        return None

    entry = _providers.get(name)
    if isinstance(entry, dict):
        probe_route_id = entry.get("probe_route_id")
        if probe_route_id is not None:
            for route in _routes:
                if route.get("id") == probe_route_id and route.get("provider") == name:
                    # An explicit route is fail-closed: do not silently fall
                    # back to another route if its target is no longer tunneled.
                    return route_probe_url(route)
            return None
        pinned = entry.get("probe_url")
        if isinstance(pinned, str) and pinned.startswith("https://"):
            host = urllib.parse.urlsplit(pinned).hostname
            if host and is_tunneled(host.lower()):
                return pinned

    if routing.get("mode") == "safe-list":
        default_provider = routing.get("default_provider")
        if isinstance(default_provider, str) and _effective_route_provider(default_provider) == name:
            default_probe = egress_settings().get("probe_url")
            host = urllib.parse.urlsplit(default_probe).hostname if isinstance(default_probe, str) else None
            if host and is_tunneled(host.lower()):
                return default_probe

    for route in _routes:
        if route.get("provider") != name:
            continue
        for host in route.get("domains", []):
            host = host.lstrip("*.").strip().lower()
            if not host or "." not in host or host.startswith(".") or is_direct(host):
                continue
            if routing.get("mode") == "vpn-list":
                vpn_domains = routing.get("vpn_domains") or []
                if not any(matches_domain(host, vpn) for vpn in vpn_domains):
                    continue
            return f"https://{host}{_PROBE_DOMAIN_PATHS.get(host, '')}"
    return None


def _classify_probe_body(status: int, text: str) -> str | None:
    """Reputation-block reason for an HTTP response body, else None."""
    if re.search(r"error\s*code\s*[:=]?\s*1010|cloudflare.{0,20}1010", text, re.IGNORECASE):
        return "cloudflare-1010"
    if (status in (403, 1010)) and "cloudflare" in text.lower():
        return "cloudflare-403"
    return None


def _probe_failure_reason(status: int, text: str) -> tuple[str | None, str | None]:
    """(error, block_reason) for a probe response. A reputation block is both
    an error and a block marker; an upstream rate limit (HTTP 429) is an error
    only — never a block (it is a transient quota signal, not an egress-IP
    reputation block, so it must route through the error-policy exhaust path,
    not mark_blocked)."""
    reason = _classify_probe_body(status, text)
    if reason is not None:
        return reason, reason
    if status == 429:
        return "rate-limit-429", None
    return None, None


def _probe_via_curl(*, port: int, url: str, timeout: float) -> dict:
    """One probe via curl: its TLS handshake survives Cloudflare bot
    management that resets python-urllib clients on fingerprint (seen live:
    `egress check` reported dead on an exit serving HTTP 200 at that moment).
    Same transport route_watcher's transparent probes already use. The
    write-out line carries the HTTP status and total time; the response body
    (first 4 KiB) feeds the reputation-block classification."""
    # Issue #64: validate at connection time, including what the name resolves
    # to right now, so imported/tampered config cannot aim curl at loopback,
    # LAN, link-local or metadata endpoints.
    violation = unsafe_probe_target(url, resolved_addresses=resolve_target_addresses(url))
    if violation is not None:
        return {"ok": False, "latency_ms": None, "status": None,
                "error": f"unsafe probe target: {violation}", "block_reason": None}
    connect = max(1.0, min(float(timeout), 4.0))
    command = [
        "curl", "--proxy", f"http://127.0.0.1:{port}", "--noproxy", "",
        "--silent", "--show-error", "--output", "-",
        "--write-out", "\n%{http_code} %{time_total}",
        "--connect-timeout", f"{connect:g}", "--max-time", f"{float(timeout):g}",
        "--user-agent", egress_settings()["probe_user_agent"],
        url,
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=float(timeout) + 2.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "latency_ms": None, "status": None,
                "error": _egress_error_text(exc), "block_reason": None}
    out = (result.stdout or b"").decode("utf-8", "replace")
    err = (result.stderr or b"").decode("utf-8", "replace")
    status, latency_ms = 0, None
    if "\n" in out:
        body, tail = out.rsplit("\n", 1)
        parts = tail.split()
        if parts and parts[0].isdigit():
            status = int(parts[0])
            if len(parts) > 1:
                try:
                    latency_ms = round(float(parts[1]) * 1000.0, 2)
                except ValueError:
                    latency_ms = None
        else:
            body = out
    else:
        body = out
    if status == 0:
        # No HTTP response: transport-level failure; curl's stderr says why
        # (exit 7 connect refused, 28 timeout, 35 SSL handshake, 56 read).
        error = f"curl({result.returncode}): {err.strip()[-200:] or 'no response'}"
        return {"ok": False, "latency_ms": None, "status": None,
                "error": error, "block_reason": None}
    error, block_reason = _probe_failure_reason(status, body[:4096])
    return {
        "ok": error is None,
        "latency_ms": latency_ms,
        "status": status,
        "error": error,
        "block_reason": block_reason,
    }


def probe_egress(*, port: int | None = None, url: str | None = None, timeout: float | None = None,
                 opener=None, clock=time.monotonic) -> dict:
    """One small HTTP GET through the router's proxy listener (the tunnel) and
    a parsed outcome: ok, latency, status, error. Prefers curl when installed
    (bot-management-resistant TLS); ``opener``/``clock`` force the legacy
    urllib path for tests and systems without curl."""
    port = port or _port
    url = url or egress_settings()["probe_url"]
    timeout = timeout if timeout is not None else egress_settings()["probe_timeout"]
    # Issue #64: connection-time validation (scheme, credentials, literal and
    # resolved private/metadata targets). Injected test openers skip the DNS
    # revalidation but still get the static checks.
    violation = unsafe_probe_target(url)
    if violation is None:
        dns_addresses = None if opener is not None else resolve_target_addresses(url)
        violation = unsafe_probe_target(url, resolved_addresses=dns_addresses)
    if violation is not None:
        return {"ok": False, "latency_ms": None, "status": None,
                "error": f"unsafe probe target: {violation}", "block_reason": None}
    if opener is None and shutil.which("curl") is not None:
        return _probe_via_curl(port=port, url=url, timeout=float(timeout))
    if opener is None:
        proxy = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    request = urllib.request.Request(
        url, headers={"User-Agent": egress_settings()["probe_user_agent"], "Accept": "*/*"}
    )
    started = clock()
    response = None
    try:
        response = _open_probe(opener, request, timeout)
        body = response.read(4096)
        latency = (clock() - started) * 1000.0
        status = int(getattr(response, "status", getattr(response, "code", 200)))
        text = body.decode("utf-8", "replace")
        error, block_reason = _probe_failure_reason(status, text)
        return {
            "ok": error is None,
            "latency_ms": round(latency, 2),
            "status": status,
            "error": error,
            "block_reason": block_reason,
        }
    except Exception as exc:  # network errors are data, never a crash
        return {
            "ok": False,
            "latency_ms": None,
            "status": None,
            "error": _egress_error_text(exc),
            "block_reason": None,
        }
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _tls_failed(record: dict) -> bool:
    """Return whether repeated TLS failures crossed the configured strike gate."""
    return int(record.get("tls_fails") or 0) >= int(egress_settings()["fail_threshold"])


def _cool_tls_failure(name: str, profile: Path, record: dict) -> None:
    """Quarantine repeated no-HTTP TLS failures using the effective TLS policy."""
    if _tls_failed(record) and not is_cooled_down(name, profile):
        _apply_upstream_failure(name, profile, "tls", 300)


def probe_profile(name: str, profile: Path, *, port: int | None = None,
                  _defer_tls_cooldown: bool = False) -> tuple[bool, dict | None]:
    """Probe egress for ``profile`` (the provider's active exit) through the
    tunnel, persist the outcome, and add a blocked marker when the probe itself
    hit a Cloudflare reputation block. Returns (ok, record); record is None
    when the provider has no routed domain to probe through."""
    url = probe_url_for(name)
    if url is None:
        return True, None
    result = probe_egress(port=port, url=url)
    dns_ok = None
    if (not result["ok"] and result["status"] is None
            and _transport_reason(result["error"]) != "tls"):
        # TLS has progressed beyond resolution, but has NOT proved HTTPS
        # works. Other connection failures still need the DNS distinction.
        host = urllib.parse.urlsplit(url).hostname or ""
        dns_ok = egress_dns_probe(host, port=port) if host else None
    record = record_egress(name, profile, ok=result["ok"], latency_ms=result["latency_ms"],
                           status=result["status"], error=result["error"], dns_ok=dns_ok,
                           target=url)
    if not _defer_tls_cooldown:
        _cool_tls_failure(name, profile, record)
    if result["block_reason"]:
        mark_blocked(name, profile, result["block_reason"])
    elif result["error"] == "rate-limit-429":
        # The probe observed an upstream rate limit (HTTP 429) on this exit
        # THROUGH the real tunnel: apply the 429 error-policy entry (exhaust
        # + cooldown by default) so rotation skips the lane until the reset —
        # exactly as a real-traffic 429 does via `rotate --reason 429`. A
        # probe 429 is direct evidence the exit's egress IP is throttled, so
        # it acts immediately (no fail_threshold wait, unlike connection
        # blips which can be transient handshake races).
        seconds = int(_providers.get(name, {}).get("cooldown_seconds", 60))
        _apply_upstream_failure(name, profile, "429", seconds)
    elif (not result["ok"] and result["status"] is None
          and not is_cooled_down(name, profile)
          and dns_ok is True
          and _transport_reason(result["error"]) != "tls"
          and int(record.get("fails") or 0) >= int(egress_settings()["fail_threshold"])):
        # Connection-level failure (dial/connect/timeout/reset — no HTTP
        # status, no TLS handshake): the tunnel path itself is broken, so the
        # exit is failed for real traffic. Cool it so rotation and
        # resolve_active avoid it instead of re-picking the same dead exit.
        # Seconds come from the effective error policy for the reason class
        # (connection; built-in default matches the merged 300s rule).
        # Multi-strike: a single transient blip must not dead-mark a healthy
        # exit; only fail_threshold (default 2) CONSECUTIVE failures cool it,
        # mirroring keepalive's dead_strikes and _egress_rank.
        # TLS-classified failures (SSL EOF / SSL_ERROR_SYSCALL / TLS alert)
        # are deliberately excluded: the TCP CONNECT already rode the tunnel,
        # so the path works and the upstream is throttling — never a cooldown.
        # TLS uses its separate target-scoped streak above, never HTTP fails.
        # dns_ok False is excluded too: resolution rides the direct path, so
        # a DNS flake never proves the tunnel dead (degraded, not dead).
        # Only a positive DNS signal permits cooldown. False means the direct
        # resolver failed; None is inconclusive. Neither proves the tunnel
        # dead, so DNS failures/flakes never trigger rotation.
        reason = _transport_reason(result["error"])
        _action, seconds = policy_action(name, reason)
        mark_cooldown(name, profile, seconds)
        print(f"router: marked {profile.stem} failed (transport/{reason}; cooldown {seconds}s)", file=sys.stderr)
    return result["ok"], record


def _probe_with_settle(name: str, profile: Path, *, port: int | None = None) -> tuple[bool, dict | None]:
    """Probe once, then quarantine repeated TLS failures after settling.

    A freshly switched WireGuard exit can briefly blackhole inner TLS, so the
    first failure is deferred through the configured settle window. Steady
    probes keep their normal multi-strike behavior; setting the window to zero
    applies the TLS threshold immediately.
    """
    try:
        settle = max(0.0, float(egress_settings().get("probe_settle_seconds", 20.0)))
    except (TypeError, ValueError):
        settle = 20.0
    ok, record = probe_profile(name, profile, port=port,
                               _defer_tls_cooldown=settle > 0)
    if ok or settle <= 0:
        return ok, record
    print(f"router: probe failed for {profile.stem}; retrying once after {settle:.0f}s settle",
          file=sys.stderr)
    # Poll the settle window instead of sleeping through it: an exit whose
    # handshake completes early is detected within one poll step instead of
    # always paying the full settle (measured worst case: 20s of dead-riding
    # traffic per failed rotation).
    poll_step = min(2.0, max(0.5, settle / 10.0))
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        time.sleep(min(poll_step, max(0.0, deadline - time.monotonic())))
        ok, record = probe_profile(name, profile, port=port,
                                   _defer_tls_cooldown=True)
        if ok:
            return ok, record
    if record is not None:
        _cool_tls_failure(name, profile, record)
    return ok, record


_DNS_ERROR_RE = re.compile(
    r"(getaddrinfo|no such host|nodename nor servname|name or service not known|"
    r"temporary failure in name resolution|could not resolve|servfail)",
    re.IGNORECASE,
)


def _dns_error_markers(text: str) -> bool:
    """True when an error string describes a failed DNS resolution rather than
    a transport/connect failure (used to classify probe failures)."""
    return bool(text) and bool(_DNS_ERROR_RE.search(text))


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


def egress_dns_probe(host: str, *, port: int | None = None, timeout: float | None = None,
                     opener=None) -> bool | None:
    """Secondary tunnel-DNS signal for the egress live check: does resolution
    of ``host`` work THROUGH the tunnel?

    - Direct-resolver baseline first: if the hostname does not resolve
      directly at all, nothing can be attributed to the tunnel (None).
    - Then a tiny proxied GET forces the engine to resolve+connect ``host``
      through the tunnel; a response proves the resolution path worked
      (True), a DNS-flavored error (getaddrinfo/no such host/...) means the
      engine's resolution path failed (False), and any other transport
      error is inconclusive (None). Resolution rides the direct path by
      design (build_singbox_config), so False signals a direct-DNS failure,
      not a dead tunnel.

    Bounded (getaddrinfo worker timeout + short request timeout), injectable
    openers for tests, no new dependencies.
    """
    timeout = timeout if timeout is not None else max(2.0, min(egress_settings()["probe_timeout"], 5.0))
    if _bounded_getaddrinfo(host, 443, min(timeout, 3.0)) is None:
        return None  # hostname itself unresolvable: not a tunnel signal
    result = probe_egress(port=port, url=f"http://{host}/", timeout=timeout, opener=opener)
    if result["ok"] or result["status"] is not None:
        return True  # a response rode the tunnel: resolution worked
    if _dns_error_markers(result["error"]):
        return False
    return None


def check_egress_live(name: str, profile: Path, *, port: int | None = None,
                      url: str | None = None) -> tuple[str, dict | None]:
    """Live check of ``profile`` (provider ``name``'s active exit) THROUGH the
    running tunnel. Returns (status, record):

    - ``alive``: the HTTPS probe got an HTTP response through the tunnel.
    - ``degraded``: an HTTP response arrived but was not ok (e.g. Cloudflare
      1010/403 reputation block or 5xx), or a TLS failure below
      ``egress.fail_threshold``. A completed HTTP response always proves
      transport, unlike CONNECT alone.
    - ``dead``: the probe failed at connection level (no HTTP status at all,
      including repeated TLS failure), i.e. this exit cannot serve the target.
      The DNS signal sharpens the reason: ``dns_ok is True`` means the later
      dial/read stage through the tunnel failed; ``dns_ok is False`` means
      resolution failed on the DIRECT DNS path (DNS is pinned direct by
      design) — the tunnel was never dialed, so the exit is ``degraded``,
      not dead. An unknown/failed direct DNS signal remains degraded; only a
      positive ``dns_ok`` signal permits the dead verdict.

    The outcome is persisted in the normal egress health record (including
    ``dns_ok`` when determined) and reputation-block reasons still raise a
    blocked marker, exactly like probe_profile.
    """
    url = url or probe_url_for(name)
    if url is None:
        return "alive", None
    probe = probe_egress(port=port, url=url)
    if not probe["ok"] and probe["status"] is None:
        # One transport-level blip (bot-managed reset, handshake race) must
        # not dead-mark an exit that may be serving real traffic: retry once,
        # briefly. A genuinely dead tunnel fails both probes.
        time.sleep(2.0)
        probe = probe_egress(port=port, url=url)
    if probe["ok"]:
        status, dns_ok = "alive", True
    elif probe["status"] is not None:
        status, dns_ok = "degraded", True  # HTTP response rode the tunnel
    elif _transport_reason(probe["error"]) == "tls":
        # A single TLS handshake blip is degraded; the persisted target-scoped
        # streak below decides when repeated failures warrant failover.
        status, dns_ok = "degraded", True
    else:
        host = urllib.parse.urlsplit(url).hostname or ""
        dns_ok = egress_dns_probe(host, port=port) if host else None
        # DNS rides the DIRECT path by design (build_singbox_config), so a
        # A lookup failure or inconclusive result means the direct DNS path
        # did not prove the tunnel dead. Keep it degraded; only a positive
        # DNS signal permits the conservative dead verdict.
        status = "dead" if dns_ok is True else "degraded"

    # A successful probe is fresh evidence that this profile is usable. Clear
    # an old failure cooldown before the next config build can omit a recovered
    # endpoint (especially important for providers with one profile, such as
    # WARP).
    if status == "alive":
        _clear_cooldown(name, profile)
    record = record_egress(name, profile, ok=probe["ok"], latency_ms=probe["latency_ms"],
                           status=probe["status"], error=probe["error"], dns_ok=dns_ok,
                           target=url)
    if _tls_failed(record):
        status = "dead"
        _cool_tls_failure(name, profile, record)
    if probe["block_reason"]:
        mark_blocked(name, profile, probe["block_reason"])
    elif probe["error"] == "rate-limit-429":
        # The probe got an HTTP 429 through the real tunnel: the exit's egress
        # IP is rate-limited. Same immediate exhaust/cooldown as probe_profile
        # (and `rotate --reason 429`), so scheduled rotation and the sweep
        # skip the lane until the reset. Keepalive still sees "degraded" above
        # and never rotates on a throttle — this only steers future switches.
        seconds = int(_providers.get(name, {}).get("cooldown_seconds", 60))
        _apply_upstream_failure(name, profile, "429", seconds)
    elif (status == "dead" and not is_cooled_down(name, profile)
          and int(record.get("fails") or 0) >= int(egress_settings()["fail_threshold"])):
        # Connection-level death (no HTTP status, no TLS handshake): the exit
        # is failed for real traffic. Cool it so resolve_active/rotation stop
        # re-picking the same dead exit. Seconds come from the effective error
        # policy for the reason class (connection; built-in default is the
        # merged 300s rule). TLS-classified failures never reach here — they
        # are degraded (upstream throttle), not dead. Multi-strike: a single
        # transient blip must not dead-mark an exit that recovers; only
        # fail_threshold CONSECUTIVE dead checks cool it (keepalive's
        # dead_strikes=2 gate already rotates only on repeated deaths).
        reason = _transport_reason(probe["error"])
        _action, seconds = policy_action(name, reason)
        mark_cooldown(name, profile, seconds)
        print(f"router: marked {profile.stem} dead (cooldown {seconds}s)", file=sys.stderr)
    return status, record


def _egress_rank(record: dict, now: int | None = None) -> tuple[int, float]:
    """Rotation preference: lower is better. Recently-OK profiles rank by
    latency (fastest first); known-slow-but-OK and unknown profiles rank
    second; profiles with RECENT repeated failures rank last.

    Failure streaks expire with the ok window: a record whose last probe is
    older than that window carries no signal (it was typically written by
    an era of dishonest probes or long-gone network conditions), so it
    ranks as unknown instead of poisoning the exit forever."""
    if not record:
        return (1, float("inf"))
    now = int(now if now is not None else time.time())
    ok = record.get("ok")
    last_ok = record.get("last_ok_at") or record.get("checked_at")
    checked_at = record.get("checked_at")
    fails = int(record.get("fails") or 0)
    settings = egress_settings()
    window = int(settings["ok_window"])
    fresh = checked_at is not None and now - int(checked_at) < window
    if ok and last_ok and now - int(last_ok) < window:
        latency = float(record.get("latency_ms") or float("inf"))
        if latency < float(settings["slow_latency_ms"]):
            return (0, latency)
        return (2, latency)
    if fails >= int(settings["fail_threshold"]) and fresh:
        return (3, float("inf"))
    return (1, float("inf"))


def record_rotation(name: str, profile: Path) -> None:
    """Persist the last switch (profile + epoch) for status --json."""
    record = {"profile": profile.stem, "at": int(time.time())}
    path = ROOT / "state" / f"{name}.rotation"
    _atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + "\n", 0o600)
    _hand_back_ownership(path)


def scheduled_interval() -> int:
    """Configured scheduled-rotation interval in seconds (0 = off)."""
    try:
        return int(_rotation.get("interval_seconds", 0) or 0)
    except (TypeError, ValueError):
        return 0


def rotation_policy() -> str:
    """Configured exit-selection policy: 'latency' (default) or
    'least-recent' (autoroute: prefer the exit used longest ago)."""
    policy = _rotation.get("policy", DEFAULT_ROTATION_SETTINGS["policy"])
    return policy if policy in ("latency", "least-recent") else DEFAULT_ROTATION_SETTINGS["policy"]


def _lru_key(record: dict) -> int:
    """Autoroute key: epoch of the exit's last verified OK probe (older =
    preferred; 0 = never used = preferred first)."""
    try:
        return int(record.get("last_ok_at") or record.get("checked_at") or 0)
    except (TypeError, ValueError):
        return 0


def last_rotation_at(name: str) -> int | None:
    """Epoch of the last recorded rotation for ``name``
    (state/<name>.rotation "at"), or None when there is no record."""
    record = ROOT / "state" / f"{name}.rotation"
    if not record.is_file():
        return None
    try:
        return int(json.loads(record.read_text())["at"])
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def next_rotation_at(name: str) -> int | None:
    """Epoch of the next scheduled rotation for ``name``, or None when
    rotation is disabled or no rotation has ever been recorded."""
    interval = scheduled_interval()
    if interval <= 0:
        return None
    at = last_rotation_at(name)
    if at is None:
        return None
    jitter = int(_rotation.get("jitter_seconds", DEFAULT_ROTATION_SETTINGS["jitter_seconds"]) or 0)
    # Deterministic per-rotation jitter: seeded by the last rotation time, so
    # repeated checks agree instead of re-rolling every tick and potentially
    # deferring forever at the boundary.
    offset = random.Random(at).randint(-(jitter // 2), jitter // 2) if jitter > 0 else 0
    return at + interval + offset


def rotate_due(provider: str | None = None) -> int:
    """Scheduled rotation pass: rotate every provider whose interval elapsed.

    Read-only when nothing is due (exit 3). Rotates via the normal ``rotate``
    path (verify-then-switch, rollback, cooldowns); the current exit is NOT
    marked as an upstream failure — a scheduled switch is a preference, not a
    failure signal. Providers without a rotation record are seeded with now
    (first rotation waits a full interval). In TUN mode it returns 3 without
    changing state so shared long-lived flows remain connected. Returns 0 when
    a provider was rotated or seeded, 3 otherwise.
    """
    interval = scheduled_interval()
    if interval <= 0:
        return 3
    # A TUN engine is shared by every routed domain. Background profile
    # rotation reloads that engine and can drop unrelated long-lived flows
    # (notably the Discord gateway), so scheduled rotation is proxy-mode only.
    # Explicit `rotate <provider>` remains available when an intentional TUN
    # interruption is acceptable.
    if current_mode() == "tun":
        return 3
    if provider is not None:
        names = [provider]
    else:
        suffix = ".active"
        names = sorted(
            p.name[: -len(suffix)]
            for p in (ROOT / "state").glob(f"*{suffix}")
            if p.name.endswith(suffix) and p.name[: -len(suffix)] in _providers
        )
    if not names:
        return 3
    now = int(time.time())
    handled = False
    for name in names:
        at = last_rotation_at(name)
        if at is None:
            active = persisted_active(name)
            if active is not None:
                record_rotation(name, active)
            else:
                _atomic_write(
                    ROOT / "state" / f"{name}.rotation",
                    json.dumps({"profile": None, "at": now}, sort_keys=True) + "\n",
                )
            handled = True
            continue
        next_at = next_rotation_at(name)
        if next_at is None or now < next_at:
            continue
        handled = rotate(name, automatic=True) == 0 or handled
    return 0 if handled else 3


def _clear_cooldown(name: str, profile: Path) -> None:
    """Drop a profile's persisted cooldown (last-good rollback restore)."""
    (ROOT / "state" / "cooldowns" / name / f"{profile.stem}.until").unlink(missing_ok=True)


def _apply_upstream_failure(name: str, profile: Path | None, reason: str, cooldown_seconds: int) -> None:
    """rotate --reason: the CURRENT profile just failed upstream (429/503/
    timeout/1010...). Apply the configured error policy for the reason:
    cooldown (rotation skips until reset), exhaust (cooldown + an
    ``exhausted`` marker with a machine-readable reset time in the egress
    record, so status --json/external scripts see the lane is dead for this
    turn), or block (reputation block: rotation skips the exit entirely until
    the marker expires or --force). ``cooldown_seconds`` is the legacy per-
    provider rotate hint and is kept for call compatibility; policy seconds
    are authoritative when configured."""
    if profile is None:
        return
    action, seconds = policy_action(name, reason)
    if action != "block" and _is_block_reason(reason):
        action = "block"  # 1010/403 text always blocks, matching the old rule
    mark_cooldown(name, profile, seconds)
    record = read_egress(name, profile)
    record["upstream_error"] = str(reason)
    record["upstream_error_at"] = int(time.time())
    record["error"] = f"upstream:{reason}"
    if action == "exhaust":
        record["exhausted"] = True
        record["exhausted_at"] = int(time.time())
        record["exhausted_until"] = _iso_ts(int(time.time()) + seconds)
    else:
        record["exhausted"] = False
        record["exhausted_at"] = None
        record["exhausted_until"] = None
    write_egress(name, profile, record)
    if action == "block":
        mark_blocked(name, profile, reason, seconds)
    print(f"router: marked {profile.stem} upstream error '{reason}' ({action} {seconds}s)", file=sys.stderr)


def persisted_active(name: str) -> Path | None:
    """The profile the running tunnel was last configured with
    (state/<name>.active), regardless of cooldown/block state.

    Cooldown marks and blocked markers never reload the engine: the live
    tunnel keeps routing via the persisted active profile even after a probe
    cools it. Attribution/probing therefore must use THIS profile —
    ``resolve_active`` skips cooled profiles and would blame a different
    exit for the tunnel's health (one dead exit poisoning the whole pool's
    records). Returns the profile from the state file, or None when there is
    no state file / the stem has no matching *.conf (callers fall back to
    resolve_active without a preference).
    """
    profiles = provider_files(name)
    if not profiles:
        return None
    live = configured_profile(name) if engine_alive() else None
    if live is not None:
        state = ROOT / "state" / f"{name}.active"
        try:
            marker = state.read_text().strip() if state.is_file() else ""
        except OSError:
            marker = ""
        if marker != live.stem:
            # A staged reload can temporarily make the generated config differ
            # from the committed marker. Repair only when both files agree;
            # otherwise keep the marker authoritative until the probe commits.
            try:
                candidate = SING_BOX_CONFIG.read_text()
                committed = LAST_GOOD_FILE.read_text()
            except OSError:
                candidate = committed = None
            if candidate is not None and candidate == committed:
                set_active(name, live)
            else:
                return next((p for p in profiles if p.stem == marker), None)
        return live
    state = ROOT / "state" / f"{name}.active"
    if state.is_file():
        stem = state.read_text().strip()
        return next((p for p in profiles if p.stem == stem), None)
    return None


def configured_profile(name: str) -> Path | None:
    """Return the provider profile represented by the generated sing-box config.

    The active marker is desired state, not proof of what sing-box loaded.
    Compare endpoint payloads in memory; never print or persist private keys.
    """
    if not SING_BOX_CONFIG.is_file():
        return None
    try:
        config = json.loads(SING_BOX_CONFIG.read_text())
        endpoint = next(
            item for item in config.get("endpoints", [])
            if item.get("tag") == name and item.get("type") == "wireguard"
        )
    except (json.JSONDecodeError, OSError, StopIteration, AttributeError, TypeError):
        return None

    def identity(value: dict) -> dict:
        normalized = {
            key: item for key, item in value.items()
            if key not in {"tag", "domain_resolver"}
        }
        normalized.setdefault("mtu", DEFAULT_ENDPOINT_MTU)
        return normalized

    target = identity(endpoint)
    for profile in provider_files(name):
        try:
            if identity(parse_wireguard(profile)) == target:
                return profile
        except (SystemExit, KeyError, ValueError, configparser.Error, OSError):
            continue
    return None


def resolve_active(name: str) -> Path | None:
    profiles = provider_files(name)
    if not profiles:
        return None
    state = ROOT / "state" / f"{name}.active"
    if state.is_file():
        stem = state.read_text().strip()
        match = next((p for p in profiles if p.stem == stem), None)
        if match is not None and not is_cooled_down(name, match):
            return match
    return next((p for p in profiles if not is_cooled_down(name, p)), None)


def set_active(name: str, profile: Path) -> None:
    state = ROOT / "state" / f"{name}.active"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(profile.stem)
    os.chmod(state, 0o600)
    _hand_back_ownership(state)


def _profile_error(profile: Path) -> str | None:
    """Return an error message when ``profile`` cannot be parsed, else None.

    The engine's parser raises (SystemExit for bad Endpoints/missing
    AllowedIPs, KeyError/ValueError for missing/typed sections) on malformed
    files; converting that into a string lets callers skip one bad profile
    without losing the whole provider or producing a traceback (F2/F6).
    """
    try:
        parse_wireguard(profile)
        dns_server_for(profile)
        return None
    except (SystemExit, KeyError, ValueError, configparser.Error, OSError) as exc:
        return str(exc) or type(exc).__name__


def _usable_profile(name: str, preferred: Path | None = None) -> Path | None:
    """Select a valid profile without dropping a one-profile provider."""
    profiles = provider_files(name)
    if not profiles:
        return None
    active = preferred or resolve_active(name)
    # ``resolve_active`` intentionally avoids cooled profiles. Remember the
    # persisted selection so a provider with no non-cooled alternatives keeps a
    # valid endpoint instead of disappearing from the generated config.
    persisted_active = active
    if persisted_active is None and preferred is None:
        state = ROOT / "state" / f"{name}.active"
        try:
            stem = state.read_text(encoding="utf-8").strip()
            persisted_active = next((p for p in profiles if p.stem == stem), None)
        except OSError:
            persisted_active = None
    if active is not None:
        error = _profile_error(active)
        if error is None:
            return active
        print(f"router: skipping bad active profile {active.name} for '{name}': {error}", file=sys.stderr)
    for profile in profiles:
        if active is not None and profile == active:
            continue  # already logged above
        error = _profile_error(profile)
        if error is not None:
            print(f"router: skipping bad profile {profile.name} for '{name}': {error}", file=sys.stderr)
            continue
        if not is_cooled_down(name, profile):
            return profile
    if persisted_active is not None:
        error = _profile_error(persisted_active)
        if error is None:
            return persisted_active
    return None


# ---------------------------------------------------------------------------
# sing-box config generation
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> str:
    """Resolve a WireGuard peer host to an IP literal.

    IPv6 literals (with or without brackets) and IPv4 literals pass through;
    domains are resolved with a preference for IPv6: the network this machine
    runs on silently drops the WARP IPv4 endpoint (handshake never completes)
    while the IPv6 endpoint answers.

    Note (M10): this preference is deliberately independent of the DNS
    ``strategy`` in the generated config. `dns.strategy` governs how domain
    *destinations* are resolved: the tunnels in this router are IPv4-only
    (profiles assign e.g. 10.2.0.2/32), so destinations default to
    ``ipv4_only``. Peer *endpoints*, on the other hand, may be IPv6 because
    that is the only family some networks route to the WARP server. Both are
    tunable via ``vpn.dns_strategy`` / ``vpn.prefer_ipv6_peers`` so a
    deployment can express one consistent policy.
    """
    host = host.strip().strip("[]")
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_aton(host)
        return host  # already an IPv4 literal
    except OSError:
        pass
    prefer_ipv6 = bool(_vpn.get("prefer_ipv6_peers", True))
    resolved: list[str] = []

    def _resolve() -> None:
        # Runs on a daemon worker so a slow/broken resolver can never stall
        # config build indefinitely (F7).
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
        except (socket.gaierror, OSError):
            return
        for info in infos:
            if prefer_ipv6 and info[0] == socket.AF_INET6:
                resolved.append(info[4][0])
                return
            if not prefer_ipv6 and info[0] == socket.AF_INET:
                resolved.append(info[4][0])
                return
        if infos:
            resolved.append(infos[0][4][0])

    worker = threading.Thread(target=_resolve, name=f"dns-{host}", daemon=True)
    worker.start()
    worker.join(timeout=5.0)
    if resolved:
        return resolved[0]
    # Bounded DNS failed (timeout/unresolvable): pass the hostname through and
    # let sing-box's own resolver deal with it (previous gaierror behavior).
    return host


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


def parse_wireguard(profile: Path) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profile)
    interface, peer = parser["Interface"], parser["Peer"]
    host, port = parse_endpoint(peer["Endpoint"].strip())
    host = resolve_host(host)
    allowed_ips = [a.strip() for a in re.split(r"[,\s]+", peer.get("AllowedIPs", "").strip()) if a]
    if not allowed_ips:
        raise SystemExit(f"missing AllowedIPs in {profile.name}")
    endpoint = {
        "type": "wireguard",
        "tag": "",  # set by caller to the provider name
        "address": [a.strip() for a in re.split(r"[,\s]+", interface["Address"].strip()) if a],
        "private_key": interface["PrivateKey"].strip(),
        "peers": [{"address": host.strip(), "port": int(port), "public_key": peer["PublicKey"].strip(), "allowed_ips": allowed_ips}],
    }
    if peer.get("PresharedKey", "").strip():
        endpoint["peers"][0]["pre_shared_key"] = peer["PresharedKey"].strip()
    if peer.get("PersistentKeepalive", "").strip():
        endpoint["peers"][0]["persistent_keepalive_interval"] = int(peer["PersistentKeepalive"].strip())
    if interface.get("MTU", "").strip():
        endpoint["mtu"] = int(interface["MTU"].strip())
    else:
        endpoint["mtu"] = int(_vpn.get("mtu") or DEFAULT_ENDPOINT_MTU)
    return endpoint


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


_DNS_STRATEGIES = ("ipv4_only", "ipv6_only", "ipv4_prefer", "ipv6_prefer")


def dns_strategy() -> str:
    """Address-family strategy for DNS resolution of domain *destinations*.

    Defaults to ``ipv4_only`` because the WireGuard tunnels this router builds
    carry only the IPv4 addresses assigned in each profile (e.g. 10.2.0.2/32).
    Tunable per-machine with ``vpn.dns_strategy`` in router.json (see
    resolve_host for why peer endpoints are handled separately, M10).
    """
    strategy = _vpn.get("dns_strategy", "ipv4_only")
    if strategy not in _DNS_STRATEGIES:
        return "ipv4_only"
    return strategy


def dns_transport() -> str:
    """DNS server transport for provider-pinned resolution.

    Some networks drop UDP 53 to external resolvers (captive-portal/school
    firewalls) while allowing DoH (TCP 443). ``vpn.dns_transport`` switches
    the generated ``dns-<provider>`` servers between ``udp`` (default) and
    ``https`` (DoH, 1.1.1.1) so tunneled domains still resolve there.
    """
    transport = _vpn.get("dns_transport", "udp")
    if transport not in ("udp", "https"):
        return "udp"
    return transport


def _autodetect_state_path(source: str) -> Path:
    if not isinstance(source, str) or not _PROVIDER_NAME.fullmatch(source):
        raise ValueError("invalid autodetect source")
    return ROOT / "state" / "autodetect" / f"{source}.json"


def _read_autodetect_state(source: str) -> dict:
    try:
        value = json.loads(_autodetect_state_path(source).read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _autodetected_domains_by_route() -> dict[str, list[str]]:
    """Return non-expired exact learned hosts grouped by route.

    Autodetected dependencies belong to the configured route, not the provider
    that happened to serve the discovery request. This keeps them routed when
    the route fails over or is reassigned to another provider.
    """
    result: dict[str, list[str]] = {}
    if not _autodetect.get("enabled"):
        return result
    for source, settings in (_autodetect.get("sources") or {}).items():
        if not isinstance(settings, dict):
            continue
        state = _read_autodetect_state(source)
        if state.get("route_id") != settings.get("route_id"):
            continue
        domains = domain_autodetect.active_domains(state)
        if domains:
            result.setdefault(settings["route_id"], []).extend(domains)
    return {route_id: sorted(set(domains)) for route_id, domains in result.items()}


def _routes_with_autodetected_domains(routes: list[dict]) -> list[dict]:
    if not _autodetect.get("enabled"):
        return routes
    learned = _autodetected_domains_by_route()
    roots: dict[str, list[str]] = {}
    for settings in (_autodetect.get("sources") or {}).values():
        if not isinstance(settings, dict):
            continue
        route_id = settings.get("route_id")
        if not isinstance(route_id, str):
            continue
        roots.setdefault(route_id, []).extend(
            root for root in settings.get("roots", []) if isinstance(root, str)
        )
    if not learned and not roots:
        return routes
    expanded: list[dict] = []
    for route in routes:
        route_copy = dict(route)
        domains = list(route.get("domains") or [])
        route_id = route.get("id")
        for root in roots.get(route_id, []):
            if root not in domains:
                domains.append(root)
        for host in learned.get(route_id, []):
            if not any(domain_autodetect.host_matches_root(host, str(domain).lstrip("*."))
                       for domain in domains):
                domains.append(host)
        route_copy["domains"] = domains
        expanded.append(route_copy)
    return expanded


def autodetect_status() -> dict:
    """Read-only status for configured hostname discovery sources."""
    sources = {}
    for source, settings in (_autodetect.get("sources") or {}).items():
        state = _read_autodetect_state(source)
        sources[source] = {
            "route_id": settings.get("route_id"),
            "provider": settings.get("provider"),
            "seed": settings.get("seed"),
            "ttl_seconds": settings.get("ttl_seconds"),
            "updated_at": state.get("updated_at"),
            "domains": domain_autodetect.active_domains(state),
        }
    return {
        "enabled": bool(_autodetect.get("enabled")),
        "interval_seconds": _autodetect.get("interval_seconds", 300),
        "timeout_seconds": _autodetect.get("timeout_seconds", 12),
        "auto_sources": bool(_autodetect.get("auto_sources", True)),
        "sources": sources,
    }


def _routes_by_health_order(routes: list[dict], selected: dict[str, Path]) -> list[dict]:
    """Stable-sort routes so providers with healthy egress records lead.

    Ranks come from the persisted probe record of each provider's selected
    profile (`_egress_rank`): healthy-fast first, unknown/slow in the middle,
    recently-failing last. Routes within the same provider keep their config
    order (stable sort). This powers ``routing.health_order``: when a second
    provider (e.g. WARP) is healthy it wins the shared school domains; when
    it degrades, the healthy lane's rules move ahead automatically without
    any manual route reorder.
    """
    ranks: dict[str, tuple[int, float]] = {}
    for name, profile in selected.items():
        ranks[name] = _egress_rank(read_egress(name, profile))
    return sorted(
        routes,
        key=lambda route: ranks.get(_effective_route_provider(route.get("provider", "")), (1, float("inf"))),
    )


def _capture_domain_name(value: object) -> str | None:
    """Normalize one route target for destination-IP capture."""
    if not isinstance(value, str):
        return None
    domain = value.strip().lower().rstrip(".")
    while domain.startswith("*."):
        domain = domain[2:]
    return domain or None


def _route_capture_cidrs(routes: list[dict], routing: dict,
                         active: dict[str, dict]) -> list[str]:
    """Resolve configured tunneled route targets into TUN route CIDRs.

    A TUN inbound can install destination IP routes, not hostname routes. The
    route-based capture mode therefore snapshots the currently resolved IPs of
    configured domain routes; sing-box still sniffs those captured flows to
    select the provider. Any unresolved explicit route domain fails the build
    rather than silently widening or bypassing the route.
    """
    routing_mode = routing.get("mode", "default")
    vpn_domains = {
        domain for value in (routing.get("vpn_domains") or [])
        if (domain := _capture_domain_name(value))
    }
    direct_domains = {
        domain for value in (routing.get("direct_domains") or [])
        if (domain := _capture_domain_name(value))
    }
    target_domains: set[str] = set()
    raw_cidrs: list[str] = []

    for route in routes:
        route_provider = _effective_route_provider(route.get("provider", ""))
        if route_provider not in active:
            continue
        for value in (route.get("domains") or []):
            domain = _capture_domain_name(value)
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
        # Keep IP routes aligned with the existing route-rule behavior: the
        # vpn-list domain allow-list does not activate arbitrary IP routes.
        if routing_mode != "vpn-list":
            raw_cidrs.extend(route.get("ip_cidr") or [])

    unresolved_domains: list[str] = []
    for domain in sorted(target_domains):
        # Use a bounded worker: a broken system resolver must not hang a
        # config build or keepalive-triggered reload indefinitely.
        answers = _bounded_getaddrinfo(domain, 443, timeout=3.0)
        if not answers:
            unresolved_domains.append(domain)
            continue
        resolved_domain = False
        for host in answers:
            try:
                host = str(host).split("%", 1)[0]
                address = ipaddress.ip_address(host)
            except (IndexError, TypeError, ValueError):
                continue
            raw_cidrs.append(f"{address}/{address.max_prefixlen}")
            resolved_domain = True
        if not resolved_domain:
            unresolved_domains.append(domain)

    if unresolved_domains:
        raise SystemExit(
            "selective tun: could not resolve route domains: "
            + ", ".join(unresolved_domains)
        )

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in raw_cidrs:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    collapsed = list(ipaddress.collapse_addresses(
        [network for network in networks if network.version == 4]
    )) + list(ipaddress.collapse_addresses(
        [network for network in networks if network.version == 6]
    ))
    return [
        str(network) for network in sorted(
            collapsed,
            key=lambda network: (network.version, int(network.network_address), network.prefixlen),
        )
    ]


def build_singbox_config(active_overrides: dict[str, Path] | None = None) -> tuple[dict, dict[str, Path]]:
    active: dict[str, dict] = {}
    selected: dict[str, Path] = {}
    dns_map: dict[str, str] = {}
    for name in _providers:
        # SOCKS-backed providers are supplied by an external local client
        # (for example official WARP proxy mode), not by WireGuard profiles.
        # Ignore any stale *.conf files left in the old provider directory so
        # the provider gets exactly one outbound and never duplicate tags.
        if is_proxy_provider(name):
            continue
        # A failed primary must not remain as a second live WireGuard tunnel
        # underneath its fallback; that recreates concurrent-session and
        # endpoint-contention failures.
        if active_fallback(name):
            continue
        preferred = active_overrides.get(name) if active_overrides else None
        profile = _usable_profile(name, preferred=preferred)
        if profile is None:
            continue
        try:
            endpoint = parse_wireguard(profile)
            dns_map[name] = dns_server_for(profile)
        except (SystemExit, KeyError, ValueError, configparser.Error, OSError) as exc:
            # Defensive: _usable_profile already validated, but a file changed
            # between the check and the build must never kill the config.
            print(f"router: skipping bad profile {profile.name} for '{name}': {exc}", file=sys.stderr)
            continue
        endpoint["tag"] = name
        # sing-box 1.12+: provider endpoint routed through this endpoint is
        # resolved with an explicit per-endpoint resolver instead of the
        # deprecated implicit DNS rule path. DialerOptions is embedded flat.
        # Provisional per-provider tag; deduped below once all resolvers
        # are known (identical servers collapse to one shared entry).
        endpoint["domain_resolver"] = f"dns-{name}"
        active[name] = endpoint
        selected[name] = profile

    # DNS resolution must NOT ride the tunnel: a WireGuard blip would then
    # take down resolution for the very request we're trying to route, which
    # surfaces as "Connection error" storms upstream. DNS queries go out the
    # direct physical path (no detour; sing-box 1.13 rejects detouring a DNS
    # server to the "direct" outbound with "empty direct outbound" at start).
    # The resolved IP still gets dialed through the provider's endpoint
    # outbound, so the destination traffic stays provider-routed.
    # Deduplicate identical resolvers: multiple providers commonly share the
    # same DNS (e.g. every Proton profile pins 1.1.1.1). One server entry per
    # distinct (type, server, port) keeps sing-box's connection pool warm in
    # ONE session instead of fragmenting into N identical DoH handshakes;
    # per-provider tags become aliases resolved to the shared entry.
    def _dns_entry(tag: str, name: str) -> dict:
        return {
            "type": dns_transport(),
            "tag": tag,
            "server": dns_map[name],
            **({"server_port": 443} if dns_transport() == "https" else {}),
        }

    dns_servers: list[dict] = []
    dns_alias: dict[str, str] = {}
    seen_dns: dict[tuple, str] = {}  # (type, server, port) -> canonical tag
    for name in active:
        entry = _dns_entry(f"dns-{name}", name)
        key = (entry["type"], entry["server"], entry.get("server_port"))
        if key in seen_dns:
            dns_alias[name] = seen_dns[key]
        else:
            seen_dns[key] = entry["tag"]
            dns_servers.append(entry)
    # Rewrite provisional per-provider resolver tags to the canonical entry.
    for name in active:
        active[name]["domain_resolver"] = dns_alias.get(name, f"dns-{name}")
    # Proxy-backed providers (local SOCKS5 upstream, e.g. warp-cli mode
    # proxy): no WireGuard endpoint in the shared engine. Each live one gets
    # a socks outbound; its assigned domains route to that tag exactly like
    # a WireGuard lane. Revalidated here (not just at load) so a
    # programmatically-set provider table gets the same loop rejection.
    proxy_live = active_proxy_providers()
    proxy_outbounds: list[dict] = []
    for name, (upstream_host, upstream_port) in proxy_live.items():
        if upstream_port == _port:
            raise SystemExit(
                f"proxy provider '{name}': upstream {upstream_host}:{upstream_port} "
                "is the router's own listener (proxy loop)"
            )
        proxy_outbounds.append({
            "type": "socks",
            "tag": name,
            "server": upstream_host,
            "server_port": upstream_port,
            "version": "5",
        })
    # sing-box 1.12+: any dial without an explicit resolver needs
    # route.default_domain_resolver; the system (local) transport keeps
    # non-routed domains away from the tunnels and silences the deprecated
    # implicit fallback. Route DNS rules still pin tunneled domains to the
    # provider's own server.
    dns_servers.append({"type": "local", "tag": "dns-local"})
    routing = routing_state()
    routing_mode = routing["mode"]
    # health_order: emit provider rules in egress-health order instead of
    # pure route-table order, so a healthy lane leads shared domains and a
    # degraded one trails (or drops out) without manual reorders. Falls back
    # to the configured route order when the flag is off.
    routed_domains = _routes_with_autodetected_domains(_routes)
    if routing.get("health_order") and selected:
        build_routes = _routes_by_health_order(routed_domains, selected)
    else:
        build_routes = routed_domains
    dns_rules = []
    if routing_mode == "safe-list" and routing["direct_domains"]:
        # Safe-list: trusted domains go DIRECT, so their DNS must resolve via
        # the local resolver, never a provider's DNS server - pinning them to
        # a provider resolver would leak direct traffic's DNS through the
        # tunnel. The rule comes first so a domain listed both here and in a
        # provider route always wins the direct resolver.
        dns_rules.append({"domain_suffix": list(routing["direct_domains"]), "server": "dns-local"})
    vpn_domains = frozenset(routing["vpn_domains"]) | frozenset(
        domain for domains in _autodetected_domains_by_route().values() for domain in domains
    )
    for route in build_routes:
        route_provider = _effective_route_provider(route["provider"])
        if ((route_provider != "direct" and route_provider not in active
                and route_provider not in proxy_live)
                or not route.get("domains")):
            continue
        domains = route["domains"]
        if routing_mode == "vpn-list":
            domains = [
                domain for domain in domains
                if any(domain == vpn or domain.endswith("." + vpn) for vpn in vpn_domains)
            ]
        if domains:
            if route_provider == "direct" or route_provider in proxy_live:
                # Direct and SOCKS5-hopped traffic share the local resolver:
                # there is no tunnel DNS to pin to, and pinning to a
                # provider resolver would leak direct-path queries.
                dns_rules.append({"domain_suffix": domains, "server": "dns-local"})
            else:
                dns_rules.append({"domain_suffix": domains,
                                  "server": dns_alias.get(route_provider, f"dns-{route_provider}")})

    # Route rules: safe-list direct-domain pins first (a trusted domain is
    # never tunneled even if a provider route also mentions it), then the
    # per-domain provider routes, then the loopback/localhost pins. With no
    # routing section (default mode) direct_pins is empty and the rule list
    # is byte-identical to the pre-routing-modes output.
    provider_rules = []
    for route in build_routes:
        route_provider = _effective_route_provider(route["provider"])
        if (route_provider != "direct" and route_provider not in active
                and route_provider not in proxy_live):
            continue
        rule = {"outbound": route_provider}
        if route.get("domains"):
            domains = route["domains"]
            if routing_mode == "vpn-list":
                domains = [
                    domain for domain in domains
                    if any(domain == vpn or domain.endswith("." + vpn) for vpn in vpn_domains)
                ]
            if domains:
                rule["domain_suffix"] = domains
            elif not route.get("ip_cidr"):
                continue
        if route.get("ip_cidr"):
            if routing_mode == "vpn-list":
                continue
            rule["ip_cidr"] = route["ip_cidr"]
        provider_rules.append(rule)
    direct_pins: list[dict] = []
    if routing_mode == "safe-list" and routing["direct_domains"]:
        direct_pins.append({"domain_suffix": list(routing["direct_domains"]), "outbound": "direct"})
    rules = direct_pins + provider_rules + [
        {"domain": ["localhost"], "outbound": "direct"},
        {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
    ]

    mode = current_mode()
    if mode == "tun":
        blockers = _tun_proxy_blockers(build_routes, routing, proxy_live)
        if blockers:
            raise SystemExit(
                "tun mode cannot carry proxy-backed provider(s) "
                + ", ".join(f"'{name}'" for name in blockers) +
                " through a local SOCKS5 hop (TCP-only; arbitrary TUN UDP would bypass "
                "it silently). Use proxy mode for these routes, or move their domains "
                "to a WireGuard provider."
            )
    rule_sets: list[dict] = []
    if mode == "tun":
        tun: dict = {
            "type": "tun",
            "tag": "tun-in",
            "address": _vpn.get("address", DEFAULT_TUN_ADDRESS),
            "mtu": int(_vpn.get("mtu", DEFAULT_TUN_MTU)),
            "stack": _vpn.get("stack", DEFAULT_TUN_STACK),
            "strict_route": False,
        }
        # Selective TUN: sing-box installs only the routes from
        # ``route_address_set`` while leaving unmatched destinations on the
        # OS route table. ``auto_route`` must remain enabled on macOS; the
        # selective address-set is what prevents a default-route detour.
        capture = _vpn.get("capture")
        if capture is None:
            capture = "ruleset" if _vpn.get("selective") else "routes"
        if capture not in ("ruleset", "routes"):
            raise SystemExit("vpn.capture must be 'ruleset' or 'routes'")
        selective = _vpn.get("selective") if capture == "ruleset" else None
        rule_sets: list[dict] = []
        if selective:
            if not isinstance(selective, str) or not _PROVIDER_NAME.fullmatch(selective):
                raise SystemExit("selective tun: name must contain only letters, digits, dots, underscores, or hyphens")
            ruleset_path = ROOT / "rulesets" / f"{selective}.json"
            try:
                selective_data = json.loads(ruleset_path.read_text())
            except FileNotFoundError:
                raise SystemExit(f"selective tun: missing ruleset {ruleset_path}") from None
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(f"selective tun: could not read {ruleset_path}: {exc}") from None
            if not isinstance(selective_data, dict) or not isinstance(selective_data.get("ip_cidr"), list):
                raise SystemExit(f"selective tun: {ruleset_path} needs an ip_cidr string list")
            cidrs = selective_data["ip_cidr"]
            if not cidrs or not all(isinstance(cidr, str) and cidr for cidr in cidrs):
                raise SystemExit(f"selective tun: {ruleset_path} has no valid ip_cidr entries")
            provider = selective_data.get("provider", _vpn.get("selective_provider", "cloudflare"))
            effective_provider = _effective_route_provider(provider)
            if effective_provider not in active:
                raise SystemExit(f"selective tun: provider '{provider}' has no active profile")
            tag = f"ruleset-{selective}"
            rule_sets.append({
                "type": "inline",
                "tag": tag,
                "rules": [{"ip_cidr": cidrs}],
            })
            tun["auto_route"] = True
            tun["route_address_set"] = [tag]
            # Once a matching packet enters the TUN, send it through the
            # selected provider. The TUN field only controls OS capture.
            rules.insert(0, {"rule_set": [tag], "outbound": effective_provider})
        else:
            tun["auto_route"] = True
            if capture == "routes" and _vpn.get("capture") == "routes":
                # Hostnames are not valid TUN route entries. Snapshot the
                # configured route domains into an inline IP rule-set so
                # unmatched destinations bypass the TUN entirely.
                capture_cidrs = _route_capture_cidrs(build_routes, routing, active)
                if not capture_cidrs:
                    raise SystemExit(
                        "selective tun: no resolved route CIDRs; check routed domains, vpn_domains, and DNS"
                    )
                tag = "ruleset-routes"
                rule_sets.append({
                    "type": "inline",
                    "tag": tag,
                    "rules": [{"ip_cidr": capture_cidrs}],
                })
                tun["route_address_set"] = [tag]
            # Route-based TUN receives raw IP flows, so domain_suffix rules do
            # not have a hostname until sing-box sniffs TLS/HTTP metadata.
            # Place sniff after DNS hijacking and before provider rules so
            # captured domains still select their configured provider.
            rules.insert(0, {"action": "sniff"})
        exclude_cidr = _vpn.get("exclude_cidr") or []
        if exclude_cidr:
            # Destinations pinned outside the engine entirely: sing-box
            # excludes these routes from the TUN, so they always ride the
            # physical path and never see a reload/switch blip (agent
            # backends, work VPNs, anything that must stay up 24/7).
            tun["route_exclude_address"] = list(exclude_cidr)
        # Keep the mixed proxy listener ALONGSIDE the TUN: apps pinned to
        # 127.0.0.1:PORT (hermes gateway, with-proxy, keepalive egress
        # probes) must keep working while TUN captures selected destinations
        # at the IP layer. Both inbound types share the same route rules, so
        # no packet is processed twice.
        inbounds = [
            tun,
            {"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": _port},
        ]
        route_final = "direct"
        # In tun mode the OS resolver's queries enter the tunnel; hijack them
        # into sing-box's DNS module so dns.rules still pin routed domains to
        # the provider's own resolver instead of leaking through the physical
        # network. The hijack must come FIRST (before the domain/outbound
        # rules): routes match DNS queries too, and a query sent to 'proton'
        # outbound would bypass dns.rules. hijack-dns is a rule action added
        # in sing-box 1.12 (confirmed against the 1.12 binary), so the tun
        # config needs the same 1.12 minimum as proxy mode.
        rules.insert(0, {"protocol": "dns", "action": "hijack-dns"})
    else:
        inbounds = [{"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": _port}]
        route_final = "direct"

    if routing_mode == "safe-list":
        # route.final must be a live outbound tag: everything not pinned
        # direct rides the default provider. Fail the build with a precise
        # error when that provider has no active profile - never emit a
        # dangling final.
        default_provider = _effective_route_provider(routing["default_provider"])
        if (default_provider != "direct" and default_provider not in active
                and default_provider not in proxy_live):
            raise SystemExit(
                f"routing mode 'safe-list': default_provider '{default_provider}' has no active profile; "
                "cannot emit a dangling route.final (drop *.conf into providers/<name>/ first)"
            )
        route_final = default_provider

    config = {
        # warn in steady state: info logs a line per connection, which costs
        # syscall/IO on the proxy host and grows logs/sing-box.log for no benefit.
        # Diagnostics can flip back via `router.py log-level info` if needed.
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "endpoints": list(active.values()),
        "outbounds": [{"type": "direct", "tag": "direct"}, *proxy_outbounds],
        # Without dns.final, unmatched queries hit the FIRST server (tunnel-riding
        # provider DNS); pin them to the always-present local resolver instead.
        "dns": {"servers": dns_servers, "rules": dns_rules, "strategy": dns_strategy(), "final": "dns-local"},
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-local",
            "rules": rules,
            "rule_set": rule_sets,
            "final": route_final,
        },
    }
    return config, selected


def write_sing_box(config: dict) -> None:
    has_wireguard = any(endpoint.get("type") == "wireguard" for endpoint in config.get("endpoints", []))
    has_proxy_hop = any(outbound.get("type") == "socks" for outbound in config.get("outbounds", []))
    if not has_wireguard and not has_proxy_hop:
        print("router: refusing to write an egress-less sing-box config; keeping existing file",
              file=sys.stderr)
        return
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=SING_BOX_CONFIG.parent,
            prefix=f".{SING_BOX_CONFIG.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(config, indent=2) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, SING_BOX_CONFIG)
        temporary = None
        os.chmod(SING_BOX_CONFIG, 0o600)
        _hand_back_ownership(SING_BOX_CONFIG)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_config() -> bool:
    sing_box = resolve_sing_box()
    if sing_box is None:
        print(_sing_box_missing_message(), file=sys.stderr)
        return False
    try:
        result = subprocess.run(
            [sing_box, "check", "-c", str(SING_BOX_CONFIG)],
            capture_output=True, text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        print("router: sing-box config check timed out", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"router: could not run sing-box config check: {exc}", file=sys.stderr)
        return False
    if result.returncode == 0:
        return True
    print(result.stderr or result.stdout, file=sys.stderr)
    return False


def write_last_good() -> None:
    """Snapshot the current generated config as ``sing-box.json.last-good``.

    Only called after the engine demonstrably came up with a freshly built +
    validated config, so last-good is always a config the engine HAS RUN (a
    config that fails validation/start is never snapshotted). Atomic write,
    mode 0600, same as every other config write."""
    try:
        content = SING_BOX_CONFIG.read_text()
    except OSError:
        return
    _atomic_write(LAST_GOOD_FILE, content, 0o600)


def restore_last_good() -> int:
    """Restore ``sing-box.json.last-good`` and get the engine back up on it.

    Called when a freshly generated config fails validation or the engine
    fails to come up after it was written. One bounded restore, never a
    loop: a missing last-good, or a last-good that also fails validation or
    refuses to start, fails with a clear message."""
    if not LAST_GOOD_FILE.is_file():
        return fail(f"no {LAST_GOOD_FILE.name} to restore; leaving the engine alone")
    try:
        content = LAST_GOOD_FILE.read_text()
    except OSError as exc:
        return fail(f"could not read {LAST_GOOD_FILE.name}: {exc}")
    _atomic_write(SING_BOX_CONFIG, content, 0o600)
    if not validate_config():
        return fail(f"restored {LAST_GOOD_FILE.name} failed sing-box check; engine not started")
    pid = None
    try:
        if PID_FILE.is_file():
            pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        pid = None
    if pid is not None and _pid_matches(pid):
        reload_log_from = log_offset()
        try:
            os.kill(pid, signal.SIGHUP)  # hot-reload the restored config in place
        except PermissionError:
            print("router: engine runs as root (started via sudo); restored config will apply on the next sudo start", file=sys.stderr)
            return 1
        except ProcessLookupError:
            return engine_start(use_existing_config=True)
        if wait_engine(2.0, log_from=reload_log_from):
            return 0
    print("router: starting engine with the restored last-good config", file=sys.stderr)
    return engine_start(use_existing_config=True)


def listener_up() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", _port)) == 0


def _any_our_engine_running() -> bool:
    """True when an exact owned engine process is present.

    Ambiguous/unavailable process-table evidence is treated as unknown by this
    health getter; lifecycle Stop handles the same condition as a hard error.
    """
    if os.name == "nt":
        expected = _expected_engine_command()
        if expected is None:
            return False
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Process).CommandLine"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False
        return any(_command_is_our_engine(line) for line in result.stdout.splitlines())
    try:
        return bool(_find_our_engine_pids())
    except EngineIdentityError:
        return False


def _pid_matches(pid: int) -> bool:
    """True when PID is the exact resolved engine command line."""
    expected = _expected_engine_command()
    if expected is None:
        return False
    try:
        if os.name == "nt":
            # Windows helper lifecycle is authoritative; this fallback remains
            # conservative and requires the configured path in the command line.
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            return bool(out) and _command_is_our_engine(out)
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "uid=,command="],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    parts = (result.stdout or "").strip().split(None, 1)
    return len(parts) == 2 and parts[0].isdigit() and _command_is_our_engine(parts[1])


def engine_alive() -> bool:
    """True when a sing-box started by us is still running (tun mode has no
    TCP listener to probe, so process liveness is the health check). Also
    refuses foreign/recycled PIDs so a stale pid file can't claim liveness."""
    if sys.platform == "darwin" and _effective_uid() != 0:
        helper = _helper_status()
        if helper and helper.get("installed") and helper.get("running"):
            return True
    if not PID_FILE.is_file():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except PermissionError:
        # Root-owned pid file (started via `sudo vpn on`): cannot read the
        # pid, but liveness is verifiable from the process table; declaring
        # the engine dead here churns a doomed regular-user restart that
        # clobbers the pid file.
        return _any_our_engine_running()
    except (ValueError, OSError):
        return False
    if not _pid_matches(pid):
        return False
    trim_live_log_if_needed()
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True, timeout=3).stdout
            return str(pid) in out
        os.kill(pid, 0)
        return True
    except PermissionError:
        # Engine started via `sudo vpn on` runs as root: we may not probe
        # it, but the pid file is ours and the process exists, so it is our
        # engine (H3 foreign-PID check still holds — a recycled foreign pid
        # file would never have been written by us).
        return True
    except (ProcessLookupError, ValueError, OSError):
        return False


def engine_mode_consistent() -> bool:
    """True when the running engine's config actually matches current_mode.

    Prevents the H2 false-positive: a proxy-mode engine running while
    state/mode says 'tun' (or vice versa) is NOT the state we claim."""
    if sys.platform == "darwin" and _effective_uid() != 0:
        helper = _helper_status()
        if helper and helper.get("installed") and helper.get("running"):
            return helper.get("mode") == current_mode()
    if not SING_BOX_CONFIG.is_file():
        return False
    try:
        config = json.loads(SING_BOX_CONFIG.read_text())
    except (json.JSONDecodeError, OSError):
        return False
    inbounds = config.get("inbounds", [])
    if current_mode() == "tun":
        return any(i.get("type") == "tun" for i in inbounds)
    # Engine builds always include the mixed proxy listener (kept in TUN
    # mode too), so proxy mode is only consistent when there is NO tun.
    return not any(i.get("type") == "tun" for i in inbounds) and any(
        i.get("type") in ("mixed", "socks", "http") for i in inbounds
    )


def log_offset() -> int:
    try:
        return LOG_FILE.stat().st_size
    except OSError:
        return 0


def log_has_fatal(after: int) -> bool:
    """True when logs/sing-box.log contains a FATAL line after byte offset ``after``.

    tun mode fails fast with 'FATAL ... operation not permitted' when it lacks
    root/wintun; the process can be alive for a few ms before dying, so the
    log is the only reliable failure signal within the settle window."""
    try:
        with LOG_FILE.open("rb") as fh:
            fh.seek(after)
            tail = fh.read(64 * 1024).decode("utf-8", "replace")
    except OSError:
        return False
    return "FATAL" in tail or "fatal" in tail


def _tun_egress_probe(timeout: float) -> bool:
    """Tun-mode egress proof: at least one routed target must answer through
    the local proxy listener (which coexists with the TUN and rides the same
    rules). A TLS-classed failure still counts as the path working (CONNECT
    rode the tunnel); a connection-level failure means the tunnel is
    up-but-dead. Returns True when nothing routed exists to prove."""
    for name in _providers:
        if active_fallback(name):
            continue
        if _usable_profile(name) is None:
            continue
        url = probe_url_for(name)
        if url is None:
            continue
        result = probe_egress(url=url, timeout=timeout)
        if result.get("ok") or result.get("status") is not None:
            return True
        if _transport_reason(result.get("error") or "") == "tls":
            return True
        return False
    return True


def wait_engine(timeout: float = 8.0, log_from: int = 0) -> bool:
    """Mode-aware readiness: the engine must come up AND survive a settle
    window without a FATAL in the log.

    - proxy mode is ready when OUR process listens (engine_alive + the
      listener probe): a foreign process answering on the port while our
      sing-box dies on `bind: address already in use` is NOT a healthy
      start (H2).
    - tun mode is ready when OUR process survives the launch window AND a
      routed target answers through the tunnel (bounded egress probe): a
      captive portal / filtered network leaves the process alive but the
      tunnel dead, so liveness alone would silently pass ensure and later
      storm rotate_dead.

    Either way the first "up" poll just opens a 0.5s settle window instead of
    returning immediately, because sing-box can emit its FATAL a moment after
    the first successful poll (e.g. bind conflict or interface setup)."""
    deadline = time.time() + timeout
    first = True
    probe_at = 0.0
    while time.time() < deadline:
        if log_has_fatal(log_from):
            return False
        if current_mode() == "tun":
            ok = engine_alive() and engine_mode_consistent()
        else:
            ok = listener_up() and engine_alive()
        if ok:
            if first:
                first = False
                time.sleep(0.5)
                continue
            if not log_has_fatal(log_from):
                if current_mode() != "tun":
                    return True
                now = time.time()
                if now >= probe_at:
                    probe_at = now + 1.0  # re-probe cadence, bounded by deadline
                    probe_timeout = min(max(0.5, deadline - now),
                                        float(egress_settings()["probe_timeout"]))
                    if _tun_egress_probe(probe_timeout):
                        return True
        time.sleep(0.2)
    return False


def wait_listener(timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if listener_up():
            return True
        time.sleep(0.2)
    return False


def ensure_tray_started() -> None:
    """Best-effort macOS menu-bar startup after an explicit engine start.

    The tray is a separate launchd user agent, so ``router.py start`` must not
    spawn a second tray process directly. Prefer kickstart when it is already
    loaded; if the login agent exists but is not loaded yet, bootstrap that
    exact plist once and kickstart it. Failures are warnings only because the
    engine itself remains usable from the CLI.
    """
    if sys.platform != "darwin" or _effective_uid() == 0:
        return
    domain = f"gui/{os.getuid()}"
    label = f"{domain}/com.proxy-router.tray"
    plist = Path.home() / "Library" / "LaunchAgents" / "com.proxy-router.tray.plist"

    def run_launchctl(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["launchctl", *args], capture_output=True, text=True, timeout=10,
        )

    try:
        result = run_launchctl("kickstart", "-k", label)
        if result.returncode == 0:
            return
        if plist.is_file():
            boot = run_launchctl("bootstrap", domain, str(plist))
            # bootstrap returns nonzero when a concurrently-starting login
            # agent won the race; kickstart is still safe to retry afterward.
            result = run_launchctl("kickstart", "-k", label)
            if result.returncode == 0:
                return
            detail = (result.stderr or result.stdout or boot.stderr or boot.stdout
                      or "launchctl failed").strip()
        else:
            detail = (result.stderr or result.stdout or
                      f"missing tray plist: {plist}").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        detail = type(exc).__name__
    print(f"router: tray startup warning: {detail[-200:]}", file=sys.stderr)


# ---------------------------------------------------------------------------
# engine lifecycle
# ---------------------------------------------------------------------------

def route_watcher_start() -> None:
    """Start the independent routed-connection watcher best-effort."""
    try:
        import route_watcher

        result = route_watcher.start(ROOT)
        if result.get("error"):
            print(f"router: route watcher unavailable: {result['error']}", file=sys.stderr)
    except Exception as exc:  # watcher failure must not take down the proxy
        print(f"router: route watcher unavailable: {type(exc).__name__}", file=sys.stderr)


def route_watcher_stop() -> None:
    """Stop only our watcher; never signal arbitrary processes."""
    try:
        import route_watcher

        route_watcher.stop(ROOT)
    except Exception as exc:
        print(f"router: route watcher stop warning: {type(exc).__name__}", file=sys.stderr)


def prepare_log_directory() -> None:
    """Create the private runtime log directory and import legacy root logs."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(LOG_FILE.parent, 0o700)
    if LOG_FILE.parent != ROOT / "logs":
        return
    for legacy in (ROOT / "sing-box.log", ROOT / "sing-box.log.1"):
        target = LOG_FILE.parent / legacy.name
        if legacy.is_file() and not target.exists():
            shutil.copy2(legacy, target)
            os.chmod(target, 0o600)


def rotate_log_if_needed() -> None:
    """Archive an oversized logs/sing-box.log to logs/sing-box.log.1.

    Called from engine_start only, when no engine holds the log fd.
    """
    try:
        if LOG_FILE.stat().st_size < LOG_MAX_BYTES:
            os.chmod(LOG_FILE, 0o600)
            return
    except OSError:
        return
    archive = Path(str(LOG_FILE) + ".1")
    archive.unlink(missing_ok=True)
    try:
        LOG_FILE.rename(archive)
        os.chmod(archive, 0o600)
    except OSError:
        pass
    try:
        os.chmod(LOG_FILE, 0o600)
    except OSError:
        pass


def trim_live_log_if_needed() -> None:
    """Bound a live log without renaming the inode sing-box has open."""
    try:
        if LOG_FILE.stat().st_size < LOG_MAX_BYTES:
            os.chmod(LOG_FILE, 0o600)
            return
        keep = LOG_MAX_BYTES - 256
        with LOG_FILE.open("r+b") as handle:
            handle.seek(-keep, os.SEEK_END)
            tail = handle.read()
            handle.seek(0)
            handle.write(b"router: log trimmed; older entries archived by size\n")
            handle.write(tail)
            handle.truncate()
        os.chmod(LOG_FILE, 0o600)
    except (OSError, ValueError):
        pass


def engine_start(use_existing_config: bool = False, *, recover: bool = True) -> int:
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    if not sing_box_at_least(MIN_SING_BOX_VERSION):
        return fail(f"{_sing_box_version_message(MIN_SING_BOX_VERSION)}")
    # Issue #76: surface a missing startup permission before anything else.
    # The launchd-autostarted tray hits this on every login when the one-time
    # elevation grant is missing; diagnosing it only after config assembly
    # made the gap look like a broken engine instead of the one-time fix.
    # Scoped to TUN like the helper consult below: plain proxy-mode starts
    # work unprivileged and must never depend on helper state (issue #62).
    if sys.platform == "darwin" and _effective_uid() != 0 and current_mode() == "tun":
        helper = _helper_status()
        if not (helper and helper.get("installed")):
            return fail(_HELPER_NOT_INSTALLED)
    active: dict[str, Path] = {}
    if use_existing_config:
        # restore_last_good path: boot the sing-box.json file as it now
        # stands (already validated + written from last-good), without
        # regenerating it from router.json/profiles (which produced the
        # config that just failed).
        if not SING_BOX_CONFIG.is_file():
            return fail(f"no {SING_BOX_CONFIG.name} to start (use_existing_config)")
    else:
        try:
            config, active = build_singbox_config()
        except (SystemExit, KeyError, ValueError, OSError, configparser.Error) as exc:
            return fail(f"could not build sing-box config: {exc}")
        if not active:
            return fail("no provider profile available (drop *.conf into providers/<name>/)")
        write_sing_box(config)
        if not validate_config():
            if LAST_GOOD_FILE.is_file():
                print("router: generated config failed validation; restoring last-good", file=sys.stderr)
                return restore_last_good()
            return fail("sing-box config check failed")
    try:
        prepare_log_directory()
    except OSError as exc:
        return fail(f"could not prepare log directory: {exc}")
    # Capture the pre-spawn offset BEFORE any engine spawn decision (helper
    # or local): a FATAL written between spawn and a post-spawn log_offset()
    # read would be skipped as historical, yet wait_engine relies on early
    # FATAL detection (issue #62). Capturing unconditionally here keeps the
    # ordering guarantee independent of which start path runs below, and the
    # status probe itself must never be mistaken for an engine spawn.
    spawn_log_offset = log_offset()
    # Probe/consult the privileged helper only when a root-continuity start is
    # actually plausible: TUN mode requested, or a live ROOT-owned engine is
    # on record. An ambiently-running helper (other context, stale launchd
    # state) must never capture plain proxy-mode starts — those work fine
    # unprivileged and keep their spawn-ordering guarantees (issue #62).
    helper_relevant = False
    if current_mode() == "tun":
        helper_relevant = True
    elif PID_FILE.is_file():
        try:
            pid_text = PID_FILE.read_text().strip()
            if pid_text.isdigit() and int(pid_text) > 0:
                pid_int = int(pid_text)
                if _pid_matches(pid_int):
                    if sys.platform == "win32":
                        helper_relevant = True
                    else:
                        out = subprocess.run(
                            ["ps", "-o", "uid=", "-p", str(pid_int)],
                            capture_output=True, text=True, timeout=5,
                        ).stdout.strip()
                        helper_relevant = bool(out) and int(out) == 0
        except (OSError, subprocess.TimeoutExpired, ValueError,
                TypeError, AttributeError):
            # Under mocked environments Popen may lack context-manager
            # support; a non-root verdict is the safe fallback.
            helper_relevant = False

    if sys.platform == "darwin" and _effective_uid() != 0 and helper_relevant:
        # Issue #76: the missing-grant case was already surfaced (with the
        # actionable message) by the early permission gate above, so reaching
        # this point means the helper is installed and authorized.
        rc = _helper_run("start")
        if rc != 0:
            return rc
        if not use_existing_config:
            write_last_good()
            for provider, profile in active.items():
                set_active(provider, profile)
        return 0
    stop_rc = engine_stop()
    if stop_rc != 0:
        # The engine is root-owned (started via `sudo vpn on`) and could not
        # be stopped: starting a second engine would clobber the pid file and
        # strand the live root engine untracked.
        return stop_rc
    # Only rotate here, with the old engine already stopped: renaming a live
    # engine's log would detach its (still open) fd and growth would continue
    # invisibly instead of being bounded.
    rotate_log_if_needed()
    log_handle = None
    try:
        log_handle = LOG_FILE.open("ab")
        popen_kwargs = {"stdout": log_handle, "stderr": subprocess.STDOUT, "cwd": ROOT}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen([sing_box, "run", "-c", str(SING_BOX_CONFIG)], **popen_kwargs)
    except OSError as exc:
        if recover and not use_existing_config and LAST_GOOD_FILE.is_file():
            print("router: could not start generated config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return fail(f"could not start sing-box: {exc}")
    finally:
        if log_handle is not None:
            log_handle.close()
    PID_FILE.write_text(str(process.pid))
    os.chmod(PID_FILE, 0o600)
    _hand_back_ownership(PID_FILE)
    # The elevated start opened LOG_FILE as root (log_handle above); hand it
    # back so non-root readers (log_has_fatal, keepalive rotation, status)
    # can still open it. The engine keeps writing through its inherited fd.
    _hand_back_ownership(LOG_FILE)
    if not wait_engine(log_from=spawn_log_offset):
        engine_stop()
        if recover and not use_existing_config and LAST_GOOD_FILE.is_file():
            print("router: generated config failed to come up; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return fail("sing-box failed to come up")
    if not use_existing_config:
        # The engine demonstrably runs this config: snapshot it as last-good
        # (a later failed reload/start can restore from it) and persist the
        # exact profile selection that was actually launched.
        write_last_good()
        for provider, profile in active.items():
            set_active(provider, profile)
    else:
        # A last-good restore is also allowed to repair stale marker state.
        for provider in _providers:
            live = configured_profile(provider)
            if live is not None:
                set_active(provider, live)
    return 0


def engine_switch() -> int:
    """Apply a provider switch with a hard stop/start lifecycle.

    Route edits can use ``engine_reload``/SIGHUP, but changing WireGuard exits
    must terminate the old process before the new tunnel is brought up. This
    prevents the old session from surviving underneath the selected profile.
    """
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    if not sing_box_at_least(MIN_SING_BOX_VERSION):
        return fail(_sing_box_version_message(MIN_SING_BOX_VERSION))
    previous_config = None
    try:
        if SING_BOX_CONFIG.is_file():
            previous_config = SING_BOX_CONFIG.read_text()
        # A hard switch is an explicit desired-state transition. Do not let
        # configured_profile() prefer the still-running old engine while the
        # new marker is being applied.
        active_overrides: dict[str, Path] = {}
        for name in _providers:
            marker = ROOT / "state" / f"{name}.active"
            if not marker.is_file():
                continue
            stem = marker.read_text().strip()
            profile = next((p for p in provider_files(name) if p.stem == stem), None)
            if profile is not None:
                active_overrides[name] = profile
        config, active = build_singbox_config(active_overrides=active_overrides)
    except (SystemExit, KeyError, ValueError, OSError, configparser.Error) as exc:
        return fail(f"could not build sing-box config: {exc}")
    if not active and not active_proxy_providers():
        return fail("no provider endpoint available")
    write_sing_box(config)
    if not validate_config():
        if previous_config is not None:
            _atomic_write(SING_BOX_CONFIG, previous_config, 0o600)
        return fail("sing-box config check failed")
    if engine_stop() != 0:
        if previous_config is not None:
            _atomic_write(SING_BOX_CONFIG, previous_config, 0o600)
        return fail("engine stop failed during server switch")
    if engine_start(use_existing_config=True) == 0:
        write_last_good()
        return 0
    print("router: new server failed to start; restoring previous config", file=sys.stderr)
    if previous_config is not None:
        _atomic_write(SING_BOX_CONFIG, previous_config, 0o600)
        if validate_config() and engine_start(use_existing_config=True) == 0:
            return 1
    if LAST_GOOD_FILE.is_file():
        restore_last_good()
    return 1


def _config_inputs_fingerprint() -> tuple | None:
    """Cheap fingerprint of everything build_singbox_config() reads.

    Covers router.json plus every provider profile and active/cooldown
    marker under state/, by (path, mtime_ns, size). When this is unchanged,
    the generated config cannot have changed either, so the expensive
    rebuild+compare in _config_drifted can be skipped (keepalive calls
    ensure every 15s; the rebuild includes bounded DNS lookups per peer).
    """
    try:
        entries: list[tuple[str, int, int]] = []
        config_path = CONFIG_FILE
        st = config_path.stat()
        entries.append((str(config_path), st.st_mtime_ns, st.st_size))
        for pattern in ("providers/*/*.conf", "state/*.active", "state/*.cooldown",
                        "state/mode", "state/fallback", "state/egress/*/*.json",
                        "state/autodetect/*.json"):
            for path in ROOT.glob(pattern):
                try:
                    st = path.stat()
                except OSError:
                    continue
                entries.append((str(path), st.st_mtime_ns, st.st_size))
        return tuple(sorted(entries))
    except OSError:
        return None


_DRIFT_CACHE: dict = {"fingerprint": None, "drifted": False}


def _config_drifted() -> bool:
    """True when the running engine's config no longer matches what the
    current router.json + active markers would generate.

    Live-verified failure mode (2026-08-17): after heavy route/marker
    editing the on-disk sing-box.json diverged from reality — the proxy
    listener TLS-failed while transparent capture served traffic, until a
    manual reload converged. The ensure watchdog heals that drift with the
    same graceful in-place reload rotations use.

    The full rebuild+compare runs only when an input file changed since the
    last check; unchanged inputs short-circuit to the cached verdict.
    """
    fingerprint = _config_inputs_fingerprint()
    if fingerprint is not None and fingerprint == _DRIFT_CACHE["fingerprint"]:
        return _DRIFT_CACHE["drifted"]
    try:
        fresh, _active = build_singbox_config()
        running = json.loads(SING_BOX_CONFIG.read_text())
    except (SystemExit, KeyError, ValueError, OSError, configparser.Error, json.JSONDecodeError):
        # never block ensure on a build/read problem; don't cache either
        return False
    drifted = json.dumps(fresh, sort_keys=True) != json.dumps(running, sort_keys=True)
    if fingerprint is not None:
        _DRIFT_CACHE["fingerprint"] = fingerprint
        _DRIFT_CACHE["drifted"] = drifted
    return drifted


def engine_ensure(*, allow_network_off: bool = False) -> int:
    if MANUAL_OFF_FILE.is_file():
        # The user disconnected manually (tray Disconnect / `router.py
        # stop`). keepalive.sh also skips its maintenance while the marker
        # exists (see its manual-off quiescence check), but a stray direct
        # `router.py ensure` must not resurrect the engine either. Return 3
        # (NOT 0): 0 means "healthy, maintenance may proceed" and would let
        # keepalive run egress checks/rotations against a deliberately
        # disconnected tunnel (manual-off is quiescent, not healthy).
        print("router: manually disconnected (manual-off marker present); "
              "run 'router.py start' to reconnect", file=sys.stderr)
        return 3
    if network_off_marker().is_file() and not allow_network_off:
        print("router: Wi-Fi unavailable (network-off marker present); waiting for reconnect",
              file=sys.stderr)
        return 3
    if current_mode() == "tun":
        # A proxy engine running while state/mode says tun is NOT healthy
        # (status/vpn status report it as down); restart into the persisted
        # mode instead of declaring victory (M13).
        if engine_alive() and engine_mode_consistent():
            if _config_drifted():
                print("router: engine config drifted from router.json; reloading in place", file=sys.stderr)
                rc = engine_reload()
                if rc != 0:
                    return rc
            route_watcher_start()
            return 0
        rc = engine_start()
        if rc == 0:
            route_watcher_start()
            return 0
        if rc != 0 and _vpn.get("capture") == "routes":
            # Route-based TUN is explicitly fail-open: remove a dead utun
            # state and leave normal applications on their ordinary routes.
            route_watcher_stop()
            engine_stop()
            set_mode("proxy")
            if sys.platform == "darwin":
                system_proxy_off()
            print("router: transparent TUN unavailable; failing open to direct egress", file=sys.stderr)
        return rc
    # Proxy mode: only a listener owned by OUR engine is "up". A foreign
    # process answering the port while our pid is dead/mismatched is NOT
    # healthy (F1): start the engine instead of declaring victory.
    if listener_up() and engine_alive():
        if _config_drifted():
            print("router: engine config drifted from router.json; reloading in place", file=sys.stderr)
            rc = engine_reload()
            if rc != 0:
                return rc
        route_watcher_start()
        return 0
    rc = engine_start()
    if rc == 0:
        route_watcher_start()
    else:
        route_watcher_stop()
    return rc


class EngineIdentityError(RuntimeError):
    """The process table could not prove engine identity safely."""


def _expected_engine_command() -> str | None:
    """Return the exact command line emitted by ``engine_start``."""
    binary = resolve_sing_box()
    if binary is None:
        return None
    return f"{binary} run -c {SING_BOX_CONFIG}"


def _command_is_our_engine(cmd: str) -> bool:
    """Return true only for the exact resolved binary/argv command line."""
    expected = _expected_engine_command()
    if expected is None:
        return False
    try:
        return shlex.split(str(cmd).strip()) == shlex.split(expected)
    except ValueError:
        return False


def _find_our_engine_pids() -> list[int]:
    """Find exact engine processes, including root-owned orphan candidates.

    The PID file is bookkeeping, not identity.  This scan is deliberately
    fail-closed: an unavailable process table cannot be treated as proof that
    no owned engine exists.
    """
    expected = _expected_engine_command()
    if expected is None:
        raise EngineIdentityError("sing-box binary is unavailable; engine identity is unknown")
    if os.name == "nt":
        # The privileged helper owns Windows lifecycle in supported installs;
        # retain a conservative no-result path for the cross-platform CLI.
        raise EngineIdentityError("exact orphan scan is unavailable on Windows")
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,uid=,command="],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngineIdentityError(f"cannot scan engine processes: {exc}") from exc
    if result.returncode != 0:
        raise EngineIdentityError("cannot scan engine processes")
    pids: list[int] = []
    for line in (result.stdout or "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid = int(parts[0])
            int(parts[1])  # Parse UID as part of the authenticated row.
        except ValueError:
            continue
        if pid > 1 and _command_is_our_engine(parts[2]):
            pids.append(pid)
    return sorted(set(pids))


def _terminate_pid(pid: int) -> bool:
    """Terminate one PID after verifying its exact engine identity."""
    if not _pid_matches(pid):
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            return True
        os.kill(pid, signal.SIGTERM)
        grace_deadline = time.monotonic() + 0.4
        while time.monotonic() < grace_deadline:
            if not _pid_matches(pid):
                break
            time.sleep(0.02)
        if _pid_matches(pid):
            os.kill(pid, signal.SIGKILL)
            kill_deadline = time.monotonic() + 0.5
            while time.monotonic() < kill_deadline:
                if not _pid_matches(pid):
                    break
                time.sleep(0.02)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        raise


def engine_stop() -> int:
    if sys.platform == "darwin" and _effective_uid() != 0:
        helper = _helper_status()
        if helper and helper.get("installed") and helper.get("running"):
            return _helper_run("stop")
    pid_from_file: int | None = None
    if PID_FILE.is_file():
        try:
            pid_from_file = int(PID_FILE.read_text().strip())
        except PermissionError:
            print(_ROOT_ENGINE_HINT, file=sys.stderr)
            return 1
        except (ValueError, OSError):
            PID_FILE.unlink(missing_ok=True)
            pid_from_file = None
        else:
            if not _pid_matches(pid_from_file):
                PID_FILE.unlink(missing_ok=True)
                pid_from_file = None
            else:
                try:
                    _terminate_pid(pid_from_file)
                except PermissionError:
                    print(_ROOT_ENGINE_HINT, file=sys.stderr)
                    return 1
                PID_FILE.unlink(missing_ok=True)
                pid_from_file = None
    try:
        orphans = _find_our_engine_pids()
    except EngineIdentityError as exc:
        print(f"router: cannot prove engine termination: {exc}", file=sys.stderr)
        return 1
    if orphans:
        for pid in orphans:
            try:
                _terminate_pid(pid)
            except PermissionError:
                print(_ROOT_ENGINE_HINT, file=sys.stderr)
                return 1
        # Final proof: per-PID verification, not substring sweep, so a foreign
        # recycled PID that happens to contain our config path cannot cause a
        # false failure and an orphan that changed argv cannot be missed.
        try:
            remaining = [pid for pid in _find_our_engine_pids() if _pid_matches(pid)]
        except EngineIdentityError as exc:
            print(f"router: cannot prove engine termination: {exc}", file=sys.stderr)
            return 1
        if remaining:
            print(f"router: engine survived termination (pids {remaining})", file=sys.stderr)
            return 1
        PID_FILE.unlink(missing_ok=True)
    elif PID_FILE.is_file():
        try:
            maybe = int(PID_FILE.read_text().strip())
        except PermissionError:
            print(_ROOT_ENGINE_HINT, file=sys.stderr)
            return 1
        except (ValueError, OSError):
            PID_FILE.unlink(missing_ok=True)
        else:
            if not _pid_matches(maybe):
                PID_FILE.unlink(missing_ok=True)
    return 0


def _elevated_reload() -> int:
    """Reload through the exact root-owned helper, never checkout code."""
    status = _helper_status()
    if not status or not status.get("installed"):
        # Issue #76: same actionable wording as the start path — this fires
        # from the tray's preset-apply/reload when only elevation is missing.
        return fail(_HELPER_NOT_INSTALLED)
    return _helper_run("reload")

# ---------------------------------------------------------------------------
# network-aware preset switching
# ---------------------------------------------------------------------------

def current_ssid() -> str | None:
    """Active Wi-Fi SSID via `ipconfig getsummary` (macOS, read-only).

    Returns None when Wi-Fi is off or no interface answers. Pure getter;
    tests inject synthetic output through subprocess mocks.
    """
    for iface in ("en0", "en1"):
        try:
            probe = subprocess.run(
                ["ipconfig", "getsummary", iface],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode != 0:
            continue
        for line in probe.stdout.splitlines():
            if line.strip().startswith("SSID"):
                _, _, value = line.partition(":")
                ssid = value.strip()
                return ssid or None
    return None


def network_status() -> dict:
    """Return the current physical Wi-Fi state without touching the engine.

    The guard is implemented for macOS, where ``ipconfig getsummary`` is the
    same read-only source already used by network-aware presets. Other
    platforms report ``supported: false`` and stay connected so keepalive
    cannot tear down a VPN based on an unavailable platform probe.
    """
    checked_at = int(time.time())
    if sys.platform != "darwin":
        return {"connected": True, "ssid": None, "supported": False,
                "checked_at": checked_at}
    ssid = current_ssid()
    return {"connected": bool(ssid), "ssid": ssid, "supported": True,
            "checked_at": checked_at}


def network_off_marker(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else ROOT) / "state" / "network-off"


def _write_network_off() -> int:
    """Publish an automatic network-stop latch before teardown."""
    try:
        _atomic_write(
            network_off_marker(),
            f"network unavailable {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n",
        )
    except OSError as exc:
        print(f"router: could not write network-off marker: {exc}", file=sys.stderr)
        return 1
    return 0


def _clear_network_off() -> int:
    """Clear the automatic latch, or report a durable-state failure."""
    try:
        network_off_marker().unlink(missing_ok=True)
    except OSError as exc:
        print(f"router: cannot clear network-off marker: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_network_status(as_json: bool = False) -> int:
    result = network_status()
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        state = "connected" if result["connected"] else "disconnected"
        ssid = f" ({result['ssid']})" if result.get("ssid") else ""
        print(f"network: {state}{ssid}")
    return 0 if result["connected"] else 1


def cmd_network_disconnect() -> int:
    """Stop proxy-router after Wi-Fi loss while allowing later auto-reconnect."""
    if MANUAL_OFF_FILE.is_file():
        return 3
    if _write_network_off() != 0:
        return 1
    route_watcher_stop()
    proxy_rc = system_proxy_off() if sys.platform == "darwin" else 0
    engine_rc = _with_lock(engine_stop, timeout=5.0)
    if proxy_rc != 0 or engine_rc != 0:
        if proxy_rc != 0:
            print("router: network disconnect could not disable system proxy", file=sys.stderr)
        if engine_rc != 0:
            print("router: network disconnect could not prove engine stopped; retrying", file=sys.stderr)
        return proxy_rc or engine_rc
    print("router: Wi-Fi unavailable; proxy-router disconnected until the network returns")
    return 0


def cmd_network_reconnect() -> int:
    """Re-arm proxy-router after the Wi-Fi network returns."""
    if MANUAL_OFF_FILE.is_file():
        return 3
    if not network_off_marker().is_file():
        return 0
    if sys.platform == "darwin" and not current_ssid():
        return 2
    if load_config() != 0:
        return 1
    rc = _with_lock(lambda: engine_ensure(allow_network_off=True), timeout=5.0)
    if rc != 0:
        return rc
    route_watcher_start()
    if sys.platform == "darwin":
        proxy_rc = system_proxy_on() if current_mode() == "proxy" else system_proxy_off()
        if proxy_rc != 0:
            route_watcher_stop()
            _with_lock(engine_stop, timeout=5.0)
            return proxy_rc
    if _clear_network_off() != 0:
        return 1
    print("router: Wi-Fi returned; proxy-router reconnected")
    return 0


def network_preset_map() -> dict[str, str]:
    """SSID -> preset mapping from ``vpn.network_presets``."""
    raw = _vpn.get("network_presets") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(ssid): str(name) for ssid, name in raw.items() if ssid and name}


def network_auto_enabled() -> bool:
    return bool(_vpn.get("network_auto", False))


def preset_for_current_network() -> str | None:
    """Preset mapped to the connected SSID, or None when auto is off."""
    if not network_auto_enabled():
        return None
    ssid = current_ssid()
    if not ssid:
        return None
    return network_preset_map().get(ssid)


def network_preset_marker(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else ROOT) / "state" / "network-preset.json"


def apply_network_preset(*, reload_engine: bool = True, root: Path | None = None) -> dict:
    """Auto-switch the routing preset for the current network; no-op when unchanged.

    Applies the mapped preset with ``setup_tui.apply_preset_by_name`` (lossless
    merge: routes/providers are added, nothing removed) and, when the preset
    changed, reloads the engine so the change goes live. Writes the
    ``state/network-preset.json`` marker for the status/tray surface.
    """
    root = Path(root) if root is not None else ROOT
    preset = preset_for_current_network()
    now = int(time.time())
    if preset is None:
        return {"applied": False, "reason": "no network mapping", "checked_at": now}
    try:
        current = json.loads((root / "router.json").read_text()).get("preset")
    except (OSError, json.JSONDecodeError):
        current = None
    if current == preset:
        return {"applied": False, "reason": "already active", "preset": preset, "checked_at": now}
    from setup_tui import apply_preset_by_name
    result = apply_preset_by_name(root, preset)
    marker = network_preset_marker(root)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({
        "ssid": current_ssid(),
        "preset": preset,
        "applied_at": now,
    }))
    os.chmod(marker, 0o600)
    if reload_engine:
        if _engine_runs_as_root():
            result["reload_rc"] = _elevated_reload()
        else:
            result["reload_rc"] = engine_reload()
    return {"applied": True, **result, "preset": preset, "checked_at": now}


def cmd_network_check() -> int:
    """Auto-switch the routing preset for the current network (SSID)."""
    def apply() -> dict | int:
        # Read the config under the same lock as the preset write/reload. This
        # prevents a concurrent route or fallback edit from leaving the
        # in-memory provider table out of sync with the file being applied.
        if load_config() != 0:
            return 1
        return apply_network_preset()

    # Network-aware preset application rewrites router.json and may reload the
    # engine. It is also invoked by the route watcher, so it must share the
    # lifecycle lock with stop/reload/rotate rather than racing them.
    result = _with_lock(apply)
    if not isinstance(result, dict):
        return int(result) if isinstance(result, int) else 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("reload_rc", 0) == 0 else 1


def engine_reload(active_overrides: dict[str, Path] | None = None) -> int:
    overrides = dict(active_overrides or {})
    if RELOAD_OVERRIDE_FILE.is_file():
        # an elevated rerun picks up the invoking user's pending candidates
        try:
            pending = json.loads(RELOAD_OVERRIDE_FILE.read_text())
            if isinstance(pending, dict):
                overrides.update({name: Path(path) for name, path in pending.items()})
        except (OSError, json.JSONDecodeError, TypeError):
            pass
        RELOAD_OVERRIDE_FILE.unlink(missing_ok=True)
    active_overrides = overrides or None
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    if not sing_box_at_least(MIN_SING_BOX_VERSION):
        return fail(f"{_sing_box_version_message(MIN_SING_BOX_VERSION)}")
    try:
        config, active = build_singbox_config(active_overrides)
    except (SystemExit, KeyError, ValueError, OSError, configparser.Error) as exc:
        # Nothing was written or reloaded, so the running engine keeps its
        # old in-memory config; fail cleanly (no last-good restore needed).
        return fail(f"could not build sing-box config: {exc}")
    if not active and not active_proxy_providers():
        return fail("no provider endpoint available")
    write_sing_box(config)
    if not validate_config():
        # The bad config is already on disk; restore the last known-good one
        # so a crash/restart can never boot it (F2: bad generated config must
        # not leave the proxy dead while a known-good config exists).
        print("router: new sing-box config failed validation; restoring last-good", file=sys.stderr)
        return restore_last_good()
    if sys.platform == "darwin" and _effective_uid() != 0:
        helper = _helper_status()
        if helper and helper.get("installed") and helper.get("running"):
            rc = _helper_run("reload")
            if rc == 0:
                write_last_good()
                for provider, profile in active.items():
                    set_active(provider, profile)
            return rc
    if not PID_FILE.is_file():
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        write_last_good()
        return 0
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        PID_FILE.unlink(missing_ok=True)
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        write_last_good()
        return 0
    if not _pid_matches(pid):
        PID_FILE.unlink(missing_ok=True)
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        write_last_good()
        return 0
    if os.name == "nt":
        # Windows has no SIGHUP; stop+start applies the fresh config.
        if engine_stop() != 0:
            return fail("engine stop failed during reload")
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        write_last_good()
        return 0
    reload_log_from = log_offset()
    try:
        os.kill(pid, signal.SIGHUP)  # SIGHUP: sing-box hot-reloads the config in place
    except PermissionError:
        if _effective_uid() != 0:
            if overrides:
                RELOAD_OVERRIDE_FILE.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write(RELOAD_OVERRIDE_FILE,
                              json.dumps({name: str(path) for name, path in overrides.items()}), 0o600)
            print("router: engine runs as root; reloading through the safe helper",
                  file=sys.stderr)
            return _elevated_reload()
        return fail("root engine reload requires `router.py elevate install`; "
                    "whole-controller sudo is intentionally disabled")
    except ProcessLookupError:
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        write_last_good()
        return 0
    # In tun mode a fresh WireGuard handshake routinely needs >2s before an
    # end-to-end egress probe can succeed; a 2s budget almost always failed
    # here and degraded every tun-mode reload into a full stop/start
    # (multi-second traffic cut). Give the handshake a realistic budget —
    # proxy mode keeps the snappy 2s (listener answers in ms).
    reload_wait = 12.0 if current_mode() == "tun" else 2.0
    if wait_engine(reload_wait, log_from=reload_log_from):
        # The new config demonstrably runs: snapshot it as last-good.
        write_last_good()
        return 0
    # SIGHUP did not come up cleanly; try a full (re)start of the new config
    # before giving up and restoring last-good.
    print("router: engine did not come up after SIGHUP; trying a full start", file=sys.stderr)
    if engine_start(recover=False) != 0:
        print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
        return restore_last_good()
    # The restart path applies the new config just like a clean SIGHUP
    # would; snapshot it so the next failure restores THIS config, not an
    # older one (parity with the SIGHUP success path).
    write_last_good()
    return 0


def rotate(name: str, *, reason: str | None = None, force: bool = False, probe: bool = True,
           to: str | None = None, automatic: bool = False) -> int:
    """Switch to the next healthy profile for ``name``.

    - Egress-aware selection: cooled-down profiles are skipped as before, and
      blocked exits (Cloudflare 1010/403) too unless ``force``; the remaining
      candidates are ranked so recently-OK, lower-latency exits are preferred
      over unknown ones and known-failing ones.
    - ``reason`` (rotate --reason): the CURRENT profile just failed upstream;
      it gets a longer cooldown + recorded reason (and a blocked marker for
      reputation-block reasons) so the next rotation prefers a different exit.
    - ``to`` (rotate --to PROFILE): switch to this exact exit instead of the
      ranked next one (used by the tray provider picker). The profile must
      exist and parse; blocked exits are honored unless ``force``, so a manual
      pick can still be refused when the exit is reputation-blocked.
    - Last-good rollback: after switching, the new exit is probed through the
      tunnel (proxy mode); if it fails to come up cleanly, the previous good
      profile is restored.
    - ``automatic`` marks a supervisor-triggered rotation. It is rejected in
      TUN mode so a mode change between the keepalive shell check and this
      controller call cannot reload the shared engine.
    """
    if automatic and not _automatic_proxy_mode():
        return 3
    if active_fallback(name):
        return fail(f"provider '{name}': fallback active; clear it before rotating the primary")
    if is_proxy_provider(name):
        return fail(f"provider '{name}' is proxy-backed (a SOCKS5 hop has no profiles to rotate); "
                      "use its fallback to move routes instead")
    profiles = provider_files(name)
    if not profiles:
        return fail(f"provider '{name}' has no profiles")
    # Keep only parseable profiles so one bad *.conf cannot wedge rotation
    # (F6); log every skipped filename (F2).
    valid: list[Path] = []
    for profile in profiles:
        error = _profile_error(profile)
        if error is not None:
            print(f"router: skipping bad profile {profile.name} of '{name}': {error}", file=sys.stderr)
            continue
        valid.append(profile)
    if not valid:
        return fail(f"provider '{name}' has no valid profiles (all *.conf are malformed)")
    try:
        seconds = int(_providers.get(name, {}).get("cooldown_seconds", 60))
    except (TypeError, ValueError):
        return fail(f"provider '{name}': cooldown_seconds must be an integer")
    current = persisted_active(name) or resolve_active(name)
    chosen = None
    if to is not None:
        chosen = next((p for p in valid if p.stem == to), None)
        if chosen is None:
            return fail(f"provider '{name}': no valid profile named '{to}' (have {', '.join(p.stem for p in valid)})")
        # Re-selecting the already-active exit is a no-op. It must NOT
        # cooldown the current profile or fail on its own cooldown state
        # -- the old code marked the current exit cooling, then refused
        # the pick with "exit is cooling down", a nonsense error for a
        # click that should just confirm "already on it".
        if not force and chosen == current:
            print(f"already on {name} -> {chosen.stem}")
            return 0
    if reason is not None:
        # Keep an established TLS quarantine intact when keepalive reports the
        # same failure through its generic timeout channel. Only borrow the TLS
        # policy when profile, target, and recorded failure all match.
        if automatic and reason == "timeout" and current is not None:
            record = read_egress(name, current)
            target = probe_url_for(name)
            if (target and _tls_failed(record) and is_cooled_down(name, current)
                    and record.get("upstream_error") == "tls"
                    and record.get("tls_target") == hashlib.sha256(target.encode()).hexdigest()):
                reason = "tls"
        _apply_upstream_failure(name, current, reason, seconds)
    elif current is not None and not is_cooled_down(name, current) and not force:
        mark_cooldown(name, current, seconds)
    if to is not None:
        assert chosen is not None  # resolved and validated in the block above
        if not force and egress_is_blocked(name, chosen):
            return fail(f"provider '{name}': exit '{to}' is blocked (use 'rotate --force' to override)")
        if not force and current is not None and is_cooled_down(name, chosen) and chosen == current:
            mark_cooldown(name, current, seconds)  # keep the manual pick from pinning a cooling exit
        if not force and is_cooled_down(name, chosen):
            return fail(f"provider '{name}': exit '{to}' is cooling down (use 'rotate --force' to override)")
    else:
        if current in valid:
            start = valid.index(current) + 1
            ordered = valid[start:] + valid[:start]
        else:
            ordered = valid
        if force:
            chosen = ordered[0]
        else:
            cooled = [p for p in ordered if not is_cooled_down(name, p)]
            if not cooled:
                return fail(f"provider '{name}': all profiles cooling down")
            unblocked = [p for p in cooled if not egress_is_blocked(name, p)]
            if not unblocked:
                return fail(f"provider '{name}': no unblocked profile available (use 'rotate --force' to override)")
            if rotation_policy() == "least-recent":
                # Autoroute: among known-good exits (no repeated failures),
                # prefer the one used longest ago so usage spreads across
                # the pool and upstream rate limits see a fresh egress IP.
                candidates = [
                    p for p in unblocked
                    if _egress_rank(read_egress(name, p))[0] < 3
                ] or unblocked
                chosen = min(candidates, key=lambda p: (_lru_key(read_egress(name, p)), p.stem))
            else:
                chosen = min(unblocked, key=lambda p: _egress_rank(read_egress(name, p)))
    if force:
        clear_blocked(name, chosen)
    previous = current
    rc = engine_reload({name: chosen})
    if rc != 0:
        # The old marker remains intact, so a failed reload cannot claim the
        # candidate is live. engine_reload restores last-good when possible.
        return rc
    set_active(name, chosen)
    record_rotation(name, chosen)
    print(f"switched {name} -> {chosen.stem}")
    # The reload applied the new exit in place: SIGHUP regenerates the
    # endpoint set without restarting the process, so the TUN interface,
    # routes, and listener sockets survive the switch (in-flight flows
    # still reset; nothing else does). If SIGHUP could not come up,
    # engine_reload already fell back to a full start internally.
    if probe and not listener_up():
        # Transparent TUN keeps the mixed listener alongside the TUN inbound,
        # so rotation can still validate the new profile through 127.0.0.1.
        # Only skip the probe when no local listener is actually available.
        probe = False
    if not probe:
        return 0
    ok, _ = _probe_with_settle(name, chosen)
    if ok:
        return 0
    # The new exit did not come up cleanly: restore the last good profile
    # (one bounded step, never a loop) so the listener keeps working.
    print(f"router: egress probe failed for {chosen.stem}; restoring '{name}' to previous profile", file=sys.stderr)
    if previous is None or previous == chosen or previous not in valid or egress_is_blocked(name, previous):
        print("router: no usable previous profile to roll back to", file=sys.stderr)
        return 1
    mark_cooldown(name, chosen, max(seconds * 2, int(egress_settings()["upstream_cooldown_seconds"])))
    if reason is None:
        # Plain rotations cooldown the previous profile only as a mild
        # preference; restoring it must undo that so the last-good exit is
        # immediately usable again. A --reason rotation marks the previous
        # profile as FAILED upstream (429/503/TLS...); its cooldown is the
        # whole point of the mark and must survive the rollback, otherwise
        # we ping-pong A -> B -> A -> C -> A forever, burning the pool while
        # the tunnel keeps returning to the broken exit.
        _clear_cooldown(name, previous)
    set_active(name, previous)
    record_rotation(name, previous)
    print(f"switched {name} -> {previous.stem} (rollback)")
    rollback_rc = engine_reload({name: previous})
    # The rollback restored service, but the requested rotation failed. A
    # non-zero result is required so callers can activate the configured
    # provider fallback instead of treating the rollback as success.
    return rollback_rc if rollback_rc != 0 else 1


def provider_count(name: str) -> int:
    """Number of rotation candidates for a provider (used as a retry budget by
    hermes-opencode.sh); at least 1 so callers always attempt once."""
    return max(1, len(provider_files(name)))


# ---------------------------------------------------------------------------
# route table management
# ---------------------------------------------------------------------------

def save_config() -> int:
    try:
        data = json.loads(CONFIG_FILE.read_text())
        data["routes"] = _routes
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=CONFIG_FILE.parent,
                prefix=f".{CONFIG_FILE.name}.", suffix=".tmp", delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(json.dumps(data, indent=2) + "\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, CONFIG_FILE)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        os.chmod(CONFIG_FILE, 0o600)
    except (json.JSONDecodeError, OSError, TypeError) as exc:
        return fail(f"could not save {CONFIG_FILE.name}: {exc}")
    return 0


def routes_list() -> int:
    for route in _routes:
        targets = ",".join(route.get("domains", []) + route.get("ip_cidr", []))
        print(f"  {route['id']:<16} {targets:<52} -> {route['provider']}")
    return 0


def _routes_add_entry(target: str, key: str, id_: str | None, provider: str) -> tuple[str, str] | None:
    """Add or update a route in the in-memory table.

    Merges into the existing entry's list (appending unique values) instead of
    overwriting, so ``routes add`` never drops previously configured targets
    (F4). Returns (key, id) on success, or None when the target is empty or
    the provider is unknown.
    """
    if not target or provider not in _providers:
        return None
    id_ = id_ or re.sub(r"[^a-z0-9-]", "-", target.lower())
    existing = next((r for r in _routes if r.get("id") == id_), None)
    if existing is None:
        existing = {"id": id_, "provider": provider}
        _routes.append(existing)
    entries = existing.get(key)
    if not isinstance(entries, list):
        entries = []
    if target not in entries:
        entries.append(target)
    existing[key] = entries
    existing["provider"] = provider
    return key, id_


def routes_add(args) -> int:
    # Honor BOTH --domain and --ip when provided (F4).
    targets: list[tuple[str, str]] = []
    if args.domain:
        targets.append(("domains", args.domain))
    if args.ip:
        targets.append(("ip_cidr", args.ip))
    if not targets:
        return fail("need --domain or --ip")
    if args.provider not in _providers:
        return fail(f"unknown provider '{args.provider}' (have {', '.join(_providers)})")
    for key, target in targets:
        _routes_add_entry(target, key, args.id, args.provider)
    if save_config() != 0:
        return 1
    if engine_reload() != 0:
        return fail("route saved but engine reload failed")
    routes_list()
    return 0


def _routes_remove_entry(id_: str) -> bool:
    """Remove the route with the given id from the in-memory table."""
    before = len(_routes)
    _routes[:] = [r for r in _routes if r.get("id") != id_]
    return len(_routes) != before


def routes_remove(id_: str) -> int:
    if not _routes_remove_entry(id_):
        return fail(f"no route with id '{id_}'")
    if save_config() != 0:
        return 1
    if engine_reload() != 0:
        return fail("route removed but engine reload failed")
    return 0


# ---------------------------------------------------------------------------
# routing modes (safe-list / vpn-list)
# ---------------------------------------------------------------------------

ROUTING_MODES = ("safe-list", "vpn-list")


def routing_state() -> dict:
    """Effective routing-mode view: ``mode`` (default|safe-list|vpn-list),
    ``direct_domains``, ``vpn_domains``, ``default_provider``.

    An absent ``routing`` section means 'default' mode (per-domain provider
    routes, ``route.final`` = direct) - the pre-routing-modes behavior.
    """
    routing = _routing if isinstance(_routing, dict) else {}
    return {
        "mode": routing.get("mode", "default"),
        "direct_domains": list(routing.get("direct_domains", []) or []),
        "vpn_domains": list(routing.get("vpn_domains", []) or []),
        "default_provider": routing.get("default_provider"),
        "health_order": bool(routing.get("health_order", False)),
    }


def _routing_error(routing: dict, known_providers: set) -> str | None:
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


def _routing_mutate(routing: dict) -> int:
    """Persist a routing section into router.json atomically (temp + replace,
    mode 0600, same convention as every other config write) and refresh the
    in-memory state. Never touches the engine - the operator runs
    ensure/reload separately."""
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict):
            return fail(f"bad {CONFIG_FILE.name}: top level must be an object")
        data["routing"] = routing
        _atomic_write(CONFIG_FILE, json.dumps(data, indent=2) + "\n", 0o600)
    except (json.JSONDecodeError, OSError, TypeError) as exc:
        return fail(f"could not save routing in {CONFIG_FILE.name}: {exc}")
    global _routing
    _routing = dict(routing)
    return 0


def _routing_print(state: dict, *, note: bool = False) -> None:
    """Print an effective routing state: JSON on stdout (machine-readable),
    one human summary line on stderr. ``note`` adds the no-reload reminder
    (mutating commands only)."""
    print(json.dumps(state, indent=2, sort_keys=True))
    if state["mode"] == "safe-list":
        direct = ", ".join(state["direct_domains"]) or "(none)"
        print(f"mode safe-list: direct {direct}; everything else via {state['default_provider']}", file=sys.stderr)
    elif state["mode"] == "vpn-list":
        vpn = ", ".join(state["vpn_domains"]) or "(none)"
        print(f"mode vpn-list: tunnel {vpn}; everything else direct", file=sys.stderr)
    else:
        print("mode default: per-domain provider routes, route.final = direct", file=sys.stderr)
    if note:
        print("config saved; the engine was NOT reloaded - run 'router.py ensure' (or 'router.py reload') to apply", file=sys.stderr)


def routing_cli_show() -> int:
    _routing_print(routing_state())
    return 0


def routing_cli_set(mode: str, default_provider: str | None) -> int:
    routing = dict(_routing if isinstance(_routing, dict) else {})
    routing["mode"] = mode
    if default_provider is not None:
        routing["default_provider"] = default_provider
    error = _routing_error(routing, set(_providers))
    if error is not None:
        return fail(error)
    if _routing_mutate(routing) != 0:
        return 1
    _routing_print(routing_state(), note=True)
    return 0


def routing_cli_add(mode: str, domain: str) -> int:
    key = "direct_domains" if mode == "safe-list" else "vpn_domains"
    routing = dict(_routing if isinstance(_routing, dict) else {})
    entries = list(routing.get(key, []) or [])
    if domain in entries:
        print(f"routing: '{domain}' is already on the {key} list (no change)", file=sys.stderr)
        _routing_print(routing_state(), note=True)
        return 0
    entries.append(domain)
    routing[key] = entries
    error = _routing_error(routing, set(_providers))
    if error is not None:
        return fail(error)
    if _routing_mutate(routing) != 0:
        return 1
    _routing_print(routing_state(), note=True)
    return 0


def routing_cli_remove(mode: str, domain: str) -> int:
    key = "direct_domains" if mode == "safe-list" else "vpn_domains"
    routing = dict(_routing if isinstance(_routing, dict) else {})
    entries = list(routing.get(key, []) or [])
    if domain not in entries:
        print(f"routing: '{domain}' is not on the {key} list (no change)", file=sys.stderr)
        _routing_print(routing_state(), note=True)
        return 0
    entries.remove(domain)
    routing[key] = entries
    if _routing_mutate(routing) != 0:
        return 1
    _routing_print(routing_state(), note=True)
    return 0


# ---------------------------------------------------------------------------
# VPN (TUN) toggle
# ---------------------------------------------------------------------------

def vpn_note() -> None:
    """Per-OS caveats when switching to tun mode; prints to stderr, not an error."""
    if current_mode() != "tun":
        return
    if sys.platform == "darwin":
        print("router: tun mode on macOS needs root (create utun interface); run with sudo", file=sys.stderr)
        print("router: tun mode on macOS is NOT a System Settings VPN entry (requires a signed NE app); it is a utun interface", file=sys.stderr)
    elif os.name == "nt":
        print("router: tun mode on Windows needs an elevated shell (admin) and wintun.dll next to sing-box.exe", file=sys.stderr)


def _write_manual_off() -> int:
    """Publish manual-stop intent atomically before lifecycle teardown."""
    try:
        MANUAL_OFF_FILE.parent.mkdir(parents=True, exist_ok=True)
        MANUAL_OFF_FILE.write_text(
            f"manual stop {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n",
            encoding="utf-8",
        )
        try:
            MANUAL_OFF_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        print(f"router: could not write manual-off marker: {exc}", file=sys.stderr)
        return 1
    return 0


def _clear_manual_off() -> int:
    """Clear both explicit and automatic disconnect latches."""
    try:
        MANUAL_OFF_FILE.unlink(missing_ok=True)
        network_off_marker().unlink(missing_ok=True)
    except OSError as exc:
        print(f"router: cannot clear disconnect marker: {exc}", file=sys.stderr)
        return 1
    return 0


def vpn_on() -> int:
    # Explicit reconnect must reconcile manual-off only after the new engine
    # and its required surface have succeeded.
    if current_mode() == "tun":
        if engine_alive() and engine_mode_consistent():
            print("vpn: tun already up")
            route_watcher_start()
            if sys.platform == "darwin":
                proxy_rc = system_proxy_off()
                if proxy_rc != 0:
                    _clear_manual_off()
                    return proxy_rc
            return _clear_manual_off()
        set_mode("proxy")

    old_mode = current_mode()
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    if not sing_box_at_least(MIN_SING_BOX_VERSION):
        return fail(f"{_sing_box_version_message(MIN_SING_BOX_VERSION)}")

    # Pre-flight BEFORE persisting mode (H5): build + validate the tun config
    # with the current providers. On failure, state/mode is restored and the
    # keepalive keeps running the proxy instead of hammering a broken tun.
    set_mode("tun")
    ok = False
    try:
        config, active = build_singbox_config()
        if not active:
            return fail("no provider profile available (drop *.conf into providers/<name>/)")
        write_sing_box(config)
        if not validate_config():
            return fail("sing-box config check failed for tun mode")
        ok = True
    except SystemExit as exc:
        return fail(str(exc) or "config build failed")
    except Exception as exc:  # noqa: BLE001 - CLI boundary: report, don't crash
        return fail(f"tun pre-flight failed: {exc}")
    finally:
        if not ok:
            set_mode(old_mode)

    vpn_note()
    rc = engine_start()
    if rc != 0:
        # Engine failed to come up (e.g. no root for utun on macOS): restore
        # the previous mode. engine_start already stopped whatever proxy was
        # running, so bring the proxy engine back immediately instead of
        # leaving the user without connectivity until keepalive re-arms it.
        set_mode(old_mode)
        if old_mode == "proxy" and not listener_up():
            engine_start()
        return rc
    # Tun mode routes ordinary traffic through the utun interface while the
    # generated config keeps the mixed 127.0.0.1:<port> listener alongside it
    # for proxy-pinned clients. Leaving the macOS system proxy enabled would
    # still force browsers through that listener instead of using transparent
    # capture, so disable it once tun is up.
    if sys.platform == "darwin":
        proxy_rc = system_proxy_off()
        if proxy_rc != 0:
            # The engine is up; remove the stale manual latch so supervision
            # can keep the verified engine alive while the caller retries the
            # non-critical system-proxy cleanup.
            _clear_manual_off()
            return proxy_rc
    return _clear_manual_off()


def _vpn_off_without_config() -> int:
    """Fail open to direct egress when TUN cannot be replaced from bad config."""
    if _write_manual_off() != 0:
        return 1
    if sys.platform == "darwin" and system_proxy_off() != 0:
        print("router: vpn off: could not disable system proxy", file=sys.stderr)
        return 1
    route_watcher_stop()
    rc = _with_lock(engine_stop, timeout=5.0)
    if rc != 0:
        return rc
    set_mode("proxy")
    print(
        "router: vpn off: configuration is unusable; engine stopped and traffic "
        "left direct (repair router.json before reconnecting)",
        file=sys.stderr,
    )
    return 1


def vpn_off() -> int:
    """Switch from TUN to proxy mode as one stop-then-start transaction."""
    rc = engine_stop()
    if rc != 0:
        # Do not claim proxy mode while the TUN engine is still alive.
        return rc

    # The old engine is proven down; now commit the replacement mode and
    # reconcile any previous manual-off latch because this is an explicit
    # reconnect-like operation, not a full Disconnect.
    set_mode("proxy")
    if _clear_manual_off() != 0:
        return 1
    rc = engine_start()
    if rc != 0:
        print("router: vpn off: proxy engine failed to start", file=sys.stderr)
        return rc
    if sys.platform == "darwin":
        proxy_rc = system_proxy_on()
        if proxy_rc != 0:
            return proxy_rc
    return 0


def vpn_restart() -> int:
    """Stop the current engine and bring TUN back up in a single operation.

    One elevated invocation means one macOS admin-password prompt for the
    whole cycle, instead of two with `vpn off && vpn on`."""
    rc = engine_stop()
    if rc != 0:
        return rc
    return vpn_on()


def vpn_capture(scope: str) -> int:
    """Set TUN capture scope and reload an already-running TUN engine."""
    if scope not in ("ruleset", "routes"):
        return fail("vpn capture scope must be 'ruleset' or 'routes'")
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict):
            return fail(f"bad {CONFIG_FILE.name}: top level must be an object")
        vpn = data.get("vpn", {})
        if not isinstance(vpn, dict):
            return fail(f"bad {CONFIG_FILE.name}: vpn must be an object")
        vpn["capture"] = scope
        data["vpn"] = vpn
        _atomic_write(CONFIG_FILE, json.dumps(data, indent=2) + "\n", 0o600)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return fail(f"could not write {CONFIG_FILE.name}: {exc}")
    _vpn.clear()
    _vpn.update(vpn)
    if current_mode() == "tun" and engine_alive():
        rc = engine_reload()
        if rc != 0:
            return rc
    print(f"vpn: capture={scope} (engine not started)")
    return 0


def _status_report() -> tuple[int, str]:
    """Single liveness check shared by `status` and `vpn status` (M13): both
    commands must report the same up/down state and exit code so automation
    cannot disagree with a human reading one or the other.

    Returns (rc, line) with rc == 0 only when the engine is running AND its
    generated config matches the persisted mode (tun engine for tun mode,
    proxy listener for proxy mode); anything else is a degraded/down state
    with rc == 1.
    """
    mode = current_mode()
    if mode == "tun":
        if engine_alive() and engine_mode_consistent():
            return 0, "up (tun)"
        if engine_alive():
            return 1, "down (running engine does not match tun mode; run 'vpn on')"
        return 1, "down (mode set to tun; run 'vpn on')"
    if listener_up() and engine_alive():
        proxy_status, _effective = _system_proxy_status_readonly()
        suffix = "" if proxy_status in {"ok", "skipped"} else f"; {proxy_status}"
        return 0, "up (proxy 127.0.0.1:{}{})".format(_port, suffix)
    if listener_up():
        # F1: something answers the port but it is not our engine (stale pid
        # file or a recycled/foreign process); never report that as up.
        return 1, "down (foreign listener on 127.0.0.1:{}; run 'start')".format(_port)
    return 1, "down (proxy mode; run 'vpn on' for tun, 'start' for proxy)"


def _macos_dns_snapshot(runner=subprocess.run) -> dict:
    """Read configured and DHCP DNS state without changing network settings."""
    configured: dict[str, list[str]] = {}
    services = network_services(runner)
    for service in services:
        try:
            result = _run_result(runner, ["networksetup", "-getdnsservers", service],
                                 capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
            continue
        if getattr(result, "returncode", 0) != 0:
            continue
        servers = []
        for line in (getattr(result, "stdout", "") or "").splitlines():
            value = line.strip()
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            servers.append(value)
        configured[service] = servers

    iface = None
    try:
        route = _run_result(runner, ["route", "-n", "get", "default"], capture_output=True,
                            text=True, timeout=5)
        for line in (getattr(route, "stdout", "") or "").splitlines():
            if "interface:" in line:
                iface = line.split()[-1]
                break
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        pass
    dhcp: list[str] = []
    if iface:
        try:
            packet = _run_result(runner, ["ipconfig", "getpacket", iface], capture_output=True,
                                 text=True, timeout=5)
            text = getattr(packet, "stdout", "") or ""
            for value in re.findall(r"(?:domain_name_server|name_server)[^:]*:\s*\(?([^\)]*)\)?",
                                    text, re.IGNORECASE):
                for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,}", value):
                    try:
                        ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if candidate not in dhcp:
                        dhcp.append(candidate)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
            pass
    active = active_service_name(runner)
    active_configured = configured.get(active or "", [])
    return {
        "active_service": active,
        "configured": configured,
        "active_configured": active_configured,
        "dhcp": dhcp,
        "public_configured": any(not _probe_addr_is_private(server)
                                  for server in active_configured),
        "dhcp_available": bool(dhcp),
    }


def _direct_https_probe(url: str, *, opener=None, timeout: float = 4.0,
                        clock=time.monotonic, resolved_addresses=None) -> dict:
    """Bounded HTTPS request that explicitly bypasses HTTP proxy settings."""
    violation = unsafe_probe_target(url, resolved_addresses=resolved_addresses)
    if violation:
        return {"status": "skipped", "error": f"unsafe probe target: {violation}"}
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": "proxy-router-doctor/1.0"})
    started = clock()
    response = None
    try:
        response = _open_probe(opener, request, timeout)
        response.read(4096)
        code = int(getattr(response, "status", getattr(response, "code", 200)))
        return {"status": "ok" if 200 <= code < 500 else "failed",
                "http_status": code, "latency_ms": round((clock() - started) * 1000, 2)}
    except urllib.error.HTTPError as exc:
        # HTTP 403/429 is an application response and proves the direct path
        # reached the endpoint; it is not a DNS or connection failure.
        return {"status": "ok" if exc.code < 500 else "direct_connection_failed",
                "http_status": int(exc.code), "error": None if exc.code < 500 else str(exc)}
    except (OSError, urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        detail = _egress_error_text(exc)
        return {"status": "direct_connection_failed", "error": detail}
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _diagnostic_host_is_routed(host: str) -> bool:
    """Return whether a host is selected by the configured VPN route graph."""
    host = (host or "").rstrip(".").lower()
    routing = routing_state()
    direct = routing.get("direct_domains") or [] if routing.get("mode") == "safe-list" else []
    if any(host == str(domain).lstrip("*.").lower() or
           host.endswith("." + str(domain).lstrip("*.").lower()) for domain in direct):
        return False
    if routing.get("mode") == "safe-list" and routing.get("default_provider"):
        return True
    for route in _routes:
        for domain in route.get("domains") or []:
            normalized = str(domain).lstrip("*.").lower()
            if host == normalized or host.endswith("." + normalized):
                return True
    return False


def _diagnostic_direct_url() -> str | None:
    """Choose a public HTTPS target that is explicitly outside the route graph."""
    candidates = [DEFAULT_DIRECT_PROBE_URL, "https://example.org/", "https://www.iana.org/"]
    for candidate in candidates:
        host = urllib.parse.urlsplit(candidate).hostname
        if host and not _diagnostic_host_is_routed(host):
            return candidate
    return None


def _network_diagnostic(*, runner=subprocess.run, opener=None,
                        clock=time.monotonic) -> dict:
    """Run the explicit, bounded direct/routed connectivity matrix.

    This function has no rotation, DNS-write, or engine-restart side effects.
    All subprocess/network dependencies are injectable for hermetic tests.
    """
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proxy = _effective_proxy_state(runner)
    proxy_status = "unknown"
    if proxy.get("known"):
        proxy_status = "ok" if _effective_proxy_matches(proxy, _port) else "system_proxy_mismatch"
    direct_url = _diagnostic_direct_url()
    if direct_url is None:
        return {
            "checked_at": checked_at, "status": "direct_probe_skipped",
            "proxy": proxy, "proxy_status": proxy_status,
            "direct_dns": {"status": "skipped", "reason": "no unrouted HTTPS target"},
            "direct": {"status": "skipped", "reason": "no unrouted HTTPS target"},
            "routed": {"status": "skipped", "reason": "no unrouted HTTPS target"},
            "routed_url": None, "dns": _macos_dns_snapshot(runner) if sys.platform == "darwin" or runner is not subprocess.run else {},
            "recovery": None,
        }
    direct_host = urllib.parse.urlsplit(direct_url).hostname
    direct_dns = {"status": "unknown", "host": direct_host}
    if direct_host:
        addresses = _bounded_getaddrinfo(direct_host, 443, timeout=3.0)
        if addresses:
            direct_dns.update({"status": "ok", "addresses": addresses})
        else:
            direct_dns["status"] = "direct_dns_unavailable"
    direct = ({"status": "direct_dns_unavailable", "error": "direct resolver returned no address"}
              if direct_dns["status"] != "ok" else
              _direct_https_probe(direct_url, opener=opener, timeout=4.0, clock=clock,
                                  resolved_addresses=direct_dns.get("addresses")))

    routed_url = None
    if _providers:
        for provider in _providers:
            candidate = probe_url_for(provider)
            if candidate and not unsafe_probe_target(candidate):
                routed_url = candidate
                break
    if routed_url:
        routed = probe_egress(port=_port, url=routed_url, timeout=4.0,
                              opener=opener, clock=clock)
        routed = dict(routed)
        # An HTTP response (including 403/429) proves the routed path is
        # reachable. It is an upstream/application result, not a dead tunnel.
        routed["status"] = ("ok" if routed.get("ok") else
                             ("reachable_http_error" if routed.get("status") is not None
                              else "routed_path_failed"))
    else:
        routed = {"status": "skipped", "reason": "no configured routed HTTPS target"}

    if proxy_status == "system_proxy_mismatch":
        overall = "system_proxy_mismatch"
    elif direct_dns["status"] != "ok":
        overall = "direct_dns_unavailable"
    elif direct.get("status") != "ok":
        overall = "direct_connection_failed"
    elif routed.get("status") == "routed_path_failed":
        overall = "routed_path_failed"
    elif proxy_status == "unknown":
        overall = "system_proxy_unknown"
    else:
        overall = "ok"
    recovery = None
    if overall == "direct_dns_unavailable":
        recovery = "inspect configured/DHCP DNS, restore automatic DHCP DNS, run 'router.py reload', then rerun 'router.py doctor --network'"
    return {
        "checked_at": checked_at, "status": overall, "proxy": proxy,
        "proxy_status": proxy_status, "direct_dns": direct_dns,
        "direct": direct, "routed": routed, "routed_url": routed_url,
        "dns": _macos_dns_snapshot(runner) if sys.platform == "darwin" or runner is not subprocess.run else {},
        "recovery": recovery,
    }


def _cached_network_diagnostic() -> dict | None:
    try:
        data = json.loads(NETWORK_DIAGNOSTIC_FILE.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def doctor(network: bool = False) -> int:
    """One-command health audit: config, pools, engine, sing-box, grants.

    The default audit is read-only and performs no network probes.  The
    explicit ``--network`` mode adds bounded direct/routed checks and caches
    their result for status UIs.
    """
    findings: list[tuple[str, str, str]] = []

    def note(severity: str, area: str, detail: str) -> None:
        findings.append((severity, area, detail))

    if load_config() != 0:
        note("fail", "config", "router.json rejected: run 'router.py status' for the reason")
    else:
        note("ok", "config", f"{len(_providers)} provider(s), {len(_routes)} route(s), mode {current_mode()}")
        for name in _providers:
            count = len(provider_files(name))
            (note("fail", "pool", f"provider '{name}' has no profiles (drop .conf files into its directory)")
             if count == 0 else note("ok", "pool", f"{name}: {count} profile(s), active {persisted_active(name) or '-'}"))
    sing_box = resolve_sing_box()
    if sing_box is None:
        note("fail", "sing-box", _sing_box_missing_message())
    elif not sing_box_at_least(MIN_SING_BOX_VERSION):
        note("fail", "sing-box", _sing_box_version_message(MIN_SING_BOX_VERSION))
    else:
        note("ok", "sing-box", str(sing_box))
    if engine_alive():
        drift = "config DRIFTED from router.json (ensure reloads it in place on the next tick)" \
            if _config_drifted() else "config matches router.json"
        note("ok" if "matches" in drift else "warn", "engine", f"alive, mode {current_mode()} — {drift}")
    else:
        note("warn", "engine", f"down (mode {current_mode()}); run 'router.py ensure' to start it")
    if _effective_uid() != 0 and shutil.which("sudo"):
        note("ok" if _sudoers_installed() else "warn", "elevate",
             "safe root-owned lifecycle helper active" if _sudoers_installed()
             else "helper absent; run 'router.py elevate install' for TUN lifecycle")
    if sys.platform == "darwin":
        probe = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
        has_agent = "com.proxy-router.keepalive" in (probe.stdout or "")
        note("ok" if has_agent else "warn", "keepalive",
             "launchd agent loaded" if has_agent else "launchd agent NOT loaded (examples/install-launchd.sh)")
        # Issue #76: the autostarted tray is the surface users actually see;
        # a silently-not-loaded agent means every action happens in a TUI
        # instead and the tray looks broken. Verify it like the keepalive.
        has_tray = "com.proxy-router.tray" in (probe.stdout or "")
        note("ok" if has_tray else "warn", "tray",
             "menu-bar agent loaded" if has_tray
             else "menu-bar agent NOT loaded (examples/install-tray.sh)")
    if network:
        diagnostic = _network_diagnostic()
        try:
            _atomic_write(NETWORK_DIAGNOSTIC_FILE,
                          json.dumps(diagnostic, indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            note("fail", "network", f"could not cache diagnostic: {exc}")
        severity = "ok" if diagnostic.get("status") == "ok" else "fail"
        note(severity, "network", diagnostic.get("status", "unknown"))
        if diagnostic.get("recovery"):
            note("warn", "recovery", diagnostic["recovery"])
    for severity, area, detail in findings:
        mark = {"ok": "[ok]  ", "warn": "[warn]", "fail": "[FAIL]"}[severity]
        print(f"{mark} {area:<10} {detail}")
    fails = sum(1 for severity, _a, _d in findings if severity == "fail")
    warns = sum(1 for severity, _a, _d in findings if severity == "warn")
    print(f"doctor: {len(findings) - fails - warns} ok · {warns} warn · {fails} fail")
    return 1 if fails else 0


def vpn_status() -> int:
    rc, line = _status_report()
    print(f"vpn: {line}")
    return rc


def _provider_status(name: str) -> dict:
    """Machine-readable view of one provider: profiles, active, cooldowns,
    last rotation, and persisted egress records."""
    proxy_backed = is_proxy_provider(name)
    profiles = [] if proxy_backed else [p.stem for p in provider_files(name)]
    # Report the PERSISTED active profile (what the engine is configured with)
    # rather than resolve_active(), which skips a cooled-down active when
    # picking the next candidate. Proxy-backed providers have one synthetic
    # SOCKS lane; stale WireGuard markers/files must not shadow its status.
    if proxy_backed:
        active_stem = _PROXY_PROFILE_STEM
    else:
        active_profile = persisted_active(name)
        active_stem = active_profile.stem if active_profile is not None else None
    entry = {"profiles": profiles, "active": active_stem}
    if proxy_backed:
        try:
            upstream_host, upstream_port = proxy_upstream(name)
        except ValueError as exc:
            entry["upstream_error"] = str(exc)
        else:
            entry["upstream"] = f"{upstream_host}:{upstream_port}"
        proxy_record = read_egress(name, proxy_profile_key(name))
        if proxy_record:
            entry["egress"] = {_PROXY_PROFILE_STEM: proxy_record}
    fallback = fallback_status(name)
    if fallback["configured"] or fallback["active"]:
        entry["fallback"] = fallback
    if not proxy_backed:
        cooldowns = {}
        for stem in profiles:
            path = ROOT / "state" / "cooldowns" / name / f"{stem}.until"
            try:
                if path.is_file():
                    cooldowns[stem] = int(path.read_text().strip())
            except (ValueError, OSError):
                pass
        if cooldowns:
            entry["cooldown_until"] = cooldowns
    if not proxy_backed:
        rotation = ROOT / "state" / f"{name}.rotation"
        try:
            if rotation.is_file():
                entry["last_rotation"] = json.loads(rotation.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    if not proxy_backed:
        egress = {}
        for stem in profiles:
            record = read_egress(name, Path(stem + ".conf"))
            if record:
                egress[stem] = record
        if egress:
            entry["egress"] = egress
    return entry


def _legacy_launch_agents() -> list[str]:
    """Read-only probe for known legacy proxy-router launch agents.

    An older install (e.g. com.hermes.proxy-router) can coexist with the
    current keepalive/tray agents and resurrect a stale engine on login.
    The installer prints migration steps when it finds one; status surfaces
    the same fact read-only so a live box is never silently half-migrated.
    """
    if sys.platform != "darwin":
        return []
    agents_dir = Path.home() / "Library" / "LaunchAgents"
    if not agents_dir.is_dir():
        return []
    found = []
    for plist in sorted(agents_dir.glob("com.hermes.proxy-router*.plist")):
        found.append(plist.name)
    return found


def _launchd_agent_state(label: str) -> bool:
    """True when the given launchd agent label is loaded for this user.

    Read-only `launchctl list` probe. Issue #76: a tray/keepalive agent that
    launchd silently refused to load (bad interpreter, missing GUI session)
    is indistinguishable from "not installed" for the user; doctor and
    `status --json` must surface the difference so the autostart path can be
    verified instead of assumed.
    """
    if sys.platform != "darwin":
        return False
    try:
        probe = subprocess.run(
            ["launchctl", "list"], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return f"{label}" in (probe.stdout or "")


def status_json() -> dict:
    """Full machine-readable status for `status --json`."""
    rc, line = _status_report()
    data = {"up": rc == 0, "state": line, "mode": current_mode(), "port": _port,
            "sing_box": resolve_sing_box(), "schema_version": SCHEMA_VERSION}
    # Local settings inspection is read-only and does not perform a network
    # probe. Keep engine liveness separate from proxy readiness so a listener
    # alone cannot make the tray claim that GUI traffic is connected.
    proxy_status, effective = _system_proxy_status_readonly()
    data["system_proxy"] = {"status": proxy_status, "effective": effective}
    cached = _cached_network_diagnostic()
    if cached is not None:
        data["network"] = cached
    try:
        if PID_FILE.is_file():
            data["pid"] = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        pass
    data["providers"] = {name: _provider_status(name) for name in _providers}
    data["error_policy"] = {name: error_policy_for(name) for name in _providers}
    data["routes"] = [{
        "id": route.get("id"),
        "provider": route.get("provider"),
        "domains": route.get("domains", []),
        "ip_cidr": route.get("ip_cidr", []),
    } for route in _routes]
    data["autodetect"] = autodetect_status()
    data["routing"] = routing_state()
    try:
        cfg = json.loads(CONFIG_FILE.read_text())
        data["preset"] = cfg.get("preset")
    except (OSError, json.JSONDecodeError):
        data["preset"] = None
    try:
        import route_watcher

        data["watcher"] = route_watcher.status(ROOT)
    except Exception:
        data["watcher"] = {"running": False, "enabled": False, "scope": "proxy-observable only"}
    try:
        data["legacy_agents"] = _legacy_launch_agents()
    except Exception:
        data["legacy_agents"] = []
    # Issue #76: expose the startup-permission state so the tray (and any
    # dashboard) can tell a permission gap apart from a broken engine and
    # offer the one-click repair instead of a generic failure.
    helper = None
    if sys.platform == "darwin" and _effective_uid() != 0:
        try:
            helper = _helper_status()
        except Exception:
            helper = {"installed": False, "error": "helper status probe crashed"}
    data["elevation"] = {
        "platform": sys.platform,
        "root_engine": _engine_runs_as_root(),
        "helper_installed": bool(helper and helper.get("installed")),
        "sudo_grant": _sudoers_installed(),
        # The one-time fix every consumer should point at when any of the
        # flags above shows the grant missing.
        "fix_hint": _HELPER_FIX,
    }
    if sys.platform == "darwin":
        data["elevation"]["tray_agent"] = _launchd_agent_state("com.proxy-router.tray")
        data["elevation"]["keepalive_agent"] = _launchd_agent_state(
            "com.proxy-router.keepalive")
    rotation = {
        "interval_seconds": scheduled_interval(),
        "jitter_seconds": int(_rotation.get("jitter_seconds", DEFAULT_ROTATION_SETTINGS["jitter_seconds"]) or 0),
        "policy": rotation_policy(),
    }
    if rotation["interval_seconds"] > 0:
        next_times = [n for n in (next_rotation_at(name) for name in _providers) if n is not None]
        if next_times:
            rotation["next_at"] = min(next_times)
    data["rotation"] = rotation
    return data


def _check_active_fallback(primary: str, fallback: str) -> tuple[Path | None, str, dict | None]:
    """Check the live fallback endpoint while preserving primary-route attribution."""
    if is_proxy_provider(fallback):
        try:
            proxy_upstream(fallback)
        except ValueError:
            return None, "dead", None
        key = proxy_profile_key(fallback)
        status, record = check_egress_live(
            fallback,
            key,
            url=probe_url_for(primary),
        )
        return key, status, record
    profile = persisted_active(fallback) or resolve_active(fallback)
    if profile is None:
        return None, "dead", None
    status, record = check_egress_live(
        fallback,
        profile,
        url=probe_url_for(primary),
    )
    return profile, status, record


def egress_probe(name: str | None = None) -> int:
    """Probe the active exit of every provider (or just ``name``) through the
    tunnel, persist the outcome, print it as JSON; exit 1 when any probe
    failed."""
    # The generated tun config keeps the mixed 127.0.0.1:<port> listener
    # alongside the TUN (config builder: "Keep the mixed proxy listener
    # ALONGSIDE the TUN"), so probing through it exercises the same route
    # rules and tunnel path in either mode.
    if not listener_up():
        return fail(f"engine not listening on 127.0.0.1:{_port}; start it first")
    providers = [name] if name is not None else list(_providers)
    results = {}
    any_failed = False
    for provider in providers:
        if provider not in _providers:
            results[provider] = {"error": "unknown provider"}
            any_failed = True
            continue
        if is_proxy_provider(provider):
            try:
                proxy_upstream(provider)
            except ValueError as exc:
                results[provider] = {"error": f"bad socks5 upstream: {exc}"}
                any_failed = True
                continue
            active: Path | None = proxy_profile_key(provider)
        else:
            active = persisted_active(provider) or resolve_active(provider)
        fallback = active_fallback(provider)
        if fallback:
            fallback_profile, status, record = _check_active_fallback(provider, fallback)
            results[provider] = {
                "profile": active.stem if active else None,
                "fallback_profile": fallback_profile.stem if fallback_profile else None,
                "ok": status != "dead",
                "status": "fallback",
                "fallback_provider": fallback,
            }
            if record is not None and record.get("dns_ok") is not None:
                results[provider]["dns_ok"] = record["dns_ok"]
            any_failed = any_failed or status == "dead"
            continue
        if active is None:
            results[provider] = {"error": "no active profile"}
            any_failed = True
            continue
        ok, _record = probe_profile(provider, active)
        results[provider] = {"profile": active.stem, "ok": ok}
        any_failed = any_failed or not ok
    print(json.dumps(results, indent=2, sort_keys=True))
    return 1 if any_failed else 0


def egress_check(name: str | None = None, as_json: bool = False) -> int:
    """Read-only liveness check of the ACTIVE exit of every provider (or just
    ``name``) through the running tunnel.

    Unlike `egress probe` (which exits 1 on any probe failure), this
    classifies each exit alive/degraded/dead (see check_egress_live) and
    exits 1 only when an exit is DEAD - i.e. the tunnel path itself is broken
    - so a caller like keepalive can auto-rotate on a genuinely dead tunnel
    without reacting to reputation-block HTTP statuses (403/1010), TUN mode,
    or a temporarily down engine.

    Never rotates, never touches the engine; the only write is the normal
    egress health record. Bounded probes make it safe to run every 30-60s.
    Every provider is checked even after a dead one is found, so egress
    records stay fresh for status UIs (a dead-first provider must not freeze
    other providers' records at their last failure). In human mode a trailing
    ``dead: <provider>`` line (and exit code 1) is the machine contract
    keepalive parses; only the first dead provider is named so keepalive
    rotates exactly one provider. ``--json`` emits the same data as one JSON
    document.
    """
    # The tun config keeps the mixed listener (see egress_probe), so the
    # read-only liveness check works through 127.0.0.1:<port> in either mode.
    if not listener_up():
        return fail(f"engine not listening on 127.0.0.1:{_port}; tunnel is down")
    if name is not None and name not in _providers:
        return fail(f"unknown provider '{name}' (have {', '.join(_providers)})")
    providers = [name] if name is not None else list(_providers)
    results: dict[str, dict] = {}
    dead: list[str] = []

    def _check_one(provider: str) -> tuple[str, dict, bool]:
        """Probe one provider; returns (provider, entry, is_dead).

        Probes are independent (each rides the shared local listener), so
        they run concurrently: a dead exit costs its own probe timeout once,
        not once per provider in sequence (3 providers x 8s timeout used to
        serialize into ~24s+ per check cycle).
        """
        if is_proxy_provider(provider):
            try:
                proxy_upstream(provider)
            except ValueError as exc:
                return provider, {"profile": None, "ok": False, "status": "dead",
                                  "detail": f"bad socks5 upstream: {exc}"}, True
            active = proxy_profile_key(provider)
        else:
            active = persisted_active(provider) or resolve_active(provider)
        fallback = active_fallback(provider)
        if fallback:
            fallback_profile, status, record = _check_active_fallback(provider, fallback)
            entry: dict = {
                "profile": active.stem if active else None,
                "fallback_profile": fallback_profile.stem if fallback_profile else None,
                "ok": status != "dead",
                "status": "fallback",
                "fallback_provider": fallback,
            }
            if record is not None and record.get("dns_ok") is not None:
                entry["dns_ok"] = record["dns_ok"]
            if status == "dead":
                entry["detail"] = "dns" if entry.get("dns_ok") is False else "probe connection"
                return provider, entry, True
            if status == "degraded" and record is not None:
                entry["detail"] = (f"HTTP {record['status']}" if record.get("status") is not None
                                   else "throttled (TLS)")
            return provider, entry, False
        if active is None:
            return provider, {"profile": None, "ok": True, "status": "skipped",
                              "detail": "no active profile"}, False
        status, record = check_egress_live(provider, active)
        entry: dict = {"profile": active.stem, "ok": status != "dead", "status": status}
        if record is not None and record.get("dns_ok") is not None:
            entry["dns_ok"] = record["dns_ok"]
        if status == "dead":
            entry["detail"] = "dns" if entry.get("dns_ok") is False else "probe connection"
            return provider, entry, True
        if status == "degraded" and record is not None:
            entry["detail"] = (f"HTTP {record['status']}" if record.get("status") is not None
                               else "throttled (TLS)")
        return provider, entry, False

    if len(providers) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(8, len(providers)),
                                thread_name_prefix="egress-check") as pool:
            for provider, entry, is_dead in pool.map(_check_one, providers):
                results[provider] = entry
                if is_dead:
                    dead.append(provider)
    else:
        for provider in providers:
            provider, entry, is_dead = _check_one(provider)
            results[provider] = entry
            if is_dead:
                dead.append(provider)
    # No break after a dead provider: every provider's record must be
    # refreshed each cycle so status UIs never show stale failures from a
    # provider that merely follows a dead-first one in check order.
    if as_json:
        print(json.dumps({"dead": dead, "results": results}, indent=2, sort_keys=True))
    else:
        for provider, entry in results.items():
            status = entry["status"]
            if status == "skipped":
                print(f"{provider}: skipped (no active profile)")
            elif status == "fallback":
                print(f"{provider}: fallback ({entry.get('fallback_provider', 'unknown')})")
            elif status == "alive":
                print(f"{provider}: alive ({entry['profile']})")
            elif status == "degraded":
                print(f"{provider}: degraded ({entry['profile']}; {entry.get('detail', 'HTTP response')})")
            else:
                print(f"{provider}: dead ({entry['profile']}; {entry.get('detail', 'probe connection')})")
        if dead:
            print(f"dead: {dead[0]}")
    return 1 if dead else 0


def egress_sweep(name: str | None = None, as_json: bool = False,
                 *, allow_tun: bool = False) -> int:
    """Probe every profile once and leave the engine on the best alive one.

    Every profile change is an in-place SIGHUP reload: the process, TUN
    interface, and listener sockets survive each hop. If no profile is
    alive, the original active profile is restored when possible, so a
    diagnostic sweep cannot strand the tunnel on the last dead profile it
    tested.

    TUN sweeps require the explicit ``allow_tun`` acknowledgement. The
    keepalive path intentionally omits it, so a mode change between its shell
    check and controller invocation cannot trigger a shared-engine sweep.
    """
    if not allow_tun and (current_mode() == "tun" or _generated_config_mode() in ("tun", "unknown")):
        return fail("egress sweep skipped in TUN mode; pass --allow-tun for an explicit interruption")
    # The tun config keeps the mixed listener (see egress_probe), so the
    # full-pool sweep probes through 127.0.0.1:<port> in either mode.
    if not listener_up():
        return fail(f"engine not listening on 127.0.0.1:{_port}; start it first")
    providers = [name] if name is not None else list(_providers)
    results: dict[str, dict] = {}
    dead: list[str] = []
    for provider in providers:
        if MANUAL_OFF_FILE.is_file():
            results[provider] = {"error": "cancelled (manual-off)"}
            dead.append(provider)
            continue
        if provider not in _providers:
            results[provider] = {"error": "unknown provider"}
            dead.append(provider)
            continue
        fallback = active_fallback(provider)
        if fallback:
            fallback_profile, status, record = _check_active_fallback(provider, fallback)
            results[provider] = {
                "status": "fallback",
                "fallback_provider": fallback,
                "fallback_profile": fallback_profile.stem if fallback_profile else None,
                "ok": status != "dead",
            }
            if record is not None and record.get("dns_ok") is not None:
                results[provider]["dns_ok"] = record["dns_ok"]
            if status == "dead":
                dead.append(provider)
            continue
        # Keep only parseable profiles so one bad *.conf cannot wedge the
        # sweep (F6); log every skipped filename (F2), same as rotate.
        # Proxy-backed providers have no profiles to hop across: one liveness
        # probe of the SOCKS5 hop, reported under the fixed "socks" key.
        if is_proxy_provider(provider):
            try:
                proxy_upstream(provider)
            except ValueError:
                results[provider] = {"error": "bad socks5 upstream"}
                dead.append(provider)
                continue
            key = proxy_profile_key(provider)
            ok, record = _probe_with_settle(provider, key)
            error = record.get("error") if record else None
            usable = ok or _transport_reason(error) == "tls"
            results[provider] = {key.stem: {
                "ok": ok,
                "usable": usable,
                "latency_ms": record.get("latency_ms") if record else None,
                "status": record.get("status") if record else None,
            }}
            if not usable:
                dead.append(provider)
            continue
        valid: list[Path] = []
        for profile in provider_files(provider):
            error = _profile_error(profile)
            if error is not None:
                print(f"router: skipping bad profile {profile.name} of '{provider}': {error}", file=sys.stderr)
                continue
            valid.append(profile)
        if not valid:
            results[provider] = {"error": "no valid profiles"}
            dead.append(provider)
            continue
        current = persisted_active(provider) or resolve_active(provider)
        original = current if current in valid else None
        actual = original
        if original is not None:
            start = valid.index(original)
            ordered = valid[start:] + valid[:start]
        else:
            ordered = valid
        entry: dict[str, dict] = {}
        switch_failed = False

        def switch_to(profile: Path) -> int:
            nonlocal actual
            if MANUAL_OFF_FILE.is_file():
                return 1
            if actual == profile:
                return 0

            def apply_switch() -> int:
                nonlocal actual
                if MANUAL_OFF_FILE.is_file():
                    return 1
                # The lifecycle lock covers only the engine/config mutation;
                # probes and settle waits deliberately happen outside it.
                rc = engine_reload({provider: profile})
                if rc != 0 or MANUAL_OFF_FILE.is_file():
                    return rc or 1
                set_active(provider, profile)
                actual = profile
                record_rotation(provider, profile)
                print(f"switched {provider} -> {profile.stem} (sweep)")
                return 0

            return _with_lock(apply_switch, timeout=5.0)

        for profile in ordered:
            if MANUAL_OFF_FILE.is_file():
                switch_failed = True
                break
            if switch_to(profile) != 0:
                entry[profile.stem] = {
                    "ok": False,
                    "usable": False,
                    "latency_ms": None,
                    "status": None,
                    "error": "profile switch failed" if not MANUAL_OFF_FILE.is_file() else "cancelled (manual-off)",
                }
                switch_failed = True
                break
            if MANUAL_OFF_FILE.is_file():
                switch_failed = True
                break
            if actual != original:
                # Don't hold the lifecycle lock over a blind sleep if stop was
                # requested - check cancellation and use short polling.
                if MANUAL_OFF_FILE.is_file():
                    switch_failed = True
                    break
                time.sleep(1.5)  # WireGuard handshake settle
                if MANUAL_OFF_FILE.is_file():
                    switch_failed = True
                    break
            if MANUAL_OFF_FILE.is_file():
                switch_failed = True
                break
            ok, record = _probe_with_settle(provider, profile)
            error = record.get("error") if record else None
            # A TLS-classed failure means the TCP CONNECT rode the tunnel and
            # the upstream endpoint is throttling: the exit still serves real
            # traffic (probes false-dead while traffic succeeds), so count it
            # usable — an all-throttled pool must not read as "zero alive"
            # and strand keepalive on fallback or churn the active profile.
            usable = ok or _transport_reason(error) == "tls"
            entry[profile.stem] = {
                "ok": ok,
                "usable": usable,
                "latency_ms": record.get("latency_ms") if record else None,
                "status": record.get("status") if record else None,
            }
        if MANUAL_OFF_FILE.is_file():
            switch_failed = True
        alive = [stem for stem, r in entry.items() if r["usable"]]
        if alive and not switch_failed and not MANUAL_OFF_FILE.is_file():
            best = min(alive, key=lambda stem: (
                entry[stem]["latency_ms"] is None,
                entry[stem]["latency_ms"] or 0.0,
            ))
            best_profile = next(p for p in ordered if p.stem == best)
            if switch_to(best_profile) != 0:
                switch_failed = True
        if switch_failed:
            if provider not in dead:
                dead.append(provider)
            if original is not None and actual != original:
                if switch_to(original) != 0:
                    print(
                        f"router: could not restore original profile {original.name} for '{provider}'",
                        file=sys.stderr,
                    )
        elif not alive:
            dead.append(provider)
            if original is not None:
                switch_to(original)
        results[provider] = entry
    if as_json:
        print(json.dumps({"dead": dead, "results": results}, indent=2, sort_keys=True))
    else:
        for provider, entry in results.items():
            if "error" in entry:
                print(f"{provider}: {entry['error']}")
                continue
            if entry.get("status") == "fallback":
                print(f"{provider}: fallback ({entry['fallback_provider']})")
                continue
            alive = [stem for stem, r in entry.items() if r["ok"]]
            best = min(alive, key=lambda stem: (
                entry[stem]["latency_ms"] is None,
                entry[stem]["latency_ms"] or 0.0,
            )) if alive else None
            suffix = f" (best: {best})" if best is not None else ""
            print(f"{provider}: sweep done, {len(alive)}/{len(entry)} alive{suffix}")
    return 1 if dead else 0


def egress_show(name: str | None = None) -> int:
    """Print persisted egress records (state/egress/**) as JSON."""
    providers = [name] if name is not None else list(_providers)
    if name is not None and name not in _providers:
        return fail(f"unknown provider '{name}' (have {', '.join(_providers)})")
    records = {}
    for provider in providers:
        records[provider] = {}
        for profile in provider_files(provider):
            record = read_egress(provider, profile)
            if record:
                records[provider][profile.stem] = record
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# provider validity preflight (`providers check`, issue #51)
# ---------------------------------------------------------------------------

def _provider_config_errors(name: str, entry: dict) -> list[str]:
    """Static config errors for one provider entry (offline, no probing).

    ``load_config`` already enforces the schema-wide rules (types, fallback
    references, directory containment); this re-checks only what a single
    provider entry controls, so the report can name the offending provider
    instead of failing the whole load.
    """
    errors: list[str] = []
    cooldown = entry.get("cooldown_seconds")
    if cooldown is not None and not isinstance(cooldown, int):
        # Non-integer cooldowns are coerced elsewhere with int(); flag the
        # ones that would raise at rotation time.
        try:
            int(cooldown)
        except (TypeError, ValueError):
            errors.append(f"cooldown_seconds must be an integer (got {cooldown!r})")
    probe_url = entry.get("probe_url")
    if probe_url is not None and not (isinstance(probe_url, str) and probe_url.startswith("https://")):
        errors.append("probe_url must be an https:// URL when set")
    return errors


def _check_provider_validity(name: str) -> dict:
    """One provider's validity verdict: config, profile pool, parseability,
    active-profile state. Offline by design (no probes, no engine I/O).

    Returns a machine-readable dict; ``valid`` is False whenever any finding
    means the provider cannot carry traffic right now (issue #51: providers
    that look configured but silently never work)."""
    result: dict = {"name": name, "valid": True, "issues": [], "profiles": 0}
    issues: list[str] = result["issues"]
    entry = _providers.get(name)

    if not isinstance(entry, dict):
        result["valid"] = False
        issues.append("not a configured provider object")
        return result

    if is_proxy_provider(name):
        # No profile directory: the lane is one validated SOCKS5 hop.
        result["profiles"] = 0
        try:
            upstream_host, upstream_port = proxy_upstream(name)
        except ValueError as exc:
            result["valid"] = False
            issues.append(str(exc))
            return result
        result["upstream"] = f"{upstream_host}:{upstream_port}"
        result["active"] = _PROXY_PROFILE_STEM
        issues.extend(_provider_config_errors(name, entry))
        return result

    try:
        directory = provider_dir(name)
        relative = directory.relative_to(ROOT)
    except ValueError as exc:
        result["valid"] = False
        issues.append(str(exc))
        return result
    result["directory"] = str(relative)
    if not directory.is_dir():
        result["valid"] = False
        issues.append(f"missing profile directory {relative} "
                      f"(create it and drop valid .conf files inside)")
        return result

    profiles = provider_files(name)
    result["profiles"] = len(profiles)
    if not profiles:
        result["valid"] = False
        issues.append(f"no .conf profiles in {relative}")
        return result

    bad_profiles = []
    for profile in profiles:
        error = _profile_error(profile)
        if error is not None:
            bad_profiles.append({"profile": profile.stem, "error": error})
    result["bad_profiles"] = [item["profile"] for item in bad_profiles]
    usable_count = len(profiles) - len(bad_profiles)
    if bad_profiles:
        issues.append(
            f"{len(bad_profiles)} unparseable profile(s): "
            + ", ".join(item["profile"] for item in bad_profiles)
        )
    if usable_count == 0:
        result["valid"] = False
        issues.insert(0, "no parseable profiles remain")
        return result

    cooled = [p.stem for p in profiles
              if p.stem not in {item["profile"] for item in bad_profiles}
              and is_cooled_down(name, p)]
    result["cooled_down"] = cooled

    active = persisted_active(name) or resolve_active(name)
    result["active"] = active.stem if active else None
    if active is None:
        result["valid"] = False
        detail = "every remaining profile is cooled down" if cooled \
            else "no active profile could be selected"
        issues.append(detail)

    issues.extend(_provider_config_errors(name, entry))
    return result


def providers_check(name: str | None = None, as_json: bool = False) -> int:
    """Preflight every configured provider (or just ``name``): does its
    configuration and profile pool describe a lane that can carry traffic?

    Read-only and offline — no probes ride the tunnel and no engine action is
    taken — so it answers "is this provider VALID?" separately from the live
    `egress check` answer "is the exit HEALTHY?". Issue #51's failure mode is
    exactly the gap between the two: providers that stay configured but can
    never serve traffic (empty/missing directories, every profile unparseable,
    all exits cooled down) drag the working-provider count down without any
    single loud error.

    Human output prints one line per provider plus a summary line;
    invalid providers are also listed on stderr. Exit code: 0 when every
    checked provider is valid, 1 otherwise (so scripts/keepalive can gate on
    it); unknown provider names fail fast with exit 2.
    """
    if name is not None and name not in _providers:
        print(f"router: unknown provider '{name}' (have {', '.join(_providers)})", file=sys.stderr)
        return 2
    providers = [name] if name is not None else sorted(_providers)
    results = [_check_provider_validity(provider) for provider in providers]
    if as_json:
        report = {
            "total": len(results),
            "valid": sum(1 for r in results if r["valid"]),
            "invalid": sum(1 for r in results if not r["valid"]),
            "results": results,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in results:
            mark = "ok" if result["valid"] else "INVALID"
            line = f"{result['name']}: {mark} ({result['profiles']} profile(s)"
            if result.get("active"):
                line += f", active {result['active']}"
            line += ")"
            print(line)
            for issue in result["issues"]:
                print(f"    ! {issue}")
        invalid = [r["name"] for r in results if not r["valid"]]
        print(f"providers check: {sum(1 for r in results if r['valid'])}/{len(results)} valid")
        if invalid:
            print(f"invalid: {', '.join(invalid)}", file=sys.stderr)
    return 0 if all(r["valid"] for r in results) else 1


# ---------------------------------------------------------------------------
# macOS system proxy toggle
# ---------------------------------------------------------------------------

def _run_result(runner, command: list[str], **kwargs):
    """Call an injected subprocess runner without coupling helpers to globals."""
    return runner(command, **kwargs)


def _parse_networksetup_proxy(text: str | None) -> dict:
    """Parse one ``networksetup -get*proxy`` response strictly.

    ``networksetup`` prints a human-readable record.  Keep this parser small
    and key based so unrelated lines (including authenticated proxy fields)
    can never be mistaken for the endpoint we own.
    """
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip()
        if key in {"Enabled", "Server", "Port"}:
            values[key] = value.strip()
    enabled = values.get("Enabled")
    port = values.get("Port")
    server = values.get("Server")
    if server and "@" in server:
        # Defensive redaction: networksetup normally returns a host only,
        # but never persist userinfo if a custom service reports a URL.
        server = server.rsplit("@", 1)[-1]
        if "://" in server:
            server = urllib.parse.urlsplit(server).hostname or server
    return {
        "known": enabled is not None,
        "enabled": (enabled.lower() == "yes") if enabled is not None else None,
        "server": server,
        "port": int(port) if port and port.isdigit() else None,
    }


def _parse_scutil_proxy(text: str | None) -> dict:
    """Parse global effective proxy keys from ``scutil --proxy``.

    Scoped dictionaries are deliberately ignored.  The effective global
    HTTP/HTTPS keys are the only state that proves ordinary applications will
    use the local listener.
    """
    wanted = {"HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy",
              "HTTPSPort", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"}
    values: dict[str, str] = {}
    scoped = False
    for line in (text or "").splitlines():
        if "__SCOPED__" in line:
            scoped = True
            continue
        if scoped:
            continue
        match = re.fullmatch(r" {2}([A-Za-z][A-Za-z0-9]+)\s*:\s*(.*?)\s*", line)
        if not match:
            continue
        key, value = match.groups()
        if key in wanted:
            values[key] = value.strip().strip('"')

    def integer(key: str) -> int | None:
        value = values.get(key)
        return int(value) if value is not None and value.isdigit() else None

    def enabled(key: str) -> bool | None:
        value = values.get(key)
        if value is None:
            return None
        if value in {"1", "Yes", "yes", "true", "True"}:
            return True
        if value in {"0", "No", "no", "false", "False"}:
            return False
        return None

    http = {"enabled": enabled("HTTPEnable"), "server": values.get("HTTPProxy"),
            "port": integer("HTTPPort")}
    https = {"enabled": enabled("HTTPSEnable"), "server": values.get("HTTPSProxy"),
             "port": integer("HTTPSPort")}
    known = (http["enabled"] is not None and https["enabled"] is not None
             and (not http["enabled"] or (http["server"] is not None and http["port"] is not None))
             and (not https["enabled"] or (https["server"] is not None and https["port"] is not None)))
    return {"known": known, "http": http, "https": https,
            "scoped_present": scoped,
            "pac_enabled": enabled("ProxyAutoConfigEnable"),
            "wpad_enabled": enabled("ProxyAutoDiscoveryEnable")}


def _effective_proxy_state(runner=subprocess.run) -> dict:
    """Read the effective global proxy state without changing the system."""
    try:
        result = _run_result(runner, ["scutil", "--proxy"], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        return {"known": False, "http": {}, "https": {}, "error": "scutil unavailable"}
    if getattr(result, "returncode", 0) != 0:
        return {"known": False, "http": {}, "https": {},
                "error": (getattr(result, "stderr", "") or "scutil failed").strip()}
    state = _parse_scutil_proxy(getattr(result, "stdout", "") or "")
    if not state.get("known"):
        state["error"] = "scutil output missing global HTTP/HTTPS keys"
    return state


def _connected_network_services(runner=None) -> list[str]:
    """Return connected network-extension services reported by ``scutil``."""
    run = runner or subprocess.run
    try:
        result = _run_result(run, ["scutil", "--nc", "list"], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        return []
    if getattr(result, "returncode", 0) != 0:
        return []
    names = []
    for line in (getattr(result, "stdout", "") or "").splitlines():
        match = re.fullmatch(r"\s*\*?\s*\(Connected\)\s+.*?(?:\s*:\s*)?\"([^\"]+)\"\s*", line)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


def _service_proxy_state(service: str, protocol: str, runner=subprocess.run) -> dict:
    flag = "-getwebproxy" if protocol == "http" else "-getsecurewebproxy"
    try:
        result = _run_result(runner, ["networksetup", flag, service], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        return {"known": False, "enabled": None, "server": None, "port": None}
    if getattr(result, "returncode", 0) != 0:
        return {"known": False, "enabled": None, "server": None, "port": None}
    return _parse_networksetup_proxy(getattr(result, "stdout", "") or "")


def network_services(runner=subprocess.run) -> list[str]:
    """Return enabled macOS network services, excluding the separator row."""
    try:
        result = _run_result(runner,
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        return []
    if getattr(result, "returncode", 0) != 0:
        return []
    services = []
    for line in (getattr(result, "stdout", "") or "").splitlines():
        service = line.strip()
        if not service or service.startswith("An asterisk") or service.startswith("*"):
            continue
        services.append(service)
    return services


def active_service_name(runner=subprocess.run) -> str | None:
    """Return the service for the current default interface, when known.

    ``-listnetworkserviceorder`` maps the route's interface to the current
    service name, so a user-renamed Wi-Fi service is handled correctly.  The
    hardware-port output remains a compatibility fallback for older macOS.
    """
    try:
        iface = None
        route_result = _run_result(runner,
            ["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5,
        )
        out = getattr(route_result, "stdout", "") or ""
        for line in out.splitlines():
            if "interface:" in line:
                iface = line.split()[-1]
        if not iface:
            return None
        service = None
        ordered = _run_result(runner,
            ["networksetup", "-listnetworkserviceorder"], capture_output=True,
            text=True, timeout=5,
        )
        service = None
        for line in (getattr(ordered, "stdout", "") or "").splitlines():
            match = re.fullmatch(r"\s*\(\d+\)\s+(.+?)\s*", line)
            if match:
                service = match.group(1).strip()
                continue
            match = re.fullmatch(r"\s*\(Hardware Port: .*?, Device: ([^\)]+)\)\s*", line)
            if match and match.group(1).strip() == iface and service:
                return service
        hardware_result = _run_result(runner,
            ["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=5,
        )
        out = getattr(hardware_result, "stdout", "") or ""
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
        return None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            service = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and line.split()[-1] == iface:
            return service
    return None


def _proxy_target_services(runner=None) -> list[str]:
    """Active physical service plus connected network-extension services.

    Each networksetup call costs ~0.1-0.2s; toggling all 9 services is 63
    spawns (~5s) on every connect. Only the default route's service is
    actually used by macOS clients, so target it and fall back to all
    services when detection fails (previous behavior, never fail-closed).
    """
    active = active_service_name() if runner is None else active_service_name(runner)
    services = ([active] if active else
                (network_services() if runner is None else network_services(runner)))
    connected = (_connected_network_services() if runner is None
                 else _connected_network_services(runner))
    for service in connected:
        if service not in services:
            services.append(service)
    return services


def _proxy_endpoint_matches(state: dict, port: int, server: str = "127.0.0.1") -> bool:
    known = state.get("known", state.get("enabled") is not None)
    return bool(known and state.get("enabled")
                and state.get("server") == server and state.get("port") == int(port))


def _capture_proxy_aux(service: str, runner=subprocess.run) -> dict:
    """Capture PAC/WPAD/bypass metadata without storing proxy credentials."""
    result: dict = {}
    for key, command in {
        "pac": ["networksetup", "-getautoproxyurl", service],
        "wpad": ["networksetup", "-getproxyautodiscovery", service],
        "bypass": ["networksetup", "-getproxybypassdomains", service],
    }.items():
        try:
            probe = _run_result(runner, command, capture_output=True, text=True, timeout=10)
            if getattr(probe, "returncode", 0) == 0:
                text = (getattr(probe, "stdout", "") or "").strip()
                if key == "pac":
                    enabled = re.search(r"^Enabled:\s*(Yes|No)\s*$", text, re.MULTILINE)
                    url = re.search(r"^URL:\s*(\S+)\s*$", text, re.MULTILINE)
                    safe_url = url.group(1) if url else None
                    if safe_url:
                        parsed = urllib.parse.urlsplit(safe_url)
                        if parsed.username or parsed.password:
                            safe_url = urllib.parse.urlunsplit((parsed.scheme, parsed.hostname or "",
                                                                parsed.path, parsed.query, parsed.fragment))
                    result[key] = {"enabled": enabled.group(1) == "Yes" if enabled else None,
                                   "url": safe_url}
                elif key == "wpad":
                    enabled = re.search(r"^Enabled:\s*(Yes|No)\s*$", text, re.MULTILINE)
                    result[key] = {"enabled": enabled.group(1) == "Yes" if enabled else None}
                else:
                    domains = [line.strip() for line in text.splitlines()
                               if line.strip() and not line.lower().startswith((
                                   "there aren't", "there are no", "enabled:"))]
                    result[key] = {"domains": domains}
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError):
            continue
    return result


def _proxy_state_read() -> dict | None:
    try:
        data = json.loads(SYSTEM_PROXY_STATE_FILE.read_text())
        return data if isinstance(data, dict) and data.get("version") == 1 else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _proxy_state_write(state: dict) -> None:
    _atomic_write(SYSTEM_PROXY_STATE_FILE, json.dumps(state, indent=2, sort_keys=True) + "\n")


def _disable_owned_protocol(service: str, protocol: str, runner=subprocess.run) -> None:
    flag = "-setwebproxystate" if protocol == "http" else "-setsecurewebproxystate"
    _run_result(runner, ["networksetup", flag, service, "off"], check=True,
                capture_output=True, timeout=10)


def _effective_proxy_matches(effective: dict, port: int) -> bool:
    return bool(effective.get("known")
                and _proxy_endpoint_matches(effective.get("http", {}), port)
                and _proxy_endpoint_matches(effective.get("https", {}), port))


def _wait_effective_proxy(port: int, runner=subprocess.run, timeout: float = 2.0) -> dict:
    """Poll effective settings until both protocols point at our endpoint."""
    deadline = time.monotonic() + timeout
    effective = _effective_proxy_state(runner)
    while not _effective_proxy_matches(effective, port) and time.monotonic() < deadline:
        time.sleep(0.1)
        effective = _effective_proxy_state(runner)
    return effective


def _system_proxy_status_readonly() -> tuple[str, dict]:
    """Return proxy readiness plus raw effective state without a network probe."""
    if sys.platform != "darwin":
        return "skipped", {"known": False, "reason": "macOS only"}
    effective = _effective_proxy_state()
    if not effective.get("known"):
        return "unknown", effective
    return ("ok" if _effective_proxy_matches(effective, _port)
            else "system_proxy_mismatch"), effective


def system_proxy_on(runner=None) -> int:
    """Enable HTTP and HTTPS on owned services and verify effective state.

    ``runner`` exists for hermetic tests and diagnostics.  Production uses
    ``subprocess.run`` and performs the strict effective-state check on macOS.
    """
    injected = runner is not None
    run = runner or subprocess.run
    services = _proxy_target_services(runner) if runner is not None else _proxy_target_services()
    if not services:
        return fail("could not determine any macOS network services")
    strict = injected or sys.platform == "darwin"
    snapshots = []
    conflicts = []
    for service in services:
        before = {protocol: _service_proxy_state(service, protocol, run)
                  for protocol in ("http", "https")}
        if strict:
            for protocol, state in before.items():
                if not state.get("known"):
                    conflicts.append(f"{service} {protocol} proxy state unavailable")
                elif state.get("enabled") and not _proxy_endpoint_matches(state, _port):
                    conflicts.append(f"{service} {protocol} proxy {state.get('server')}:{state.get('port')}")
        snapshots.append({"service": service, "service_id": service, "port": _port,
                          "before": before,
                          "aux": _capture_proxy_aux(service, run),
                          "owned": {"http": False, "https": False}})
    if conflicts:
        return fail("foreign system proxy conflict: " + "; ".join(conflicts))

    state = {"version": 1, "endpoint": {"server": "127.0.0.1", "port": _port},
             "services": snapshots, "changed_at": int(time.time())}
    try:
        # Persist the ownership intent before the first mutation.  A crash or
        # partial command sequence therefore remains recoverable by Disconnect.
        if strict:
            _proxy_state_write(state)
        def apply_record(record: dict) -> None:
            service = record["service"]
            commands = [
                ["networksetup", "-setwebproxy", service, "127.0.0.1", str(_port)],
                ["networksetup", "-setsecurewebproxy", service, "127.0.0.1", str(_port)],
                ["networksetup", "-setwebproxystate", service, "on"],
                ["networksetup", "-setsecurewebproxystate", service, "on"],
                # Manual proxy mode must win over PAC/WPAD. Otherwise a
                # network-provided wpad.dat can silently replace or bypass
                # 127.0.0.1:2080 for GUI apps.
                ["networksetup", "-setautoproxystate", service, "off"],
                ["networksetup", "-setproxyautodiscovery", service, "off"],
                ["networksetup", "-setproxybypassdomains", service, "*.local", "localhost", "127.0.0.1", "::1"],
            ]
            for index, command in enumerate(commands):
                _run_result(run, command, check=True, capture_output=True, timeout=10)
                if index == 0:
                    record["owned"]["http"] = True
                elif index == 1:
                    record["owned"]["https"] = True
                if strict and index in {0, 1}:
                    _proxy_state_write(state)
            record["owned"] = {"http": True, "https": True}

        # Apply the physical/default-route service first. A connected
        # extension is touched only if the effective global state still does
        # not converge to our endpoint after that local change.
        active_service = active_service_name(run) if injected else active_service_name()
        if active_service and any(r["service"] == active_service for r in snapshots):
            physical = [r for r in snapshots if r["service"] == active_service]
            extensions = [r for r in snapshots if r["service"] != active_service]
        else:
            # If the default route cannot be identified, every configured
            # service is a physical fallback candidate; there is no safe way
            # to label one as a network extension.
            physical, extensions = snapshots, []
        for record in physical:
            apply_record(record)
        if strict:
            effective = _wait_effective_proxy(_port, run)
            if not _effective_proxy_matches(effective, _port) and extensions:
                for record in extensions:
                    apply_record(record)
                effective = _wait_effective_proxy(_port, run)
            if not _effective_proxy_matches(effective, _port):
                reason = effective.get("error") or "global HTTP/HTTPS settings did not converge"
                raise RuntimeError(f"effective system proxy verification failed: {reason}")
        else:
            for record in extensions:
                apply_record(record)
        if strict:
            _proxy_state_write(state)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
        rollback_errors = []
        if strict:
            try:
                _proxy_state_write(state)
            except OSError as state_exc:
                rollback_errors.append(f"persist rollback ownership: {state_exc}")
        for record in reversed(snapshots):
            service = record["service"]
            for protocol in ("https", "http"):
                if not record["owned"].get(protocol):
                    continue
                try:
                    current = _service_proxy_state(service, protocol, run)
                    if _proxy_endpoint_matches(current, _port):
                        _disable_owned_protocol(service, protocol, run)
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as rollback_exc:
                    rollback_errors.append(f"{service} {protocol}: {rollback_exc}")
            aux = record.get("aux") or {}
            for flag, key in (("-setautoproxystate", "pac"),
                              ("-setproxyautodiscovery", "wpad")):
                previous = aux.get(key, {}).get("enabled")
                if previous is None:
                    continue
                try:
                    _run_result(run, ["networksetup", flag, service,
                                      "on" if previous else "off"], check=True,
                                capture_output=True, timeout=10)
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as rollback_exc:
                    rollback_errors.append(f"{service} {key}: {rollback_exc}")
            if "bypass" in aux and aux["bypass"].get("domains") is not None:
                try:
                    _run_result(run, ["networksetup", "-setproxybypassdomains", service,
                                      *aux["bypass"].get("domains", [])], check=True,
                                capture_output=True, timeout=10)
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as rollback_exc:
                    rollback_errors.append(f"{service} bypass: {rollback_exc}")
        detail = f"could not enable system proxy: {exc}"
        if rollback_errors:
            detail += "; rollback failed: " + "; ".join(rollback_errors)
        elif strict:
            try:
                SYSTEM_PROXY_STATE_FILE.unlink(missing_ok=True)
            except OSError as state_exc:
                detail += f"; rollback record cleanup failed: {state_exc}"
        return fail(detail)
    print(f"system proxy enabled on {len(services)} network service(s) -> 127.0.0.1:{_port}")
    return 0


def _proxy_points_at_us(service: str, port: int | None = None, runner=None) -> bool:
    """True when ``service`` has our 127.0.0.1 proxy still switched on.

    Stale ON states strand traffic at a dead listener with
    ERR_PROXY_CONNECTION_FAILED once the engine stops (seen live on the
    ProtonVPN and Tailscale services after the all-services fan-out era).
    Only our own endpoint counts: a foreign proxy is never touched.
    """
    run = runner or subprocess.run
    endpoint_port = _port if port is None else int(port)
    try:
        for protocol in ("http", "https"):
            if _proxy_endpoint_matches(_service_proxy_state(service, protocol, run), endpoint_port):
                return True
    except (OSError, subprocess.TimeoutExpired, TypeError):
        pass
    return False


def system_proxy_off(runner=None) -> int:
    """Clear only endpoints owned by a prior Connect operation.

    A legacy install without an ownership record uses conservative exact
    endpoint matching.  HTTP and HTTPS are handled independently so a foreign
    setting on one protocol is never disabled with the other.
    """
    injected = runner is not None
    run = runner or subprocess.run
    state = _proxy_state_read()
    services = _proxy_target_services(runner) if runner is not None else _proxy_target_services()
    # A network handoff can temporarily hide every service from the live
    # discovery commands.  A recorded Connect operation still gives us the
    # exact service names and port needed for safe cleanup, so do not abandon
    # ownership-based teardown just because discovery is empty.
    recorded_services = [record.get("service") for record in (state or {}).get("services", [])
                         if isinstance(record, dict) and record.get("service")]
    if not services and recorded_services:
        services = list(dict.fromkeys(recorded_services))
    if not services:
        return fail("could not determine any macOS network services")
    strict = injected or sys.platform == "darwin"
    # Preserve the historical test/non-macOS path: there is no scutil
    # effective state to inspect, so target the active service and sweep
    # explicitly detected stale local endpoints.
    if not strict and not state:
        failures = []
        try:
            for service in services:
                for protocol in ("http", "https"):
                    _disable_owned_protocol(service, protocol, run)
                for flag in ("-setautoproxystate", "-setproxyautodiscovery"):
                    _run_result(run, ["networksetup", flag, service, "off"], check=True,
                                capture_output=True, timeout=10)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
            failures.append(str(exc))
        swept = 0
        for other in network_services():
            if other in services or not _proxy_points_at_us(other):
                continue
            try:
                for protocol in ("http", "https"):
                    _disable_owned_protocol(other, protocol, run)
                swept += 1
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
                failures.append(f"{other}: {exc}")
        print(f"system proxy disabled on {len(services)} network service(s)")
        if swept:
            print(f"system proxy cleared stale endpoint on {swept} other service(s)")
        return fail("could not fully disable system proxy: " + "; ".join(failures)) if failures else 0
    failures = []
    cleared = 0
    records = {r.get("service"): r for r in (state or {}).get("services", [])
               if isinstance(r, dict) and r.get("service")}
    candidates = list(dict.fromkeys(list(records) + services))
    if strict and not state:
        all_services = network_services(runner) if runner is not None else network_services()
        candidates = list(dict.fromkeys(candidates + all_services))
        # Legacy cleanup remains conservative: an unrecorded non-target
        # service is considered only when its current endpoint exactly matches
        # our listener.  This is also the path that cleans stale VPN/extension
        # services after a handoff.
        candidates = [service for service in candidates
                      if service in services or _proxy_points_at_us(service)]

    for service in candidates:
        record = records.get(service)
        expected_port = ((record or {}).get("port") or (state or {}).get("endpoint", {}).get("port")
                         or _port)
        for protocol in ("http", "https"):
            owned = bool(record and (record.get("owned") or {}).get(protocol))
            try:
                current = _service_proxy_state(service, protocol, run)
                if strict and not current.get("known") and (owned or not state):
                    failures.append(f"{service} {protocol}: proxy state unavailable")
                    continue
                # With a record we trust only its exact endpoint.  Legacy
                # cleanup is equally conservative and never touches foreign
                # proxies.
                if (owned or not state or not strict) and _proxy_endpoint_matches(current, int(expected_port)):
                    _disable_owned_protocol(service, protocol, run)
                    cleared += 1
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
                failures.append(f"{service} {protocol}: {exc}")

        if record:
            # PAC/WPAD were explicitly disabled by Connect. Restore only when
            # the current state still looks like our post-Connect state;
            # user changes made after Connect are preserved.
            for flag, key in (("-setautoproxystate", "pac"),
                              ("-setproxyautodiscovery", "wpad")):
                before_entry = (record.get("aux") or {}).get(key, {})
                before = before_entry.get("enabled")
                if before is None:
                    continue
                try:
                    current_entry = _capture_proxy_aux(service, run).get(key, {})
                    current = current_entry.get("enabled")
                    same_pac_url = (key != "pac" or
                                    current_entry.get("url") == before_entry.get("url"))
                    if current is False and before is True and same_pac_url:
                        _run_result(run, ["networksetup", flag, service, "on"], check=True,
                                    capture_output=True, timeout=10)
                    elif current is True and before is False and same_pac_url:
                        _run_result(run, ["networksetup", flag, service, "off"], check=True,
                                    capture_output=True, timeout=10)
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
                    failures.append(f"{service} {key}: {exc}")

            before_domains = (record.get("aux") or {}).get("bypass", {}).get("domains")
            if before_domains is not None:
                try:
                    current_domains = _capture_proxy_aux(service, run).get("bypass", {}).get("domains")
                    ours_domains = ["*.local", "localhost", "127.0.0.1", "::1"]
                    if current_domains == ours_domains and current_domains != before_domains:
                        _run_result(run, ["networksetup", "-setproxybypassdomains", service, *before_domains],
                                    check=True, capture_output=True, timeout=10)
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, TypeError) as exc:
                    failures.append(f"{service} bypass: {exc}")

    # Keep the ownership record until every owned endpoint is handled.  A
    # retry after a partial failure can then finish cleanup safely.
    if not failures and state:
        try:
            SYSTEM_PROXY_STATE_FILE.unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"remove ownership record: {exc}")
    print(f"system proxy disabled on {len(services)} network service(s)")
    if cleared:
        print(f"system proxy cleared {cleared} owned endpoint(s)")
    if failures:
        return fail("could not fully disable system proxy: " + "; ".join(failures))
    return 0


# ---------------------------------------------------------------------------
# Fail-open proxy runner
# ---------------------------------------------------------------------------

PROXY_ENV_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")


def _config_port() -> int:
    """Read the mixed-proxy port from router.json without full validation so
    with-proxy stays usable even with a broken/missing config."""
    try:
        if CONFIG_FILE.is_file():
            port = int(json.loads(CONFIG_FILE.read_text()).get("port", DEFAULT_PORT))
            if 1 <= port <= 65535:
                return port
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return DEFAULT_PORT


def _listener_healthy(port: int, timeout: float) -> bool:
    """True when a TCP listener answers on 127.0.0.1:port. Read-only probe:
    never starts the engine, never touches state."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def with_proxy(cmd: list[str], *, timeout_ms: int = 300,
               force_proxy: bool = False, force_direct: bool = False,
               check: bool = False) -> int:
    """Fail-open command runner: exec ``cmd`` through the local proxy when the
    listener is up, otherwise strip the proxy env and run direct.

    Use when:
    - Wrapping apps pointed at 127.0.0.1:<port> (hermes, curl, ...) so they
      keep working when the engine is stopped / manual-off.
    - Health checks: ``--check`` prints the proxy URL and exits 0 when the
      listener answers, exits 1 when it does not.

    Expects:
    - ``cmd``: argv to exec via os.execvpe (child replaces this process; exit
      code flows through).
    - ``--force-proxy`` refuses to run (exit 4) when the listener is down;
      ``--force-direct`` skips the probe and always strips the proxy env.
    - ``--check`` ignores ``cmd``.

    Returns:
    - Child exit code (exec path), 4 for a refused --force-proxy run, 1 for
      --check when the listener is down, 1 for a missing command.
    """
    timeout = max(0.001, timeout_ms / 1000.0)
    if check:
        port = _config_port()
        if _listener_healthy(port, timeout):
            print(f"http://127.0.0.1:{port}")
            return 0
        return 1
    if not cmd:
        return fail("with-proxy: no command given (usage: router.py with-proxy [flags] -- <cmd...>)")
    if force_proxy and force_direct:
        return fail("with-proxy: --force-proxy and --force-direct are mutually exclusive")
    port = _config_port()
    healthy = _listener_healthy(port, timeout)
    if force_proxy and not healthy:
        print(f"router: proxy listener 127.0.0.1:{port} is down; refusing --force-proxy run", file=sys.stderr)
        return 4
    env = dict(os.environ)
    if (healthy and not force_direct) or force_proxy:
        url = f"http://127.0.0.1:{port}"
        for var in PROXY_ENV_VARS:
            env[var] = url
    else:
        for var in PROXY_ENV_VARS:
            env.pop(var, None)
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as exc:
        return fail(f"with-proxy: cannot execute {cmd[0]}: {exc}")
    return 127  # unreachable: execvpe only returns on error


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _engine_runs_as_root() -> bool:
    """True when an exact engine process is currently owned by root.

    The PID-file inode is deliberately ignored: root may hand that file back
    to the invoking user while the engine remains root-owned.  Ambiguous
    process-table evidence is not a reason to signal locally; the lifecycle
    path will fail closed or use the installed helper.
    """
    if os.name == "nt" or _effective_uid() == 0:
        return False
    try:
        pids = _find_our_engine_pids()
    except EngineIdentityError:
        return False
    for pid in pids:
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "uid="],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip() in {"0", "root"}:
            return True
    return False


def _needs_elevation(args) -> bool:
    """Normal commands never re-execute the user-writable controller as root.

    Root lifecycle is delegated inside engine_start/stop/reload to the exact
    root-owned helper. Missing helper state fails closed at that boundary.
    """
    return False


def profile_copy(provider: str, sources: list[str]) -> int:
    """Copy validated local WireGuard profiles into a configured provider.

    This is the short, scriptable path for sharing profiles: it accepts files
    or directories, sanitizes names, avoids overwrites, and preserves private
    profile permissions without ever printing profile contents.
    """
    if not isinstance(provider, str) or not _PROVIDER_NAME.fullmatch(provider):
        return fail(f"profile copy: invalid provider '{provider}'")
    if provider not in _providers:
        return fail(f"profile copy: unknown provider '{provider}'")
    try:
        import setup_tui
        destination = provider_dir(provider)
        results = []
        for raw in sources:
            source = Path(os.path.expanduser(raw))
            results.append(setup_tui.import_profiles(source, destination))
    except (OSError, ValueError, TypeError) as exc:
        return fail(f"profile copy: {exc}")
    imported = sum(result["imported"] for result in results)
    rejected = sum(result["rejected"] for result in results)
    files = [name for result in results for name in result["files"]]
    rejected_files = [entry for result in results for entry in result["rejected_files"]]
    if imported:
        print(f"profile copy: imported {imported} profile(s) into {destination.relative_to(ROOT)}")
        for name in files:
            print(f"  + {name}")
    for entry in rejected_files:
        print(f"  - {entry['name']}: {entry['reason']}", file=sys.stderr)
    if rejected:
        print(f"profile copy: rejected {rejected} file(s)", file=sys.stderr)
    return 0 if imported else 1


def _elevate_macos() -> int:
    """Authenticate one hash-pinned installer snapshot through macOS."""
    if sys.argv[1:3] != ["elevate", "install"]:
        return fail("administrator dialog is reserved for `elevate install`")
    owner_uid = os.getuid()
    owner_gid = os.getgid()
    members = ("router.py", "privileged_helper.py", "privileged_installer.py", "sing-box-release.json")
    archive_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="proxy-router-bootstrap-", suffix=".zip", delete=False
        ) as handle:
            archive_path = Path(handle.name)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in members:
                source = Path(__file__).resolve() if name == "router.py" else ROOT / name
                archive.writestr(name, _safe_source_bytes(source, owner_uid))
        os.chmod(archive_path, 0o600)
        archive_bytes = archive_path.read_bytes()
        digest = hashlib.sha256(archive_bytes).hexdigest()
        bootstrap = (
            "import hashlib,io,os,runpy,sys,tempfile,zipfile\n"
            "path,digest,user_root,legacy_python,legacy_router,uid,gid=sys.argv[1:]\n"
            "data=open(path,'rb').read(2*1024*1024+1)\n"
            "if len(data)>2*1024*1024 or hashlib.sha256(data).hexdigest()!=digest: raise SystemExit('bootstrap digest mismatch')\n"
            "names={'router.py','privileged_helper.py','privileged_installer.py','sing-box-release.json'}\n"
            "z=zipfile.ZipFile(io.BytesIO(data),'r')\n"
            "if set(z.namelist())!=names or not all(not i.is_dir() and i.file_size<=1024*1024 for i in z.infolist()): raise SystemExit('bootstrap archive shape mismatch')\n"
            "with tempfile.TemporaryDirectory(prefix='proxy-router-install-',dir='/private/var/tmp') as d:\n"
            "  for n in names:\n"
            "    p=os.path.join(d,n); f=open(p,'xb'); f.write(z.read(n)); f.close(); os.chmod(p,0o600)\n"
            "  os.environ.clear(); os.environ.update({'PROXY_ROUTER_ROOT':user_root,'PROXY_ROUTER_INSTALL_SOURCE':d,'PROXY_ROUTER_LEGACY_PYTHON':legacy_python,'PROXY_ROUTER_LEGACY_ROUTER':legacy_router,'SUDO_UID':uid,'SUDO_GID':gid})\n"
            "  sys.path.insert(0,d); sys.argv=[os.path.join(d,'router.py'),'elevate','install']; runpy.run_path(sys.argv[0],run_name='__main__')\n"
        )
        command = [
            "/usr/bin/python3", "-I", "-S", "-c", bootstrap,
            str(archive_path), digest, str(ROOT), sys.executable,
            os.path.abspath(__file__), str(owner_uid), str(owner_gid),
        ]
        content = shlex.join(command).replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "{content}" with administrator privileges'
        proc = subprocess.run(["osascript", "-e", script], text=True)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        return fail(f"could not prepare privileged helper installer: {exc}")
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)
    if proc.returncode != 0:
        print("router: privileged helper installation canceled or failed", file=sys.stderr)
    return proc.returncode


SUDOERS_FILE = Path("/private/etc/sudoers.d/91-proxy-router")
PRIVILEGED_HELPER = Path(
    "/Library/PrivilegedHelperTools/com.proxy-router/current/privileged_helper.py"
)
PRIVILEGED_STATE_BASE = Path("/private/var/db/proxy-router")
PRIVILEGED_ENV = "/usr/bin/env"
# The helper deliberately runs under the SYSTEM python via `env -i` (minimal
# environment): sudoers grants an exact interpreter path, and pointing it at a
# user-managed interpreter (e.g. /opt/anaconda3/bin/python3) would couple root
# elevation to that install. Launchd plists that invoke router.py directly must
# still keep their interpreter FIRST in PATH to match the legacy grant — do not
# "unify" these two interpreter identities; they are separate contracts.
PRIVILEGED_PYTHON = "/usr/bin/python3"
PRIVILEGED_OPERATIONS = frozenset({"status", "start", "stop", "reload", "uninstall"})


def _helper_command(operation: str, uid: int | None = None) -> list[str]:
    """Exact argv authorized by the v2 root-helper sudoers policy."""
    if operation not in PRIVILEGED_OPERATIONS:
        raise ValueError(f"unknown privileged helper operation: {operation}")
    owner = os.getuid() if uid is None else uid
    if isinstance(owner, bool) or not isinstance(owner, int) or owner <= 0:
        raise ValueError("privileged helper uid is invalid")
    return [
        "sudo", "-n",
        PRIVILEGED_ENV, "-i", "HOME=/var/empty",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C",
        PRIVILEGED_PYTHON, "-I", "-S", str(PRIVILEGED_HELPER),
        operation, str(owner),
    ]


def _helper_status() -> dict | None:
    """Return canonical helper status, or None when exact NOPASSWD is absent."""
    try:
        result = subprocess.run(
            _helper_command("status"),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError):
        return None
    stdout = getattr(result, "stdout", "") or ""
    stderr_text = getattr(result, "stderr", "") or ""
    if result.returncode != 0:
        stderr = stderr_text.lower()
        if any(token in stderr for token in _SUDO_DENIAL_TOKENS):
            return None
        return {"installed": False, "error": (stderr_text or stdout or "helper failed")[-300:]}
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return {"installed": False, "error": "helper returned invalid JSON"}
    required = {"installed", "running", "pid", "mode", "schema_version"}
    if not isinstance(value, dict) or not required <= set(value) or value.get("schema_version") != 1:
        return {"installed": False, "error": "helper status schema mismatch"}
    return value


def _helper_denied_reason(stderr: str) -> str | None:
    """Classify why a `sudo -n` helper invocation was refused (issue #76).

    The launchd-autostarted tray runs without a TTY and cannot fall back to
    an admin dialog, so when the one-time elevation grant is missing or
    stale every lifecycle action fails at the sudo boundary. Distinguishing
    that from a genuine helper failure lets callers print the ONE fix
    (`router.py elevate install`) instead of raw sudo jargon.
    """
    lowered = (stderr or "").lower()
    if any(token in lowered for token in _SUDO_DENIAL_TOKENS):
        return "not-granted"
    if "no such file" in lowered or "command not found" in lowered:
        return "helper-missing"
    return None


_HELPER_FIX = "run `router.py elevate install` once in a terminal (admin password), then Connect again"
_HELPER_NOT_INSTALLED = (
    "startup permission not set up yet: the automatic (launchd) app cannot "
    "control the VPN engine without it; " + _HELPER_FIX)


def _helper_run(operation: str) -> int:
    """Run one exact helper lifecycle operation without any dialog fallback."""
    try:
        result = subprocess.run(
            _helper_command(operation),
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return fail(f"privileged helper {operation} failed: {exc}")
    if result.returncode != 0:
        stderr_text = result.stderr or ""
        stdout_text = result.stdout or ""
        detail = (stderr_text or stdout_text or "helper denied the operation")[-300:]
        if _helper_denied_reason(stderr_text) == "not-granted":
            # Issue #76: the autostarted tray/keepalive has no TTY and no way
            # to answer sudo's password prompt; a raw "a password is
            # required" reads like a broken app. Name the actual gap and the
            # exact one-time fix so the error is actionable everywhere,
            # including launchd logs.
            return fail(
                f"VPN startup permission missing (sudo grant denied during "
                f"'{operation}'): {_HELPER_FIX}. raw error: {detail.strip()}"
            )
        return fail(f"privileged helper {operation} failed: {detail}")
    return 0

# stderr markers that prove `sudo -n` DENIED (vs the command itself
# failing). A sudoers grant is a snapshot of the command shapes at install
# time, so a command added later (e.g. `start`/`stop` for issue #12) can
# hit a denial even when the probe passes; callers fall back to the admin
# dialog on these markers instead of surfacing a raw sudo error.
_SUDO_DENIAL_TOKENS = (
    "a password is required",
    "not in the sudoers",
    "must have a tty",
    # Issue #76: non-interactive contexts (launchd agents, cron) hit these
    # phrasings instead; they prove the same sudo grant denial.
    "no tty present",
    "no askpass program",
)

# Legacy root-owned engine: regular users cannot signal it directly; direct
# them to the safe helper migration. Shared by engine_stop error paths.
_ROOT_ENGINE_HINT = ("router: engine runs as root; run `router.py elevate install` "
                     "to manage it through the safe root-owned helper")


def _sudoers_rules(user: str, uid: int) -> str:
    """Render only exact root-owned helper operations; never checkout code."""
    import privileged_installer

    return privileged_installer.render_sudoers(user, uid, PRIVILEGED_HELPER)


def _sudoers_installed() -> bool:
    """True only when the exact root-owned helper status command succeeds."""
    if _effective_uid() == 0:
        return True
    status = _helper_status()
    return bool(status and status.get("installed"))


def _elevate() -> int:
    """Fail closed: whole-controller root re-execution was removed by #56."""
    return fail(
        "unsafe whole-controller elevation is disabled; "
        "run `router.py elevate install` for the safe privileged helper"
    )


def _safe_source_bytes(path: Path, owner_uid: int, *, maximum: int = 4 * 1024 * 1024) -> bytes:
    """Snapshot one authenticated installer source file without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != owner_uid
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or info.st_size > maximum
        ):
            raise RuntimeError(f"unsafe installer source: {path}")
        payload = os.read(fd, maximum + 1)
    finally:
        os.close(fd)
    if len(payload) > maximum:
        raise RuntimeError(f"oversized installer source: {path}")
    return payload


def _install_privileged_helper_root() -> int:
    """Authenticated root phase: revoke legacy grant, stage helper, install v2."""
    if _effective_uid() != 0:
        return fail("privileged helper install root phase requires administrator approval")
    try:
        import privileged_helper
        import privileged_installer

        root_info = os.lstat(ROOT)
        owner_uid = int(os.environ.get("SUDO_UID") or root_info.st_uid)
        owner_gid = int(os.environ.get("SUDO_GID") or root_info.st_gid)
        if owner_uid <= 0 or root_info.st_uid != owner_uid or not stat.S_ISDIR(root_info.st_mode):
            raise RuntimeError("installer root must be owned by the authenticated non-root user")
        if pwd is None:
            raise RuntimeError("the privileged macOS helper is unavailable on Windows")
        username = pwd.getpwuid(owner_uid).pw_name
        source_root = Path(os.environ.get("PROXY_ROUTER_INSTALL_SOURCE") or ROOT).resolve()
        source_owner = 0 if os.environ.get("PROXY_ROUTER_INSTALL_SOURCE") else owner_uid
        helper_source = _safe_source_bytes(source_root / "privileged_helper.py", source_owner)
        installer_source = _safe_source_bytes(source_root / "privileged_installer.py", source_owner)
        manifest_path = source_root / "sing-box-release.json"
        manifest_source = _safe_source_bytes(manifest_path, source_owner)
        machine = platform.machine().lower()
        architecture = "arm64" if machine == "arm64" else "x86_64" if machine in {"x86_64", "amd64"} else machine
        layout = privileged_installer.InstallLayout()
        policy = privileged_installer.render_sudoers(username, owner_uid)

        def stop_legacy() -> None:
            route_watcher_stop()
            if engine_stop() != 0:
                raise RuntimeError("could not stop the verified legacy root engine")

        def stage():
            release = privileged_helper.release_for_architecture(
                manifest_path,
                architecture,
                owner_uid=source_owner,
                anchor=source_root,
            )
            request = urllib.request.Request(release["url"], headers={"User-Agent": "proxy-router-installer/2"})
            with urllib.request.urlopen(request, timeout=60) as response:
                archive = response.read(release["size"] + 1)
            binary = privileged_helper.verified_release_binary(archive, release)
            bundle = privileged_installer.stage_bundle(
                layout,
                helper_bytes=helper_source,
                installer_bytes=installer_source,
                manifest_bytes=manifest_source,
                binary_bytes=binary,
            )
            privileged_installer.write_install_metadata(
                layout,
                uid=owner_uid,
                gid=owner_gid,
                user_root=ROOT,
                user_root_device=root_info.st_dev,
                user_root_inode=root_info.st_ino,
                bundle_digest=bundle["bundle_digest"],
                binary_sha256=bundle["binary_sha256"],
            )
            privileged_installer.install_policy(layout, policy)
            return bundle

        privileged_installer.migrate_install(
            layout,
            legacy_python=os.environ.get("PROXY_ROUTER_LEGACY_PYTHON", sys.executable),
            legacy_router=os.environ.get("PROXY_ROUTER_LEGACY_ROUTER", os.path.abspath(__file__)),
            stop_legacy=stop_legacy,
            stage=stage,
        )
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        return fail(f"privileged helper install failed: {exc}")
    print("elevate: installed root-owned privileged helper; lifecycle commands are now passwordless")
    return 0


def cmd_elevate(action: str) -> int:
    """Manage the root-owned helper; install is the sole admin-dialog path."""
    if action == "status":
        if _sudoers_installed():
            print("elevate: safe root-owned privileged helper is active")
            return 0
        print("elevate: not installed; run `router.py elevate install` for one-time setup",
              file=sys.stderr)
        return 1
    if action == "uninstall":
        if _effective_uid() == 0:
            return fail("run uninstall through the installed helper as the owning user")
        return _helper_run("uninstall")
    if _effective_uid() != 0:
        if not sys.stdin.isatty():
            return fail("elevate install needs an interactive terminal for administrator approval")
        return _elevate_macos()
    return _install_privileged_helper_root()


def main() -> int:
    parser = argparse.ArgumentParser(prog="router", description="selective WireGuard proxy router")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("ensure", help="ensure the engine is up (0 = healthy, 1 = failure, 3 = manual-off quiescent)")
    sub.add_parser("start")
    sub.add_parser("stop")
    status = sub.add_parser("status")
    doctor_parser = sub.add_parser("doctor", help="one-command health audit (read-only)")
    doctor_parser.add_argument("--network", action="store_true",
                               help="run bounded direct/routed connectivity and DNS checks")
    status.add_argument("--json", action="store_true", help="machine-readable status (JSON)")
    sub.add_parser("reload")
    autodetect = sub.add_parser("autodetect", help="discover routed web-app dependency hostnames")
    autodetect.add_argument("source", nargs="?", default="twitch",
                            help="configured discovery source (default: twitch)")
    autodetect.add_argument("--no-reload", action="store_true",
                            help="persist discoveries without reloading sing-box")
    autodetect.add_argument("--quiet", action="store_true",
                            help="suppress normal discovery output")
    sub.add_parser("routes")
    sub.add_parser("up")
    sub.add_parser("down")

    routing = sub.add_parser("routing", help="routing modes (safe-list / vpn-list): show|set|add|remove")
    routing_sub = routing.add_subparsers(dest="routing_action")
    routing_sub.add_parser("show", help="show the effective routing mode and lists (JSON + human)")
    routing_set = routing_sub.add_parser("set", help="switch routing mode (safe-list / vpn-list / default)")
    routing_set.add_argument("--mode", required=True, choices=list(ROUTING_MODES) + ["default"])
    routing_set.add_argument("--default-provider", default=None,
                             help="provider carrying everything not pinned direct (safe-list)")
    for action in ("add", "remove"):
        routing_mut = routing_sub.add_parser(action, help=f"{action} a domain on a routing list")
        routing_mut.add_argument("--mode", required=True, choices=list(ROUTING_MODES))
        routing_mut.add_argument("--domain", required=True)

    egress = sub.add_parser("egress", help="egress health for provider exits")
    egress.add_argument("action", choices=["probe", "show", "check", "sweep"])
    egress.add_argument("provider", nargs="?", default=None,
                        help="provider name (positional, for probe/show/sweep)")
    egress.add_argument("--provider", dest="provider_opt", default=None,
                        help="provider name to check (egress check)")
    egress.add_argument("--json", action="store_true",
                        help="egress check/sweep: machine-readable JSON output")
    egress.add_argument("--allow-tun", action="store_true",
                        help="allow an explicit full-pool sweep to reload the shared TUN engine")

    init = sub.add_parser("init")
    init.add_argument("--force", action="store_true", help="overwrite an existing router.json")

    vpn = sub.add_parser("vpn", help="toggle TUN mode (on|off|restart|status|capture)")
    vpn.add_argument("action", choices=["on", "off", "restart", "status", "capture"])
    vpn.add_argument("capture", nargs="?", choices=["ruleset", "routes"],
                     help="TUN capture scope for `vpn capture`")

    # setup / monitor / watcher delegate to their modules with a
    # parse_known_args passthrough, but they mirror each module's real
    # flags so `--help` documents the actual surface instead of an opaque
    # catch-all REMAINDER argument.
    def _add_delegated_flags(parser: argparse.ArgumentParser,
                             flags: tuple[tuple[tuple[str, ...], dict], ...]) -> None:
        for fargs, fkwargs in flags:
            parser.add_argument(*fargs, **fkwargs)

    setup = sub.add_parser("setup", help="interactive Proton/WARP setup wizard")
    _add_delegated_flags(setup, (
        (("--guide",), {"choices": ("proton", "warp", "all"), "metavar": "PROVIDER",
                        "help": "print a setup guide (proton, warp, or all)"}),
        (("--check",), {"action": "store_true",
                        "help": "verify router.json and provider profiles"}),
        (("--import-proton",), {"nargs": "+", "metavar": "PATH",
                                "help": "import WireGuard .conf file(s)/directory into providers/proton"}),
        (("--import-warp",), {"nargs": "+", "metavar": "PATH",
                              "help": "import WireGuard .conf file(s)/directory into providers/cloudflare"}),
        (("--preset",), {"nargs": "?", "const": "default", "metavar": "NAME",
                         "help": "apply a preset by name (built-in or custom; bare --preset applies 'default')"}),
        (("--preset-list",), {"action": "store_true",
                              "help": "list available presets (built-in and custom)"}),
        (("--preset-add",), {"metavar": "NAME",
                             "help": "create a custom preset file under presets/"}),
        (("--provider",), {"metavar": "PROVIDER",
                           "help": "provider for --preset-add (e.g. proton, cloudflare)"}),
        (("--domain",), {"action": "append", "default": [], "metavar": "DOMAIN",
                         "help": "domain for --preset-add (repeatable)"}),
        (("--bridge-install",), {"action": "store_true",
                                 "help": "install the Hermes OpenCode auto-rotation bridge"}),
        (("--bridge-check",), {"action": "store_true",
                               "help": "verify the installed OpenCode auto-rotation bridge"}),
    ))
    # Unlisted wizard flags (--fallback*, --autocheck*, --keepalive-*,
    # --transparent*, ...) still reach setup_tui.main via parse_known_args.

    monitor = sub.add_parser("monitor", help="opt-in network monitoring")
    monitor.add_argument("monitor_action", nargs="?",
                         choices=["check", "on", "off", "status", "logs"],
                         help="monitor subcommand (default status)")
    monitor.add_argument("--interval", type=int, default=None,
                         help="worker sample interval in seconds")
    monitor.add_argument("--lines", type=int, default=20,
                         help="log tail length for `monitor logs`")
    monitor.add_argument("--root", default=None, help=argparse.SUPPRESS)
    monitor.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)

    watcher = sub.add_parser("watcher", help="standalone routed-connection watcher")
    watcher.add_argument("watcher_action", nargs="?",
                         choices=["status", "on", "off", "logs"],
                         help="watcher subcommand (default status)")
    watcher.add_argument("--interval", type=float, default=None,
                         help="poll interval in seconds")
    watcher.add_argument("--lines", type=int, default=20,
                         help="log tail length for `watcher logs`")
    watcher.add_argument("--root", default=None, help=argparse.SUPPRESS)
    watcher.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)

    r_add = sub.add_parser("add")
    r_add.add_argument("--id")
    r_add.add_argument("--domain")
    r_add.add_argument("--ip")
    r_add.add_argument("--provider", required=True)

    r_rm = sub.add_parser("remove")
    r_rm.add_argument("id")

    r_rot = sub.add_parser("rotate")
    r_rot.add_argument("provider", nargs="?", help="provider name (optional with --if-due)")
    r_rot.add_argument("--if-due", action="store_true",
                       help="scheduled rotation: only rotate when the configured interval elapsed (exit 3 when not due)")
    r_rot.add_argument("--to", default=None,
                       help="switch to this exact exit profile instead of the ranked next one (e.g. 01-NL-FREE-140)")
    r_rot.add_argument("--reason", default=None,
                       help="mark the current profile with an upstream error/cooldown before rotating (e.g. 503, 429, timeout, 1010)")
    r_rot.add_argument("--force", action="store_true",
                       help="ignore cooldowns and blocked-exit markers and switch anyway")
    r_rot.add_argument("--no-probe", action="store_true",
                       help="skip the post-switch egress probe")
    r_rot.add_argument("--automatic", action="store_true", help=argparse.SUPPRESS)

    r_event = sub.add_parser("response-event", help="handle an observed upstream response")
    r_event.add_argument("--host", required=True, help="destination hostname observed by the proxy")
    r_event.add_argument("--status", required=True, type=int, help="HTTP response status (0 when no response was received)")
    r_event.add_argument("--provider", default=None, help="expected route provider")
    r_event.add_argument("--reason", default=None, choices=["timeout", "tls", "connection"],
                         help="real-traffic stall class: rotates the exit through error-policy handling even without an HTTP status")
    r_event.add_argument("--dedupe-seconds", type=int, default=5,
                         help="suppress duplicate events for this many seconds")

    w_proxy = sub.add_parser("with-proxy", help="run a command through the proxy when up, else direct (fail-open)")
    w_proxy.add_argument("--timeout-ms", type=int, default=300, help="listener probe timeout (default 300)")
    w_proxy_group = w_proxy.add_mutually_exclusive_group()
    w_proxy_group.add_argument("--force-proxy", action="store_true",
                               help="fail (exit 4) instead of running direct when the listener is down")
    w_proxy_group.add_argument("--force-direct", action="store_true",
                               help="skip the probe and always run direct")
    w_proxy.add_argument("--check", action="store_true",
                         help="print the proxy URL and exit 0 if the listener answers, else exit 1")
    w_proxy.add_argument("cmd_tail", nargs=argparse.REMAINDER,
                         help="-- <cmd...> (argv after a leading --)")

    failover = sub.add_parser("failover", help="activate or clear a provider fallback")
    failover.add_argument("provider")
    failover.add_argument("action", choices=["on", "off", "status", "recover", "restore"])
    failover.add_argument("--host", help="failing routed hostname for confirmed recovery")
    failover.add_argument("--to", default=None, help="fallback provider (must match config)")
    failover.add_argument("--reason", default="transport")
    failover.add_argument("--json", action="store_true")
    failover.add_argument("--automatic", action="store_true", help=argparse.SUPPRESS)

    r_count = sub.add_parser("provider-count")
    r_count.add_argument("provider")

    providers = sub.add_parser(
        "providers",
        help="provider pool maintenance (check: offline validity preflight)",
    )
    providers_sub = providers.add_subparsers(dest="providers_action")
    p_check = providers_sub.add_parser(
        "check",
        help="offline validity preflight: config, profile pool, active exit (issue #51)",
    )
    p_check.add_argument("provider", nargs="?", default=None,
                         help="check a single provider instead of all")
    p_check.add_argument("--json", action="store_true",
                         help="machine-readable JSON report")

    profile = sub.add_parser("profile", help="manage local WireGuard profiles")
    profile_sub = profile.add_subparsers(dest="profile_action")
    profile_copy_parser = profile_sub.add_parser(
        "copy", help="copy validated .conf file(s)/directory into a provider"
    )
    profile_copy_parser.add_argument("sources", nargs="+", metavar="PATH")
    profile_copy_parser.add_argument("--provider", required=True,
                                    help="configured destination provider (e.g. proton)")

    elevate = sub.add_parser("elevate", help="one-time passwordless-sudo grant (install|uninstall|status)")
    elevate.add_argument("action", choices=["install", "uninstall", "status"])

    sub.add_parser("network-check", help="auto-switch routing preset for the current Wi-Fi network")
    network_status_parser = sub.add_parser(
        "network-status", help="report whether the current Wi-Fi network is available"
    )
    network_status_parser.add_argument("--json", action="store_true", help="machine-readable JSON")
    sub.add_parser("network-disconnect", help="stop proxy-router until Wi-Fi returns")
    sub.add_parser("network-reconnect", help="reconnect after Wi-Fi returns")

    args, passthrough = parser.parse_known_args()
    if args.cmd == "elevate":
        return cmd_elevate(args.action)
    if args.cmd == "network-check":
        return cmd_network_check()
    if args.cmd == "network-status":
        return cmd_network_status(as_json=args.json)
    if args.cmd == "network-disconnect":
        return cmd_network_disconnect()
    if args.cmd == "network-reconnect":
        return cmd_network_reconnect()
    if _needs_elevation(args):
        return _elevate()
    def _delegated_setup_argv() -> list[str]:
        """Forward exactly the wizard flags the operator passed on.

        Mirrored arguments are parsed above so `--help` documents them;
        they are rebuilt here so setup_tui's own parser stays the single
        authority for validation and defaults.
        """
        forwarded: list[str] = []
        if args.guide:
            forwarded += ["--guide", args.guide]
        if args.check:
            forwarded.append("--check")
        if args.import_proton:
            forwarded += ["--import-proton", *args.import_proton]
        if args.import_warp:
            forwarded += ["--import-warp", *args.import_warp]
        if args.preset is not None:  # bare --preset arrives as the "default" const
            forwarded += ["--preset", args.preset]
        if args.preset_list:
            forwarded.append("--preset-list")
        if args.preset_add:
            forwarded += ["--preset-add", args.preset_add]
        if args.provider:
            forwarded += ["--provider", args.provider]
        for domain in args.domain:
            forwarded += ["--domain", domain]
        if args.bridge_install:
            forwarded.append("--bridge-install")
        if args.bridge_check:
            forwarded.append("--bridge-check")
        return forwarded

    if args.cmd == "setup":
        import setup_tui

        return setup_tui.main(["setup", *_delegated_setup_argv(), *passthrough], root=ROOT)
    if args.cmd == "monitor":
        import monitor

        forwarded = []
        if args.monitor_action:
            forwarded.append(args.monitor_action)
        if args.interval is not None:
            forwarded += ["--interval", str(args.interval)]
        if args.lines != 20:
            forwarded += ["--lines", str(args.lines)]
        if args.root:
            forwarded += ["--root", args.root]
        if args.worker:
            forwarded.append("--worker")
        return monitor.main(["monitor", *forwarded, *passthrough], root=ROOT)
    if args.cmd == "watcher":
        import route_watcher

        forwarded = []
        if args.watcher_action:
            forwarded.append(args.watcher_action)
        if args.interval is not None:
            forwarded += ["--interval", str(args.interval)]
        if args.lines != 20:
            forwarded += ["--lines", str(args.lines)]
        if args.root:
            forwarded += ["--root", args.root]
        if args.worker:
            forwarded.append("--worker")
        return route_watcher.main(["watcher", *forwarded, *passthrough], root=ROOT)
    if passthrough:
        parser.error("unrecognized arguments: " + " ".join(passthrough))
    if args.cmd == "with-proxy":
        # Fail-open must work even with a broken/missing router.json, so it
        # bypasses the load_config gate below (it only reads the port).
        tail = args.cmd_tail
        if tail and tail[0] == "--":
            tail = tail[1:]
        return with_proxy(tail, timeout_ms=args.timeout_ms, force_proxy=args.force_proxy,
                          force_direct=args.force_direct, check=args.check)
    if args.cmd == "init":
        return write_default_config(force=getattr(args, "force", False))
    if args.cmd is None:
        # Bare `proxy-router` opens the interactive TUI (settings, presets,
        # routing modes, health). The wizard never starts or reloads the
        # engine on its own — the only lifecycle action is menu item 8,
        # operator-initiated. Help stays available via `router.py --help`
        # (argparse handles that before we get here).
        import setup_tui

        return setup_tui.main([], root=ROOT)

    if args.cmd == "up":
        if sys.platform != "darwin":
            return fail("up requires macOS (v1 scope)")
        rc = load_config()
        if rc:
            return rc

        def _up_with_latch() -> int:
            rc = engine_start()
            if rc != 0:
                return rc
            return _clear_manual_off()

        rc = _with_lock(_up_with_latch)
        if rc == 0:
            route_watcher_start()
            ensure_tray_started()
            return system_proxy_on()
        return rc
    # Emergency teardown paths must not require a valid router.json.
    # `stop` and `down` are explicit disconnects; they stop engines and
    # disable system proxy even when configuration is missing/malformed.
    if args.cmd == "down":
        if sys.platform != "darwin":
            return fail("down requires macOS (v1 scope)")
        return system_proxy_off()
    if args.cmd == "stop":
        # Publish intent before any global side effect or lock wait.  This is
        # the linearization point that prevents ensure/sweep from resurrecting
        # the engine while Disconnect is waiting.
        if _write_manual_off() != 0:
            return 1
        if sys.platform == "darwin":
            proxy_rc = system_proxy_off()
            if proxy_rc != 0:
                print("router: system proxy disable failed; engine left available for retry", file=sys.stderr)
                return proxy_rc
        route_watcher_stop()
        rc = _with_lock(engine_stop, timeout=5.0)
        if rc != 0:
            # Keep manual-off on every failure.  That suppresses maintenance
            # while the user-visible control surface reports a retryable,
            # potentially partial disconnect rather than silently resurrecting.
            return rc
        try:
            remaining = _find_our_engine_pids()
        except EngineIdentityError as exc:
            print(f"router: cannot prove engine termination: {exc}", file=sys.stderr)
            return 1
        if remaining:
            print(f"router: engine survived stop despite manual-off (pids {remaining})", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "vpn" and args.action == "off":
        # A broken provider graph must not block TUN teardown. If config is
        # valid, the normal dispatch below performs the full transaction; if
        # not, fail open to a stopped/direct state with a repair hint.
        rc = load_config()
        if rc:
            return _vpn_off_without_config()
    else:
        rc = load_config()
    if rc:
        # A broken/missing router.json is a degraded state: `status` and
        # `vpn status` still print a state line and exit 1 (M13); the reason
        # is already on stderr from load_config.
        if args.cmd == "status":
            if args.json:
                print(json.dumps({"up": False, "state": "down (unusable config; see error above)",
                                  "mode": None, "port": None, "providers": {}, "routes": [],
                                  "routing": {"mode": None, "direct_domains": [], "vpn_domains": [],
                                              "default_provider": None}},
                                 indent=2, sort_keys=True))
            else:
                print("down (unusable config; see error above)")
            return 1
        if args.cmd == "vpn":
            print("vpn: down (unusable config; see error above)")
            return 1
        return rc

    if args.cmd == "ensure":
        rc = _with_lock(engine_ensure)
        if rc == 0:
            route_watcher_start()
        else:
            route_watcher_stop()
        return rc
    if args.cmd == "start":
        route_watcher_stop()
        def _start_with_latch():
            rc = engine_start()
            if rc != 0:
                return rc
            return _clear_manual_off()
        rc = _with_lock(_start_with_latch)
        if rc == 0:
            route_watcher_start()
            ensure_tray_started()
            # `start` is the user-facing Connect path. In proxy mode the
            # engine can be healthy while GUI apps still bypass it unless the
            # macOS service proxy is enabled here too. Keep TUN mode's proxy
            # disabled: TUN has no reason to point apps at 127.0.0.1:2080.
            if sys.platform == "darwin":
                proxy_rc = (system_proxy_on() if current_mode() == "proxy"
                            else system_proxy_off())
                if proxy_rc != 0:
                    return proxy_rc
        return rc
    # (legacy stop branch removed — early stop before load_config is authoritative)
    if args.cmd == "doctor":
        return doctor(network=bool(args.network))
    if args.cmd == "status":
        if resolve_sing_box() is None:
            print(f"router: {_sing_box_missing_message()}", file=sys.stderr)
        rc, line = _status_report()
        if args.json:
            print(json.dumps(status_json(), indent=2, sort_keys=True))
        else:
            print(line)
            try:
                legacy = _legacy_launch_agents()
            except Exception:
                legacy = []
            if legacy:
                names = ", ".join(legacy)
                print(f"router: legacy launch agent(s) still installed: {names}",
                      file=sys.stderr)
                print("router: migrate with `router.py elevate install` or remove "
                      "them from ~/Library/LaunchAgents", file=sys.stderr)
        return rc
    if args.cmd == "reload":
        rc = _with_lock(engine_reload)
        if rc == 0:
            route_watcher_start()
        return rc
    if args.cmd == "autodetect":
        return _with_lock(lambda: autodetect_source(
            args.source, reload=not args.no_reload, quiet=args.quiet
        ))
    if args.cmd == "rotate":
        if args.if_due:
            return _with_lock(lambda: rotate_due(args.provider))
        if not args.provider:
            parser.error("rotate needs a provider (or use --if-due for scheduled rotation)")
        return _with_lock(lambda: rotate(args.provider, reason=args.reason, force=args.force,
                                         probe=not args.no_probe, to=args.to,
                                         automatic=args.automatic))
    if args.cmd == "response-event":
        return _with_lock(lambda: response_event(
            args.host, args.status, provider=args.provider,
            reason=args.reason, dedupe_seconds=args.dedupe_seconds,
        ))
    if args.cmd == "failover":
        if args.action in ("recover", "restore"):
            if not args.host:
                parser.error(f"failover {args.action} requires --host")
            handler = recover_route if args.action == "recover" else restore_fallback
            return _with_lock(lambda: handler(args.provider, args.host))
        if args.action == "on":
            return _with_lock(lambda: activate_fallback(
                args.provider, target=args.to, reason=args.reason,
                automatic=args.automatic))
        if args.action == "off":
            return _with_lock(lambda: deactivate_fallback(
                args.provider, automatic=args.automatic))
        state = fallback_status(args.provider)
        if args.json:
            print(json.dumps(state, indent=2, sort_keys=True))
        else:
            print(f"fallback {args.provider}: configured={state['configured'] or 'none'} "
                  f"active={state['active'] or 'none'}")
        return 0
    if args.cmd == "egress":
        if args.action == "probe":
            return egress_probe(args.provider)
        if args.action == "check":
            return egress_check(args.provider_opt or args.provider, as_json=args.json)
        if args.action == "sweep":
            # Sweep locks each short engine/config mutation itself; holding the
            # lifecycle lock around the full network/probe loop starves Stop.
            return egress_sweep(args.provider, as_json=args.json, allow_tun=args.allow_tun)
        return egress_show(args.provider)
    if args.cmd == "provider-count":
        print(provider_count(args.provider))
        return 0
    if args.cmd == "providers":
        if args.providers_action == "check":
            return providers_check(args.provider, as_json=args.json)
        parser.error("providers needs an action: check")
    if args.cmd == "profile":
        if args.profile_action == "copy":
            return profile_copy(args.provider, args.sources)
        parser.error("profile needs an action: copy")
    if args.cmd == "routes":
        return routes_list()
    if args.cmd == "routing":
        if args.routing_action == "show":
            return routing_cli_show()
        if args.routing_action == "set":
            return routing_cli_set(args.mode, args.default_provider)
        if args.routing_action == "add":
            return routing_cli_add(args.mode, args.domain)
        if args.routing_action == "remove":
            return routing_cli_remove(args.mode, args.domain)
        parser.error("routing needs an action: show | set | add | remove")
    if args.cmd == "vpn":
        if args.action == "capture":
            if args.capture is None:
                parser.error("vpn capture needs a scope: routes | ruleset")
            return _with_lock(lambda: vpn_capture(args.capture))
        if args.action == "on":
            route_watcher_stop()
            rc = _with_lock(vpn_on)
            if rc == 0:
                route_watcher_start()
            return rc
        if args.action == "restart":
            route_watcher_stop()
            rc = _with_lock(vpn_restart)
            if rc == 0:
                route_watcher_start()
            return rc
        if args.action == "off":
            route_watcher_stop()
            rc = _with_lock(vpn_off)
            if rc == 0:
                route_watcher_start()
            return rc
        return vpn_status()
    if args.cmd == "add":
        return _with_lock(lambda: routes_add(args))
    if args.cmd == "remove":
        return _with_lock(lambda: routes_remove(args.id))
    parser.print_help()
    return 2


class _EngineLock:
    """Exclusive lock on ``state/engine.lock``.

    Uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows so the
    same CLI surface works on macOS, Linux, and Windows.
    """

    def __init__(self, timeout: float | None = None) -> None:
        self._path = LOCK_FILE
        self._file = None
        self._timeout = timeout

    def __enter__(self) -> "_EngineLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("w")
        if os.name == "nt":
            import msvcrt

            self._file.write("0")
            self._file.flush()
            self._file.seek(0)
            if self._timeout is not None:
                deadline = time.monotonic() + self._timeout
                while True:
                    try:
                        msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self._file.close()
                            self._file = None
                            raise TimeoutError("engine lock busy")
                        time.sleep(0.05)
            else:
                msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            if self._timeout is not None:
                deadline = time.monotonic() + self._timeout
                while True:
                    try:
                        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            self._file.close()
                            self._file = None
                            raise TimeoutError("engine lock busy")
                        time.sleep(0.05)
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            self._file.close()
                            self._file = None
                            raise TimeoutError(f"engine lock busy: {exc}")
                        time.sleep(0.05)
            else:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self._file is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
        return False


def _with_lock(action, timeout: float | None = None) -> Any:
    # The elevated reload child is the same operation re-run as root; the
    # parent holds the flock while it waits for the child, so a child that
    # re-acquires the lock would deadlock (parent waits for child, child
    # waits for the parent's lock).
    if _effective_uid() == 0 and os.environ.get("PROXY_ROUTER_ELEVATED"):
        return action()
    try:
        with _EngineLock(timeout=timeout):
            return action()
    except TimeoutError as exc:
        print(f"router: {exc} (another operation holds the engine lock)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
