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
import json
import os
import random
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
CONFIG_FILE = ROOT / "router.json"
SING_BOX_CONFIG = ROOT / "sing-box.json"
LAST_GOOD_FILE = ROOT / "sing-box.json.last-good"
PID_FILE = ROOT / "sing-box.pid"
LOG_FILE = ROOT / "sing-box.log"
LOCK_FILE = ROOT / "state" / "engine.lock"
MODE_FILE = ROOT / "state" / "mode"
# Written by `router.py stop` (and the tray Disconnect); respected by
# keepalive.sh so a manual disconnect is NOT resurrected on the next
# ensure tick. Removed by `router.py start` / tray Connect.
MANUAL_OFF_FILE = ROOT / "state" / "manual-off"
# Pending per-provider overrides handed to an elevated `reload` when the
# engine runs as root and the invoking process cannot SIGHUP it directly.
RELOAD_OVERRIDE_FILE = ROOT / "state" / "reload-override.json"
DEFAULT_PORT = 2080
DEFAULT_TUN_ADDRESS = ["172.19.0.1/30"]
DEFAULT_TUN_MTU = 1500
# sing-box's 1500 default black-holes TCP on restrictive paths (see proton profiles)
DEFAULT_ENDPOINT_MTU = 1280
DEFAULT_TUN_STACK = "system"
DEFAULT_PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_EGRESS_SETTINGS = {
    "probe_url": DEFAULT_PROBE_URL,
    "probe_timeout": 8.0,
    # Probe identity. Cloudflare-fronted upstreams (zen's free tier) reset
    # generic clients on TLS fingerprint and gate by client type; set this to
    # the real client's UA (e.g. ``opencode/1.18.18``) so probe verdicts match
    # what the client actually experiences through the tunnel.
    "probe_user_agent": "proxy-router-egress/1.0",
    "block_seconds": 3600,
    "upstream_cooldown_seconds": 300,
    "fail_threshold": 2,
    "slow_latency_ms": 1200.0,
    "ok_window": 86400,
    # A just-switched WireGuard exit handshakes fine but can blackhole inner
    # TLS for its first seconds of life (measured on Proton free: ~10-30s).
    # Switch-adjacent probes retry once after this settle window before the
    # caller treats the exit as dead; 0 disables the retry.
    "probe_settle_seconds": 20.0,
}
# Optional scheduled rotation (router.json top-level ``rotation``): churn the
# active provider's exit every ``interval_seconds`` (0/absent = off) with
# ``jitter_seconds`` spread (default 300) instead of only rotating reactively
# on failures, so upstream rate limits see a fresh egress IP on a cadence.
DEFAULT_ROTATION_SETTINGS = {"interval_seconds": 0, "jitter_seconds": 300, "policy": "latency"}

_rotation: dict = {}
# Per-reason upstream-error policy (router.json top-level ``error_policy``,
# then per-provider ``providers.<name>.error_policy``, then these built-in
# defaults; closest scope wins). action: cooldown (rotate skips the lane until
# reset), exhaust (cooldown + ``exhausted``/``exhausted_until`` marker with a
# machine-readable reset time in the egress record), block (reputation block:
# rotate skips the lane entirely until expiry or --force).
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
# Rotate sing-box.log once it outgrows this (mirrors monitor.py sample
# rotation); the live log grows a line per connection and is unbounded.
LOG_MAX_BYTES = 10_000_000

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
_egress_settings: dict = {}
_error_policy: dict | None = None
_PROVIDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


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


def _hand_back_ownership(path: Path) -> None:
    """Chown a state file back to the user who invoked sudo.

    tun mode needs root, so `sudo vpn on` writes state files as root with
    0600; the regular-user keepalive/CLI then cannot read them and treats
    a live engine as dead (garbage pid file H6, unreadable mode/config),
    churning restarts. SUDO_UID/SUDO_GID identify who to hand back to."""
    if os.geteuid() != 0:
        return
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    try:
        os.chown(path, int(uid), int(gid))
    except (OSError, ValueError):
        pass


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


def load_config() -> int:
    global _providers, _routes, _port, _vpn, _routing
    if not CONFIG_FILE.is_file():
        return fail(f"missing {CONFIG_FILE.name}; run 'router.py init' first")
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict):
            return fail(f"bad {CONFIG_FILE.name}: top level must be an object")
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
        directory = entry.get("directory", f"providers/{name}")
        if not isinstance(directory, str):
            return fail(f"bad {CONFIG_FILE.name}: provider '{name}' directory must be a string")
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
    # Routing modes (safe-list / vpn-list): validated eagerly so a malformed
    # section fails load with a precise message, never a silent guess. Shared
    # with the `routing` CLI writer so both paths enforce the same rules.
    routing_error = _routing_error(routing, known_providers)
    if routing_error is not None:
        return fail(f"bad {CONFIG_FILE.name}: {routing_error}")
    try:
        _load_error_policy(data, providers)
        _load_rotation_settings(data)
    except ValueError as exc:
        return fail(f"bad {CONFIG_FILE.name}: {exc}")
    _load_egress_settings(data)
    _port = port
    _providers = providers
    _routes = routes
    _vpn = vpn
    _routing = dict(routing)
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
                                "fallback_providers": ["fallback-vpn"]},
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
            # vpn-list with an empty list is the safe default: route.final
            # stays "direct" and nothing is tunneled unless listed.
            "routing": {"mode": "vpn-list", "vpn_domains": []},
            "vpn": {
                "default_mode": "tun",
                "capture": "ruleset",
                "address": DEFAULT_TUN_ADDRESS,
                "mtu": DEFAULT_TUN_MTU,
                "stack": DEFAULT_TUN_STACK,
                "dns_transport": "udp",
                "selective": "roblox",
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
    path.write_text(str(int(time.time()) + seconds))
    os.chmod(path, 0o600)
    # Elevated (root) rotations write these markers; the user-level
    # keepalive/CLI must stay able to read and re-write them.
    _hand_back_ownership(path)
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
                  dns_ok: bool | None = None) -> dict:
    """Merge one probe outcome into the profile's egress record. A passing
    probe clears the fail streak and any blocked marker; a failure bumps the
    streak so rotation deprioritizes the exit. ``dns_ok`` (True/False from the
    tunnel-DNS companion check) is persisted when it could be determined."""
    record = read_egress(name, profile)
    now = int(time.time())
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
        return []
    items = raw if isinstance(raw, list) else [raw]
    seen: set[str] = set()
    chain: list[str] = []
    for target in items:
        if not isinstance(target, str) or target == name or target not in _providers or target in seen:
            continue
        seen.add(target)
        chain.append(target)
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
    return active if active in targets else None


def _effective_route_provider(name: str) -> str:
    """Map a primary route to its fallback only while failover is active."""
    return active_fallback(name) or name


def activate_fallback(name: str, *, target: str | None = None, reason: str = "transport") -> int:
    """Activate one provider from ``name``'s ordered fallback chain.

    With no explicit target, candidates are attempted in configured order. A
    candidate with no valid profiles is skipped; a failed hard switch rolls its
    marker/configuration back before the next candidate is tried.
    """
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
        profiles = provider_files(candidate)
        if not profiles or not any(_profile_error(profile) is None for profile in profiles):
            print(f"router: skipping fallback '{candidate}': no valid profiles", file=sys.stderr)
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


def deactivate_fallback(name: str) -> int:
    """Restore primary routing for ``name`` with one in-place reload."""
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


def response_event(host: str, status: int, *, provider: str | None = None,
                   dedupe_seconds: int = 5) -> int:
    """Handle a response-aware proxy event and rotate the effective route.

    This is intentionally a narrow event sink: only HTTP 429 responses for a
    configured routed host can mutate provider state. The caller owns request
    replay; this command only performs the hard switch/fallback transaction.
    """
    try:
        status = int(status)
    except (TypeError, ValueError):
        return fail("response-event: status must be an integer")
    if status != 429:
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
        print(f"response-event: suppressed duplicate 429 for {host}")
        return 0
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"at": now, "host": str(host).lower(), "status": status}) + "\n")
    try:
        marker.chmod(0o600)
    except OSError:
        pass

    effective = active_fallback(route_provider) or route_provider
    print(f"response-event: HTTP 429 for {host}; rotating {effective}")
    rc = rotate(effective, reason=str(status))
    if rc == 0:
        return 0
    if effective != route_provider:
        return rc
    return activate_fallback(route_provider, reason=str(status))


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

    entry = _providers.get(name)
    if isinstance(entry, dict):
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


def probe_profile(name: str, profile: Path, *, port: int | None = None) -> tuple[bool, dict | None]:
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
        # TLS failures prove the tunnel path (CONNECT rode it); for every
        # other connection-level failure ask whether resolution still works.
        host = urllib.parse.urlsplit(url).hostname or ""
        dns_ok = egress_dns_probe(host, port=port) if host else None
    record = record_egress(name, profile, ok=result["ok"], latency_ms=result["latency_ms"],
                           status=result["status"], error=result["error"], dns_ok=dns_ok)
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
          and dns_ok is not False
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
        # dns_ok False is excluded too: resolution rides the direct path, so
        # a DNS flake never proves the tunnel dead (degraded, not dead).
        reason = _transport_reason(result["error"])
        _action, seconds = policy_action(name, reason)
        mark_cooldown(name, profile, seconds)
        print(f"router: marked {profile.stem} failed (transport/{reason}; cooldown {seconds}s)", file=sys.stderr)
    return result["ok"], record


def _probe_with_settle(name: str, profile: Path, *, port: int | None = None) -> tuple[bool, dict | None]:
    """Probe once, and on failure retry once after the settle window.

    Used only for switch-adjacent probes (``rotate``/``egress sweep``): a
    freshly switched WireGuard exit routinely completes its handshake but
    blackholes inner TLS for its first seconds of life, so a single
    immediate probe false-marks healthy exits dead and triggers rollback
    churn. Steady-state probes (``egress check``) keep their single-shot,
    multi-strike semantics. Set ``egress.probe_settle_seconds`` to 0 to
    disable the retry."""
    ok, record = probe_profile(name, profile, port=port)
    if ok:
        return ok, record
    try:
        settle = max(0.0, float(egress_settings().get("probe_settle_seconds", 20.0)))
    except (TypeError, ValueError):
        settle = 20.0
    if settle <= 0:
        return ok, record
    print(f"router: probe failed for {profile.stem}; retrying once after {settle:.0f}s settle",
          file=sys.stderr)
    time.sleep(settle)
    return probe_profile(name, profile, port=port)


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
        except (socket.gaierror, OSError):
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
      1010/403 reputation block or 5xx), OR the failure is TLS-classified
      (SSL EOF / SSL_ERROR_SYSCALL / TLS alert): the TCP CONNECT rode the
      tunnel, so the path demonstrably works and the upstream endpoint is
      throttling — never a dead tunnel, so keepalive must not rotate on it.
    - ``dead``: the probe failed at connection level (no HTTP status at all,
      no TLS handshake), i.e. the tunnel path itself is broken. The DNS
      signal sharpens the reason: ``dns_ok is True`` means the later
      dial/read stage through the tunnel failed; ``dns_ok is False`` means
      resolution failed on the DIRECT DNS path (DNS is pinned direct by
      design) — the tunnel was never dialed, so the exit is ``degraded``,
      not dead. ``dns_ok None`` keeps the dead verdict.

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
        # TLS-handshake failure (SSL EOF / SSL_ERROR_SYSCALL / TLS alert)
        # happens AFTER the TCP CONNECT rode the tunnel: the path demonstrably
        # works and the upstream endpoint is throttling (Proton free tier
        # resets inner TLS ~1s in while real traffic still succeeds). That is
        # a degraded exit, never a dead tunnel — no cooldown, no rotation.
        status, dns_ok = "degraded", True
    else:
        host = urllib.parse.urlsplit(url).hostname or ""
        dns_ok = egress_dns_probe(host, port=port) if host else None
        # DNS rides the DIRECT path by design (build_singbox_config), so a
        # lookup failure (dns_ok False) means the direct DNS path failed and
        # the tunnel was never dialed — it cannot be blamed. Unproven is
        # degraded, not dead (same principle as the TLS case): no cooldown
        # on DNS flakes. dns_ok True/None keep the conservative dead verdict.
        status = "degraded" if dns_ok is False else "dead"
    record = record_egress(name, profile, ok=probe["ok"], latency_ms=probe["latency_ms"],
                           status=probe["status"], error=probe["error"], dns_ok=dns_ok)
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
    (first rotation waits a full interval). Returns 0 when a provider was
    rotated or seeded, 3 otherwise.
    """
    interval = scheduled_interval()
    if interval <= 0:
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
        handled = rotate(name) == 0 or handled
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
            # The engine is the source of truth for a tunnel that is already
            # running. Repair stale state before probes can blame the wrong exit.
            set_active(name, live)
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
    """Profile for ``name`` that builds cleanly: the persisted active one when
    valid, else the first non-cooled valid profile. Malformed profiles are
    logged and skipped so one bad file never disables the provider (F6)."""
    profiles = provider_files(name)
    if not profiles:
        return None
    active = preferred or resolve_active(name)
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


def build_singbox_config(active_overrides: dict[str, Path] | None = None) -> tuple[dict, dict[str, Path]]:
    active: dict[str, dict] = {}
    selected: dict[str, Path] = {}
    dns_map: dict[str, str] = {}
    for name in _providers:
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
    dns_servers = [
        {
            "type": dns_transport(),
            "tag": f"dns-{name}",
            "server": dns_map[name],
            **({"server_port": 443} if dns_transport() == "https" else {}),
        }
        for name in active
    ]
    # sing-box 1.12+: any dial without an explicit resolver needs
    # route.default_domain_resolver; the system (local) transport keeps
    # non-routed domains away from the tunnels and silences the deprecated
    # implicit fallback. Route DNS rules still pin tunneled domains to the
    # provider's own server.
    dns_servers.append({"type": "local", "tag": "dns-local"})
    routing = routing_state()
    routing_mode = routing["mode"]
    dns_rules = []
    if routing_mode == "safe-list" and routing["direct_domains"]:
        # Safe-list: trusted domains go DIRECT, so their DNS must resolve via
        # the local resolver, never a provider's DNS server - pinning them to
        # a provider resolver would leak direct traffic's DNS through the
        # tunnel. The rule comes first so a domain listed both here and in a
        # provider route always wins the direct resolver.
        dns_rules.append({"domain_suffix": list(routing["direct_domains"]), "server": "dns-local"})
    vpn_domains = frozenset(routing["vpn_domains"])
    for route in _routes:
        route_provider = _effective_route_provider(route["provider"])
        if route_provider not in active or not route.get("domains"):
            continue
        domains = route["domains"]
        if routing_mode == "vpn-list":
            domains = [
                domain for domain in domains
                if any(domain == vpn or domain.endswith("." + vpn) for vpn in vpn_domains)
            ]
        if domains:
            dns_rules.append({"domain_suffix": domains, "server": f"dns-{route_provider}"})

    # Route rules: safe-list direct-domain pins first (a trusted domain is
    # never tunneled even if a provider route also mentions it), then the
    # per-domain provider routes, then the loopback/localhost pins. With no
    # routing section (default mode) direct_pins is empty and the rule list
    # is byte-identical to the pre-routing-modes output.
    provider_rules = []
    for route in _routes:
        route_provider = _effective_route_provider(route["provider"])
        if route_provider not in active:
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
            # Route-based TUN receives raw IP flows, so domain_suffix rules do
            # not have a hostname until sing-box sniffs TLS/HTTP metadata.
            # Place sniff after DNS hijacking and before provider rules; this
            # keeps the transparent listener app-independent while preserving
            # direct fallback for unmatched traffic.
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
        # probes) must keep working while TUN captures everything else at
        # the IP layer. Both inbound types share the same route rules, so
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
        if default_provider not in active:
            raise SystemExit(
                f"routing mode 'safe-list': default_provider '{default_provider}' has no active profile; "
                "cannot emit a dangling route.final (drop *.conf into providers/<name>/ first)"
            )
        route_final = default_provider

    config = {
        "log": {"level": "info"},
        "inbounds": inbounds,
        "endpoints": list(active.values()),
        "outbounds": [{"type": "direct", "tag": "direct"}],
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
    """True when ANY sing-box process is running with our generated config
    path in its command line.

    Used when the pid file itself is unreadable (root-owned after a
    `sudo vpn on`): same identity check as ``_pid_matches``, minus the pid."""
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\").CommandLine"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            if out:
                return str(SING_BOX_CONFIG) in out
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq sing-box.exe", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=3,
            ).stdout
            return "sing-box" in out.lower()
        out = subprocess.run(
            ["ps", "-ax", "-o", "command="],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "sing-box run" in out and str(SING_BOX_CONFIG) in out


def _pid_matches(pid: int) -> bool:
    """True when PID is a sing-box we launched (cmdline contains our config,
    so a recycled/foreign PID with the same number can never be killed)."""
    try:
        if os.name == "nt":
            # tasklist only names the process, so any sing-box.exe with a
            # recycled PID would pass; read the real command line first and
            # require our generated config path in it (H3).
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine"],
                    capture_output=True, text=True, timeout=5,
                ).stdout
            except (OSError, subprocess.TimeoutExpired):
                out = ""
            if out:
                return "sing-box" in out.lower() and str(SING_BOX_CONFIG) in out
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=3,
            ).stdout
            return "sing-box" in out.lower()
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "sing-box run" in out and str(SING_BOX_CONFIG) in out


def engine_alive() -> bool:
    """True when a sing-box started by us is still running (tun mode has no
    TCP listener to probe, so process liveness is the health check). Also
    refuses foreign/recycled PIDs so a stale pid file can't claim liveness."""
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
    """True when sing-box.log contains a FATAL line after byte offset ``after``.

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
    if sys.platform != "darwin" or os.geteuid() == 0:
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


def rotate_log_if_needed() -> None:
    """Archive an oversized sing-box.log to sing-box.log.1 (mirrors monitor.py's
    samples rotation). Called from engine_start only, when no engine holds the
    log fd."""
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
    if not wait_engine(log_from=log_offset()):
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
    if not active:
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


def _config_drifted() -> bool:
    """True when the running engine's config no longer matches what the
    current router.json + active markers would generate.

    Live-verified failure mode (2026-08-17): after heavy route/marker
    editing the on-disk sing-box.json diverged from reality — the proxy
    listener TLS-failed while transparent capture served traffic, until a
    manual reload converged. The ensure watchdog heals that drift with the
    same graceful in-place reload rotations use."""
    try:
        fresh, _active = build_singbox_config()
        running = json.loads(SING_BOX_CONFIG.read_text())
    except (SystemExit, KeyError, ValueError, OSError, configparser.Error, json.JSONDecodeError):
        return False  # never block ensure on a build/read problem
    return json.dumps(fresh, sort_keys=True) != json.dumps(running, sort_keys=True)


def engine_ensure() -> int:
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


def engine_stop() -> int:
    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text().strip())
        except PermissionError:
            # Root-owned pid file (started via `sudo vpn on`): the engine may
            # be alive; keep the pid file and fail loudly (mirror of the kill
            # PermissionError below) instead of unlinking a live engine's pid
            # as "garbage" (H6).
            print(_ROOT_ENGINE_HINT, file=sys.stderr)
            return 1
        except (ValueError, OSError):
            # Garbage pid file (H6): treat as stale, clean it up, carry on.
            PID_FILE.unlink(missing_ok=True)
            return 0
        if not _pid_matches(pid):
            # Foreign/recycled PID (H3): never signal a process we don't own.
            # Remove the stale pid file so a later start can proceed.
            PID_FILE.unlink(missing_ok=True)
            return 0
        try:
            if os.name == "nt":
                # taskkill /T /F is a hard kill (TerminateProcess on the whole
                # tree); the process may already be gone, so ignore its exit code.
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.4)
                # The process may have exited, or the PID may have been
                # recycled during the grace period. Re-check ownership before
                # sending a hard kill.
                if _pid_matches(pid):
                    os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass
        except PermissionError:
            # Engine was started via `sudo vpn on` and runs as root; a
            # regular-user stop cannot signal it. Keep the pid file (the
            # engine IS alive) and tell the user to stop with sudo.
            print(_ROOT_ENGINE_HINT, file=sys.stderr)
            return 1
        PID_FILE.unlink(missing_ok=True)
    return 0


def _elevated_reload() -> int:
    """Re-run the granted `reload` shape as root.

    `sudo vpn on` starts the engine as root (TUN needs it), so a user-level
    keepalive sweep or rotation cannot SIGHUP the process. `reload` is a
    granted sudoers shape, so re-run exactly that; pending per-provider
    overrides ride in RELOAD_OVERRIDE_FILE so sweep hops keep their
    candidate-without-commit semantics across the privilege boundary."""
    command = [sys.executable, os.path.abspath(__file__), "reload"]
    env = {**os.environ, "PROXY_ROUTER_ELEVATED": "1"}
    probe = subprocess.run(["sudo", "-n", *command], env=env)
    if probe.returncode != 0:
        print("router: elevated reload denied; run `sudo python3 router.py reload` manually",
              file=sys.stderr)
    return probe.returncode


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
    if not active:
        return fail("no provider endpoint available")
    write_sing_box(config)
    if not validate_config():
        # The bad config is already on disk; restore the last known-good one
        # so a crash/restart can never boot it (F2: bad generated config must
        # not leave the proxy dead while a known-good config exists).
        print("router: new sing-box config failed validation; restoring last-good", file=sys.stderr)
        return restore_last_good()
    if not PID_FILE.is_file():
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return 0
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        PID_FILE.unlink(missing_ok=True)
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return 0
    if not _pid_matches(pid):
        PID_FILE.unlink(missing_ok=True)
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return 0
    if os.name == "nt":
        # Windows has no SIGHUP; stop+start applies the fresh config.
        if engine_stop() != 0:
            return fail("engine stop failed during reload")
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return 0
    reload_log_from = log_offset()
    try:
        os.kill(pid, signal.SIGHUP)  # SIGHUP: sing-box hot-reloads the config in place
    except PermissionError:
        if os.geteuid() != 0:
            if overrides:
                RELOAD_OVERRIDE_FILE.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write(RELOAD_OVERRIDE_FILE,
                              json.dumps({name: str(path) for name, path in overrides.items()}), 0o600)
            print("router: engine runs as root; reloading through the granted sudo shape",
                  file=sys.stderr)
            return _elevated_reload()
        return fail("engine runs as root (started via sudo); run `router.py elevate install` once, "
                    "or reload it now with `sudo python3 router.py reload`")
    except ProcessLookupError:
        if engine_start(recover=False) != 0:
            print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
            return restore_last_good()
        return 0
    if wait_engine(2.0, log_from=reload_log_from):
        # The new config demonstrably runs: snapshot it as last-good.
        write_last_good()
        return 0
    # SIGHUP did not come up cleanly; try a full (re)start of the new config
    # before giving up and restoring last-good.
    print("router: engine did not come up after SIGHUP; trying a full start", file=sys.stderr)
    if engine_start(recover=False) != 0:
        print("router: engine failed to start with new config; restoring last-good", file=sys.stderr)
        return restore_last_good()
    return 0


def rotate(name: str, *, reason: str | None = None, force: bool = False, probe: bool = True,
           to: str | None = None) -> int:
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
    """
    if active_fallback(name):
        return fail(f"provider '{name}': fallback active; clear it before rotating the primary")
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


def vpn_on() -> int:
    if current_mode() == "tun":
        if engine_alive() and engine_mode_consistent():
            print("vpn: tun already up")
            # Idempotent re-entry must leave the same surface state as a
            # fresh start: TUN capture uses the mixed listener only as an
            # explicit compatibility lane, while ordinary apps stay direct.
            route_watcher_start()
            if sys.platform == "darwin":
                system_proxy_off()
            return 0
        # state says tun but nothing consistent is running: reset to proxy so a
        # failed start below can't wedge a phantom tun, then fall through.
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
        system_proxy_off()
    return rc


def vpn_off() -> int:
    set_mode("proxy")
    rc = engine_stop()
    if rc != 0:
        return rc
    # Returning to proxy mode should leave the user with working connectivity
    # (M11): start the proxy engine so 127.0.0.1:<port> answers again.
    rc = engine_start()
    # Back on the proxy: re-point the macOS system proxy at the listener so
    # the browser keeps working without manual networksetup (mirror of the
    # disable above; tun mode has no listener to point at).
    if rc == 0 and sys.platform == "darwin":
        system_proxy_on()
    return rc


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
        return 0, "up (proxy 127.0.0.1:{})".format(_port)
    if listener_up():
        # F1: something answers the port but it is not our engine (stale pid
        # file or a recycled/foreign process); never report that as up.
        return 1, "down (foreign listener on 127.0.0.1:{}; run 'start')".format(_port)
    return 1, "down (proxy mode; run 'vpn on' for tun, 'start' for proxy)"


def doctor() -> int:
    """One-command health audit: config, pools, engine, sing-box, grants.

    Read-only (no probes, no engine actions). exit 0 when nothing failed;
    warnings never fail the run — they are drift the self-heal loop or the
    operator should know about, not outages."""
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
    if os.geteuid() != 0 and shutil.which("sudo"):
        note("ok" if _sudoers_installed() else "warn", "elevate",
             "passwordless engine grant active" if _sudoers_installed()
             else "grant absent; run 'router.py elevate install' to stop root-owned state churn")
    if sys.platform == "darwin":
        probe = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
        has_agent = "com.proxy-router.keepalive" in (probe.stdout or "")
        note("ok" if has_agent else "warn", "keepalive",
             "launchd agent loaded" if has_agent else "launchd agent NOT loaded (examples/install-launchd.sh)")
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
    profiles = [p.stem for p in provider_files(name)]
    # Report the PERSISTED active profile (what the engine is configured with)
    # rather than resolve_active(), which skips a cooled-down active when
    # picking the next candidate.
    active_profile = persisted_active(name)
    active_stem = active_profile.stem if active_profile is not None else None
    entry = {"profiles": profiles, "active": active_stem}
    fallback = fallback_status(name)
    if fallback["configured"] or fallback["active"]:
        entry["fallback"] = fallback
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
    rotation = ROOT / "state" / f"{name}.rotation"
    try:
        if rotation.is_file():
            entry["last_rotation"] = json.loads(rotation.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    egress = {}
    for stem in profiles:
        record = read_egress(name, Path(stem + ".conf"))
        if record:
            egress[stem] = record
    if egress:
        entry["egress"] = egress
    return entry


def status_json() -> dict:
    """Full machine-readable status for `status --json`."""
    rc, line = _status_report()
    data = {"up": rc == 0, "state": line, "mode": current_mode(), "port": _port,
            "sing_box": resolve_sing_box()}
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
    for provider in providers:
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
                dead.append(provider)
            elif status == "degraded" and record is not None:
                entry["detail"] = (f"HTTP {record['status']}" if record.get("status") is not None
                                   else "throttled (TLS)")
            results[provider] = entry
            continue
        if active is None:
            results[provider] = {"profile": None, "ok": True, "status": "skipped",
                                 "detail": "no active profile"}
            continue
        status, record = check_egress_live(provider, active)
        entry: dict = {"profile": active.stem, "ok": status != "dead", "status": status}
        if record is not None and record.get("dns_ok") is not None:
            entry["dns_ok"] = record["dns_ok"]
        if status == "dead":
            entry["detail"] = "dns" if entry.get("dns_ok") is False else "probe connection"
            dead.append(provider)
        elif status == "degraded" and record is not None:
            entry["detail"] = (f"HTTP {record['status']}" if record.get("status") is not None
                               else "throttled (TLS)")
        results[provider] = entry
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


def egress_sweep(name: str | None = None, as_json: bool = False) -> int:
    """Probe every profile once and leave the engine on the best alive one.

    Every profile change is an in-place SIGHUP reload: the process, TUN
    interface, and listener sockets survive each hop. If no profile is
    alive, the original active profile is restored when possible, so a
    diagnostic sweep cannot strand the tunnel on the last dead profile it
    tested.
    """
    # The tun config keeps the mixed listener (see egress_probe), so the
    # full-pool sweep probes through 127.0.0.1:<port> in either mode.
    if not listener_up():
        return fail(f"engine not listening on 127.0.0.1:{_port}; start it first")
    providers = [name] if name is not None else list(_providers)
    results: dict[str, dict] = {}
    dead: list[str] = []
    for provider in providers:
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
            if actual == profile:
                return 0
            # Graceful hop: apply the candidate through the SIGHUP reload
            # BEFORE committing the active marker, so a failed switch leaves
            # both the marker and the running exit untouched.
            rc = engine_reload({provider: profile})
            if rc != 0:
                return rc
            set_active(provider, profile)
            actual = profile
            record_rotation(provider, profile)
            print(f"switched {provider} -> {profile.stem} (sweep)")
            return 0

        for profile in ordered:
            if switch_to(profile) != 0:
                entry[profile.stem] = {
                    "ok": False,
                    "usable": False,
                    "latency_ms": None,
                    "status": None,
                    "error": "profile switch failed",
                }
                switch_failed = True
                break
            if actual != original:
                time.sleep(1.5)  # WireGuard handshake settle
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
        alive = [stem for stem, r in entry.items() if r["usable"]]
        if alive and not switch_failed:
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
# macOS system proxy toggle
# ---------------------------------------------------------------------------

def network_services() -> list[str]:
    """Return enabled macOS network services, excluding the separator row."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    services = []
    for line in result.stdout.splitlines():
        service = line.strip()
        if not service or service.startswith("An asterisk") or service.startswith("*"):
            continue
        services.append(service)
    return services


def active_service_name() -> str | None:
    """Return the service for the current default interface, when known."""
    try:
        iface = None
        out = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5,
        ).stdout
        for line in out.splitlines():
            if "interface:" in line:
                iface = line.split()[-1]
        if not iface:
            return None
        service = None
        out = subprocess.run(
            ["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            service = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and line.split()[-1] == iface:
            return service
    return None


def system_proxy_on() -> int:
    services = network_services()
    if not services:
        return fail("could not determine any macOS network services")
    try:
        for service in services:
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
            for command in commands:
                subprocess.run(command, check=True, capture_output=True, timeout=10)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return fail(f"could not enable system proxy: {exc}")
    print(f"system proxy enabled on {len(services)} network service(s) -> 127.0.0.1:{_port}")
    return 0


def system_proxy_off() -> int:
    services = network_services()
    if not services:
        return fail("could not determine any macOS network services")
    try:
        for service in services:
            subprocess.run(
                ["networksetup", "-setwebproxystate", service, "off"],
                check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["networksetup", "-setsecurewebproxystate", service, "off"],
                check=True, capture_output=True, timeout=10,
            )
            # Leaving PAC/WPAD enabled after Disconnect still allows macOS
            # clients to select a network-provided proxy unexpectedly. Clear
            # the automatic paths as part of the same direct-mode transition.
            subprocess.run(
                ["networksetup", "-setautoproxystate", service, "off"],
                check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["networksetup", "-setproxyautodiscovery", service, "off"],
                check=True, capture_output=True, timeout=10,
            )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return fail(f"could not disable system proxy: {exc}")
    print(f"system proxy disabled on {len(services)} network service(s)")
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
    """True when the live engine process is owned by root.

    An engine started via `sudo vpn on` keeps running as root after `vpn
    off` returns to proxy mode. Its pid file is root-owned mode 0600, so a
    regular user cannot read it; a root-owned pid file is therefore
    treated as "the engine is root's" (any live process behind it was
    spawned by root — re-reading it after a stale root file simply makes
    the elevated run clean it up). A readable root-owned pid file is
    confirmed against `ps` so a recycled pid never over-elevates. This
    probe is read-only and safe from any invocation.
    """
    if os.name == "nt" or os.geteuid() == 0:
        return False
    try:
        st = os.stat(PID_FILE)
    except OSError:
        return False
    if st.st_uid != 0:
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except PermissionError:
        # Root-owned 0600 file, unreadable as a regular user: root's engine.
        return True
    except (ValueError, OSError):
        return False
    try:
        probe = subprocess.run(
            ["ps", "-o", "user=", "-p", str(pid)],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.stdout.strip() == "root"


def _needs_elevation(args) -> bool:
    """Whether this invocation must re-run as root before doing anything.

    TUN mode needs root (utun creation, route table) and the engine then
    runs as root, so `vpn on` and tun-mode engine commands cannot run as a
    regular user. Proxy-mode engine commands must also elevate while the
    engine ITSELF runs as root (started via `sudo vpn on`): a user-level
    `stop` cannot signal it, and `start` would clobber the root-owned pid
    file (issue #12 — the tray Stop failed with "Cannot stop because it is
    run with sudo"). Only interactive macOS sessions elevate:
    launchd/keepalive ticks have no TTY and must never pop a password
    dialog on every interval (they keep the existing clear-error behavior
    instead). Once `elevate install` granted passwordless sudo, elevation
    is silent, so the TTY gate lifts and background ticks may also elevate.
    """
    if sys.platform != "darwin" or os.geteuid() == 0:
        return False
    if os.environ.get("PROXY_ROUTER_ELEVATED"):
        return False
    if not sys.stdin.isatty() and not _sudoers_installed():
        return False
    mode = current_mode()
    if args.cmd == "vpn":
        return args.action in ("on", "restart") or (args.action == "off" and mode == "tun")
    return (args.cmd in ("start", "stop", "ensure", "reload", "rotate", "add", "remove")
            and (mode == "tun" or _engine_runs_as_root()))


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
    """Re-run the current command with administrator privileges (macOS).

    Instead of requiring the user to type `sudo python3 router.py vpn on`,
    re-exec the exact same CLI through the standard macOS "… wants to make
    changes" password dialog (osascript `do shell script … with administrator
    privileges`), which asks for permission on every run.

    SUDO_UID/SUDO_GID are injected so `_hand_back_ownership` hands state
    files back to the invoking user; PROXY_ROUTER_ELEVATED prevents
    recursion; PATH is passed through so the bundled sing-box still resolves.
    """
    env = (
        f"SUDO_UID={os.getuid()} SUDO_GID={os.getgid()} "
        f"PROXY_ROUTER_ELEVATED=1 "
        f"PATH={shlex.quote(os.environ.get('PATH', ''))}"
    )
    cmd = shlex.join([sys.executable, os.path.abspath(__file__), *sys.argv[1:]])
    shell_cmd = f"{env} {cmd}"
    # AppleScript string literals accept only `\"` and `\\` escapes; escape
    # the shell command's quotes/backslashes but keep the literal delimiters
    # unescaped (a `\` at expression position is a syntax error).
    content = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    script = f'do shell script "{content}" with administrator privileges'
    proc = subprocess.run(["osascript", "-e", script], text=True)
    if proc.returncode != 0:
        print("router: elevation canceled or failed; run with sudo manually if needed",
              file=sys.stderr)
    return proc.returncode


SUDOERS_FILE = Path("/etc/sudoers.d/91-proxy-router")

# One NOPASSWD entry per engine-command shape the elevation path may run.
# sudoers matches the FULL argv; `*` matches exactly one argument, so
# multi-arg shapes get their own line. sudo execs the command directly
# (no shell interpolation), so `*` can never smuggle arguments into the
# interpreter or script.
SUDOERS_COMMANDS = (
    ("vpn", "*"),
    ("start",),
    ("stop",),
    ("reload",),
    ("ensure",),
    ("rotate",),
    ("rotate", "*"),
    ("rotate", "*", "--reason", "*"),
    ("add",),
    ("remove",),
)

# stderr markers that prove `sudo -n` DENIED (vs the command itself
# failing). A sudoers grant is a snapshot of the command shapes at install
# time, so a command added later (e.g. `start`/`stop` for issue #12) can
# hit a denial even when the probe passes; callers fall back to the admin
# dialog on these markers instead of surfacing a raw sudo error.
_SUDO_DENIAL_TOKENS = (
    "a password is required",
    "not in the sudoers",
    "must have a tty",
)

# Root-owned engine (started via `sudo vpn on`): a regular user cannot
# signal it, so name the one-time grant and the manual sudo escape hatch
# (issue #12). Shared by engine_stop's two PermissionError paths.
_ROOT_ENGINE_HINT = ("router: engine runs as root (started via sudo); run "
                     "`router.py elevate install` once to stop it from the tray, "
                     "or stop it now with `sudo python3 router.py stop`")


def _sudoers_rules(user: str, python: str, router_path: str) -> str:
    """Render the sudoers NOPASSWD rules for the given interpreter + script."""
    lines = ["# Managed by `proxy-router elevate install`; remove with `elevate uninstall`."]
    for shape in SUDOERS_COMMANDS:
        cmd = " ".join([python, router_path, *shape])
        lines.append(f"{user} ALL=(root) NOPASSWD: {cmd}")
    return "\n".join(lines) + "\n"


def _sudoers_installed() -> bool:
    """True when `sudo -n` may run this script's engine commands without a prompt.

    Executes (not lists) the read-only `vpn status` command with `-n`.
    `sudo -n -l` is a false positive when a sudoers rule exists but still
    requires a password: listing succeeds but executing fails, e.g. a
    plain `alice ALL=(ALL) ALL` entry. Every sudoers rule shares the
    interpreter + script prefix, so one execution proves the whole set."""
    if os.geteuid() == 0 or not shutil.which("sudo"):
        return os.geteuid() == 0
    cmd = [sys.executable, os.path.abspath(__file__), "vpn", "status"]
    probe = subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True)
    if probe.returncode == 0:
        return True
    # `vpn status` exits 1 while the engine is down (rc 0 only when the
    # engine is up and matches the persisted mode), so a nonzero exit is
    # NOT proof the grant is missing. Only a sudo-level denial on stderr
    # means the NOPASSWD rule is absent; `sudo -n` reports that denial
    # there ("a password is required", "not in the sudoers file",
    # requiretty) instead of running the command.
    stderr = (probe.stderr or "").lower()
    return not any(token in stderr for token in _SUDO_DENIAL_TOKENS)


def _elevate() -> int:
    """Re-run the current command as root: silently when `elevate install`
    granted passwordless sudo, else through the macOS admin dialog.

    A sudoers grant is a snapshot of the command shapes at install time; a
    command added to the elevation surface afterwards (e.g. `start`/`stop`
    for issue #12) can be denied even though the probe passes. A sudo-level
    denial on stderr falls back to the admin dialog; a nonzero exit that is
    NOT a denial is the elevated command itself failing and is returned
    unchanged (no dialog for a real engine error)."""
    if _sudoers_installed():
        cmd = [sys.executable, os.path.abspath(__file__), *sys.argv[1:]]
        probe = subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True)
        if probe.returncode == 0:
            return 0
        stderr = (probe.stderr or "").lower()
        if not any(token in stderr for token in _SUDO_DENIAL_TOKENS):
            return probe.returncode
    if not sys.stdin.isatty():
        # keepalive/launchd tick: never pop an admin dialog. The TTY gate in
        # _needs_elevation normally stops ticks from reaching this; a stale
        # grant whose probed shape was denied would otherwise fall through
        # to the dialog on every interval (issue #13 review finding).
        return 1
    return _elevate_macos()


def cmd_elevate(action: str) -> int:
    """`elevate install|uninstall|status`: manage the one-time sudoers grant."""
    if action == "status":
        if _sudoers_installed():
            print("elevate: passwordless sudo for engine commands is active")
            return 0
        print("elevate: not installed; run `router.py elevate install` for one-time setup",
              file=sys.stderr)
        return 1
    if action == "uninstall":
        if os.geteuid() != 0:
            return _elevate()  # re-runs as root; silent when rules exist
        # Rooted re-run: remove the file we manage.
        if SUDOERS_FILE.exists():
            SUDOERS_FILE.unlink()
            print(f"elevate: removed {SUDOERS_FILE}")
        return 0

    rules = _sudoers_rules(getpass.getuser(), sys.executable, os.path.abspath(__file__))
    if os.geteuid() != 0:
        # One prompt (or none, if sudo already works): write, validate with
        # visudo, then atomically install. Re-run as root and continue.
        # `_elevate` (not a raw `sudo -n`) so a grant that lacks the
        # `elevate install` shape (it never includes itself) falls back to
        # the admin dialog instead of a raw sudo denial.
        return _elevate()

    if SUDOERS_FILE.exists():
        existing = SUDOERS_FILE.read_text()
        managed = existing.splitlines()[0].startswith("# Managed by `proxy-router")
        if not managed:
            print(f"elevate: {SUDOERS_FILE} exists with foreign content; move it aside first",
                  file=sys.stderr)
            return 1
        if existing == rules:
            print(f"elevate: already installed ({SUDOERS_FILE})")
            return 0
        print("elevate: interpreter or script path changed; rewriting rules", file=sys.stderr)

    tmp = SUDOERS_FILE.with_name(SUDOERS_FILE.name + ".tmp")
    tmp.write_bytes(b"")
    tmp.write_text(rules)
    os.chmod(tmp, 0o440)
    if subprocess.run(["/usr/sbin/visudo", "-c", "-f", str(tmp)]).returncode != 0:
        tmp.unlink(missing_ok=True)
        print("elevate: generated sudoers rules failed visudo validation; nothing installed",
              file=sys.stderr)
        return 1
    tmp.rename(SUDOERS_FILE)
    print(f"elevate: installed {SUDOERS_FILE}; engine commands now run without a password prompt")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="router", description="selective WireGuard proxy router")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("ensure", help="ensure the engine is up (0 = healthy, 1 = failure, 3 = manual-off quiescent)")
    sub.add_parser("start")
    sub.add_parser("stop")
    status = sub.add_parser("status")
    sub.add_parser("doctor", help="one-command health audit (read-only)")
    status.add_argument("--json", action="store_true", help="machine-readable status (JSON)")
    sub.add_parser("reload")
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

    init = sub.add_parser("init")
    init.add_argument("--force", action="store_true", help="overwrite an existing router.json")

    vpn = sub.add_parser("vpn", help="toggle TUN mode (on|off|restart|status|capture)")
    vpn.add_argument("action", choices=["on", "off", "restart", "status", "capture"])
    vpn.add_argument("capture", nargs="?", choices=["ruleset", "routes"],
                     help="TUN capture scope for `vpn capture`")

    setup = sub.add_parser("setup", help="interactive Proton/WARP setup wizard")
    setup.add_argument("setup_args", nargs=argparse.REMAINDER)

    monitor = sub.add_parser("monitor", help="opt-in network monitoring")
    monitor.add_argument("monitor_args", nargs=argparse.REMAINDER)

    watcher = sub.add_parser("watcher", help="standalone routed-connection watcher")
    watcher.add_argument("watcher_args", nargs=argparse.REMAINDER)

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

    r_event = sub.add_parser("response-event", help="handle an observed upstream response")
    r_event.add_argument("--host", required=True, help="destination hostname observed by the proxy")
    r_event.add_argument("--status", required=True, type=int, help="HTTP response status")
    r_event.add_argument("--provider", default=None, help="expected route provider")
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
    failover.add_argument("action", choices=["on", "off", "status"])
    failover.add_argument("--to", default=None, help="fallback provider (must match config)")
    failover.add_argument("--reason", default="transport")
    failover.add_argument("--json", action="store_true")

    r_count = sub.add_parser("provider-count")
    r_count.add_argument("provider")

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

    args, passthrough = parser.parse_known_args()
    if args.cmd == "elevate":
        return cmd_elevate(args.action)
    if _needs_elevation(args):
        return _elevate()
    if args.cmd == "setup":
        import setup_tui

        return setup_tui.main(["setup", *passthrough, *args.setup_args], root=ROOT)
    if args.cmd == "monitor":
        import monitor

        return monitor.main(["monitor", *args.monitor_args, *passthrough], root=ROOT)
    if args.cmd == "watcher":
        import route_watcher

        return route_watcher.main(["watcher", *args.watcher_args, *passthrough], root=ROOT)
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
        # `up` is the reconnect path for the tray and CLI: remove the manual
        # disconnect marker before asking the keepalive to watch again.
        MANUAL_OFF_FILE.unlink(missing_ok=True)
        rc = load_config()
        if rc == 0 and engine_start() == 0:
            route_watcher_start()
            ensure_tray_started()
            return system_proxy_on()
        return rc
    if args.cmd == "down" and sys.platform != "darwin":
        return fail("down requires macOS (v1 scope)")

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
        # Explicit start (tray Connect / CLI) cancels any manual-off state.
        MANUAL_OFF_FILE.unlink(missing_ok=True)
        route_watcher_stop()
        rc = _with_lock(engine_start)
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
    if args.cmd == "stop":
        # Disable the macOS-wide proxy BEFORE stopping sing-box. If
        # networksetup cannot clear it, keep the engine alive rather than
        # leaving every GUI app pointed at a dead 127.0.0.1:2080 listener.
        if sys.platform == "darwin":
            proxy_rc = system_proxy_off()
            if proxy_rc != 0:
                return proxy_rc
        route_watcher_stop()
        rc = _with_lock(engine_stop)
        if rc == 0:
            # Manual disconnect: tell keepalive.sh to leave the engine down.
            # Without this marker the keepalive's next `ensure` tick
            # resurrects the proxy within 15s and the tray's Disconnect
            # looks broken.
            try:
                MANUAL_OFF_FILE.write_text(
                    f"manual stop {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n",
                    encoding="utf-8",
                )
                try:
                    MANUAL_OFF_FILE.chmod(0o600)
                except OSError:
                    pass
            except OSError as e:
                print(f"router: warning: could not write manual-off marker: {e}",
                      file=sys.stderr)
        return rc
    if args.cmd == "doctor":
        return doctor()
    if args.cmd == "status":
        if resolve_sing_box() is None:
            print(f"router: {_sing_box_missing_message()}", file=sys.stderr)
        rc, line = _status_report()
        if args.json:
            print(json.dumps(status_json(), indent=2, sort_keys=True))
        else:
            print(line)
        return rc
    if args.cmd == "reload":
        rc = _with_lock(engine_reload)
        if rc == 0:
            route_watcher_start()
        return rc
    if args.cmd == "rotate":
        if args.if_due:
            return _with_lock(lambda: rotate_due(args.provider))
        if not args.provider:
            parser.error("rotate needs a provider (or use --if-due for scheduled rotation)")
        return _with_lock(lambda: rotate(args.provider, reason=args.reason, force=args.force,
                                         probe=not args.no_probe, to=args.to))
    if args.cmd == "response-event":
        return _with_lock(lambda: response_event(
            args.host, args.status, provider=args.provider,
            dedupe_seconds=args.dedupe_seconds,
        ))
    if args.cmd == "failover":
        if args.action == "on":
            return _with_lock(lambda: activate_fallback(
                args.provider, target=args.to, reason=args.reason))
        if args.action == "off":
            return _with_lock(lambda: deactivate_fallback(args.provider))
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
            return _with_lock(lambda: egress_sweep(args.provider, as_json=args.json))
        return egress_show(args.provider)
    if args.cmd == "provider-count":
        print(provider_count(args.provider))
        return 0
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
    if args.cmd == "down":
        if sys.platform != "darwin":
            return fail("down requires macOS (v1 scope)")
        return system_proxy_off()
    parser.print_help()
    return 2


class _EngineLock:
    """Exclusive lock on ``state/engine.lock``.

    Uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows so the
    same CLI surface works on macOS, Linux, and Windows.
    """

    def __init__(self) -> None:
        self._path = LOCK_FILE
        self._file = None

    def __enter__(self) -> "_EngineLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("w")
        if os.name == "nt":
            import msvcrt

            # msvcrt.locking cannot lock an empty file, so seed one byte.
            self._file.write("0")
            self._file.flush()
            self._file.seek(0)
            msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

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


def _with_lock(action) -> int:
    # The elevated reload child is the same operation re-run as root; the
    # parent holds the flock while it waits for the child, so a child that
    # re-acquires the lock would deadlock (parent waits for child, child
    # waits for the parent's lock).
    if os.geteuid() == 0 and os.environ.get("PROXY_ROUTER_ELEVATED"):
        return action()
    with _EngineLock():
        return action()


if __name__ == "__main__":
    raise SystemExit(main())
