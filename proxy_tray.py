#!/usr/bin/env python3
"""proxy_tray.py — menu-bar / taskbar control for proxy-router.

Thin-client tray agent in the style of popular VPN daemons (Tailscale,
ProtonVPN, Cloudflare WARP): a resident status icon whose menu shows live
state and triggers the existing router CLI. It NEVER mutates engine state
itself — every action shells out to `router.py`, so rotation ownership,
cooldowns, and keepalive semantics stay exactly where they are.

Design rules:
- Reads: `router.py status --json` polled in a background thread (2.5s).
- Actions: `ensure` / `stop` / `routing set --mode` / `rotate` via the CLI.
- macOS: runs as an accessory (menu-bar only, no Dock icon); left-click opens
  a custom dark Cocoa dashboard and right-click opens the existing action menu.
- Windows: pystray falls back to the taskbar notification area automatically.

Usage:
    python3 proxy_tray.py [--root /path/to/proxy-router]
    python3 proxy_tray.py --selftest   # no GUI; validates CLI contract + dispatch

Env: PROXY_ROUTER_ROOT overrides the router directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
from pathlib import Path
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:  # --selftest and --help must work without the GUI stack
    pystray = None
    Image = ImageDraw = None

# AppKit is already pulled in by pystray's Darwin backend. Keep the import
# separate and optional so status/selftest still work on Linux, Windows, and
# headless build machines. The dashboard never becomes a hard dependency of
# the router CLI.
try:
    if sys.platform == "darwin":
        import AppKit
        import Foundation
        import objc
        _COCOA_AVAILABLE = True
    else:
        AppKit = Foundation = objc = None
        _COCOA_AVAILABLE = False
except Exception:  # pragma: no cover - depends on the host Python
    AppKit = Foundation = objc = None
    _COCOA_AVAILABLE = False

_REAL_DARWIN_PYSTRAY = bool(
    _COCOA_AVAILABLE
    and pystray is not None
    and callable(getattr(getattr(pystray, "Icon", None), "_create_menu", None))
)

POLL_SECONDS = 5.0  # live-enough menu state without spawning 24 CLI procs/min
COMMAND_TIMEOUT = 20
DASHBOARD_WIDTH = 1120
DASHBOARD_HEIGHT = 720
# Quit waits at most this long for an in-flight mutation to finish before
# stopping the engine anyway — a hung mutation must not make Quit unkillable.
MUTATION_DRAIN_TIMEOUT = COMMAND_TIMEOUT + 5.0

# Friendly, non-jargon labels for tray menu entries. The router CLI words
# (safe-list / vpn-list / rotate / exit) stay in the terminal; the tray
# speaks home / school / switch / server.
_ROUTING_MODE_LABELS = {
    "safe-list": "home (safe list)",
    "vpn-list": "school (vpn list)",
}

# Built-in presets: (name, tray label). Custom presets under `presets/*.json`
# are appended dynamically so TUI-created presets show up here too.
_BUILTIN_PRESETS = (
    ("opencode", "opencode — route opencode.ai via Proton"),
    ("roblox", "roblox — route Roblox via Cloudflare"),
    ("default", "default — opencode + roblox combo"),
    ("school-warp", "school-warp — school sites via Cloudflare"),
)

# Must match router.py's MIN_SING_BOX_VERSION = (1, 12, 0); the tray runs
# standalone (no router import), so the version label is mirrored here.
_MIN_SING_BOX_LABEL = "1.12+"

# Raw CLI error fragments -> what a non-technical user should actually do.
_FRIENDLY_ERRORS = (
    ("no sing-box binary", "VPN engine not found — run Setup, then Connect"),
    ("sing-box not found",
     f"VPN engine not found — install sing-box {_MIN_SING_BOX_LABEL} (github.com/SagerNet/sing-box/releases) or set SING_BOX, then Connect"),
    ("needs 'default_provider'", "pick a default provider first: Routing mode → home (safe list)"),
    ("no active profile", "no VPN profile yet — add one under Setup"),
    ("missing router.json", "no configuration yet — start under Setup"),
    ("all profiles cooling down",
     "no servers available right now — try again in a minute"),
    ("no valid profiles", "no usable profiles found — re-add your .conf under Setup"),
    # Issue #76: the launchd-autostarted tray has no TTY, so a missing or
    # stale elevation grant surfaces as raw sudo/helper jargon that reads
    # like "the app is broken". Map both the router's actionable message and
    # the raw sudo fragments to the one-time fix.
    ("startup permission not set up yet",
     "one-time permission needed — open Dashboard → Fix Startup Permissions (or run `router.py elevate install` once)"),
    ("VPN startup permission missing",
     "one-time permission needed — open Dashboard → Fix Startup Permissions (or run `router.py elevate install` once)"),
    ("a password is required",
     "permission needed for automatic start — run `router.py elevate install` once from a terminal"),
    ("not in the sudoers",
     "permission needed for automatic start — run `router.py elevate install` once from a terminal"),
)

# Longest tail line _humanize keeps: the sing-box missing-binary message
# (darwin) is ~424 chars, so 500 keeps it fully visible (issue #11).
_MAX_DETAIL = 500

# macOS start/stop echo their system-proxy toggle as the last CLI line
# ("system proxy disabled on 1 network service(s)"). That is status
# noise, not the action result — surfacing it after "Connect: done"
# reads like a failure (issue #50).
_SYSTEM_PROXY_ECHO = re.compile(
    r"system proxy (enabled|disabled) on \d+ network service")


def _friendly_egress_error(err: object) -> str:
    """Turn a raw probe/egress error tail into a short human label.

    The egress record stores Python-level failure strings (e.g.
    ``URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING, EOF
    occurred in violation of protocol (_ssl.c:983)]>``). Rendering that
    verbatim in the exit picker is operator jargon; map the common classes
    to plain language and keep the code when it is meaningful (429/403).
    """
    s = str(err).strip()
    low = s.lower()
    if not s:
        return "offline"
    if "ssl" in low or "certificate" in low or "unexpected_eof" in low:
        return "throttled (SSL)"
    if "timed out" in low or "timeout" in low:
        return "timed out"
    if "connection refused" in low or "connection reset" in low:
        return "offline"
    if "dns" in low or "name or service" in low or "hostname" in low:
        return "no route (DNS)"
    if "rate limit" in low or "429" in s:
        return "rate-limited"
    if "403" in s or "1010" in s or "blocked" in low:
        return "blocked"
    return s[:28]


def _humanize(out: str) -> str:
    """Translate the last CLI line from operator jargon to user-facing text.

    Success paths that only say "engine not reloaded / run router.py ensure"
    become an actionable "Connect to apply"; known raw error fragments become
    the concrete next step instead of the internal message.
    """
    if not out:
        return ""
    if "engine is untouched" in out or "engine was NOT reloaded" in out:
        return "saved — Connect to apply"
    # The sing-box missing-binary message lists every candidate path; a
    # 160-char cap cut it mid-sentence into an unexplained "Connect: Failed"
    # (issue #11). 500 chars keeps even the darwin message (measured ~424)
    # fully visible.
    detail = out.splitlines()[-1][:_MAX_DETAIL]
    if _SYSTEM_PROXY_ECHO.search(detail):
        return ""  # system-proxy echo line: not the action result (issue #50)
    for needle, repl in _FRIENDLY_ERRORS:
        if needle in detail:
            return repl
    return detail


_PERMISSION_ERROR_MARKERS = (
    "startup permission not set up yet",
    "vpn startup permission missing",
    "a password is required",
    "not in the sudoers",
)


def _permission_error_markers() -> tuple[str, ...]:
    """Needles that identify a startup-permission failure (issue #76).

    Covers both directions of the pipeline: the router's actionable message
    ("VPN startup permission missing…", "startup permission not set up
    yet") and raw sudo fragments ("a password is required", "not in the
    sudoers file") that can reach the tray before the router maps them.
    """
    return _PERMISSION_ERROR_MARKERS


def _is_permission_error(text: str | None) -> bool:
    """True when a toast/action result describes the #76 permission gap."""
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _PERMISSION_ERROR_MARKERS)


@dataclass
class RouterStatus:
    up: bool = False
    mode: str = "unknown"
    port: int | None = None
    pid: int | None = None
    watcher: bool = False
    active_providers: dict = field(default_factory=dict)
    providers: dict = field(default_factory=dict)  # name -> {active, profiles, egress}
    routing_mode: str = "default"
    default_provider: str | None = None
    preset: str | None = None
    system_proxy_status: str = "ok"
    network_status: str = "unknown"
    error: str | None = None

    @classmethod
    def from_cli(cls, rc: int, stdout: str) -> "RouterStatus":
        # `status --json` exits 1 whenever the engine is down OR not yet
        # configured, but it still prints a valid JSON payload. Treating
        # rc != 0 as an error made the tray show "! Error" on every plain
        # disconnect and "! Error status exit 1" on a fresh install — the
        # payload below carries the real state. Only an unparseable payload
        # is an error now.
        try:
            payload = stdout[stdout.find("{"):] if "{" in stdout else stdout
            d = json.JSONDecoder().raw_decode(payload)[0]
            if not isinstance(d, dict):
                raise ValueError("status payload is not an object")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            return cls(error=f"status exit {rc}" if rc else f"bad json: {e}")
        state = str(d.get("state") or "")
        diagnostic = stdout.lower()
        if ("unusable config" in state.lower()
                and "missing router.json" not in diagnostic):
            return cls(error="unusable router configuration")
        providers = {}
        provider_map = {}
        for name, info in (d.get("providers") or {}).items():
            active = info.get("active")
            if active:
                providers[name] = active
            egress = {}
            for stem, rec in (info.get("egress") or {}).items():
                egress[stem] = {
                    "ok": bool(rec.get("ok")),
                    "latency_ms": rec.get("latency_ms"),
                    "status": rec.get("status"),
                    # Keep transport probe failures separate from explicit
                    # upstream failures. The former are often transient and
                    # should not turn the menu into a wall of red warnings.
                    "error": rec.get("error"),
                    "upstream_error": rec.get("upstream_error"),
                    "blocked": bool(rec.get("blocked")),
                    "exhausted": bool(rec.get("exhausted")),
                }
            provider_map[name] = {
                "active": active,
                "profiles": list(info.get("profiles") or []),
                "egress": egress,
            }
        routing = d.get("routing") or {}
        if not isinstance(routing, dict):
            routing = {}
        watcher = d.get("watcher") or {}
        if not isinstance(watcher, dict):
            watcher = {}
        system_proxy = d.get("system_proxy") or {}
        if not isinstance(system_proxy, dict):
            system_proxy = {}
        network = d.get("network") or {}
        if not isinstance(network, dict):
            network = {}
        return cls(
            up=bool(d.get("up")),
            mode=str(d.get("mode") or "unknown"),
            port=d.get("port"),
            pid=d.get("pid"),
            watcher=bool(watcher.get("enabled") and watcher.get("running")),
            active_providers=providers,
            providers=provider_map,
            routing_mode=str(routing.get("mode") or "default"),
            default_provider=routing.get("default_provider") or None,
            preset=d.get("preset") or None,
            system_proxy_status=str(system_proxy.get("status") or (
                "unknown" if d.get("up") and d.get("mode") == "proxy" else "skipped")),
            network_status=str(network.get("status") or "unknown"),
        )

    def provider_label(self, name: str) -> str:
        """Compact single-line label for a provider row, e.g.
        'proton → 01-NL-FREE-140 · 164ms'. The dot reflects REAL health:
        a probe that rode the tunnel is not enough — a persisted upstream
        error (e.g. 429 rate-limit) or exhausted marker keeps it amber."""
        info = self.providers.get(name, {})
        active = info.get("active")
        egress = (info.get("egress") or {}).get(active or "", {})
        lat = egress.get("latency_ms")
        if active and lat:
            tag = f"{active} · {lat:.0f}ms" if isinstance(lat, (int, float)) else active
        elif active:
            tag = active
        else:
            tag = "no active exit"
        ok = egress.get("ok")
        # A lane can probe ok while the exit is actually rate-limited or
        # exhausted upstream (record keeps `upstream_error` across probes).
        # Transport-level probe failures (SSL EOF/timeout) are deliberately
        # quiet in the tray. Keep explicit upstream failures and hard markers
        # visible because they affect real traffic.
        warn = bool(egress.get("upstream_error") or egress.get("blocked")
                    or egress.get("exhausted"))
        if warn:
            mark = "▲"
        elif ok:
            mark = "●"
        elif ok is False:
            mark = "○"
        else:
            mark = "·"
        return f"{name} {mark} {tag}"

    def profile_health(self, name: str, profile: str) -> str:
        """Short health suffix for one exit, e.g. '· 164ms' or '! offline'.
        Returns '' when nothing is known yet. `upstream_error` (a persisted
        rotate --reason marker like 429/503) counts as an error even when
        the last probe succeeded — the exit is rate-limited/blocked for
        real traffic."""
        rec = (self.providers.get(name, {}).get("egress") or {}).get(profile)
        if not rec:
            return ""
        upstream_error = rec.get("upstream_error")
        if upstream_error:
            return " ! " + _friendly_egress_error(upstream_error)
        if rec.get("blocked"):
            return " ! blocked"
        if rec.get("exhausted"):
            return " ! rate-limited"
        # An HTTP response is meaningful degradation; a transport-only probe
        # failure is not. The latter is retained internally for rotation but
        # omitted from the user-facing menu because it is commonly transient.
        if rec.get("error") and rec.get("status") is not None:
            return " ! " + _friendly_egress_error(rec["error"])
        lat = rec.get("latency_ms")
        if isinstance(lat, (int, float)):
            return f" · {lat:.0f}ms"
        if rec.get("ok"):
            return " · ok"
        return ""

    def engine_label(self) -> str:
        """Describe the current engine mode without implying provider choice."""
        if self.mode == "tun":
            return "router: TUN"
        if self.mode == "proxy":
            port = f" :{self.port}" if self.port else ""
            return f"router: proxy{port}"
        return f"router: {self.mode}"

    def headline(self) -> str:
        if self.error:
            return f"proxy-router: error ({self.error})"
        degraded = self.up and self.mode == "proxy" and (
            self.system_proxy_status not in {"ok", "skipped"}
            or self.network_status not in {"ok", "unknown", "skipped"})
        state = "degraded" if degraded else ("connected" if self.up else "disconnected")
        detail = self.engine_label().removeprefix("router: ") if self.up else self.mode
        if degraded:
            reason = (self.system_proxy_status
                      if self.system_proxy_status not in {"ok", "skipped"}
                      else self.network_status)
            detail += f" · {reason}"
        watcher = "watcher on" if self.watcher else "watcher off"
        return f"proxy {state} · {detail} · {watcher}"


_DASHBOARD_MODES = (
    ("safe-list", "Home"),
    ("vpn-list", "School"),
    ("default", "Default"),
)
_DASHBOARD_MODE_LABELS = dict(_DASHBOARD_MODES)


@dataclass(frozen=True)
class DashboardViewModel:
    """Small, UI-safe projection of router status for the native window."""

    title: str
    explanation: str
    primary_label: str
    primary_action: str
    mode: str
    mode_label: str
    provider_rows: tuple[str, ...]
    provider_summary: str
    route_health: str
    port_label: str
    watcher_label: str
    error: str | None = None

    @classmethod
    def from_status(cls, status: RouterStatus) -> "DashboardViewModel":
        providers = status.providers or {}
        mode = status.routing_mode if status.routing_mode in _DASHBOARD_MODE_LABELS else "default"
        mode_label = _DASHBOARD_MODE_LABELS[mode]
        if status.error:
            title = "Router unavailable"
            explanation = "The dashboard could not read proxy-router status. Try Connect again or open Setup."
        elif not providers:
            title = "No VPN profile yet"
            explanation = "Add a provider profile from Setup, then Connect to start routing traffic."
        elif status.up:
            title = "Connected"
            explanation = "Your selected routes are using the proxy-router engine."
        else:
            title = "Disconnected"
            explanation = "Your VPN profiles are ready. Connect when you want routed traffic."

        if status.up:
            primary_label = "Disconnect"
            primary_action = "disconnect"
        elif providers:
            primary_label = "Connect"
            primary_action = "connect"
        else:
            primary_label = "Open Setup"
            primary_action = "setup"

        rows = []
        for name in sorted(providers):
            info = providers.get(name) or {}
            active = info.get("active")
            if active:
                try:
                    health = status.profile_health(name, active)
                except Exception:
                    health = ""
                suffix = health.strip() if isinstance(health, str) and health else "ready"
                rows.append(f"{name.title()}   {active}   {suffix}")
            else:
                rows.append(f"{name.title()}   no active server")
        if not rows:
            rows.append("No providers configured")

        provider_summary = ", ".join(name.title() for name in sorted(providers))
        if not provider_summary:
            provider_summary = "No provider"
        if status.error:
            route_health = "Unavailable"
        elif not providers:
            route_health = "Not configured"
        else:
            records = [
                ((info.get("egress") or {}).get(info.get("active")) or {})
                for info in (providers.get(name) or {}
                             for name in providers)
                if info.get("active")
            ]
            if any(record.get("upstream_error") or record.get("blocked")
                   or record.get("exhausted") for record in records):
                route_health = "Needs attention"
            elif any(record.get("ok") for record in records):
                route_health = "Healthy"
            else:
                route_health = "Waiting"
        port_label = f"Proxy :{status.port}" if status.up and status.port else "Not running"
        watcher_label = "Route watcher active" if status.watcher else "Route watcher idle"

        return cls(
            title=title,
            explanation=explanation,
            primary_label=primary_label,
            primary_action=primary_action,
            mode=mode,
            mode_label=mode_label,
            provider_rows=tuple(rows),
            provider_summary=provider_summary,
            route_health=route_health,
            port_label=port_label,
            watcher_label=watcher_label,
            error=status.error,
        )


class DashboardController:
    """Thread-safe lifecycle/data bridge for the optional dashboard window.

    The controller owns no router behavior. It only stores the latest status,
    creates/focuses one window, and forwards button intent to TrayApp's
    existing action methods. A factory keeps this path testable without a
    Cocoa session and makes missing AppKit fail closed.
    """

    def __init__(self, client, action_handler, window_factory=None,
                 initial_status=None):
        self.client = client
        self.action_handler = action_handler
        self.window_factory = window_factory or _make_macos_dashboard_window
        self._window = None
        self._window_create_lock = threading.Lock()
        self._status = initial_status if initial_status is not None else RouterStatus()
        self._last_action: str | None = None
        self._lock = threading.RLock()

    @property
    def window(self):
        with self._lock:
            return self._window

    @property
    def latest_model(self) -> DashboardViewModel:
        with self._lock:
            return DashboardViewModel.from_status(self._status)

    def show(self, status: RouterStatus) -> bool:
        with self._lock:
            self._status = status
            window = self._window
        if window is None:
            with self._window_create_lock:
                with self._lock:
                    window = self._window
                if window is None:
                    try:
                        created = self.window_factory(
                            self.client, self.action_handler, status)
                    except Exception as exc:
                        print(f"dashboard: unavailable: {exc}", file=sys.stderr)
                        return False
                    if created is None:
                        return False
                    with self._lock:
                        self._window = window = created
        with self._lock:
            display_status = self._status
            last_action = self._last_action
        try:
            window.update_status(display_status)
            if last_action is not None:
                window.update_action(last_action)
            window.show()
        except Exception as exc:
            print(f"dashboard: could not show window: {exc}", file=sys.stderr)
            try:
                window.close()
            except Exception as close_exc:
                print(f"dashboard: failed to close broken window: {close_exc}",
                      file=sys.stderr)
            with self._lock:
                if self._window is window:
                    self._window = None
            return False
        return True

    def update(self, status: RouterStatus) -> None:
        with self._lock:
            self._status = status
            window = self._window
        if window is not None:
            try:
                window.update_status(status)
            except Exception as exc:
                print(f"dashboard: status update skipped: {exc}", file=sys.stderr)

    def update_action(self, result: str | None) -> None:
        with self._lock:
            self._last_action = result
            window = self._window
        if window is not None:
            try:
                window.update_action(result)
            except Exception as exc:
                print(f"dashboard: action update skipped: {exc}", file=sys.stderr)

    def close(self) -> None:
        with self._window_create_lock:
            with self._lock:
                window = self._window
        if window is not None:
            try:
                window.close()
            except Exception as exc:
                print(f"dashboard: close skipped: {exc}", file=sys.stderr)


def _route_macos_click(kind: str, open_dashboard: Callable,
                       open_menu: Callable, event=None):
    """Route status-item clicks without changing pystray's menu descriptors.

    pystray's Darwin backend assigns the status button to ``activate:`` and
    calls the icon, which normally opens its menu for every click. The custom
    macOS icon detaches that menu so left-click can open the dashboard while
    right-click explicitly pops the same generated menu. Unknown events pass
    through untouched.
    """
    if kind == "left":
        try:
            open_dashboard()
        except Exception as exc:
            print(f"dashboard: click failed: {exc}", file=sys.stderr)
        return None
    if kind == "right":
        try:
            open_menu()
        except Exception as exc:
            print(f"dashboard: menu click failed: {exc}", file=sys.stderr)
        return None
    return event


def _launch_terminal(root, script_args: list[str]) -> bool:
    """Open a terminal in ``root`` running ``python setup_tui.py [*args]``.

    Shared by the dashboard one-click and the permission-repair path
    (issue #76). Never raises — a broken terminal setup must not take the
    tray down.
    """
    root = Path(root)
    tui = root / "setup_tui.py"
    if not tui.is_file():
        print(f"terminal: missing {tui}", file=sys.stderr)
        return False
    python = sys.executable or "python3"
    if sys.platform == "darwin":
        quoted_args = "".join(" " + shlex.quote(a) for a in script_args)
        script = (f"cd {shlex.quote(str(root))} && "
                  f"{shlex.quote(python)} setup_tui.py{quoted_args}")
        content = script.replace("\\", "\\\\").replace('"', '\\"')
        try:
            # Popen, not run(): this fires from a Cocoa menu callback on the
            # main thread. osascript's 10s synchronous timeout there froze
            # the entire tray (menu + icon) whenever Terminal was slow to
            # answer Apple events. We only need to LAUNCH osascript; its
            # success/failure is not worth blocking the UI for.
            subprocess.Popen(
                ["osascript", "-e",
                 f'tell application "Terminal" to do script "{content}"'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except OSError as exc:
            print(f"terminal: could not open Terminal: {exc}", file=sys.stderr)
            return False
    tail = ["setup_tui.py", *script_args]
    launchers = [
        ["x-terminal-emulator", "-e", python, *tail],
        ["gnome-terminal", "--", python, *tail],
        ["konsole", "-e", python, *tail],
        ["xterm", "-e", python, *tail],
    ]
    for launcher in launchers:
        if shutil.which(launcher[0]) is None:
            continue
        try:
            subprocess.Popen(launcher, cwd=str(root),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except OSError:
            continue
    print("terminal: no terminal emulator found (xterm/gnome-terminal/konsole)",
          file=sys.stderr)
    return False


def open_dashboard(root) -> bool:
    """Open the full dashboard TUI in a terminal window (tray one-click).

    The tray menu is compact by design; the dashboard is where profiles,
    exits, fallbacks, routing, and presets get managed. macOS: Terminal runs
    setup_tui.py in the router root. Elsewhere: the first common terminal
    emulator that exists wins. Never raises — the tray must survive a
    broken terminal setup."""
    root = Path(root)
    if not (root / "setup_tui.py").is_file():
        print(f"dashboard: missing {root / 'setup_tui.py'}", file=sys.stderr)
        return False
    return _launch_terminal(root, [])


class RouterClient:
    """Runs router.py subcommands; all mutation goes through the CLI."""

    def __init__(self, root: str):
        self.root = root
        self.python = sys.executable or "python3"
        self.router = os.path.join(root, "router.py")
        self._active_provider: str | None = None

    def _run(self, *args: str) -> tuple[int, str]:
        cmd = [self.python, self.router, *args]
        env = dict(os.environ)
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=COMMAND_TIMEOUT, env=env, cwd=self.root,
            )
            out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
            return p.returncode, out.strip()
        except subprocess.TimeoutExpired:
            return -1, f"timeout: {' '.join(cmd)}"
        except FileNotFoundError as e:
            return -2, f"missing: {e}"

    def status(self) -> RouterStatus:
        rc, out = self._run("status", "--json")
        st = RouterStatus.from_cli(rc, out)
        # The cache mirrors the latest valid payload, including an empty
        # provider set. Keeping an old provider after disconnect/error can make
        # the generic Switch server action target an unrelated lane.
        if not st.error:
            self._active_provider = next(iter(st.active_providers), None)
        return st

    def ensure(self) -> tuple[int, str]:
        return self._run("ensure")

    def _engine_runs_as_root(self) -> bool:
        """True only when a live exact engine command is root-owned.

        The PID-file inode is bookkeeping and may have been handed back to the
        user after an elevated start.  Inspect the live process UID and exact
        binary/argv instead; ambiguous or unavailable process evidence is not
        elevated optimistically.
        """
        if sys.platform != "darwin" or os.geteuid() == 0:
            return False
        config = os.path.abspath(os.path.join(self.root, "sing-box.json"))
        binaries = [
            os.environ.get("SING_BOX"),
            os.path.join(self.root, "bin", "sing-box"),
            "/opt/homebrew/bin/sing-box",
            "/usr/local/bin/sing-box",
            shutil.which("sing-box"),
        ]
        expected = {
            tuple(shlex.split(f"{binary} run -c {config}"))
            for binary in dict.fromkeys(b for b in binaries if b)
        }
        if not expected:
            return False

        pid_file = os.path.join(self.root, "sing-box.pid")
        try:
            pid_text = Path(pid_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            pid_text = ""
        commands = [
            ["ps", "-p", pid_text, "-o", "uid=,command="]
            if pid_text.isdigit()
            else ["ps", "-axo", "pid=,uid=,command="],
        ]
        try:
            result = subprocess.run(
                commands[0], capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False
        for line in (result.stdout or "").splitlines():
            if pid_text.isdigit():
                parts = line.strip().split(None, 1)
                if len(parts) != 2:
                    continue
                uid, command = parts
            else:
                parts = line.strip().split(None, 2)
                if len(parts) != 3:
                    continue
                _pid, uid, command = parts
            try:
                command_argv = shlex.split(command)
            except ValueError:
                continue
            if uid in {"0", "root"} and tuple(command_argv) in expected:
                return True
        return False

    def start(self) -> tuple[int, str]:
        # The router controller is the single lifecycle authority. It delegates
        # root-owned engines to the installed helper and reports a repair hint
        # when that helper is absent; the tray must not make a second owner
        # decision from PID-file metadata.
        return self._run("start")

    def stop(self) -> tuple[int, str]:
        return self._run("stop")

    def rotate(self) -> tuple[int, str]:
        if not self._active_provider:
            return 1, "no active provider"
        return self._run("rotate", self._active_provider)

    def rotate_to(self, provider: str, profile: str, force: bool = False) -> tuple[int, str]:
        cmd = ["rotate", provider, "--to", profile]
        if force:
            # Explicit pick of an offline/SSL exit: try it anyway, ignoring
            # the cooldown its failed probe left behind.
            cmd.append("--force")
        return self._run(*cmd)

    def set_mode(self, mode: str, default_provider: str | None = None) -> tuple[int, str]:
        cmd = ["routing", "set", "--mode", mode]
        if default_provider:
            cmd += ["--default-provider", default_provider]
        return self._run(*cmd)

    def setup_import(self, provider: str, paths) -> tuple[int, str]:
        """Import .conf profile(s) via the setup wizard CLI (no engine touch)."""
        flag = "--import-proton" if provider == "proton" else "--import-warp"
        return self._run("setup", flag, *paths)

    def setup_preset(self, name: str) -> tuple[int, str]:
        """Apply a named preset (idempotent, lossless) via the setup CLI."""
        return self._run("setup", "--preset", name)

    def elevate(self) -> tuple[int, str]:
        """One-time startup-permission install via the router CLI.

        Issue #76: this is the ONLY command that may show the macOS admin
        dialog. It is run from a Terminal window the user just opened (see
        TrayApp.action_fix_permissions), so elevation has an interactive
        context — the tray process itself never prompts.
        """
        return self._run("elevate", "install")

    def reload(self) -> tuple[int, str]:
        """Hot-reload the engine config in place (SIGHUP; no restart)."""
        return self._run("reload")

    def vpn(self, action: str) -> tuple[int, str]:
        """Toggle full-tunnel (TUN) mode via the router CLI.

        TUN mode needs root, but the tray remains a user process. router.py
        delegates only exact lifecycle operations to the installed root-owned
        helper and returns an install hint when that helper is absent.
        """
        if sys.platform == "darwin":
            return self._run_elevated("vpn", action)
        # Non-macOS: no osascript path; the CLI's clear error tells the user
        # to run it elevated (sudo) from a terminal.
        return self._run("vpn", action)

    def _run_elevated(self, *args: str) -> tuple[int, str]:
        """Run through the user controller; it delegates exact root lifecycle.

        The tray never invokes sudo/osascript or executes router.py as root.
        Missing helper state is returned as the controller's actionable error.
        """
        return self._run(*args)


def _status_icon_color(st: RouterStatus, action_result: str | None = None) -> str:
    """Choose green/red/orange from current state plus the latest action."""
    action_failed = bool(action_result and ": failed" in action_result.lower())
    if action_failed or st.error or (st.up and st.mode == "proxy" and (
            st.system_proxy_status not in {"ok", "skipped"}
            or st.network_status not in {"ok", "unknown", "skipped"})):
        return "#ff9800"
    return "#4caf50" if st.up else "#e53935"


def make_icon(color: str, size: int = 64) -> "Image.Image":
    """Small filled-circle status icon (green=up, red=down, orange=warn)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = size // 8
    draw.ellipse(
        [margin, margin, size - margin, size - margin],
        fill=color, outline=(255, 255, 255, 220), width=max(2, size // 16),
    )
    return img





if _REAL_DARWIN_PYSTRAY:
    def _dashboard_color(red: int, green: int, blue: int, alpha: float = 1.0):
        return AppKit.NSColor.colorWithSRGBRed_green_blue_alpha_(
            red / 255.0, green / 255.0, blue / 255.0, alpha)


    def _dashboard_font(size: float, weight=None):
        if weight is not None:
            return AppKit.NSFont.systemFontOfSize_weight_(size, weight)
        return AppKit.NSFont.systemFontOfSize_(size)


    def _dashboard_label(text: str, size: float, color, *, bold=False,
                         align=None, wrap=False):
        label = AppKit.NSTextField.labelWithString_(text)
        label.setFont_(_dashboard_font(
            size, AppKit.NSFontWeightSemibold if bold else None))
        label.setTextColor_(color)
        label.setSelectable_(False)
        label.setEditable_(False)
        label.setBezeled_(False)
        label.setDrawsBackground_(False)
        label.setLineBreakMode_(
            AppKit.NSLineBreakByWordWrapping
            if wrap else AppKit.NSLineBreakByTruncatingTail)
        if wrap:
            label.setMaximumNumberOfLines_(2)
        if align is not None:
            label.setAlignment_(align)
        return label


    def _dashboard_button(title: str, target, action: str, *, primary=False):
        button = AppKit.NSButton.alloc().initWithFrame_(AppKit.NSZeroRect)
        button.setTitle_(title)
        button.setTarget_(target)
        button.setAction_(action)
        button.setBezelStyle_(AppKit.NSBezelStyleRounded)
        button.setBordered_(True)
        button.setFont_(_dashboard_font(
            14, AppKit.NSFontWeightSemibold if primary else AppKit.NSFontWeightMedium))
        button.setContentTintColor_(_dashboard_color(248, 250, 252))
        if primary:
            button.setBezelColor_(_dashboard_color(43, 116, 238))
        else:
            button.setBezelColor_(_dashboard_color(42, 48, 60))
        return button


    class _DashboardRootView(AppKit.NSView):
        def initWithController_(self, controller):
            self = objc.super(_DashboardRootView, self).initWithFrame_(
                AppKit.NSMakeRect(0, 0, DASHBOARD_WIDTH, DASHBOARD_HEIGHT))
            if self:
                self.controller = controller
                self.setPostsFrameChangedNotifications_(True)
            return self

        def isFlipped(self):
            return True

        def drawRect_(self, rect):
            width = self.bounds().size.width
            height = self.bounds().size.height
            background = _dashboard_color(14, 17, 23)
            rail = _dashboard_color(17, 21, 28)
            panel = _dashboard_color(25, 30, 40)
            border = _dashboard_color(46, 54, 68)

            background.set()
            AppKit.NSRectFill_(self.bounds())
            rail.set()
            AppKit.NSRectFill_(AppKit.NSMakeRect(0, 0, 196, height))

            separator = AppKit.NSMakeRect(195, 0, 1, height)
            border.set()
            AppKit.NSRectFill_(separator)

            content_x = 228
            content_width = max(420, width - content_x - 32)
            hero_y = 72
            hero_height = min(270, max(218, height * 0.38))
            mode_y = hero_y + hero_height + 22
            mode_height = 106
            health_y = mode_y + mode_height + 22
            health_height = max(132, height - health_y - 28)
            self._round_fill(
                AppKit.NSMakeRect(content_x, hero_y, content_width, hero_height),
                18, panel, border)
            self._round_fill(
                AppKit.NSMakeRect(content_x, mode_y, content_width, mode_height),
                16, panel, border)
            self._round_fill(
                AppKit.NSMakeRect(content_x, health_y, content_width, health_height),
                16, panel, border)

        @staticmethod
        def _round_fill(rect, radius, fill, stroke=None):
            path = AppKit.NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
                rect, radius, radius)
            fill.set()
            path.fill()
            if stroke is not None:
                stroke.set()
                path.setLineWidth_(1.0)
                path.stroke()

        def layout(self):
            objc.super(_DashboardRootView, self).layout()
            self.controller._layout_dashboard(self.bounds().size.width,
                                              self.bounds().size.height)


    class _DashboardDispatcher(Foundation.NSObject):
        def initWithOwner_(self, owner):
            self = objc.super(_DashboardDispatcher, self).init()
            if self:
                self.owner = owner
            return self

        @objc.namedSelector(b"drainDashboardUI:")
        def drain_dashboard_ui(self, _sender):
            self.owner._drain_pending_ui()


    class _DashboardWindowDelegate(Foundation.NSObject):
        def initWithOwner_(self, owner):
            self = objc.super(_DashboardWindowDelegate, self).init()
            if self:
                self.owner = owner
            return self

        @objc.namedSelector(b"windowWillClose:")
        def window_will_close(self, _notification):
            self.owner._window_closed()


    class MacDashboardWindow(Foundation.NSObject):
        """Native dark macOS window; it is intentionally not an NSPanel/menu."""

        def initWithClient_action_status_(self, client, action_handler, status):
            self = objc.super(MacDashboardWindow, self).init()
            if self:
                self.client = client
                self.action_handler = action_handler
                self._status_lock = threading.Lock()
                self._pending_status = status
                self._pending_action: str | None = None
                self._ui_dispatch_queued = False
                self._model = DashboardViewModel.from_status(status)
                self._visible = False
                self._build_window()
                self._apply_status(status)
            return self

        def _build_window(self):
            style = (
                AppKit.NSWindowStyleMaskTitled
                | AppKit.NSWindowStyleMaskClosable
                | AppKit.NSWindowStyleMaskMiniaturizable
                | AppKit.NSWindowStyleMaskResizable
            )
            frame = AppKit.NSMakeRect(0, 0, DASHBOARD_WIDTH, DASHBOARD_HEIGHT)
            self.window = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
                frame, style, AppKit.NSBackingStoreBuffered, False)
            self.window.setTitle_("proxy-router")
            self.window.setTitleVisibility_(AppKit.NSWindowTitleHidden)
            self.window.setTitlebarAppearsTransparent_(True)
            self.window.setMovableByWindowBackground_(True)
            self.window.setReleasedWhenClosed_(False)
            self.window.setRestorable_(False)
            self.window.setMinSize_(AppKit.NSMakeSize(860, 620))
            self.window.setBackgroundColor_(_dashboard_color(14, 17, 23))
            self.window.setOpaque_(True)
            self.window.setHasShadow_(True)
            self.window.center()

            self._window_delegate = _DashboardWindowDelegate.alloc().initWithOwner_(self)
            self.window.setDelegate_(self._window_delegate)
            self._dispatcher = _DashboardDispatcher.alloc().initWithOwner_(self)

            self.root = _DashboardRootView.alloc().initWithController_(self)
            self.window.setContentView_(self.root)
            self.root.setAutoresizingMask_(
                AppKit.NSViewWidthSizable | AppKit.NSViewHeightSizable)

            white = _dashboard_color(242, 245, 249)
            muted = _dashboard_color(151, 161, 176)
            quiet = _dashboard_color(112, 123, 140)
            blue = _dashboard_color(82, 143, 255)

            self.brand = _dashboard_label("proxy-router", 16, white, bold=True)
            self.brand_caption = _dashboard_label("CONTROL CENTER", 9, quiet, bold=True)
            self.page_title = _dashboard_label("Home", 20, white, bold=True)
            self.page_caption = _dashboard_label("Private routing, without the mystery", 12, muted)
            # Navigation pages are not implemented yet; do not render a dead
            # home button while the dashboard has a single page.
            self.home_button = None
            # These pages are not implemented yet; do not render dead controls.
            self.servers_button = None
            self.routing_button = None
            self.settings_button = None

            self.hero_dot = _dashboard_label("●", 42, blue, bold=True,
                                            align=AppKit.NSCenterTextAlignment)
            self.hero_title = _dashboard_label(self._model.title, 30, white, bold=True,
                                               align=AppKit.NSCenterTextAlignment)
            self.hero_explanation = _dashboard_label(
                self._model.explanation, 14, muted,
                align=AppKit.NSCenterTextAlignment, wrap=True)
            self.primary_button = _dashboard_button(
                self._model.primary_label, self, "primaryAction:", primary=True)
            self.rotate_button = _dashboard_button(
                "Switch server", self, "rotateAction:", primary=False)
            self.action_label = _dashboard_label("", 11, quiet, align=AppKit.NSCenterTextAlignment)

            self.mode_title = _dashboard_label("Traffic mode", 14, white, bold=True)
            self.mode_hint = _dashboard_label(
                "Choose which destinations use the tunnel.", 12, muted)
            self.mode_popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(
                AppKit.NSZeroRect, False)
            for _mode, label in _DASHBOARD_MODES:
                self.mode_popup.addItemWithTitle_(label)
            self.mode_popup.setTarget_(self)
            self.mode_popup.setAction_("modeChanged:")
            self.mode_popup.setFont_(_dashboard_font(13, AppKit.NSFontWeightMedium))
            self.mode_popup.setContentTintColor_(white)

            self.health_title = _dashboard_label("Provider health", 14, white, bold=True)
            self.health_summary = _dashboard_label(
                self._model.route_health, 13, blue, bold=True)
            self.route_label = _dashboard_label(
                f"{self._model.provider_summary} · {self._model.port_label} · "
                f"{self._model.watcher_label}", 12, muted)
            self.provider_labels = []
            for child in (
                self.brand, self.brand_caption, self.page_title, self.page_caption,
                self.hero_dot, self.hero_title,
                self.hero_explanation, self.primary_button, self.rotate_button,
                self.action_label, self.mode_title, self.mode_hint, self.mode_popup,
                self.health_title, self.route_label,
                self.health_summary,
            ):
                self.root.addSubview_(child)

        def _layout_dashboard(self, width: float, height: float):
            content_x = 228
            content_width = max(420, width - content_x - 32)
            hero_y = 72
            hero_height = min(270, max(218, height * 0.38))
            mode_y = hero_y + hero_height + 22
            health_y = mode_y + 106 + 22
            health_height = max(132, height - health_y - 28)

            def frame(view, x, y, w, h):
                view.setFrame_(AppKit.NSMakeRect(x, y, max(0, w), max(0, h)))

            frame(self.brand, 24, 24, 148, 24)
            frame(self.brand_caption, 24, 50, 148, 16)
            frame(self.page_title, content_x, 26, 300, 28)
            frame(self.page_caption, content_x, 52, 430, 20)
            center = content_x + content_width / 2
            frame(self.hero_dot, center - 34, hero_y + 26, 68, 56)
            frame(self.hero_title, content_x + 24, hero_y + 88, content_width - 48, 42)
            frame(self.hero_explanation, content_x + 100, hero_y + 132,
                  content_width - 200, 44)
            button_width = 150
            frame(self.primary_button, center - button_width - 8,
                  hero_y + hero_height - 58, button_width, 38)
            frame(self.rotate_button, center + 8, hero_y + hero_height - 58,
                  button_width, 38)
            frame(self.action_label, content_x + 40, hero_y + hero_height - 20,
                  content_width - 80, 16)

            frame(self.mode_title, content_x + 24, mode_y + 20, 160, 22)
            frame(self.mode_hint, content_x + 24, mode_y + 49,
                  max(260, content_width - 240), 20)
            frame(self.mode_popup, content_x + content_width - 194,
                  mode_y + 26, 170, 34)

            frame(self.health_title, content_x + 24, health_y + 20, 180, 22)
            frame(self.health_summary, content_x + 220, health_y + 20, 180, 22)
            frame(self.route_label, content_x + 24, health_y + 48,
                  content_width - 48, 22)
            row_y = health_y + 78
            visible_rows = max(0, int((health_height - 78) // 28))
            for index, label in enumerate(self.provider_labels):
                label.setHidden_(index >= visible_rows)
                if index >= visible_rows:
                    continue
                frame(label, content_x + 24, row_y, content_width - 48, 23)
                row_y += 28

        def _schedule_ui_refresh(self):
            if Foundation.NSThread.isMainThread():
                self._drain_pending_ui()
                return
            with self._status_lock:
                if self._ui_dispatch_queued:
                    return
                self._ui_dispatch_queued = True
            try:
                self._dispatcher.performSelectorOnMainThread_withObject_waitUntilDone_(
                    "drainDashboardUI:", None, False)
            except Exception:
                with self._status_lock:
                    self._ui_dispatch_queued = False

        def update_status(self, status: RouterStatus):
            with self._status_lock:
                self._pending_status = status
            self._schedule_ui_refresh()

        def update_action(self, result: str | None):
            with self._status_lock:
                self._pending_action = result
            self._schedule_ui_refresh()

        def _drain_pending_ui(self):
            with self._status_lock:
                status = self._pending_status
                action = self._pending_action
                self._pending_status = None
                self._pending_action = None
                self._ui_dispatch_queued = False
            if status is not None:
                self._apply_status(status)
            if action is not None:
                self._apply_action(action)

        def _apply_status(self, status: RouterStatus):
            self._model = DashboardViewModel.from_status(status)
            self.hero_title.setStringValue_(self._model.title)
            self.hero_explanation.setStringValue_(self._model.explanation)
            self.primary_button.setTitle_(self._model.primary_label)
            mode_index = next(
                (index for index, (mode, _label) in enumerate(_DASHBOARD_MODES)
                 if mode == self._model.mode),
                len(_DASHBOARD_MODES) - 1,
            )
            self.mode_popup.selectItemAtIndex_(mode_index)
            self.mode_popup.setEnabled_(bool(status.providers))
            if status.error:
                color = _dashboard_color(242, 157, 76)
                self.hero_dot.setStringValue_("!")
            elif status.up:
                color = _dashboard_color(77, 205, 139)
                self.hero_dot.setStringValue_("●")
            else:
                color = _dashboard_color(134, 147, 166)
                self.hero_dot.setStringValue_("○")
            self.hero_dot.setTextColor_(color)
            self.health_summary.setStringValue_(self._model.route_health)
            self.route_label.setStringValue_(
                f"{self._model.provider_summary} · {self._model.port_label} · "
                f"{self._model.watcher_label}")

            for label in self.provider_labels:
                label.removeFromSuperview()
            self.provider_labels = []
            rows = list(self._model.provider_rows[:4])
            if len(self._model.provider_rows) > len(rows):
                rows[-1] = (
                    f"{rows[-1]} · +{len(self._model.provider_rows) - len(rows)} more"
                )
            for row in rows:
                label = _dashboard_label(row, 12, _dashboard_color(190, 198, 210))
                self.provider_labels.append(label)
                self.root.addSubview_(label)
            self.root.setNeedsDisplay_(True)
            self.root.setNeedsLayout_(True)

        def _apply_action(self, result: str):
            self.action_label.setStringValue_(result)
            self.root.setNeedsLayout_(True)

        def _invoke_action(self, kind: str, value=None):
            try:
                if callable(self.action_handler):
                    self.action_handler(kind, value)
                    return
                methods = {
                    "connect": ("action_connect", ()),
                    "disconnect": ("action_disconnect", ()),
                    "rotate": ("action_rotate", ()),
                    "mode": ("action_mode", (value,)),
                    "setup": ("action_setup", ()),
                }
                method_name, args = methods[kind]
                getattr(self.action_handler, method_name)(*args)
            except Exception as exc:
                self.update_action(f"{kind}: failed ({exc})")

        @objc.namedSelector(b"primaryAction:")
        def primary_action(self, _sender):
            self._invoke_action(self._model.primary_action)

        @objc.namedSelector(b"rotateAction:")
        def rotate_action(self, _sender):
            self._invoke_action("rotate")

        @objc.namedSelector(b"modeChanged:")
        def mode_changed(self, sender):
            index = sender.indexOfSelectedItem()
            if index < 0 or index >= len(_DASHBOARD_MODES):
                return
            mode = _DASHBOARD_MODES[index][0]
            self._invoke_action("mode", mode)

        def show(self):
            if not Foundation.NSThread.isMainThread():
                self.performSelectorOnMainThread_withObject_waitUntilDone_(
                    "showOnMainThread:", None, True)
                return
            self._show_now()

        @objc.namedSelector(b"showOnMainThread:")
        def show_on_main_thread(self, _sender):
            self._show_now()

        def _show_now(self):
            self._visible = True
            self.window.makeKeyAndOrderFront_(None)
            AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

        @objc.namedSelector(b"closeOnMainThread:")
        def close_on_main_thread(self, _sender):
            self._close_now()

        def _close_now(self):
            self._visible = False
            self.window.orderOut_(None)

        def close(self):
            if not Foundation.NSThread.isMainThread():
                self.performSelectorOnMainThread_withObject_waitUntilDone_(
                    "closeOnMainThread:", None, False)
                return
            self._close_now()

        def _window_closed(self):
            self._visible = False

else:
    MacDashboardWindow = None


def _make_macos_dashboard_window(client, action_handler, status):
    if not _REAL_DARWIN_PYSTRAY:
        return None
    return MacDashboardWindow.alloc().initWithClient_action_status_(
        client, action_handler, status)


def _event_type(event):
    """Read an NSEvent type while keeping click routing mockable in tests."""
    value = getattr(event, "type", None)
    return value() if callable(value) else value


def _is_right_click_event(event) -> bool:
    if not _COCOA_AVAILABLE or event is None:
        return False
    click_types = {
        getattr(AppKit, "NSRightMouseDown", None),
        getattr(AppKit, "NSRightMouseUp", None),
    }
    click_types.discard(None)
    if _event_type(event) in click_types:
        return True
    flags = getattr(event, "modifierFlags", None)
    flags = flags() if callable(flags) else flags
    control_mask = getattr(
        AppKit, "NSEventModifierFlagControl",
        getattr(AppKit, "NSControlKeyMask", 0),
    )
    return bool(flags and control_mask and flags & control_mask)


if _REAL_DARWIN_PYSTRAY:
    class _DashboardIconDelegate(Foundation.NSObject):
        def initWithOwner_(self, owner):
            self = objc.super(_DashboardIconDelegate, self).init()
            if self:
                self.owner = owner
            return self

        @objc.namedSelector(b"activateDashboard:")
        def activate_dashboard(self, _sender):
            event = AppKit.NSApp.currentEvent()
            self.owner._route_status_button_event(event)


    class _DarwinDashboardIcon(pystray.Icon):
        """pystray Darwin icon with explicit left/right click routing.

        pystray's normal Darwin backend assigns its NSMenu to NSStatusItem,
        which makes both button clicks open the menu. This subclass keeps the
        generated menu descriptors and callbacks, but leaves the status item
        menu unset and handles right-click popup explicitly. That gives the
        dashboard a real left-click entry point without changing menu actions.
        """

        def __init__(self, *args, dashboard_callback=None, **kwargs):
            self._dashboard_callback = dashboard_callback
            self._native_menu = None
            self._menu_handle = None
            super().__init__(*args, **kwargs)
            self._dashboard_delegate = _DashboardIconDelegate.alloc().initWithOwner_(self)
            self._bind_status_button()

        def _bind_status_button(self):
            status_item = getattr(self, "_status_item", None)
            delegate = getattr(self, "_dashboard_delegate", None)
            if status_item is None or delegate is None:
                return
            button = status_item.button()
            if button is None:
                return
            button.setTarget_(delegate)
            button.setAction_(b"activateDashboard:")
            try:
                button.sendActionOn_(
                    AppKit.NSLeftMouseUpMask | AppKit.NSRightMouseUpMask)
            except Exception:
                # Older AppKit/PyObjC still delivers the default left action;
                # right-click remains best-effort rather than breaking startup.
                pass
            status_item.setMenu_(None)

        def _update_menu(self):
            self._bind_status_button()
            create_menu = getattr(self, "_create_menu", None)
            if not callable(create_menu):
                self._menu_handle = None
                return
            callbacks = []
            try:
                self._native_menu = create_menu(self.menu, callbacks)
            except Exception as exc:
                self._native_menu = None
                self._menu_handle = None
                print(f"tray: native menu rebuild skipped: {exc}", file=sys.stderr)
                return
            self._menu_handle = (
                (self._native_menu, callbacks)
                if self._native_menu is not None else None)
            # The menu is intentionally not assigned to NSStatusItem. AppKit
            # would consume left-click before the button target can route it.
            status_item = getattr(self, "_status_item", None)
            if status_item is not None:
                status_item.setMenu_(None)

        def _route_status_button_event(self, event):
            kind = "right" if _is_right_click_event(event) else "left"
            callback = self._dashboard_callback or (lambda: None)
            _route_macos_click(
                kind, callback,
                lambda: self._show_native_menu(event), event=event)

        def _show_native_menu(self, event):
            menu_handle = getattr(self, "_menu_handle", None)
            if not menu_handle:
                print("tray: native menu unavailable", file=sys.stderr)
                return
            menu = menu_handle[0]
            status_item = getattr(self, "_status_item", None)
            if status_item is None:
                return
            button = status_item.button()
            try:
                AppKit.NSMenu.popUpContextMenu_withEvent_forView_(
                    menu, event, button)
            except Exception:
                # Keep a compatibility fallback for AppKit versions that do
                # not expose the context-popup selector through PyObjC.
                try:
                    bounds = button.bounds()
                    menu.popUpMenuPositioningItem_atLocation_inView_(
                        None, AppKit.NSMakePoint(0, bounds.size.height), button)
                except Exception as fallback_exc:
                    print(f"dashboard: native menu popup failed: {fallback_exc}",
                          file=sys.stderr)
                    return

else:
    class _DarwinDashboardIcon:
        """Unavailable placeholder used on non-macOS or without pystray."""

        pass


class TrayApp:
    def __init__(self, client: RouterClient, icon_image: "Image.Image",
                 initial_status: RouterStatus | None = None):
        self.client = client
        self.icon_image = icon_image
        self.latest: RouterStatus = (
            initial_status if initial_status is not None else RouterStatus())
        self.lock = threading.Lock()
        self.last_action_result: str | None = None
        self.quit_flag = threading.Event()
        self.tray = None
        self.dashboard = DashboardController(
            client, self._dispatch_dashboard_action,
            initial_status=self.latest)
        self._menu_sig: str | None = None
        self._icon_sig: str | None = None
        self._menu_lock = threading.Lock()

        # Issue #60: mutations used to run on independent daemon threads, so
        # two clicks raced each other inside router.py and an older
        # completion could overwrite newer status. One serialized worker +
        # a generation counter give every mutation a strict completion order;
        # `_status_epoch` stamps the snapshot a worker produced so a stale
        # poll can never overwrite it (polls only win when they are NEWER).
        self._mutation_gate = threading.Semaphore(0)
        self._pending_mutations: list[tuple[str, Callable]] = []
        self._pending_lock = threading.Lock()
        # Serialize the accept/reject decision with Quit.  The FIFO pump
        # already serializes execution, but a click that passed the old
        # quit_flag check could still append after Quit began draining.
        self._action_accept_lock = threading.Lock()
        self._quit_pending = False
        # Signalled whenever the mutation pump goes idle (queue drained and
        # nothing executing); action_quit waits on it, bounded.
        self._idle_cond = threading.Condition(self._pending_lock)
        self._status_epoch = 0
        self._worker_thread: threading.Thread | None = None
        # True while one mutation is popped and executing (menu controls
        # render disabled/coalesced meanwhile — issue #60).
        self._mutation_active = False
        # Quit's bounded drain window (tests shrink it; production uses
        # MUTATION_DRAIN_TIMEOUT so a hung job cannot make Quit unkillable).
        self._drain_timeout = MUTATION_DRAIN_TIMEOUT

    # ---- status polling ------------------------------------------------
    def _status_signature(self, st: RouterStatus) -> str:
        """Stable signature of everything the menu/icon renders.

        Rebuilding the pystray menu on macOS tears down the NSMenu under the
        cursor; a rebuild racing a click loses the action handler, which is
        exactly the 'half the buttons don't work' symptom. Rebuild ONLY when
        the rendered state actually changed, never on a timer tick with the
        same values.

        Issue #60: the signature must cover EVERY field the menu renders.
        It previously omitted preset, blocked/exhausted/upstream-error/HTTP
        status markers and profile lists — changes to those left stale menu
        entries indefinitely because the rebuild never fired.
        """
        health = {}
        for name, info in (st.providers or {}).items():
            health[name] = {
                p: (
                    rec.get("ok"), rec.get("error"), rec.get("latency_ms"),
                    rec.get("status"), rec.get("upstream_error"),
                    rec.get("blocked"), rec.get("exhausted"),
                )
                for p, rec in (info.get("egress") or {}).items()
            }
        return repr({
            "up": st.up, "error": st.error, "mode": st.mode, "port": st.port,
            "watcher": st.watcher, "routing": st.routing_mode,
            "preset": st.preset,
            "system_proxy": st.system_proxy_status,
            "network": st.network_status,
            "active": st.active_providers,
            "profiles": {n: list((i or {}).get("profiles") or [])
                         for n, i in (st.providers or {}).items()},
            "health": health,
            "custom_presets": self._custom_preset_signature(),
            "action": self.last_action_result,
        })

    def _refresh_icon(self) -> None:
        """Update the tray icon from the current snapshot and action state."""
        if self.tray is None:
            return
        with self.lock:
            st = self.latest
            color = _status_icon_color(st, self.last_action_result)
            if color == self._icon_sig:
                return
            try:
                self.tray.icon = make_icon(color)
            except Exception as exc:
                print(f"tray: icon refresh failed: {type(exc).__name__}",
                      file=sys.stderr)
                return
            self._icon_sig = color

    def _publish_status(self, st: RouterStatus, epoch: int | None = None) -> None:
        """Install a new status snapshot unless a NEWER one already landed.

        Polls fetch `router.py status` OUTSIDE the lock; between the fetch
        and this call a mutation worker may finish and publish its fresh
        post-action snapshot. Publishing unconditionally would roll the menu
        back to pre-action state (issue #60). The epoch check makes the
        newest observation win instead of the last writer.
        """
        with self.lock:
            if epoch is not None and epoch < self._status_epoch:
                return  # stale poll: a newer post-action snapshot won already
            if epoch is not None:
                self._status_epoch = max(self._status_epoch, epoch)
            self.latest = st
        self._refresh_icon()
        self._dashboard_update_status(st)
        self._refresh_menu()

    def _refresh_menu(self) -> None:
        """Rebuild the tray menu only when rendered state changed."""
        if self.tray is None:
            return
        # pystray replaces the native menu tree on assignment. Serialize that
        # operation and publish the signature only after the new tree exists so
        # a poll/action pair cannot tear down the menu under a click.
        try:
            with self._menu_lock:
                with self.lock:
                    st = self.latest
                    signature = self._status_signature(st)
                if signature == self._menu_sig:
                    return
                self.tray.menu = self.build_menu()
                self._menu_sig = signature
        except Exception as exc:
            self._menu_sig = None
            print(f"tray: menu refresh failed: {type(exc).__name__}",
                  file=sys.stderr)

    def poll_loop(self) -> None:
        while not self.quit_flag.is_set():
            epoch: int | None = None
            try:
                # Claim the epoch BEFORE fetching (issue #60): a poll that
                # fetched pre-action but publishes post-action must lose to
                # the mutation's snapshot, so its epoch has to be older than
                # anything the mutation claims meanwhile.
                with self.lock:
                    epoch = self._status_epoch + 1
                    self._status_epoch = epoch
                st = self.client.status()
                self._publish_status(st, epoch)
            except Exception as e:  # keep the tray alive on any poll failure
                # Keep the poll's epoch so a late failure cannot overwrite a
                # newer action snapshot that landed while status() was out.
                self._publish_status(RouterStatus(error=str(e)[:80]), epoch)
            self.quit_flag.wait(POLL_SECONDS)

    def _snapshot(self) -> RouterStatus:
        with self.lock:
            return self.latest

    def _dashboard_update_status(self, status: RouterStatus) -> None:
        """Dashboard rendering is optional and must never affect routing."""
        try:
            self.dashboard.update(status)
        except Exception as exc:
            print(f"dashboard: status update skipped: {exc}", file=sys.stderr)

    def _dashboard_update_action(self, result: str | None) -> None:
        """Keep a closed/broken UI from interrupting a CLI action."""
        try:
            self.dashboard.update_action(result)
        except Exception as exc:
            print(f"dashboard: action update skipped: {exc}", file=sys.stderr)

    # ---- actions ---------------------------------------------------------
    def _do(self, fn, label: str):
        # Issue #60: every click used to spawn its own daemon thread, so two
        # rapid clicks ran connect/disconnect/rotate CONCURRENTLY inside
        # router.py and completion order was arbitrary. Mutations now queue
        # onto ONE serialized worker: clicks coalesce into pending jobs,
        # results land strictly in click order, and the "working…" line
        # shows immediately without blocking the menu callback thread.
        # Keep the quit check and queue append in one acceptance critical
        # section.  This closes the small race where Quit could observe an
        # empty queue, stop the engine, and then a click appends work behind it.
        with self._action_accept_lock:
            if self.quit_flag.is_set() or self._quit_pending:
                return  # quitting: stop accepting mutations before they queue
            with self.lock:
                self.last_action_result = f"{label}: working…"
            self._dashboard_update_action(self.last_action_result)
            self._refresh_menu()

            with self._pending_lock:
                self._pending_mutations.append((label, fn))
                worker = self._worker_thread
                if worker is None or not worker.is_alive():
                    worker = threading.Thread(
                        target=self._mutation_worker, daemon=True,
                        name="tray-mutations")
                    self._worker_thread = worker
                    worker.start()
            # One permit per queued job: the pump pops exactly one job per
            # acquire, so FIFO order holds no matter how fast clicks arrive.
            self._mutation_gate.release()

    def _mutation_idle(self) -> bool:
        """True when no mutation is executing and the queue is empty."""
        return not self._pending_mutations and not self._mutation_active

    def _mutation_worker(self) -> None:
        """Serialized mutation pump: one job at a time, strict FIFO order."""
        while True:
            self._mutation_gate.acquire()
            with self._pending_lock:
                if not self._pending_mutations:
                    continue
                label, fn = self._pending_mutations.pop(0)
                self._mutation_active = True
            try:
                try:
                    rc, out = fn()
                except Exception as e:
                    rc, out = -1, f"{type(e).__name__}: {e}"
                detail = _humanize(out)
                result = f"{label}: {'done' if rc == 0 else 'failed'}"
                if detail:
                    result += f" — {detail}"
                try:
                    refreshed = self.client.status()
                except Exception as e:
                    refreshed = RouterStatus(error=str(e)[:80])
                with self.lock:
                    self.last_action_result = result
                    epoch = self._status_epoch + 1
                    self._status_epoch = epoch
                try:
                    self._dashboard_update_action(result)
                except Exception as exc:
                    print(f"dashboard: action update skipped: {exc}", file=sys.stderr)
                try:
                    self._publish_status(refreshed, epoch)
                except Exception as exc:
                    refresh_note = f"{result} — status refresh failed"
                    with self.lock:
                        self.last_action_result = refresh_note
                    self._dashboard_update_action(refresh_note)
                    print(f"tray: status publish skipped: {exc}", file=sys.stderr)
            finally:
                # A dashboard/UI failure must not leave the mutation gate
                # permanently active or make Quit wait for a dead worker.
                with self._idle_cond:
                    self._mutation_active = False
                    self._idle_cond.notify_all()

    def _dispatch_dashboard_action(self, kind: str, value=None):
        """Route dashboard intent back through existing tray/CLI actions."""
        if kind == "connect":
            self.action_connect()
        elif kind == "disconnect":
            self.action_disconnect()
        elif kind == "rotate":
            self.action_rotate()
        elif kind == "mode" and value in {"safe-list", "vpn-list", "default"}:
            self.action_mode(value)
        elif kind == "setup":
            self.action_setup()
        else:
            print(f"dashboard: unknown action {kind!r}", file=sys.stderr)

    def action_dashboard(self):
        # Preserve the existing right-click menu action: its Dashboard entry
        # opens the full setup wizard in Terminal. The status-item left-click
        # uses _show_native_dashboard and never takes this path.
        ok = open_dashboard(self.client.root)
        result = "dashboard opened" if ok else "dashboard: no terminal"
        with self.lock:
            self.last_action_result = result
        self._dashboard_update_action(result)
        self._refresh_menu()

    def _show_native_dashboard(self):
        """Open or focus the custom macOS dashboard without engine changes."""
        shown = self.dashboard.show(self._snapshot())
        if not shown:
            opened = open_dashboard(self.client.root)
            result = ("dashboard unavailable; opened terminal dashboard"
                      if opened else
                "dashboard unavailable; use Open Setup in Terminal from the menu")
            with self.lock:
                self.last_action_result = result
            self._dashboard_update_action(result)
            self._refresh_menu()
        return shown

    def action_setup(self):
        """Open the existing setup wizard without duplicating its logic."""
        opened = open_dashboard(self.client.root)
        result = "setup opened in Terminal" if opened else "setup: no terminal"
        with self.lock:
            self.last_action_result = result
        self._dashboard_update_action(result)
        self._refresh_menu()

    def action_connect(self):
        # start (not ensure): also clears the manual-off marker written by
        # Disconnect, so keepalive resumes watching afterwards.
        self._do(self.client.start, "connect")

    def action_disconnect(self):
        self._do(self.client.stop, "disconnect")

    def action_toggle_vpn(self):
        """Toggle full-tunnel mode from a fresh status snapshot.

        The menu snapshot may be several seconds old—or an external CLI may
        have changed mode since it was rendered. Resolve the direction inside
        the serialized worker immediately before issuing the lifecycle command.
        """
        def toggle():
            status = self.client.status()
            if status.error:
                return 1, f"cannot determine current tunnel mode: {status.error}"
            if status.mode not in {"proxy", "tun"}:
                return 1, f"cannot determine current tunnel mode: {status.mode}"
            target = "off" if status.mode == "tun" else "on"
            rc, out = self.client.vpn(target)
            return rc, f"{target}: {out}" if out else target

        self._do(toggle, "full tunnel")

    def action_rotate(self):
        self._do(self.client.rotate, "switch server")

    def action_mode(self, mode: str):
        provider = None
        if mode == "safe-list":
            # safe-list routes everything NOT on the direct list through
            # ONE provider. Prefer the persisted default even while the engine
            # is down; active exits are empty in that state by design.
            with self.lock:
                st = self.latest
                provider = (getattr(st, "default_provider", None)
                            or next(iter(st.active_providers), None))
        self._do(lambda: self.client.set_mode(mode, provider),
                 f"mode {_ROUTING_MODE_LABELS.get(mode, mode)}")

    def action_import_profile(self, provider: str):
        """Native file picker → import .conf profiles (no terminal needed)."""
        # tkinter is only imported inside the action so --selftest and --help
        # keep working on headless machines.
        try:
            import tkinter as tk
            from tkinter import filedialog
        except ImportError:
            self._do(lambda: (1, "file picker unavailable on this system — "
                                  "add the profile from the terminal, see the Setup guide"),
                     f"import {provider}")
            return

        def pick_and_import():
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            files = filedialog.askopenfilenames(
                title=f"Add {provider} VPN profile (.conf)",
                filetypes=[("WireGuard profile", "*.conf"), ("All files", "*.*")],
            )
            root.destroy()
            if not files:
                return 0, "no file selected — nothing imported"
            return self.client.setup_import(provider, list(files))

        self._do(pick_and_import, f"import {provider}")

    def action_apply_preset(self, name: str):
        """One-click preset apply (idempotent, lossless) + hot reload.

        Writing router.json alone never re-routes traffic; without the
        follow-up reload the menu reported "done" while the old exits kept
        serving. The reload applies the preset in place (SIGHUP; the engine
        keeps running) and the toast reports the combined result.
        """
        def _apply_and_reload():
            try:
                current = self.client.status()
            except Exception as exc:
                return 1, f"cannot determine engine state; preset not applied: {exc}"
            if current.error:
                return 1, ("cannot determine engine state; preset not applied: "
                            f"{current.error}")
            rc, out = self.client.setup_preset(name)
            if rc != 0:
                return rc, out
            if not current.up:
                # router.py reload starts a missing engine. A disconnected tray
                # preset click is configuration-only; Connect applies it later.
                return 0, (out + "\nengine is untouched — Connect to apply").strip()
            return self.client.reload()
        self._do(_apply_and_reload, f"preset {name}")

    def action_show_guide(self, provider: str):
        """Open the bundled setup guide in the default app (macOS) so a
        non-technical user can learn where .conf profiles come from without
        leaving the tray. Read-only; never touches engine state."""
        guide = os.path.join(
            self.client.root, "guides",
            "proton-vpn-free.md" if provider == "proton" else "cloudflare-warp.md")
        if not os.path.isfile(guide):
            self._do(lambda: (1, f"guide file missing ({guide})"), f"guide {provider}")
            return
        if sys.platform == "darwin":
            # `open` returns immediately; the default markdown/text viewer
            # takes over. Not a background process of ours.
            subprocess.Popen(["open", guide])
        else:
            # non-macOS fallback: print the guide to stdout (best effort).
            try:
                with open(guide, encoding="utf-8") as f:
                    print(f.read())
            except OSError as e:
                print(f"guide: cannot read {guide}: {e}", file=sys.stderr)

    def action_fix_permissions(self):
        """One-click repair for the startup-permission gap (issue #76).

        The launchd-autostarted tray cannot answer macOS admin prompts
        itself, so the fix opens a Terminal window running
        `router.py elevate install` — the one command that may prompt.
        The tray only reports that it handed off; the terminal session owns
        the dialog and its outcome."""
        opened = _launch_terminal(Path(self.client.root), ["elevate", "install"])
        with self.lock:
            self.last_action_result = (
                "permission repair: follow the Terminal window"
                if opened else "permission repair: no terminal available")
        self._dashboard_update_action(self.last_action_result)
        self._refresh_menu()

    def action_quit(self):
        # Quit = stop the engine AND leave the tray (Tailscale/WARP-style):
        # the engine must not keep serving after the user quits the tray.
        # Issue #60: quit used to race the per-click daemon threads — the
        # tray could vanish while a mutation was still running. Quit now
        # stops ACCEPTING mutations first, then waits (bounded) for any
        # in-flight mutation to finish before stopping the engine, so an
        # interrupted connect/rotate can never strand half-applied state.
        # Make the acceptance barrier atomic with _do(): no mutation can pass
        # its check after Quit starts waiting for the queue to drain.
        with self._action_accept_lock:
            if self.quit_flag.is_set() or self._quit_pending:
                return
            with self.lock:
                self._quit_pending = True

        def worker():
            # Wait (bounded) for any in-flight/queued mutation to drain. Do
            # not stop the engine after the deadline: the accepted mutation may
            # still be reloading/restarting it, so stopping concurrently would
            # recreate the exact late-writer race Quit is meant to prevent.
            with self._idle_cond:
                drained = self._idle_cond.wait_for(
                    self._mutation_idle, timeout=self._drain_timeout)
            if not drained:
                with self.lock:
                    self.last_action_result = (
                        "quit: waiting for active action — retry when it finishes")
                self._dashboard_update_action(self.last_action_result)
                with self._action_accept_lock:
                    with self.lock:
                        self._quit_pending = False
                self._refresh_menu()
                return
            try:
                rc, out = self.client.stop()
            except Exception as e:
                rc, out = -1, f"{type(e).__name__}: {e}"
            if rc != 0:
                print(f"quit: engine stop failed: {out}", file=sys.stderr)
                # A failed Stop must not strand the user with an invisible,
                # unmanageable engine. Keep the resident tray alive and make
                # the failed Quit retryable. quit_flag was never set, so the
                # existing poller remains resident throughout this recovery.
                detail = _humanize(out)
                with self.lock:
                    self.last_action_result = "quit: failed" + (
                        f" — {detail}" if detail else "")
                self._dashboard_update_action(self.last_action_result)
                with self._action_accept_lock:
                    with self.lock:
                        self._quit_pending = False
                self._refresh_menu()
                return
            with self._action_accept_lock:
                with self.lock:
                    self._quit_pending = False
                self.quit_flag.set()
            self.dashboard.close()
            if self.tray is not None:
                self.tray.stop()

        threading.Thread(target=worker, daemon=True).start()

    # ---- menu -------------------------------------------------------------
    def build_menu(self) -> pystray.Menu:
        with self.lock:
            st = self.latest
            last_action_result = self.last_action_result
            mutation_active = self._mutation_active
        can_disconnect = bool(st.up or st.pid is not None or st.error)
        single_provider_lane = len(st.active_providers) == 1
        items = []

        # Issue #60: while one mutation executes, further engine mutations
        # are coalesced (disabled) instead of racing it inside router.py.
        # The queue keeps clicks; they run after the active job completes.
        if mutation_active and last_action_result:
            items.append(pystray.MenuItem(
                f"{last_action_result} (queued actions run in order)",
                None, enabled=False))

        # Status header — compact, human-readable. A fresh install (no
        # providers, engine never started) gets its own banner instead of a
        # bare "Disconnected" and a first step pointing at Setup.
        first_run = not st.providers and not st.up and not st.error
        if first_run:
            state = "● No VPN set up yet"
        elif st.up and (st.mode != "proxy" or (
                st.system_proxy_status in {"ok", "skipped"}
                and st.network_status in {"ok", "unknown", "skipped"})):
            state = "● Connected"
        elif st.up:
            reason = (st.system_proxy_status
                      if st.system_proxy_status not in {"ok", "skipped"}
                      else st.network_status)
            state = f"▲ Degraded ({reason})"
        elif st.error:
            state = "! Error"
        else:
            state = "○ Disconnected"
        items.append(pystray.MenuItem(state, None))
        if st.network_status == "direct_dns_unavailable":
            items.append(pystray.MenuItem(
                "Recovery: restore DHCP DNS → reload → doctor --network", None,
                enabled=False))
        if first_run:
            items.append(pystray.MenuItem(
                "Start here: Setup → Add a profile (.conf)", None))
        if st.active_providers:
            prov = ", ".join(f"{k} → {v}" for k, v in st.active_providers.items())
            items.append(pystray.MenuItem(prov, None))
        if st.mode in {"proxy", "tun"}:
            items.append(pystray.MenuItem(st.engine_label(), None))
        if st.routing_mode != "default":
            items.append(pystray.MenuItem(
                f"mode: {_ROUTING_MODE_LABELS.get(st.routing_mode, st.routing_mode)}",
                None))
        if st.preset:
            items.append(pystray.MenuItem(
                f"preset: {st.preset}", None))
        if last_action_result and not mutation_active:
            items.append(pystray.MenuItem(
                f"last action: {last_action_result}", None))
        # Issue #76: when the failure was a permission gap, surface the
        # repair right where the error appeared instead of leaving a toast
        # the user cannot act on.
        if _is_permission_error(last_action_result):
            items.append(pystray.MenuItem(
                "Fix Startup Permissions…", self.action_fix_permissions))

        items.append(pystray.Menu.SEPARATOR)

        # The dashboard is the tray's explicit home action. On Darwin the
        # status-button left click calls it directly; on other platforms this
        # entry remains the normal pystray menu action.
        items.append(pystray.MenuItem(
            "Open Dashboard (Terminal setup)", self.action_dashboard, default=True))

        # Actions — terse, no CLI flags. Connect is only offered once at
        # least one provider exists; on a fresh install the banner above
        # directs to Setup instead of producing a raw CLI failure.
        # While a mutation runs, controls render disabled (issue #60) —
        # clicks during that window are coalesced into the queue instead.
        items.append(pystray.MenuItem(
            "Reconnect" if st.up else "Connect",
            self.action_connect, enabled=bool(st.providers)
            and not mutation_active))
        items.append(pystray.MenuItem(
            "Switch VPN server", self.action_rotate,
            enabled=st.up and single_provider_lane and not mutation_active))

        # Provider picker — like Tailscale/Proton: pick a provider, then an exit
        if st.providers and st.up:
            provider_menu = self._build_provider_menu(st)
            items.append(pystray.MenuItem("Provider", provider_menu,
                                          enabled=not mutation_active))
        items.append(pystray.MenuItem(
            "Disconnect", self.action_disconnect,
            enabled=can_disconnect and not mutation_active))
        # Full tunnel (TUN) — checked when on. Clicking toggles it, which on
        # macOS pops the standard admin dialog (the engine/utun needs root).
        items.append(pystray.MenuItem(
            "Full tunnel (TUN): on" if st.mode == "tun"
            else "Full tunnel (TUN): off",
            self.action_toggle_vpn,
            checked=lambda item: st.mode == "tun",
            enabled=not mutation_active))

        items.append(pystray.Menu.SEPARATOR)

        # Routing mode — checked submenu
        def mode_checked(m: str):
            return st.routing_mode == m

        items.append(pystray.MenuItem(
            "Routing mode",
            pystray.Menu(
                pystray.MenuItem("safe-list (home)", lambda: self.action_mode("safe-list"),
                                 checked=lambda item: mode_checked("safe-list")),
                pystray.MenuItem("vpn-list (school)", lambda: self.action_mode("vpn-list"),
                                 checked=lambda item: mode_checked("vpn-list")),
                pystray.MenuItem("default", lambda: self.action_mode("default"),
                                 checked=lambda item: mode_checked("default")),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Use safe-list at home, vpn-list at school",
                                 None, enabled=False),
            ),
            enabled=not mutation_active,
        ))

        # Setup — plain-language entries for non-terminal users. The guide
        # entries answer "where do I even get a .conf file?" before the user
        # hits the import file-picker cold.
        items.append(pystray.MenuItem(
            "Setup",
            pystray.Menu(
                pystray.MenuItem(
                    "New here? .conf files come from your VPN provider's website",
                    None, enabled=False),
                pystray.MenuItem("How to get a Proton profile (guide)",
                                 lambda: self.action_show_guide("proton")),
                pystray.MenuItem("How to get a Cloudflare WARP profile (guide)",
                                 lambda: self.action_show_guide("cloudflare")),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Add Proton profile (.conf)…",
                                 lambda: self.action_import_profile("proton")),
                pystray.MenuItem("Add Cloudflare WARP profile (.conf)…",
                                 lambda: self.action_import_profile("cloudflare")),
                pystray.Menu.SEPARATOR,
                # Issue #76: always discoverable, not only right after a
                # failed click — the autostart permission gap is easy to hit
                # long before anyone opens this menu.
                pystray.MenuItem("Fix Startup Permissions (one-time)…",
                                 self.action_fix_permissions),
            ),
        ))

        # Presets — top-level, one click each, active one checked. Custom
        # presets created in the setup TUI show up here too (read from
        # `presets/*.json`), so the tray never hides a preset the user made.
        preset_items = []
        for name, label in _BUILTIN_PRESETS:
            preset_items.append(pystray.MenuItem(
                label, lambda *_, n=name: self.action_apply_preset(n),
                checked=lambda *_, n=name: st.preset == n))
        for name in self._custom_preset_names():
            preset_items.append(pystray.MenuItem(
                self._custom_preset_label(name),
                lambda *_, n=name: self.action_apply_preset(n),
                checked=lambda *_, n=name: st.preset == n))
        items.append(pystray.MenuItem("Presets", pystray.Menu(*preset_items),
                                      enabled=not mutation_active))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Quit", self.action_quit))
        return pystray.Menu(*items)

    def _custom_preset_signature(self) -> tuple[tuple[str, int, int], ...]:
        """Return a stable filesystem signature for custom preset files."""
        root = getattr(self.client, "root", None)
        if not root:
            return ()
        try:
            entries = []
            for path in Path(root, "presets").glob("*.json"):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                entries.append((path.name, stat.st_mtime_ns, stat.st_size))
            return tuple(sorted(entries))
        except OSError:
            return ()

    def _custom_preset_names(self) -> list[str]:
        """Custom preset names from ``root/presets/*.json`` (read-only)."""
        preset_dir = os.path.join(self.client.root, "presets")
        try:
            return sorted(
                name[:-5] for name in os.listdir(preset_dir)
                if name.endswith(".json") and name[:-5]
            )
        except OSError:
            return []

    def _custom_preset_label(self, name: str) -> str:
        """One-line description for a custom preset, e.g.
        'banana — route opencode.ai via proton (custom)'."""
        try:
            with open(os.path.join(self.client.root, "presets", f"{name}.json"),
                      encoding="utf-8") as f:
                data = json.load(f)
            routes = data.get("routes") or []
            if routes:
                domains = routes[0].get("domains") or []
                provider = routes[0].get("provider") or "?"
                first = domains[0] if domains else "?"
                more = f" +{len(domains) - 1} more" if len(domains) > 1 else ""
                return f"{name} — route {first}{more} via {provider} (custom)"
        except (OSError, json.JSONDecodeError, ValueError, IndexError):
            pass
        return f"{name} (custom)"

    def _exit_disabled(self, st: RouterStatus, name: str, profile: str) -> bool:
        """An exit is un-clickable only when a hard marker is active
        (block/exhaust). Transport-dead exits (offline/SSL) stay clickable
        so a manual switch can try the server and confirm liveness — the
        router probes the new exit after switching and rolls back if dead."""
        rec = (st.providers.get(name, {}).get("egress") or {}).get(profile)
        if not rec:
            return False
        return bool(rec.get("blocked") or rec.get("exhausted"))

    def _exit_try_anyway(self, st: RouterStatus, name: str, profile: str) -> bool:
        """True when the exit died at transport level (no HTTP status, e.g.
        'offline'/'offline (SSL)') but is not hard-marked. Picking it must
        override the probe-failure cooldown (rotate --force) so the user can
        actually attempt the server; the post-switch probe still confirms."""
        rec = (st.providers.get(name, {}).get("egress") or {}).get(profile)
        if not rec:
            return False
        if rec.get("blocked") or rec.get("exhausted"):
            return False
        return rec.get("ok") is False and rec.get("status") is None

    def _build_provider_menu(self, st: RouterStatus) -> pystray.Menu:
        """Provider → exit submenu, checked on the active exit, showing health."""
        entries = []
        for name in sorted(st.providers):
            info = st.providers[name]
            active = info.get("active")
            profiles = info.get("profiles") or []

            def make_exit_action(provider=name, profile=None, force=False):
                def action():
                    self._do(lambda: self.client.rotate_to(provider, profile, force=force),
                             f"switch {provider} → {profile}")
                return action

            def pick_exit_items():
                sub = []
                # Clickable exits first; hard-disabled (blocked/exhausted)
                # last. Transport probe failures stay clickable but quiet.
                def sort_key(p):
                    return (self._exit_disabled(st, name, p),
                            self._exit_try_anyway(st, name, p), p)
                for p in sorted(profiles, key=sort_key):
                    try_anyway = self._exit_try_anyway(st, name, p)
                    label = f"{p}{st.profile_health(name, p)}"
                    sub.append(pystray.MenuItem(
                        label,
                        make_exit_action(provider=name, profile=p, force=try_anyway),
                        checked=lambda item, prof=p: prof == active,
                        enabled=not self._exit_disabled(st, name, p)))
                if not sub:
                    sub.append(pystray.MenuItem("no exits", None, enabled=False))
                return pystray.Menu(*sub)

            def make_cycle_action(provider=name):
                return lambda: self._do(lambda: self.client.rotate(provider),
                                        f"switch {provider}")

            label = st.provider_label(name)
            entries.append(pystray.MenuItem(
                label, pick_exit_items(),
                checked=lambda item, n=name: bool(st.providers.get(n, {}).get("active"))))
            entries.append(pystray.MenuItem(f"↻ switch {name}", make_cycle_action()))
        entries.append(pystray.Menu.SEPARATOR)
        entries.append(pystray.MenuItem("Click a location to switch to it", None, enabled=False))
        return pystray.Menu(*entries)

    def _make_tray_icon(self):
        menu = self.build_menu()
        if _REAL_DARWIN_PYSTRAY:
            if not callable(getattr(pystray.Icon, "_create_menu", None)):
                print("tray: native dashboard unavailable: unsupported pystray",
                      file=sys.stderr)
                return pystray.Icon(
                    "proxy-router", self.icon_image, "proxy-router", menu=menu)
            try:
                return _DarwinDashboardIcon(
                    "proxy-router", self.icon_image, "proxy-router", menu=menu,
                    dashboard_callback=self._show_native_dashboard,
                )
            except Exception as exc:
                print(f"tray: native dashboard unavailable: {exc}", file=sys.stderr)
        return pystray.Icon(
            "proxy-router", self.icon_image, "proxy-router", menu=menu)

    def run(self) -> None:
        if pystray is None:
            print("pystray is required; pip install pystray pillow", file=sys.stderr)
            sys.exit(2)

        # macOS: menu-bar agent, no Dock icon (Tailscale/WARP-style).
        if sys.platform == "darwin":
            try:
                from AppKit import (NSApplication,
                                    NSApplicationActivationPolicyAccessory)
                NSApplication.sharedApplication().setActivationPolicy_(
                    NSApplicationActivationPolicyAccessory)
            except Exception:
                pass

        def on_ready(icon):
            # Custom setup replaces pystray's default setup; explicitly show
            # the status item or the agent runs invisibly on macOS.
            bind = getattr(icon, "_bind_status_button", None)
            if callable(bind):
                bind()
            icon.visible = True
            threading.Thread(target=self.poll_loop, daemon=True,
                             name="tray-status").start()

        self.tray = self._make_tray_icon()
        # NOTE: use blocking run(), NOT run_detached(). On the Darwin backend
        # run_detached() only marks the icon ready and never starts the
        # NSApplication event loop, so the status item is created but never
        # painted and the tray runs invisibly. run() blocks on the main
        # thread driving the Cocoa loop until stop() is called.
        self.tray.run(setup=on_ready)


def _default_root() -> str:
    """Resolve the runtime root for canonical and legacy bundle layouts."""
    override = os.environ.get("PROXY_ROUTER_ROOT")
    if override:
        return override

    here = Path(__file__).resolve().parent
    if (here / "router.py").is_file():
        return str(here)

    # Older checkouts kept the tray under examples/ while router.py lived at
    # the repository root. Keep that layout usable without weakening an
    # explicit --root or PROXY_ROUTER_ROOT override.
    legacy_root = here.parent
    if (legacy_root / "router.py").is_file():
        return str(legacy_root)
    return str(here)


def selftest(root: str) -> int:
    """CLI-contract check: status parses, dispatch targets exist, no GUI."""
    print(f"selftest root: {root}")
    if not os.path.isfile(os.path.join(root, "router.py")):
        print(f"FAIL: router.py not found in {root}")
        return 1
    client = RouterClient(root)
    st = client.status()
    print(f"parsed: up={st.up} mode={st.mode} watcher={st.watcher} "
          f"routing={st.routing_mode} exits={st.active_providers}")
    if st.error:
        print(f"status parse FAIL: {st.error}")
        return 1
    model = DashboardViewModel.from_status(st)
    if model.primary_action not in {"connect", "disconnect", "setup"}:
        print(f"dashboard model FAIL: invalid primary action {model.primary_action!r}")
        return 1
    click_probe = []
    _route_macos_click(
        "left", lambda: click_probe.append("dashboard"),
        lambda: click_probe.append("menu"))
    _route_macos_click(
        "right", lambda: click_probe.append("dashboard"),
        lambda: click_probe.append("menu"))
    if click_probe != ["dashboard", "menu"]:
        print(f"dashboard click routing FAIL: {click_probe}")
        return 1
    print(f"dashboard: model={model.title!r} cocoa={_COCOA_AVAILABLE} "
          "left=window right=menu")
    # verify every menu action's CLI entry exists (--help exits 0)
    for label, args in [
        ("ensure", ["ensure", "--help"]),
        ("stop", ["stop", "--help"]),
        ("rotate", ["rotate", "--help"]),
        ("routing set", ["routing", "set", "--help"]),
        ("vpn", ["vpn", "--help"]),
    ]:
        r, o = client._run(*args)
        status = "OK" if r == 0 else f"FAIL rc={r}"
        print(f"  {label}: {status}")
    print("SELFTEST DONE")
    return 0


def _default_root() -> str:
    override = os.environ.get("PROXY_ROUTER_ROOT")
    if override:
        return override
    here = Path(__file__).resolve().parent
    if (here / "router.py").is_file():
        return str(here)
    parent = here.parent
    if (parent / "router.py").is_file():
        return str(parent)
    return str(here)


def main() -> int:
    ap = argparse.ArgumentParser(description="proxy-router tray agent")
    ap.add_argument("--root", default=_default_root())
    ap.add_argument("--selftest", action="store_true",
                    help="validate CLI contract, no GUI")
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.root)

    if pystray is None or Image is None:
        print("pystray + pillow required (pip install pystray pillow)",
              file=sys.stderr)
        return 2

    client = RouterClient(args.root)
    # Let the first poll publish real state; status can block for COMMAND_TIMEOUT.
    initial_color = _status_icon_color(RouterStatus())
    app = TrayApp(client, make_icon(initial_color))
    app._icon_sig = initial_color
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
