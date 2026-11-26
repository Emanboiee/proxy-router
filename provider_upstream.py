"""On-demand bring-up for proxy-backed providers' local upstreams.

A ``socks5: 127.0.0.1:2181`` entry proves nothing about a running WARP: config
validity is not availability. Without this seam a stopped upstream stays in the
generated config, so every routed request into that lane is refused instead of
taking the provider's fallback chain, and nothing ever brings it back.

This module owns the *policy* (validation, retry guards, state shaping) and
takes its IO as injected callables - a reachability probe, a command runner, an
atomic writer, a clock - so the decisions are testable without a socket, a
spawn, or router state. ``router.py`` keeps thin adapters plus its CLI/status
plumbing.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path
import sys

def probe_tcp(host: str, port: int, timeout: float) -> bool:
    """Default reachability probe: connect_ex on a raw socket.

    No getaddrinfo, so a literal loopback host costs one syscall, and the
    probe needs no name resolution.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def run_command(argv: list[str], *, timeout: int):
    """Default command runner: no shell, captured output, hard timeout."""
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)

DEFAULT_UPSTREAM_TIMEOUT_MS = 250
DEFAULT_ACTIVATE_COOLDOWN_SECONDS = 120
DEFAULT_ACTIVATE_MAX_ATTEMPTS = 2
DEFAULT_ACTIVATE_WINDOW_SECONDS = 600
DEFAULT_ACTIVATE_TIMEOUT_SECONDS = 30
DEFAULT_ACTIVATE_WAIT_SECONDS = 10

# Non-negative numeric knobs a provider may set for activation/upstream IO.
NON_NEGATIVE_KEYS = (
    "activate_cooldown_seconds",
    "activate_max_attempts",
    "activate_window_seconds",
    "activate_wait_seconds",
    "activate_timeout_seconds",
    "upstream_timeout_ms",
)
ARGV_KEYS = ("activate", "deactivate")


def valid_argv(value: object) -> bool:
    """True for a non-empty list of argument strings without control characters.

    argv runs without a shell, so this rejects only what could not be one
    argument at all - not anything shell-flavoured.
    """
    if not isinstance(value, list) or not value:
        return False
    return all(
        isinstance(part, str) and part.strip() and not any(ch in part for ch in "\x00\n\r")
        for part in value
    )


def provider_key_error(entry: dict) -> str | None:
    """Reason a provider's activation/upstream keys are invalid, else None."""
    for key in ARGV_KEYS:
        value = entry.get(key)
        if value is not None and not valid_argv(value):
            return (f"{key} must be a non-empty list of argument strings "
                    "without control characters")
    for key in NON_NEGATIVE_KEYS:
        value = entry.get(key)
        if value is None:
            continue
        try:
            if int(value) < 0:
                raise ValueError
        except (TypeError, ValueError):
            return f"{key} must be a non-negative integer"
    if "upstream_required" in entry and not isinstance(entry["upstream_required"], bool):
        return "upstream_required must be a boolean"
    return None


def number_setting(entry: dict, key: str, default: float, *, floor: float, ceil: float) -> float:
    """Clamp a numeric setting into a usable range (``*_ms`` keys are ms)."""
    try:
        value = float(entry.get(key, default))
    except (TypeError, ValueError):
        value = float(default)
    if key.endswith("_ms"):
        value /= 1000.0
    return max(floor, min(value, ceil))


def int_setting(entry: dict, key: str, default: int) -> int:
    try:
        return max(0, int(entry.get(key, default)))
    except (TypeError, ValueError):
        return default


def attempts_in_window(state: dict, *, now: int, window: int) -> list[int]:
    raw = state.get("attempts", [])
    if not isinstance(raw, list):
        return []
    return [int(t) for t in raw if isinstance(t, (int, float)) and now - t < window]


def guard_reason(state: dict, *, now: int, cooldown: int, cap: int, window: int) -> dict | None:
    """Why an activation attempt must be skipped, or None when it may run.

    Bounded retries mirror the rotation storm guard: a permanently broken
    provider must not fork its command on every keepalive tick.
    """
    last = state.get("last_attempt_at")
    if cooldown > 0 and isinstance(last, (int, float)) and now - int(last) < cooldown:
        return {"reason": "activation cooling down",
                "retry_in_seconds": cooldown - (now - int(last))}
    if cap > 0 and len(attempts_in_window(state, now=now, window=window)) >= cap:
        return {"reason": "activation attempt cap reached"}
    return None


def mark_listening(state: dict, *, now: int) -> dict:
    updated = dict(state)
    updated["activated_at"] = now
    updated["last_error"] = None
    return updated


def record_attempt(state: dict, *, now: int, error: str | None,
                   window: int = DEFAULT_ACTIVATE_WINDOW_SECONDS) -> dict:
    """Fold one attempt into the persisted upstream state."""
    updated = dict(state)
    attempts = attempts_in_window(updated, now=now, window=window)
    attempts.append(now)
    updated["last_attempt_at"] = now
    updated["attempts"] = sorted(attempts)[-10:]
    updated["last_error"] = error
    return updated


class Upstreams:
    """Upstream lifecycle for one router root, with all IO injected."""

    def __init__(self, *, providers: dict, root: Path, write, is_proxy, upstream_of,
                 probe=probe_tcp, runner=None, sleep=time.sleep, now=time.time):
        self._providers = providers
        self._root = Path(root)
        self._write = write
        self._is_proxy = is_proxy
        self._upstream_of = upstream_of
        self._probe = probe
        self._runner = runner or run_command
        self._sleep = sleep
        self._now = now

    def providers(self) -> dict:
        return self._providers

    def entry(self, name: str) -> dict:
        value = self._providers.get(name)
        return value if isinstance(value, dict) else {}

    def state_path(self, name: str) -> Path:
        return self._root / "state" / "upstream" / f"{name}.json"

    def state(self, name: str) -> dict:
        try:
            value = json.loads(self.state_path(name).read_text())
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _save_state(self, name: str, state: dict) -> None:
        path = self.state_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write(path, json.dumps(state, indent=2, sort_keys=True) + "\n", 0o600)

    def listening(self, name: str) -> bool:
        """True when the provider's local upstream accepts a TCP connection.

        An availability probe only: anything that stops us proving it listens
        (refused, timed out, socket layer blocked by a sandbox) means it is not
        usable, and must never take status/ensure down.
        """
        try:
            host, port = self._upstream_of(name)
        except ValueError:
            return False
        timeout = number_setting(self.entry(name), "upstream_timeout_ms",
                                 DEFAULT_UPSTREAM_TIMEOUT_MS, floor=0.05, ceil=5.0)
        try:
            return bool(self._probe(host, port, timeout))
        except (OSError, RuntimeError):
            return False

    def status(self, name: str) -> dict:
        try:
            host, port = self._upstream_of(name)
        except ValueError:
            return {"known": False, "reason": "not a proxy-backed provider"}
        state = self.state(name)
        return {
            "known": True,
            "host": host,
            "port": port,
            "listening": self.listening(name),
            "activated_at": state.get("activated_at"),
            "last_attempt_at": state.get("last_attempt_at"),
            "last_error": state.get("last_error"),
        }

    def argv(self, name: str, key: str) -> list[str] | None:
        value = self.entry(name).get(key)
        return [str(part) for part in value] if valid_argv(value) else None

    def action(self, name: str, key: str) -> dict:
        """Run a provider's configured ``activate``/``deactivate`` argv."""
        argv = self.argv(name, key)
        if argv is None:
            return {"ran": False, "ok": False, "reason": f"no {key} command configured"}
        if self._runner is None:
            return {"ran": False, "ok": False, "reason": "no runner configured"}
        timeout = int_setting(self.entry(name), "activate_timeout_seconds",
                              DEFAULT_ACTIVATE_TIMEOUT_SECONDS)
        try:
            result = self._runner(argv, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - any spawn failure is "did not run"
            return {"ran": True, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
        ok = getattr(result, "returncode", 1) == 0
        detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
        return {"ran": True, "ok": ok, "error": None if ok else (detail[-300:] or "command failed")}

    def _wait(self, name: str) -> bool:
        """Poll until the upstream answers, bounded by poll count.

        Counting polls rather than reading a clock keeps this correct with the
        injected sleep (tests make it instant) and immune to a clock that does
        not advance while the command runs.
        """
        wait = number_setting(self.entry(name), "activate_wait_seconds",
                              DEFAULT_ACTIVATE_WAIT_SECONDS, floor=0.0, ceil=120.0)
        polls = max(1, int(wait / 0.1))
        for index in range(polls):
            if self.listening(name):
                return True
            if index + 1 < polls:
                self._sleep(0.1)
        return self.listening(name)

    def activate(self, name: str, *, force: bool = False) -> dict:
        """Bring the upstream up, guarded by cooldown + per-window attempt cap."""
        if not self._is_proxy(name):
            return {"attempted": False, "ok": False, "listening": False,
                    "reason": "not a proxy-backed provider"}
        if self.listening(name):
            return {"attempted": False, "ok": True, "listening": True,
                    "reason": "upstream already listening"}
        if self.argv(name, "activate") is None:
            return {"attempted": False, "ok": False, "listening": False,
                    "reason": "no activate command configured"}
        entry = self.entry(name)
        cooldown = int_setting(entry, "activate_cooldown_seconds",
                               DEFAULT_ACTIVATE_COOLDOWN_SECONDS)
        cap = int_setting(entry, "activate_max_attempts", DEFAULT_ACTIVATE_MAX_ATTEMPTS)
        window = int_setting(entry, "activate_window_seconds", DEFAULT_ACTIVATE_WINDOW_SECONDS)
        now = int(self._now())
        state = self.state(name)
        if not force:
            skipped = guard_reason(state, now=now, cooldown=cooldown, cap=cap, window=window)
            if skipped:
                return {"attempted": False, "ok": False, "listening": False, **skipped}
        result = self.action(name, "activate")
        state = record_attempt(state, now=now, error=result.get("error"), window=window)
        if result.get("ok") and self._wait(name):
            self._save_state(name, mark_listening(state, now=now))
            return {"attempted": True, "ok": True, "listening": True, "error": None}
        self._save_state(name, state)
        if not result.get("ran"):
            return {"attempted": False, "ok": False, "listening": False,
                    "reason": result.get("reason")}
        return {"attempted": True, "ok": False, "listening": False,
                "error": result.get("error")}

    def deactivate(self, name: str) -> dict:
        """Run the provider's configured ``deactivate`` argv."""
        if not self._is_proxy(name):
            return {"attempted": False, "ok": False, "reason": "not a proxy-backed provider"}
        result = self.action(name, "deactivate")
        if not result.get("ran"):
            return {"attempted": False, "ok": False, "reason": result.get("reason")}
        state = self.state(name)
        state["deactivated_at"] = int(self._now())
        state["last_error"] = result.get("error")
        self._save_state(name, state)
        return {"attempted": True, "ok": bool(result.get("ok")),
                "listening": self.listening(name)}

    def ensure_all_logged(self, err=print) -> list[str]:
        """Activate down upstreams and report each outcome; returns recovered."""
        recovered = []
        for event in self.ensure_all():
            if event["state"] == "activated":
                recovered.append(event["provider"])
                err(f"router: {event['provider']} upstream activated")
            else:
                err(f"router: {event['provider']} upstream still down after "
                    f"activation: {event.get('detail') or 'unknown error'}")
        return recovered

    def ensure_all(self) -> list[dict]:
        """Activate every proxy provider whose upstream is down and configured."""
        events = []
        for name in self._providers:
            if not self._is_proxy(name) or self.listening(name):
                continue
            if self.argv(name, "activate") is None:
                continue
            result = self.activate(name)
            if result.get("listening"):
                events.append({"provider": name, "state": "activated"})
            elif result.get("attempted"):
                events.append({"provider": name, "state": "failed",
                               "detail": result.get("error") or result.get("reason")})
        return events


def register_commands(sub) -> None:
    """Add the ``provider`` subcommands to the router's argparse tree."""
    provider = sub.add_parser(
        "provider", help="on-demand upstream control for a proxy-backed provider")
    provider_sub = provider.add_subparsers(dest="provider_action")
    activate = provider_sub.add_parser(
        "activate",
        help="run the provider's configured activate command until its upstream listens")
    activate.add_argument("name")
    activate.add_argument("--force", action="store_true",
                          help="ignore the cooldown and attempt cap")
    activate.add_argument("--json", action="store_true", help="machine-readable JSON")
    deactivate = provider_sub.add_parser(
        "deactivate", help="run the provider's configured deactivate command")
    deactivate.add_argument("name")
    deactivate.add_argument("--json", action="store_true", help="machine-readable JSON")
    upstream = provider_sub.add_parser(
        "upstream", help="report the provider's local upstream reachability")
    upstream.add_argument("name", nargs="?", default=None)
    upstream.add_argument("--json", action="store_true", help="machine-readable JSON")
    upstream.add_argument("--ensure", action="store_true",
                          help="activate when the upstream is down (self-heal)")


def run_cli(args, upstreams, *, is_proxy, out=print, err=print) -> int:
    """Handle ``router.py provider <action>``; returns the process exit code."""
    action = getattr(args, "provider_action", None)
    if action in ("activate", "deactivate"):
        result = (upstreams.activate(args.name, force=args.force) if action == "activate"
                  else upstreams.deactivate(args.name))
        if args.json:
            out(json.dumps(result, indent=2, sort_keys=True))
        else:
            state = "listening" if result.get("listening") else "down"
            detail = result.get("error") or result.get("reason") or ""
            out(f"router: {args.name} upstream {state}" + (f" ({detail})" if detail else ""))
        if action == "activate":
            return 0 if result.get("listening") else 1
        return 0 if result.get("ok") else 1
    if action == "upstream":
        if args.name and not is_proxy(args.name):
            err(f"router: provider '{args.name}' is not proxy-backed (no local upstream)")
            return 1
        selected = [args.name] if args.name else [
            name for name in upstreams.providers() if is_proxy(name)]
        if not selected:
            err("router: no proxy-backed providers are configured")
            return 1
        reports = {}
        for name in selected:
            report = upstreams.status(name)
            if args.ensure and report.get("known") and not report.get("listening"):
                activation = upstreams.activate(name)
                if activation.get("listening"):
                    report["listening"] = True
                report["activation"] = activation
            reports[name] = report
        if args.json:
            out(json.dumps(reports, indent=2, sort_keys=True))
        else:
            for name, report in reports.items():
                state = "listening" if report.get("listening") else "DOWN"
                line = (f"router: {name} upstream "
                        f"{report.get('host')}:{report.get('port')} {state}")
                if report.get("last_error"):
                    line += f" | last error: {report['last_error']}"
                out(line)
        return 0 if all(r.get("listening") for r in reports.values()) else 1
    err("router: provider needs an action: activate | deactivate | upstream")
    return 2


def reachable(name: str, providers: dict, root, write, upstream_of) -> bool:
    """Probe one upstream with the caller's adapters, without router state."""
    return Upstreams(
        providers=providers, root=root, write=write, is_proxy=lambda n: n in providers,
        upstream_of=upstream_of).listening(name)


def fail(message: str) -> int:
    """Shared error line for configuration failures."""
    print(f"router: {message}", file=sys.stderr)
    return 1


def response_event_marker(root, provider: str) -> Path:
    """Path for one provider's recorded response event."""
    return Path(root) / "state" / "response-events" / f"{provider}.json"


def proxy_profile_key(stem: str) -> Path:
    """Synthetic egress key for a SOCKS5 provider health record."""
    return Path(f"{stem}.conf")
