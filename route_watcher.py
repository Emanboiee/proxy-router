#!/usr/bin/env python3
"""Standalone watcher for domains observed through proxy-router.

This process is deliberately independent from Hermes. It tails sing-box's
connection log, records which routed targets are active, attributes current
localhost:2080 clients when macOS exposes them through ``lsof``, and probes a
critical routed domain after it is observed. It rotates the provider only for
persistent destination-specific transport failures.

In proxy mode it can only observe traffic that uses 127.0.0.1:2080. In route-
based TUN mode it can observe routed destinations from sing-box logs even when
applications bypass the proxy; client attribution remains unavailable.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
LOG_FILE_NAME = "sing-box.log"
STATE_DIR_NAME = "state/route-watcher"
PID_NAME = "pid"
ENABLED_NAME = "enabled"
EVENTS_NAME = "events.jsonl"
WORKER_LOG_NAME = "worker.log"
ENGINE_PID_NAME = "sing-box.pid"
DEFAULT_INTERVAL = 2.0
ENGINE_DOWN_GRACE_TICKS = 3
TARGET_IDLE_SECONDS = 60.0
PROBE_EVERY_SECONDS = 10.0
CLIENT_SNAPSHOT_EVERY_SECONDS = 5.0
FAILURE_WINDOW_SECONDS = 60.0
MIN_TRANSPORT_FAILURES = 2
ROTATE_COOLDOWN_SECONDS = 120.0
EVENT_MAX_LINES = 5000
EVENT_MAX_BYTES = 2_000_000
TARGET_RE = re.compile(
    r"(?:inbound connection to|outbound connection to|open connection to)\s+"
    r"(?P<host>[^\s:]+)(?::(?P<port>\d+))?",
    re.IGNORECASE,
)
CLIENT_RE = re.compile(r"inbound connection from\s+(?P<host>[^\s:]+)", re.IGNORECASE)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FAILURE_RE = re.compile(
    r"\b(?:timeout|timed out|connection refused|connection reset|unexpected eof|"
    r"tls|ssl|eof|network is unreachable|no route to host|i/o timeout)\b",
    re.IGNORECASE,
)


def state_dir(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else ROOT) / STATE_DIR_NAME


def pid_file(root: Path | None = None) -> Path:
    return state_dir(root) / PID_NAME


def enabled_file(root: Path | None = None) -> Path:
    return state_dir(root) / ENABLED_NAME


def events_file(root: Path | None = None) -> Path:
    return state_dir(root) / EVENTS_NAME


def worker_log_file(root: Path | None = None) -> Path:
    return state_dir(root) / WORKER_LOG_NAME


def engine_pid_file(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else ROOT) / ENGINE_PID_NAME


def normalize_host(host: str) -> str:
    return host.rstrip(".").lower().strip("[]")


def domain_matches(host: str, domain: str) -> bool:
    host = normalize_host(host)
    domain = normalize_host(domain)
    return host == domain or host.endswith("." + domain)


def parse_line(line: str) -> dict | None:
    """Parse a sing-box connection line without retaining ANSI decoration."""
    clean = ANSI_RE.sub("", line).strip()
    target = TARGET_RE.search(clean)
    if target:
        return {
            "kind": "target",
            "host": normalize_host(target.group("host")),
            "port": int(target.group("port") or 443),
            "failure": bool("open connection to" in clean.lower() and FAILURE_RE.search(clean)),
            "line": clean[-400:],
        }
    client = CLIENT_RE.search(clean)
    if client:
        return {"kind": "client", "source": client.group("host"), "line": clean[-300:]}
    return None


def critical_domains(root: Path) -> tuple[str, ...]:
    """Read all configured routed domains for transparent-mode observation.

    The watcher started as an OpenCode-only guard, but route-based TUN mode
    exists specifically so the router can observe and selectively divert any
    configured target without requiring an app-level proxy setting. Keep the
    fallback for a fresh/partial config so OpenCode remains observable by
    default.
    """
    domains: list[str] = []
    try:
        config = json.loads((Path(root) / "router.json").read_text())
        for route in config.get("routes", []):
            for domain in route.get("domains", []):
                domain = normalize_host(str(domain))
                if domain:
                    domains.append(domain)
    except (OSError, ValueError, TypeError):
        pass
    return tuple(dict.fromkeys(domains or ["opencode.ai"]))


def _owned_pid(root: Path) -> int | None:
    try:
        return int((Path(root) / "sing-box.pid").read_text().strip())
    except (OSError, ValueError):
        return None


def _hand_back_ownership(*paths: Path) -> None:
    """Make root-created watcher markers readable by the invoking user."""
    if os.geteuid() != 0:
        return
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    try:
        owner = (int(uid), int(gid))
    except ValueError:
        return
    for path in paths:
        try:
            os.chown(path, *owner)
        except OSError:
            pass


def client_snapshot(root: Path, runner: Callable = subprocess.run) -> list[dict]:
    """Return current processes with sockets attached to the local proxy.

    ``lsof -F`` is macOS-native and keeps this dependency-free. Command names
    only are persisted; command lines may contain secrets and are never saved.
    """
    if sys.platform != "darwin":
        return []
    try:
        result = runner(
            ["lsof", "-nP", "-a", "-iTCP:2080", "-F", "pcn"],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    owned = _owned_pid(root)
    records: list[dict] = []
    current: dict | None = None
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            if current and current.get("pid") != owned:
                records.append(current)
            try:
                current = {"pid": int(line[1:]), "command": "", "connections": []}
            except ValueError:
                current = None
        elif current is not None and line.startswith("c"):
            current["command"] = line[1:]
        elif current is not None and line.startswith("n"):
            current["connections"].append(line[1:])
    if current and current.get("pid") != owned:
        records.append(current)
    return records


def _rotate_events(path: Path) -> None:
    try:
        if path.stat().st_size < EVENT_MAX_BYTES:
            return
        archive = Path(str(path) + ".1")
        archive.unlink(missing_ok=True)
        path.rename(archive)
    except OSError:
        pass


def append_event(root: Path, event: dict) -> None:
    path = events_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_events(path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass



class RotationGuard:
    """Persistent-failure guard used by the standalone worker."""

    def __init__(self) -> None:
        self.failure_times: dict[str, collections.deque[float]] = {}
        self.last_rotate: dict[str, float] = {}

    def record_transport_failure(self, now: float, target: str = "*") -> bool:
        target = normalize_host(target) or "*"
        failures = self.failure_times.setdefault(target, collections.deque())
        while failures and now - failures[0] > FAILURE_WINDOW_SECONDS:
            failures.popleft()
        failures.append(now)
        if len(failures) < MIN_TRANSPORT_FAILURES:
            return False
        last_rotate = self.last_rotate.get(target, 0.0)
        if last_rotate and now - last_rotate < ROTATE_COOLDOWN_SECONDS:
            failures.clear()
            return False
        self.last_rotate[target] = now
        failures.clear()
        return True


def probe_target(root: Path, host: str, *, runner: Callable = subprocess.run) -> dict:
    """Probe the exact routed target through the local proxy.

    HTTP responses prove the route reached the destination, even 401/429/5xx.
    A curl transport failure (exit code != 0) is the signal used for rotation;
    upstream HTTP errors are recorded but do not cause blind exit churn.
    """
    url = f"https://{host}/zen/v1/models" if domain_matches(host, "opencode.ai") else f"https://{host}/"
    try:
        result = runner(
            ["curl", "--proxy", "http://127.0.0.1:2080", "--noproxy", "",
             "--silent", "--show-error", "--output", "/dev/null",
             "--write-out", "%{http_code}", "--connect-timeout", "4",
             "--max-time", "8", url],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "transport_failure": True, "error": "curl timeout", "host": host}
    except OSError as exc:
        return {"ok": False, "transport_failure": True, "error": type(exc).__name__, "host": host}
    code = (result.stdout or "").strip()
    if result.returncode != 0:
        return {"ok": False, "transport_failure": True, "error": (result.stderr or "curl failed")[-200:], "host": host}
    try:
        status = int(code)
    except ValueError:
        status = 0
    return {
        "ok": 100 <= status < 600,
        "transport_failure": False,
        "status": status,
        "blocked": status in {403, 1010},
        "host": host,
    }


def provider_for_host(root: Path, host: str) -> str | None:
    """Map a failing host to the route provider that serves it.

    Reads router.json's routes (first matching route wins, mirroring
    sing-box rule evaluation) so rotation targets the exit actually carrying
    the failing domain instead of a hardcoded default. Returns None when no
    configured route matches (caller keeps its previous behavior).
    """
    try:
        config = json.loads((Path(root) / "router.json").read_text())
    except (OSError, ValueError, TypeError):
        return None
    normalized = normalize_host(str(host))
    for route in config.get("routes", []):
        for domain in route.get("domains", []):
            if domain_matches(normalized, normalize_host(str(domain))):
                provider = route.get("provider")
                return str(provider) if provider else None
    return None


def rotate_provider(root: Path, provider: str = "proton", *, runner: Callable = subprocess.run) -> dict:
    """Ask proxy-router itself to rotate; Hermes is not involved."""
    try:
        result = runner(
            [sys.executable, str(Path(root) / "router.py"), "rotate", provider,
             "--reason", "timeout"],
            cwd=str(root), capture_output=True, text=True, timeout=50,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"rotated": False, "error": type(exc).__name__}
    return {"rotated": result.returncode == 0, "returncode": result.returncode,
            "output": (result.stderr or result.stdout or "")[-300:]}


def _read_new_lines(path: Path, offset: int) -> tuple[int, list[str]]:
    try:
        size = path.stat().st_size
        if size < offset:
            offset = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            lines = handle.readlines()
            return handle.tell(), lines
    except OSError:
        return offset, []


def worker(root: Path, interval: float = DEFAULT_INTERVAL, *, sleep: Callable = time.sleep) -> int:
    root = Path(root).resolve()
    state_dir(root).mkdir(parents=True, exist_ok=True)
    pid_file(root).write_text(str(os.getpid()), encoding="ascii")
    enabled_file(root).write_text("enabled\n", encoding="ascii")
    os.chmod(pid_file(root), 0o600)
    os.chmod(enabled_file(root), 0o600)
    _hand_back_ownership(pid_file(root), enabled_file(root))
    log_path = root / LOG_FILE_NAME
    offset = log_path.stat().st_size if log_path.exists() else 0
    domains = critical_domains(root)
    last_target: dict[str, float] = {}
    last_probe: dict[str, float] = {}
    clients: list[dict] = []
    clients_at = 0.0
    guard = RotationGuard()
    engine_down_ticks = 0
    try:
        while enabled_file(root).is_file():
            # Grace before exit covers engine_switch's stop/start gap.
            if not engine_pid_alive(root):
                engine_down_ticks += 1
                if engine_down_ticks >= ENGINE_DOWN_GRACE_TICKS:
                    print(f"route-watcher: engine dead for {engine_down_ticks} ticks; exiting", file=sys.stderr)
                    break
            else:
                engine_down_ticks = 0
            # Routes can be added while the watcher is running. Refresh the
            # target set each tick so transparent capture starts observing a
            # newly configured domain without requiring a router restart.
            domains = critical_domains(root)
            offset, lines = _read_new_lines(log_path, offset)
            for line in lines:
                event = parse_line(line)
                if not event:
                    continue
                now = time.monotonic()
                host = event.get("host", "")
                if event["kind"] == "target":
                    is_critical = any(domain_matches(host, d) for d in domains)
                    if now - clients_at >= CLIENT_SNAPSHOT_EVERY_SECONDS:
                        clients = client_snapshot(root)
                        clients_at = now
                    event.update({
                        "critical": is_critical,
                        "observed_at": time.time(),
                        "clients": clients,
                    })
                    append_event(root, event)
                    if is_critical:
                        last_target[host] = now
                        if event.get("failure") and guard.record_transport_failure(now, host):
                            target = provider_for_host(root, host) or "proton"
                            result = rotate_provider(root, target)
                            append_event(root, {"kind": "rotation", "observed_at": time.time(), **result})
                elif event["kind"] == "client":
                    # Client lines are retained only as a bounded observation;
                    # exact app attribution is captured on target events.
                    append_event(root, {**event, "observed_at": time.time()})
            now = time.monotonic()
            for host, seen_at in list(last_target.items()):
                if now - seen_at > TARGET_IDLE_SECONDS or now - last_probe.get(host, 0) < PROBE_EVERY_SECONDS:
                    continue
                last_probe[host] = now
                result = probe_target(root, host)
                append_event(root, {"kind": "probe", "observed_at": time.time(), **result})
                if result.get("transport_failure") and guard.record_transport_failure(now, host):
                    target = provider_for_host(root, host) or "proton"
                    rotation = rotate_provider(root, target)
                    append_event(root, {"kind": "rotation", "observed_at": time.time(), **rotation})
            sleep(max(0.5, float(interval)))
    finally:
        _cleanup_worker_state(root, os.getpid())
    return 0


def _pid_matches(root: Path, pid: int) -> bool:
    """Reject recycled/foreign PIDs before status or stop signals them."""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    command = result.stdout.strip()
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = []
    if argv:
        if "--worker" not in argv:
            return False
        if not any(Path(token).name == Path(__file__).resolve().name for token in argv):
            return False
    else:
        # An unquoted quote in a valid filesystem path can make shlex reject
        # macOS ps output. Keep exact raw identity checks available rather than
        # misclassifying the live worker as stale.
        if not re.search(r"(?:^|\s)--worker(?:\s|$)", command):
            return False
        script_name = re.escape(Path(__file__).resolve().name)
        if not re.search(rf"(?:^|[/\s]){script_name}(?:\s|$)", command):
            return False
    root_value = None
    for index, token in enumerate(argv):
        if token == "--root" and index + 1 < len(argv):
            root_value = argv[index + 1]
            break
        if token.startswith("--root="):
            root_value = token.split("=", 1)[1]
            break
    expected_root = str(Path(root).resolve())
    if root_value is not None and str(Path(root_value).resolve()) == expected_root:
        return True
    # macOS `ps -o command=` joins argv without shell quoting, so a root with
    # spaces is split by shlex. start() always places --interval immediately
    # after --root, giving us an exact raw-command boundary without accepting
    # prefix impostors such as `<root>-foreign`.
    return (
        f"--root {expected_root} --interval " in command
        or f"--root={expected_root} --interval " in command
        or command.endswith(f"--root {expected_root}")
        or command.endswith(f"--root={expected_root}")
    )


def _pid_running(pid: int, root: Path | None = None) -> bool:
    root = Path(root) if root is not None else ROOT
    if not _pid_matches(root, pid):
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def engine_pid_alive(root: Path | None = None) -> bool:
    """True when root/sing-box.pid names a live process.

    The engine may be root-owned (tun mode) while the watcher runs as the
    regular user; PermissionError from kill(0) still means it is alive.
    """
    root = Path(root) if root is not None else ROOT
    try:
        pid = int(engine_pid_file(root).read_text().strip())
    except (OSError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except (ProcessLookupError, OSError):
        return False


def _cleanup_worker_state(root: Path, owner_pid: int) -> None:
    """Remove watcher markers only when they still belong to this worker."""
    try:
        if pid_file(root).read_text().strip() != str(owner_pid):
            return
    except (OSError, ValueError):
        return
    pid_file(root).unlink(missing_ok=True)
    enabled_file(root).unlink(missing_ok=True)


def status(root: Path | None = None) -> dict:
    root = Path(root) if root is not None else ROOT
    try:
        pid = int(pid_file(root).read_text().strip())
    except (OSError, ValueError):
        pid = None
    try:
        mode = (root / "state" / "mode").read_text().strip()
    except OSError:
        mode = "proxy"
    scope = "tun + proxy-observable" if mode == "tun" else "proxy-observable only"
    return {"enabled": enabled_file(root).is_file(), "running": bool(pid and _pid_running(pid, root)), "pid": pid,
            "events": events_file(root).is_file(), "scope": scope, "targets": list(critical_domains(root))}


def start(root: Path | None = None, *, interval: float = DEFAULT_INTERVAL) -> dict:
    root = Path(root) if root is not None else ROOT
    current = status(root)
    if current["running"]:
        return {"started": False, "already_running": True, "pid": current["pid"]}
    state_dir(root).mkdir(parents=True, exist_ok=True)
    # Publish the start intent before spawning so the child cannot observe a
    # missing enable marker and exit during the tiny parent/child race.
    enabled_file(root).write_text("enabled\n", encoding="ascii")
    os.chmod(enabled_file(root), 0o600)
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--root", str(root), "--interval", str(interval)]
    worker_log = worker_log_file(root)
    try:
        log_handle = worker_log.open("ab")
    except OSError:
        log_handle = subprocess.DEVNULL
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=log_handle, start_new_session=True)
    except OSError as exc:
        enabled_file(root).unlink(missing_ok=True)
        if log_handle is not subprocess.DEVNULL:
            log_handle.close()
        return {"started": False, "error": f"{type(exc).__name__}: {exc}"}
    if log_handle is not subprocess.DEVNULL:
        log_handle.close()  # child inherited the fd; the parent must not hold it
    pid_file(root).write_text(str(proc.pid), encoding="ascii")
    os.chmod(pid_file(root), 0o600)
    os.chmod(enabled_file(root), 0o600)
    try:
        os.chmod(worker_log, 0o600)
        _hand_back_ownership(worker_log)
    except OSError:
        pass
    _hand_back_ownership(pid_file(root), enabled_file(root))
    return {"started": True, "pid": proc.pid, "interval": interval, "log": str(worker_log)}


def _wait_until_stopped(pid: int, root: Path, *, timeout: float = 3.0,
                        poll_interval: float = 0.1) -> bool:
    """Wait until *pid* no longer exists with this watcher's full identity."""
    deadline = time.monotonic() + max(0.0, timeout)
    while _pid_running(pid, root):
        now = time.monotonic()
        if now >= deadline:
            return False
        time.sleep(min(max(0.01, poll_interval), deadline - now))
    return True


def stop(root: Path | None = None, *, timeout: float = 3.0,
         poll_interval: float = 0.1) -> dict:
    root = Path(root) if root is not None else ROOT
    try:
        pid = int(pid_file(root).read_text().strip())
    except (OSError, ValueError):
        pid = None
    had_state = pid_file(root).exists() or enabled_file(root).exists()
    if not pid or not _pid_running(pid, root):
        pid_file(root).unlink(missing_ok=True)
        enabled_file(root).unlink(missing_ok=True)
        return {"stopped": True, "pid": pid, "stale": had_state}

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        if _pid_running(pid, root):
            return {
                "stopped": False,
                "pid": pid,
                "error": f"failed to signal watcher: {type(exc).__name__}: {exc}",
            }

    if not _wait_until_stopped(
        pid, root, timeout=timeout, poll_interval=poll_interval,
    ):
        return {
            "stopped": False,
            "pid": pid,
            "error": f"timeout waiting for watcher PID {pid} to stop",
        }

    pid_file(root).unlink(missing_ok=True)
    enabled_file(root).unlink(missing_ok=True)
    return {"stopped": True, "pid": pid, "stale": False}


def main(argv: Iterable[str] | None = None, root: Path | None = None) -> int:
    global ROOT
    if root is not None:
        ROOT = Path(root).resolve()
    parser = argparse.ArgumentParser(prog="proxy-router watcher")
    parser.add_argument("action", nargs="?", choices=["status", "on", "off", "logs"])
    parser.add_argument("--root", default=None)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument("--lines", type=int, default=20)
    parser.add_argument("--worker", action="store_true")
    argv = list(argv) if argv is not None else sys.argv[1:]
    if argv and argv[0] == "watcher":
        argv = argv[1:]
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT
    if args.worker:
        return worker(root, args.interval)
    if args.action in (None, "status"):
        print(json.dumps(status(root), indent=2, sort_keys=True))
        return 0
    if args.action == "on":
        print(json.dumps(start(root, interval=args.interval), indent=2, sort_keys=True))
        return 0
    if args.action == "off":
        result = stop(root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("stopped") else 1
    path = events_file(root)
    if path.is_file():
        try:
            with path.open(encoding="utf-8") as handle:
                print("".join(collections.deque(handle, maxlen=max(1, min(args.lines, 100)))))
        except OSError:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
