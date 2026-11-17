"""Explicit, user-level startup for local SOCKS5 providers.

Startup is saved locally by the provider editor, not imported from routing
presets. Executables run without a shell or inherited root privileges.
"""
from __future__ import annotations

import json
import math
import contextlib
import tempfile
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path

import worker_lock


class StartupError(ValueError):
    pass


def startup_data(value: object) -> dict:
    if value is None:
        return {"mode": "external"}
    if not isinstance(value, dict) or value.get("mode") not in {"external", "warp", "command"}:
        raise StartupError("Choose external, automatic WARP, or startup command")
    mode = value["mode"]
    if mode != "command":
        return {"mode": mode}
    command = value.get("command")
    if not isinstance(command, str) or not command.strip() or len(command) > 4096:
        raise StartupError("Enter one executable and its arguments")
    try:
        args = command_args(command)
    except ValueError as exc:
        raise StartupError("The startup command has invalid quoting") from exc
    if not args or any(arg in {"|", "||", "&&", ";", "&", ">", ">>", "<"} for arg in args):
        raise StartupError("Use one program and arguments; shell operators are not supported")
    if Path(args[0]).name.lower() in {"sudo", "doas", "runas"}:
        raise StartupError("Startup commands run as your user; configure privileged clients separately")
    return {"mode": mode, "command": command.strip()}


def command_args(command: str) -> list[str]:
    args = shlex.split(command, posix=os.name != "nt")
    return [arg[1:-1] if os.name == "nt" and len(arg) > 1 and arg[0] == arg[-1] == '"' else arg for arg in args]


def socks_ready(host: str, port: int, *, timeout: float = 0.4) -> bool:
    """Check the SOCKS greeting within one connect/write/read budget.

    Issue #225: a successful greeting proves only that a TCP listener answered,
    not that it will carry traffic. Use :func:`socks_connect_result` for usable
    egress evidence; ``socks_ready`` stays as the cheap startup readiness probe.
    """
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=_remaining(deadline)) as connection:
            connection.settimeout(_remaining(deadline))
            connection.sendall(b"\x05\x01\x00")
            connection.settimeout(_remaining(deadline))
            return connection.recv(2) == b"\x05\x00"
    except (OSError, StartupError):
        return False


def socks_connect_result(host: str, port: int, target_host: str, target_port: int = 443,
                         *, timeout: float = 0.8) -> dict:
    """Issue #225: bounded SOCKS5 CONNECT evidence for one upstream.

    Sends the greeting then a CONNECT request for ``target_host:target_port`` and
    classifies the reply. A TCP accept and a valid greeting are NOT enough: a
    listener that replies ``REP=4/5`` (host unreachable / connection refused)
    accepts bytes but cannot carry routed traffic. All socket operations share
    one monotonic deadline, so a blackhole listener is bounded.

    Returns ``{"ok": bool, "code": int | None, "error": str | None}``. ``ok`` is
    True only on ``REP=0x00``. ``code`` is the reply code when one was read.
    """
    result = {"ok": False, "code": None, "error": None}
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        result["error"] = "invalid timeout"
        return result
    deadline = time.monotonic() + float(timeout)
    try:
        with socket.create_connection((host, port), timeout=_remaining(deadline)) as connection:
            connection.settimeout(_remaining(deadline))
            connection.sendall(b"\x05\x01\x00")
            greeting = _recv_exact(connection, 2, deadline)
            if greeting != b"\x05\x00":
                result["error"] = "socks greeting rejected"
                return result
            try:
                host_b = target_host.encode("idna")
            except (UnicodeError, AttributeError):
                result["error"] = "invalid CONNECT target"
                return result
            if not host_b or len(host_b) > 255 or not 0 < int(target_port) <= 65535:
                result["error"] = "invalid CONNECT target"
                return result
            request = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + bytes([
                (target_port >> 8) & 0xFF, target_port & 0xFF])
            connection.settimeout(_remaining(deadline))
            connection.sendall(request)
            reply = _recv_exact(connection, 4, deadline)
            if len(reply) < 2:
                result["error"] = "short CONNECT reply"
                return result
            if reply[0] != 0x05:
                result["error"] = "invalid CONNECT reply version"
                return result
            result["code"] = reply[1]
            if reply[1] == 0x00:
                result["ok"] = True
            else:
                result["error"] = f"socks connect rejected (rep={reply[1]})"
            return result
    except (OSError, StartupError) as exc:
        result["error"] = f"socks connect failed: {type(exc).__name__}"
        return result


def _recv_exact(connection, size: int, deadline: float) -> bytes:
    """Read exactly ``size`` bytes within the shared deadline (CodeRabbit:
    ``recv(n)`` may return fewer than ``n`` bytes, splitting a SOCKS reply)."""
    data = b""
    while len(data) < size:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise StartupError("Provider did not become ready within the startup timeout")
    return remaining


def referenced_providers(config: dict) -> set[str]:
    """Read generated routing only, not unused outbound inventory."""
    result = set()
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"outbound", "final"} and isinstance(item, str):
                    result.add(item)
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(config.get("route", {}))
    return result


def connect_target_for(config: dict, name: str) -> tuple[str, int]:
    """#225: pick a CONNECT target actually routed through ``name``.

    Probing a fixed external host can false-dead a working proxy that only
    permits its configured destinations, which would flip routed traffic to
    direct (an IP leak). Prefer the first concrete domain this provider routes;
    fall back to example.com only when config exposes no routable domain.
    """
    def walk(value):
        if isinstance(value, dict):
            if value.get("outbound") == name:
                for key in ("domain", "domain_suffix", "full_domain"):
                    hosts = value.get(key)
                    if isinstance(hosts, list) and hosts and isinstance(hosts[0], str):
                        host = hosts[0].lstrip(".")
                        if host and "." in host and not host.startswith("*"):
                            return host
            for child in value.values():
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found:
                    return found
        return None
    return (walk(config.get("route", {})) or "example.com", 443)


def _launch_options(root: Path) -> dict:
    env = dict(os.environ)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["PATH"] = os.pathsep.join(filter(None, [env.get("PATH"), "/opt/homebrew/bin", "/usr/local/bin"]))
    options = {"cwd": str(root), "env": env, "stdin": subprocess.DEVNULL,
               "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name != "nt":
        options["start_new_session"] = True
        if os.geteuid() == 0:
            import pwd
            owner = pwd.getpwuid(root.stat().st_uid)
            if owner.pw_uid == 0:
                raise StartupError("Provider startup needs a user-owned runtime directory")
            options.update(user=owner.pw_uid, group=owner.pw_gid, extra_groups=[])
            env = {"PATH": env["PATH"], "HOME": owner.pw_dir,
                   "USER": owner.pw_name, "LOGNAME": owner.pw_name}
            options["env"] = env
    else:
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    return options


def _warp_binary(env: dict) -> str | None:
    binary = shutil.which("warp-cli", path=env["PATH"])
    if binary or os.name != "nt":
        return binary
    installed = Path(env.get("ProgramFiles", r"C:\Program Files")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    return str(installed) if installed.is_file() else None


def _warp_status(binary: str, options: dict, *, timeout: float = 3) -> str:
    try:
        result = subprocess.run([binary, "--json", "status"], **{
            **options, "stdout": subprocess.PIPE}, timeout=timeout)
        return str(json.loads(result.stdout).get("status", "")) if result.returncode == 0 else ""
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ""


def ensure(root: Path, name: str, host: str, port: int, *, timeout: float = 20) -> bool:
    """Bound lock, probes and startup by one deadline; failed-child cleanup adds at most 4s."""
    if not math.isfinite(timeout) or timeout < 0:
        raise StartupError("Provider startup timeout must be finite and nonnegative")
    deadline = time.monotonic() + timeout
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise StartupError("Invalid provider ID")
    try:
        store = json.loads((root / "state/dashboard_profiles.json").read_text())
        startup = startup_data(store.get("providers", {}).get(name, {}).get("startup"))
    except FileNotFoundError:
        return False
    except (OSError, ValueError, AttributeError) as exc:
        raise StartupError("Could not read provider startup settings") from exc
    if startup["mode"] == "external":
        return False
    if host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535:
        raise StartupError("Managed startup requires a local SOCKS5 endpoint")
    with worker_lock.exclusive(root / "state" / f"provider-startup-{name}.lock", timeout=_remaining(deadline)) as lock:
        if os.name != "nt" and os.geteuid() == 0:
            os.fchown(lock.fileno(), root.stat().st_uid, root.stat().st_gid)
        options = _launch_options(root)
        warp = startup["mode"] == "warp"
        binary = _warp_binary(options["env"]) if warp else None
        if warp and not binary:
            raise StartupError("Install and register the official WARP client before using automatic startup")
        def ready() -> bool:
            listening = socks_ready(host, port, timeout=min(0.4, _remaining(deadline)))
            return listening and (not warp or _warp_status(
                binary, options, timeout=min(3, _remaining(deadline))) == "Connected")

        if ready():
            _remaining(deadline)
            return True
        failure = root / "state" / f"provider-startup-{name}.failure"
        try:
            failed_at = float(failure.read_text())
        except (OSError, ValueError):
            failed_at = 0
        if time.time() - failed_at < 5:
            raise StartupError("Provider startup recently failed; retry in a few seconds")
        process = None
        became_ready = False
        try:
            if warp:
                if host != "127.0.0.1":
                    raise StartupError("WARP local proxy uses 127.0.0.1")
                for args in ([binary, "mode", "proxy"], [binary, "proxy", "port", str(port)], [binary, "connect"]):
                    result = subprocess.run(args, **options, timeout=_remaining(deadline))
                    if result.returncode != 0:
                        raise StartupError("WARP startup failed; check registration and client permissions")
            else:
                args = command_args(startup["command"])
                _remaining(deadline)
                process = subprocess.Popen(args, **options)
            while time.monotonic() < deadline:
                if ready():
                    _remaining(deadline)
                    failure.unlink(missing_ok=True)
                    became_ready = True
                    return True
                if process is not None and process.poll() not in {None, 0}:
                    raise StartupError(f"Provider startup exited with code {process.returncode}")
                time.sleep(min(0.15, _remaining(deadline)))
            raise StartupError("Provider did not become ready within the startup timeout")
        except (StartupError, OSError, subprocess.TimeoutExpired) as exc:
            with contextlib.suppress(OSError):
                fd, temporary = tempfile.mkstemp(dir=failure.parent, prefix=".provider-failure-")
                with os.fdopen(fd, "w") as handle:
                    handle.write(str(time.time()))
                os.replace(temporary, failure)
                if os.name != "nt" and os.geteuid() == 0:
                    os.chown(failure, root.stat().st_uid, root.stat().st_gid)
            if isinstance(exc, StartupError):
                raise
            raise StartupError("Could not start provider; check executable, arguments, and permissions") from exc
        finally:
            # Failed foreground launches must not leave an unmanaged orphan.
            if process is not None and not became_ready and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def ensure_routed(root: Path, config: dict, providers: dict, endpoint) -> None:
    """Start managed SOCKS5 providers referenced by generated routing."""
    for name in referenced_providers(config):
        if isinstance(providers.get(name, {}).get("socks5"), dict):
            host, port = endpoint(name)
            ensure(root, name, host, port)


def startup_error(root: Path, config: dict, providers: dict, endpoint) -> str | None:
    try:
        ensure_routed(root, config, providers, endpoint)
    except (OSError, ValueError, TimeoutError) as exc:
        return f"provider startup failed: {exc}"
    return None


def recover_routed(root: Path, name: str, config_path: Path, endpoint,
                   write_record=None) -> dict | None:
    """Recover one active proxy; caller checks engine liveness first.

    Issue #225: a listener that answers TCP and the SOCKS greeting but rejects
    CONNECT cannot carry traffic. Probe CONNECT as well and persist a fresh
    failed egress record through ``write_record(name, record)`` so status
    reports the lane degraded instead of trusting an older green record.
    """
    try:
        config = json.loads(config_path.read_text())
        if name not in referenced_providers(config):
            return None
        host, port = endpoint(name)
        ensure(root, name, host, port)
    except (OSError, ValueError, TimeoutError) as exc:
        return {"detail": f"provider startup failed: {exc}", "dns_ok": None}
    target_host, target_port = connect_target_for(config, name)
    connect = socks_connect_result(host, port, target_host, target_port, timeout=0.8)
    if not connect["ok"]:
        # #225: one bounded retry before a hard dead verdict. A transient
        # rejection (handshake race, single lost reply) must not dead-mark an
        # exit that the next probe would accept — that could drive fail-open
        # to direct and leak the client IP. Mirrors the HTTP probe's retry.
        time.sleep(0.25)
        connect = socks_connect_result(host, port, target_host, target_port, timeout=0.8)
    if not connect["ok"]:
        record = {"ok": False, "checked_at": int(time.time()),
                  "socks_connect_ok": False, "error": connect["error"]}
        if connect["code"] is not None:
            record["socks_connect_code"] = connect["code"]
        if write_record is not None:
            write_record(name, record)
        return record
    return None
