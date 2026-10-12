"""Explicit, user-level startup for local SOCKS5 providers.

Startup is saved locally by the provider editor, not imported from routing
presets. Executables run without a shell or inherited root privileges.
"""
from __future__ import annotations

import json
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


def socks_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4) as connection:
            connection.sendall(b"\x05\x01\x00")
            return connection.recv(2) == b"\x05\x00"
    except OSError:
        return False


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


def _warp_status(binary: str, options: dict) -> str:
    try:
        result = subprocess.run([binary, "--json", "status"], **{
            **options, "stdout": subprocess.PIPE}, timeout=3)
        return str(json.loads(result.stdout).get("status", "")) if result.returncode == 0 else ""
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ""


def ensure(root: Path, name: str, host: str, port: int, *, timeout: float = 20) -> bool:
    """Start only an explicitly managed provider; saving/status never calls this."""
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
    with worker_lock.exclusive(root / "state" / f"provider-startup-{name}.lock", timeout=timeout + 2) as lock:
        if os.name != "nt" and os.geteuid() == 0:
            os.fchown(lock.fileno(), root.stat().st_uid, root.stat().st_gid)
        options = _launch_options(root)
        warp = startup["mode"] == "warp"
        binary = _warp_binary(options["env"]) if warp else None
        if warp and not binary:
            raise StartupError("Install and register the official WARP client before using automatic startup")
        if socks_ready(host, port) and (not warp or _warp_status(binary, options) == "Connected"):
            return True
        failure = root / "state" / f"provider-startup-{name}.failure"
        try:
            failed_at = float(failure.read_text())
        except (OSError, ValueError):
            failed_at = 0
        if time.time() - failed_at < 5:
            raise StartupError("Provider startup recently failed; retry in a few seconds")
        deadline = time.monotonic() + timeout
        process = None
        try:
            if warp:
                if host != "127.0.0.1":
                    raise StartupError("WARP local proxy uses 127.0.0.1")
                for args in ([binary, "mode", "proxy"], [binary, "proxy", "port", str(port)], [binary, "connect"]):
                    result = subprocess.run(args, **options, timeout=max(0.1, deadline-time.monotonic()))
                    if result.returncode != 0:
                        raise StartupError("WARP startup failed; check registration and client permissions")
            else:
                args = command_args(startup["command"])
                process = subprocess.Popen(args, **options)
            while time.monotonic() < deadline:
                if socks_ready(host, port) and (not warp or _warp_status(binary, options) == "Connected"):
                    failure.unlink(missing_ok=True)
                    return True
                if process is not None and process.poll() not in {None, 0}:
                    raise StartupError(f"Provider startup exited with code {process.returncode}")
                time.sleep(0.15)
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
            if process is not None and not socks_ready(host, port) and process.poll() is None:
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


def recover_routed(root: Path, name: str, config_path: Path, endpoint) -> dict | None:
    """Recover one active proxy; caller checks engine liveness first."""
    try:
        config = json.loads(config_path.read_text())
        if name in referenced_providers(config):
            host, port = endpoint(name)
            ensure(root, name, host, port)
    except (OSError, ValueError, TimeoutError) as exc:
        return {"detail": f"provider startup failed: {exc}", "dns_ok": None}
    return None
