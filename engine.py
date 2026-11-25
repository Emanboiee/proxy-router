"""Pure engine-identity helpers extracted from router.py (issue #66 E1).

Leaf module: imports only the standard library. Router-owned values (the
sing-box resolver, config path, and sibling callables) are passed in as
explicit parameters so this module never imports upward. router.py keeps
signature-identical trampolines that read its own globals at call time, which
preserves monkeypatch interception in the existing test suite.

Signatures gained 1-3 typed parameters; bodies are otherwise verbatim from
router.py so behavior is unchanged.
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable


class EngineIdentityError(RuntimeError):
    """The process table could not prove engine identity safely."""


# Cache keyed by the full command string: relocation or a patched resolver
# changes the key, so no stale argv can be served (design B, arena-verified).
_argv_cache: list[str] | None = None
_argv_cache_source: str | None = None


def expected_engine_command(resolve: Callable[[], str | None],
                            config_path: Path | str) -> str | None:
    """Return the exact command line emitted by ``engine_start``."""
    binary = resolve()
    if binary is None:
        return None
    return f"{binary} run -c {config_path}"


def expected_engine_argv(command: str | None) -> list[str] | None:
    """``expected_engine_command()`` split once, not per process-table row."""
    global _argv_cache, _argv_cache_source
    if command is None:
        return None
    if _argv_cache_source != command:
        try:
            _argv_cache = shlex.split(command)
        except ValueError:
            return None
        _argv_cache_source = command
    return _argv_cache


def command_is_our_engine(cmd: str, expected_argv: list[str] | None) -> bool:
    """Return true only for the exact resolved binary/argv command line."""
    if not expected_argv:
        return False
    try:
        return shlex.split(str(cmd).strip()) == expected_argv
    except ValueError:
        return False


def find_our_engine_pids(expected_argv: list[str] | None,
                         resolve: Callable[[], str | None],
                         command_is_ours: Callable[[str], bool]) -> list[int]:
    """Find exact engine processes, including root-owned orphan candidates.

    The PID file is bookkeeping, not identity.  This scan is deliberately
    fail-closed: an unavailable process table cannot be treated as proof that
    no owned engine exists.
    """
    if not expected_argv:
        raise EngineIdentityError("sing-box binary is unavailable; engine identity is unknown")
    engine_binary = expected_argv[0]
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
    raw_engine_binary = resolve() or ""
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
        # Cheap prefilter: only a row carrying the normalized or raw binary
        # can match, so unrelated rows skip shlex entirely.
        if engine_binary not in parts[2] and not (
            raw_engine_binary and raw_engine_binary in parts[2]
        ):
            continue
        if pid > 1 and command_is_ours(parts[2]):
            pids.append(pid)
    return sorted(set(pids))


def pid_matches(pid: int, expected_command: str | None,
                command_is_ours: Callable[[str], bool]) -> bool:
    """True when PID is the exact resolved engine command line."""
    if expected_command is None:
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
            return bool(out) and command_is_ours(out)
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
    return len(parts) == 2 and parts[0].isdigit() and command_is_ours(parts[1])


def terminate_pid(pid: int, matches: Callable[[int], bool]) -> bool:
    """Terminate one PID after verifying its exact engine identity."""
    if not matches(pid):
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            return True
        os.kill(pid, signal.SIGTERM)
        grace_deadline = time.monotonic() + 0.4
        while time.monotonic() < grace_deadline:
            if not matches(pid):
                break
            time.sleep(0.02)
        if matches(pid):
            os.kill(pid, signal.SIGKILL)
            kill_deadline = time.monotonic() + 0.5
            while time.monotonic() < kill_deadline:
                if not matches(pid):
                    break
                time.sleep(0.02)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        raise
