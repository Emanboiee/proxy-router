"""Test-only safety helpers for proxy-router hermetic tests.

This module provides pure classification, signal validation, child tracking,
and snapshot diff utilities.  It never touches the real network, never signals
any process, and never spawns a subprocess.  All side-effectful operations
(conftest guards) live in ``tests/conftest.py``.
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Preserved originals for use by cleanup helpers (NOT a public escape hatch).
# Accessed via the module-level names; conftest imports them directly.
# ---------------------------------------------------------------------------

_original_os_kill = os.kill
_original_os_killpg = getattr(os, "killpg", None)
_original_os_waitpid = os.waitpid


# ---------------------------------------------------------------------------
# Command classification (shlex-safe, nested-command-aware)
# ---------------------------------------------------------------------------

_SHELL_BASENAMES = frozenset({"bash", "sh", "zsh", "ksh", "csh", "tcsh", "fish"})


@dataclass(frozen=True)
class CommandVerdict:
    allowed: bool
    reason: str


def _normalize_argv(cmd: Any) -> list[str]:
    """Coerce a command into a list of strings for inspection.

    Handles str (split with shlex for shell-safety), list, and tuple inputs.
    """
    if isinstance(cmd, str):
        try:
            return shlex.split(cmd)
        except ValueError:
            # Malformed shell string — fall back to simple split
            return cmd.split()
    if isinstance(cmd, (list, tuple)):
        return [str(c) for c in cmd]
    raise TypeError(f"unsupported command type: {type(cmd)!r}")


def _classify_argv(argv: list[str], depth: int = 0) -> CommandVerdict:
    if depth > 8:
        return CommandVerdict(False, "shell command nesting exceeds safety limit")
    if not argv:
        return CommandVerdict(True, "empty command")

    # Fail closed with a read-only allowlist. networksetup has many mutators
    # that do not begin with `-set` (for example `-adddnsservers`). Wrappers
    # such as env/nice/nohup cannot hide the executable because every token is
    # inspected for the real basename.
    networksetup_indexes = [
        index for index, token in enumerate(argv)
        if os.path.basename(token) == "networksetup"
    ]
    for index in networksetup_indexes:
        operation = next(
            (token for token in argv[index + 1:] if token.startswith("-")),
            None,
        )
        if operation is None:
            continue
        if operation.startswith(("-get", "-list")) or operation in {"-h", "--help", "-help"}:
            continue
        return CommandVerdict(False, f"non-read-only networksetup operation: {operation}")

    if (any("route_watcher" in token for token in argv)
            and any("--worker" in token for token in argv)):
        return CommandVerdict(False, "route-watcher worker spawn blocked")

    # Recursively inspect every shell `-c` payload. This covers nested shells
    # and prefixed forms such as `env bash -c ...`.
    shell_payload_indexes: set[int] = set()
    for index, token in enumerate(argv):
        if os.path.basename(token) not in _SHELL_BASENAMES:
            continue
        for flag_index in range(index + 1, len(argv)):
            if argv[flag_index] not in {"-c", "--command"}:
                continue
            if flag_index + 1 >= len(argv):
                return CommandVerdict(False, "shell command flag has no payload")
            payload_index = flag_index + 1
            shell_payload_indexes.add(payload_index)
            nested = _classify_argv(_normalize_argv(argv[payload_index]), depth + 1)
            if not nested.allowed:
                return CommandVerdict(False, f"nested {nested.reason}")
            break

    # An embedded occurrence outside a parsed shell payload (for example a
    # Python `-c` script) cannot be classified safely, so reject it.
    if any(
        "networksetup" in token
        for index, token in enumerate(argv)
        if index not in shell_payload_indexes and index not in networksetup_indexes
    ):
        return CommandVerdict(False, "embedded networksetup command is not provably read-only")
    return CommandVerdict(True, "allowed command")


def classify_command(cmd: Any) -> CommandVerdict:
    """Classify a command as allowed or blocked for test execution.

    Blocked:
    - Any ``networksetup`` invocation with a ``-set*`` flag (mutating).
    - Route-watcher worker spawns (``route_watcher.py --worker``).
    - Nested variants inside shell strings (``bash -c '...'``).

    Uses ``shlex.split`` so shell-quoted strings are inspected correctly.
    """
    return _classify_argv(_normalize_argv(cmd))


# ---------------------------------------------------------------------------
# Child registry
# ---------------------------------------------------------------------------

@dataclass
class RegisteredChild:
    pid: int
    pgid: int
    command: list[str]
    test_id: str
    proc: subprocess.Popen | None = field(default=None, repr=False)


class ChildRegistry:
    """Thread-safe registry of spawned test children.

    Each registered child stores its PID, PGID, command, owning test ID,
    and the ``Popen`` object (so cleanup can ``communicate()`` and close
    pipes).  The registry never spawns processes itself.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._children: dict[int, RegisteredChild] = {}

    def register(self, *, pid: int, pgid: int, command: list[str],
                 test_id: str, proc: subprocess.Popen | None = None) -> None:
        with self._lock:
            self._children[pid] = RegisteredChild(
                pid=pid, pgid=abs(pgid), command=command, test_id=test_id,
                proc=proc,
            )

    def unregister(self, pid: int) -> RegisteredChild | None:
        with self._lock:
            return self._children.pop(pid, None)

    def is_registered(self, pid: int) -> bool:
        with self._lock:
            return pid in self._children

    def is_pgid_registered(self, pgid: int) -> bool:
        with self._lock:
            return any(c.pgid == pgid for c in self._children.values())

    def children_for_test(self, test_id: str) -> list[RegisteredChild]:
        with self._lock:
            return [c for c in self._children.values() if c.test_id == test_id]

    def all_children(self) -> list[RegisteredChild]:
        with self._lock:
            return list(self._children.values())

    def clear(self) -> list[RegisteredChild]:
        with self._lock:
            children = list(self._children.values())
            self._children.clear()
            return children

    # ------------------------------------------------------------------
    # Cleanup helper — used by conftest teardown and session finalizer.
    # Uses preserved originals so it is never blocked by the guard layer.
    # ------------------------------------------------------------------

    def cleanup_child(self, child: RegisteredChild, *,
                      timeout: float = 3.0,
                      pytest_pgid: int | None = None,
                      baseline_pids: set[int] | None = None) -> bool:
        """Reap *child* cleanly.  Returns True if the child was still alive.

        Distinguishes completed children (unregister silently) from live
        leaks (report, signal, wait, escalate, close pipes).  Never signals
        the current pytest process group.  Only signals the child's private
        registered PGID when pgid != pytest_pgid; otherwise terminates PID.

        If *baseline_pids* contains the child's PID, refuse cleanup before
        any wait or signal operation.  A baseline PID can never be owned by
        this test session.
        """
        import time

        if baseline_pids and child.pid in baseline_pids:
            raise RuntimeError(
                f"TEST SAFETY: refusing to clean protected baseline PID {child.pid}"
            )

        if pytest_pgid is None:
            pytest_pgid = os.getpgrp()

        if self._child_exited(child):
            self.unregister(child.pid)
            self._close_pipes(child)
            return False

        # Group-signal only a proven private process group.  Merely differing
        # from pytest's PGID is insufficient: it could be another shared group.
        private_group = child.pgid == child.pid and child.pgid != pytest_pgid
        if private_group:
            try:
                if _original_os_killpg is not None:
                    _original_os_killpg(child.pgid, signal.SIGTERM)
                else:
                    _original_os_kill(-child.pgid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        else:
            # Cannot group-signal; terminate PID only
            try:
                _original_os_kill(child.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass

        # Wait boundedly with polling — never block forever
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._child_exited(child):
                self.unregister(child.pid)
                self._close_pipes(child)
                return True
            time.sleep(0.05)

        # Timeout — escalate to KILL
        try:
            if private_group and _original_os_killpg is not None:
                _original_os_killpg(child.pgid, signal.SIGKILL)
            else:
                _original_os_kill(child.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        if child.proc is not None:
            try:
                child.proc.wait(timeout=1)
            except (ChildProcessError, subprocess.TimeoutExpired):
                pass
        else:
            try:
                _original_os_waitpid(child.pid, 0)
            except ChildProcessError:
                pass

        self.unregister(child.pid)
        self._close_pipes(child)
        return True

    @staticmethod
    def _child_exited(child: RegisteredChild) -> bool:
        if child.proc is not None:
            return child.proc.poll() is not None
        try:
            pid, _ = _original_os_waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            return True
        return pid != 0

    def _close_pipes(self, child: RegisteredChild) -> None:
        """Close any open pipes on the stored Popen object and wait for it
        to finish, preventing ResourceWarning."""
        if child.proc is None:
            return
        for stream in (child.proc.stdin, child.proc.stdout, child.proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        # Ensure the Popen object knows the child has exited
        try:
            child.proc.wait(timeout=1)
        except Exception:
            pass


# Global session-scoped registry shared with conftest.
_session_registry = ChildRegistry()


def get_session_registry() -> ChildRegistry:
    return _session_registry


# ---------------------------------------------------------------------------
# Signal validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignalVerdict:
    allowed: bool
    reason: str


def validate_signal_target(pid: int, *,
                           registry: ChildRegistry | None = None,
                           pytest_pgid: int | None = None,
                           ) -> SignalVerdict:
    """Validate whether a signal target (os.kill / os.killpg) is safe.

    Rules:
    - Negative PID means "signal the process group |pid|".  If that PGID
      equals the current pytest PGID, reject unconditionally.
    - Positive PIDs must be registered in the child registry.
    """
    if pytest_pgid is None:
        pytest_pgid = os.getpgrp()
    if registry is None:
        registry = get_session_registry()

    if pid < 0:
        target_pgid = abs(pid)
        if target_pgid == pytest_pgid:
            return SignalVerdict(
                allowed=False,
                reason=f"rejecting signal to current pytest process group {target_pgid}",
            )
        if registry.is_pgid_registered(target_pgid):
            return SignalVerdict(allowed=True, reason="registered child group")
        return SignalVerdict(
            allowed=False,
            reason=f"unregistered process group {target_pgid}",
        )

    if registry.is_registered(pid):
        return SignalVerdict(allowed=True, reason="registered child")

    return SignalVerdict(
        allowed=False,
        reason=f"unregistered/foreign PID {pid}",
    )


# ---------------------------------------------------------------------------
# Process-tree diff
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessTreeDiff:
    new: set[int]
    removed: set[int]


def parse_process_tree(ps_output: str) -> dict[int, dict]:
    """Parse ``ps -axo pid=,ppid=,pgid=,command=`` output into {pid: info}."""
    tree: dict[int, dict] = {}
    for line in ps_output.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            pgid = int(parts[2])
        except ValueError:
            continue
        tree[pid] = {"pid": pid, "ppid": ppid, "pgid": pgid, "command": parts[3]}
    return tree


def process_tree_diff(baseline: dict[int, dict], current: dict[int, dict]) -> ProcessTreeDiff:
    """Compare two snapshots of {pid: info} dicts and report new/removed PIDs."""
    return ProcessTreeDiff(
        new=set(current) - set(baseline),
        removed=set(baseline) - set(current),
    )


def is_descendant(pid: int, ancestor: int, tree: dict[int, dict]) -> bool:
    """Check whether *pid* is a descendant of *ancestor* by walking ppid."""
    if pid == ancestor:
        return False
    current = pid
    visited: set[int] = set()
    while current in tree and current not in visited:
        visited.add(current)
        ppid = tree[current]["ppid"]
        if ppid == ancestor:
            return True
        current = ppid
    return False


def find_new_descendants(ancestor: int, tree: dict[int, dict],
                         baseline: set[int]) -> set[int]:
    """Find PIDs in *tree* that descend from *ancestor* but not in *baseline*."""
    return {pid for pid in tree
            if pid not in baseline and is_descendant(pid, ancestor, tree)}


# ---------------------------------------------------------------------------
# Proxy snapshot diff
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProxySnapshotDiff:
    changed: set[str]
    baseline: dict[str, str]
    current: dict[str, str]


def proxy_snapshot_diff(baseline: dict[str, str],
                        current: dict[str, str]) -> ProxySnapshotDiff:
    """Field-level comparison of two proxy-scutil snapshots."""
    all_keys = set(baseline) | set(current)
    changed = {k for k in all_keys if baseline.get(k) != current.get(k)}
    return ProxySnapshotDiff(changed=changed, baseline=baseline, current=current)


_SCUTIL_PROXY_FIELDS = frozenset({
    "HTTPEnable", "HTTPProxy", "HTTPPort",
    "HTTPSEnable", "HTTPSProxy", "HTTPSPort",
    "ProxyAutoConfigEnable", "ProxyAutoConfigURLString",
    "ProxyAutoDiscoveryEnable",
    "SOCKSEnable", "SOCKSProxy", "SOCKSPort",
})


def normalize_scutil_proxy(output: str) -> dict[str, str]:
    """Normalize stable proxy/PAC/WPAD fields from ``scutil --proxy``."""
    normalized: dict[str, str] = {}
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, value = (part.strip() for part in raw_line.split(":", 1))
        if key in _SCUTIL_PROXY_FIELDS:
            normalized[key] = value
    return dict(sorted(normalized.items()))


def normalize_service_proxy_outputs(outputs: dict[str, str]) -> dict[str, str]:
    """Namespace and normalize read-only ``networksetup -get*`` output."""
    normalized: dict[str, str] = {}
    for namespace, output in sorted(outputs.items()):
        for raw_line in output.splitlines():
            if ":" not in raw_line:
                continue
            key, value = raw_line.split(":", 1)
            stable_key = "_".join(key.strip().lower().split())
            normalized[f"{namespace}.{stable_key}"] = value.strip().lower()
    return normalized


def normalize_lsof_listener_owners(output: str) -> tuple[tuple[int, str, str], ...]:
    """Normalize ``lsof -Fpcn`` records owning 127.0.0.1:2080."""
    owners: set[tuple[int, str, str]] = set()
    pid: int | None = None
    command = ""
    for line in output.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            try:
                pid = int(value)
            except ValueError:
                pid = None
            command = ""
        elif field == "c":
            command = value
        elif field == "n" and pid is not None and "127.0.0.1:2080" in value:
            owners.add((pid, command, value))
    return tuple(sorted(owners))


@dataclass(frozen=True)
class HostSnapshotComparison:
    status: str
    changed: tuple[str, ...]
    attributed: bool


def compare_host_snapshots(baseline: dict[str, Any], current: dict[str, Any], *,
                           guard_attempts: list[str] | tuple[str, ...] = (),
                           strict: bool = False) -> HostSnapshotComparison:
    """Classify host drift without blaming uncorrelated ambient activity."""
    keys = set(baseline) | set(current)
    changed = tuple(sorted(
        key for key in keys if baseline.get(key) != current.get(key)
    ))
    if guard_attempts:
        return HostSnapshotComparison(
            status="guard_violation",
            changed=changed,
            attributed=bool(changed),
        )
    if changed:
        return HostSnapshotComparison(
            status="failed" if strict else "environment_changed",
            changed=changed,
            attributed=False,
        )
    return HostSnapshotComparison(status="ok", changed=(), attributed=False)
