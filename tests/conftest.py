"""Fail-closed pytest safety guards for proxy-router tests."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from typing import Any

import pytest

from tests.safety import (
    classify_command,
    compare_host_snapshots,
    find_new_descendants,
    get_session_registry,
    normalize_lsof_listener_owners,
    normalize_scutil_proxy,
    normalize_service_proxy_outputs,
    parse_process_tree,
    validate_signal_target,
)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "safety_guard: verifies the fail-closed test safety layer"
    )


_ORIGINAL_SUBPROCESS = {
    "Popen": subprocess.Popen,
    "run": subprocess.run,
    "check_call": subprocess.check_call,
    "check_output": subprocess.check_output,
    "call": subprocess.call,
}
_ORIGINAL_OS = {
    name: getattr(os, name)
    for name in (
        "system", "kill", "killpg", "fork", "forkpty", "posix_spawn", "posix_spawnp",
        "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
        "spawnvp", "spawnvpe",
    )
    if hasattr(os, name)
}
_DIRECT_SPAWN_NAMES = tuple(
    name for name in _ORIGINAL_OS
    if name.startswith("fork") or name.startswith("spawn") or name.startswith("posix_spawn")
)

_PRE_EXISTING_PIDS: set[int] = set()
_BASELINE_TREE: dict[int, dict] = {}
_HOST_BASELINE: dict[str, Any] = {}
_GUARD_ATTEMPTS: list[tuple[str, bool, str]] = []
_current_test_nodeid = "unknown"
_expected_guard_attempt = False


def _raw_capture(argv: list[str]) -> tuple[int, str]:
    """Run a reviewed read-only snapshot command through preserved Popen."""
    try:
        proc = _ORIGINAL_SUBPROCESS["Popen"](
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, _ = proc.communicate()
    except OSError:
        return 127, ""
    return int(proc.returncode or 0), stdout


def _raw_process_tree() -> dict[int, dict]:
    _, stdout = _raw_capture(["ps", "-axo", "pid=,ppid=,pgid=,command="])
    return parse_process_tree(stdout)


def _host_snapshot() -> dict[str, Any]:
    """Capture proxy/PAC/WPAD and production-listener ownership read-only."""
    snapshot: dict[str, Any] = {
        "proxy": {},
        "services": {},
        "listener_2080": (),
    }
    if sys.platform == "darwin":
        scutil = shutil.which("scutil") or "/usr/sbin/scutil"
        _, proxy_output = _raw_capture([scutil, "--proxy"])
        snapshot["proxy"] = normalize_scutil_proxy(proxy_output)

        networksetup = shutil.which("networksetup") or "/usr/sbin/networksetup"
        rc, service_output = _raw_capture([networksetup, "-listallnetworkservices"])
        services: dict[str, dict[str, str]] = {}
        if rc == 0:
            for raw_service in service_output.splitlines():
                service = raw_service.strip()
                if not service or service.startswith("An asterisk"):
                    continue
                service = service.lstrip("*").strip()
                outputs = {}
                for namespace, operation in (
                    ("web", "-getwebproxy"),
                    ("secure", "-getsecurewebproxy"),
                    ("pac", "-getautoproxyurl"),
                    ("discovery", "-getproxyautodiscovery"),
                ):
                    query_rc, query_output = _raw_capture(
                        [networksetup, operation, service]
                    )
                    outputs[namespace] = (
                        query_output if query_rc == 0 else f"error:{query_rc}"
                    )
                services[service] = normalize_service_proxy_outputs(outputs)
        snapshot["services"] = dict(sorted(services.items()))

    lsof = shutil.which("lsof") or "/usr/sbin/lsof"
    _, listener_output = _raw_capture([
        lsof, "-nP", "-a", "-iTCP@127.0.0.1:2080", "-sTCP:LISTEN", "-Fpcn",
    ])
    snapshot["listener_2080"] = normalize_lsof_listener_owners(listener_output)
    return snapshot


def _record_guard_attempt(kind: str) -> None:
    _GUARD_ATTEMPTS.append((kind, _expected_guard_attempt, _current_test_nodeid))


def _guard_command(cmd: Any) -> None:
    verdict = classify_command(cmd)
    if not verdict.allowed:
        _record_guard_attempt(f"command:{verdict.reason}")
        raise RuntimeError(f"TEST SAFETY: blocked command {cmd!r}: {verdict.reason}")


def _guarded_popen(cmd: Any, *args: Any, **kwargs: Any) -> subprocess.Popen:
    _guard_command(cmd)
    proc = _ORIGINAL_SUBPROCESS["Popen"](cmd, *args, **kwargs)
    try:
        pgid = os.getpgid(proc.pid) if os.name == "posix" else proc.pid
    except (OSError, ProcessLookupError):
        pgid = proc.pid
    command = [str(part) for part in cmd] if isinstance(cmd, (list, tuple)) else [str(cmd)]
    get_session_registry().register(
        pid=proc.pid,
        pgid=pgid,
        command=command,
        test_id=_current_test_nodeid,
        proc=proc,
    )
    return proc


def _guarded_run(cmd: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
    _guard_command(cmd)
    return _ORIGINAL_SUBPROCESS["run"](cmd, *args, **kwargs)


def _guarded_check_call(cmd: Any, *args: Any, **kwargs: Any) -> int:
    _guard_command(cmd)
    return _ORIGINAL_SUBPROCESS["check_call"](cmd, *args, **kwargs)


def _guarded_check_output(cmd: Any, *args: Any, **kwargs: Any) -> bytes:
    _guard_command(cmd)
    return _ORIGINAL_SUBPROCESS["check_output"](cmd, *args, **kwargs)


def _guarded_call(cmd: Any, *args: Any, **kwargs: Any) -> int:
    _guard_command(cmd)
    return _ORIGINAL_SUBPROCESS["call"](cmd, *args, **kwargs)


def _blocked_direct_spawn(*args: Any, **kwargs: Any) -> int:
    del args, kwargs
    _record_guard_attempt("direct-spawn")
    raise RuntimeError(
        "TEST SAFETY: direct os spawn/fork is blocked; use registered subprocess.Popen"
    )


def _blocked_os_system(cmd: str) -> int:
    del cmd
    _record_guard_attempt("os.system")
    raise RuntimeError(
        "TEST SAFETY: os.system is blocked; use registered subprocess.Popen"
    )


def _guarded_os_kill(pid: int, sig: int) -> None:
    verdict = validate_signal_target(pid)
    if not verdict.allowed:
        _record_guard_attempt(f"signal:{verdict.reason}")
        raise RuntimeError(f"TEST SAFETY: blocked signal to PID {pid}: {verdict.reason}")
    _ORIGINAL_OS["kill"](pid, sig)


def _guarded_os_killpg(pgid: int, sig: int) -> None:
    verdict = validate_signal_target(-pgid)
    if not verdict.allowed:
        _record_guard_attempt(f"signal-group:{verdict.reason}")
        raise RuntimeError(f"TEST SAFETY: blocked killpg to PGID {pgid}: {verdict.reason}")
    if "killpg" in _ORIGINAL_OS:
        _ORIGINAL_OS["killpg"](pgid, sig)
    else:
        _ORIGINAL_OS["kill"](-pgid, sig)


@pytest.fixture(autouse=True, scope="session")
def _install_safety_guards():
    global _BASELINE_TREE, _HOST_BASELINE, _PRE_EXISTING_PIDS
    _BASELINE_TREE = _raw_process_tree()
    _PRE_EXISTING_PIDS = set(_BASELINE_TREE)
    _HOST_BASELINE = _host_snapshot()

    subprocess.Popen = _guarded_popen  # type: ignore[assignment]
    subprocess.run = _guarded_run  # type: ignore[assignment]
    subprocess.check_call = _guarded_check_call  # type: ignore[assignment]
    subprocess.check_output = _guarded_check_output  # type: ignore[assignment]
    subprocess.call = _guarded_call  # type: ignore[assignment]
    os.system = _blocked_os_system  # type: ignore[assignment]
    os.kill = _guarded_os_kill  # type: ignore[assignment]
    if "killpg" in _ORIGINAL_OS:
        os.killpg = _guarded_os_killpg  # type: ignore[assignment]
    for name in _DIRECT_SPAWN_NAMES:
        setattr(os, name, _blocked_direct_spawn)

    yield

    for name, original in _ORIGINAL_SUBPROCESS.items():
        setattr(subprocess, name, original)
    for name, original in _ORIGINAL_OS.items():
        setattr(os, name, original)


@pytest.fixture(autouse=True)
def _per_test_child_cleanup(request):
    global _current_test_nodeid, _expected_guard_attempt
    previous = _current_test_nodeid
    previous_expected = _expected_guard_attempt
    _current_test_nodeid = request.node.nodeid
    _expected_guard_attempt = request.node.get_closest_marker("safety_guard") is not None
    try:
        yield
    finally:
        test_id = request.node.nodeid
        _current_test_nodeid = previous
        _expected_guard_attempt = previous_expected
        registry = get_session_registry()
        live = []
        protected = []
        for child in registry.children_for_test(test_id):
            try:
                if registry.cleanup_child(
                    child,
                    pytest_pgid=os.getpgrp(),
                    baseline_pids=_PRE_EXISTING_PIDS,
                ):
                    live.append(child)
            except RuntimeError:
                protected.append(child)
        if live or protected:
            details = [child.pid for child in [*live, *protected]]
            pytest.fail(
                f"TEST SAFETY: test {test_id!r} left live/protected child PID(s): {details}"
            )


@pytest.fixture
def safety_nodeid(request) -> str:
    """Expose the exact registry ownership key to focused safety tests."""
    return request.node.nodeid


def pytest_sessionfinish(session, exitstatus):
    del exitstatus
    registry = get_session_registry()
    live_registered = []
    protected_registered = []
    for child in registry.all_children():
        try:
            if registry.cleanup_child(
                child,
                pytest_pgid=os.getpgrp(),
                baseline_pids=_PRE_EXISTING_PIDS,
            ):
                live_registered.append(child.pid)
        except RuntimeError:
            protected_registered.append(child.pid)

    current = _raw_process_tree()
    descendants = find_new_descendants(os.getpid(), current, _PRE_EXISTING_PIDS)
    descendants = {
        pid for pid in descendants
        if "ps -axo pid=,ppid=,pgid=,command=" not in current[pid].get("command", "")
    }

    strict = (
        os.environ.get("CI", "").lower() in {"1", "true", "yes"}
        or os.environ.get("PROXY_ROUTER_STRICT_HOST_INVARIANTS") == "1"
    )
    unexpected_attempts = [
        (kind, nodeid)
        for kind, expected, nodeid in _GUARD_ATTEMPTS
        if not expected
    ]
    host_comparison = compare_host_snapshots(
        _HOST_BASELINE,
        _host_snapshot(),
        guard_attempts=[kind for kind, _ in unexpected_attempts],
        strict=strict,
    )

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if host_comparison.status == "environment_changed" and reporter is not None:
        reporter.write_line(
            "TEST SAFETY environment changed in categories "
            f"{list(host_comparison.changed)}; rerun during a quiet window before claiming verification",
            yellow=True,
        )

    if (live_registered or protected_registered or descendants
            or host_comparison.status in {"guard_violation", "failed"}):
        message = (
            "TEST SAFETY session backstop: "
            f"live_registered={live_registered}, "
            f"protected_registered={protected_registered}, "
            f"unregistered_descendants={sorted(descendants)}, "
            f"host_status={host_comparison.status}, "
            f"host_changed={list(host_comparison.changed)}, "
            f"unexpected_guard_attempts={len(unexpected_attempts)}, "
            f"unexpected_guard_nodes={sorted({nodeid for _, nodeid in unexpected_attempts})}"
        )
        if reporter is not None:
            reporter.write_line(message, red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
