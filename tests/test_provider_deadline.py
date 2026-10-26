"""Managed startup spends one wall-clock budget, including readiness probes."""
import contextlib
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import provider_lifecycle as lifecycle


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds

    monkeypatch.setattr(lifecycle, "time", SimpleNamespace(
        monotonic=lambda: now[0], time=lambda: 1000, sleep=sleep))
    return now


def settings(root, mode="command"):
    (root / "state").mkdir()
    (root / "state/dashboard_profiles.json").write_text(json.dumps({
        "providers": {"test": {"startup": {"mode": mode, "command": "fake-proxy"}}}}))


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_or_empty_budget_never_probes_or_launches(tmp_path, monkeypatch, clock, timeout):
    settings(tmp_path)
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a, **k: pytest.fail("extra probe"))
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: pytest.fail("spawn"))
    with pytest.raises(lifecycle.StartupError):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 1234, timeout=timeout)
    assert clock[0] == 0


def test_slow_probes_and_sleeps_share_deadline_without_final_probe(tmp_path, monkeypatch, clock):
    settings(tmp_path)
    probes = []
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: process)

    def probe(*args, timeout):
        probes.append(timeout)
        clock[0] += timeout
        return False

    monkeypatch.setattr(lifecycle, "socks_ready", probe)
    with pytest.raises(lifecycle.StartupError, match="startup timeout"):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 1234, timeout=1)
    assert clock[0] == pytest.approx(1)
    assert probes == pytest.approx([0.4, 0.4, 0.05])
    process.terminate.assert_called_once()
    process.wait.assert_called_once_with(timeout=2)


def test_lock_wait_consumes_startup_budget(tmp_path, monkeypatch, clock):
    settings(tmp_path)
    received = []

    @contextlib.contextmanager
    def lock(path, timeout):
        received.append(timeout)
        clock[0] += 0.8
        yield Mock()

    monkeypatch.setattr(lifecycle.worker_lock, "exclusive", lock)
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a, timeout: received.append(timeout) or True)
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 1234, timeout=1)
    assert received == pytest.approx([1, 0.2])


def test_late_success_does_not_sleep_or_cleanup_probe(tmp_path, monkeypatch, clock):
    settings(tmp_path)
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: process)
    calls = []

    def probe(*args, timeout):
        calls.append(timeout)
        clock[0] += min(timeout, 0.25)
        return len(calls) == 3

    monkeypatch.setattr(lifecycle, "socks_ready", probe)
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 1234, timeout=1)
    assert clock[0] < 1
    assert len(calls) == 3
    process.terminate.assert_not_called()


def test_warp_commands_stop_at_deadline(tmp_path, monkeypatch, clock):
    settings(tmp_path, "warp")
    monkeypatch.setattr(lifecycle, "_warp_binary", lambda env: "fake-warp")
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a, **k: False)
    commands = []

    def run(args, *, timeout, **kwargs):
        commands.append((args, timeout))
        elapsed = min(0.6, timeout)
        clock[0] += elapsed
        if elapsed < 0.6:
            raise subprocess.TimeoutExpired(args, timeout)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(lifecycle.subprocess, "run", run)
    with pytest.raises(lifecycle.StartupError):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 1234, timeout=1)
    assert [args[1] for args, _ in commands] == ["mode", "proxy"]
    assert [timeout for _, timeout in commands] == pytest.approx([1, 0.4])
    assert clock[0] == pytest.approx(1)


def test_socks_connect_write_read_share_one_budget(monkeypatch, clock):
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    connection.sendall.side_effect = lambda data: clock.__setitem__(0, clock[0] + 0.1)
    connection.recv.return_value = b"\x05\x00"

    def connect(address, timeout):
        assert timeout == pytest.approx(0.4)
        clock[0] += 0.2
        return connection

    monkeypatch.setattr(lifecycle.socket, "create_connection", connect)
    assert lifecycle.socks_ready("127.0.0.1", 1234)
    assert [c.args[0] for c in connection.settimeout.call_args_list] == pytest.approx([0.2, 0.1])
