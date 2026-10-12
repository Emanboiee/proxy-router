import json
import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import provider_lifecycle as lifecycle


def managed(root, startup):
    (root / "state").mkdir(exist_ok=True)
    (root / "state/dashboard_profiles.json").write_text(json.dumps({
        "providers": {"test": {"startup": startup}},
    }))


def test_external_and_presets_never_execute_commands(tmp_path, monkeypatch):
    (tmp_path / "router.json").write_text(json.dumps({
        "providers": {"test": {"startup": {"mode": "command", "command": "bad"}}},
    }))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected spawn"))
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 12345) is False
    managed(tmp_path, {"mode": "external"})
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 12345) is False


@pytest.mark.parametrize("command", ["sudo warp-cli connect", "x | y", "x && y", "", '"unterminated'])
def test_command_validation(command):
    with pytest.raises(lifecycle.StartupError):
        lifecycle.startup_data({"mode": "command", "command": command})


@pytest.mark.enable_socket
@pytest.mark.allow_hosts(["127.0.0.1"])
def test_foreground_proxy_starts_once_and_recovers_after_exit(tmp_path):
    import socket
    from concurrent.futures import ThreadPoolExecutor
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    script = tmp_path / "proxy.py"
    script.write_text("""
import os, socket, sys
from pathlib import Path
Path(sys.argv[2]).write_text(str(os.getpid()))
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', int(sys.argv[1])))
    server.listen()
    while True:
        conn, _ = server.accept()
        with conn:
            if conn.recv(3) == bytes([5,1,0]):
                conn.sendall(bytes([5,0]))
""")
    pidfile = tmp_path / "pid"
    command = shlex.join([sys.executable, str(script), str(port), str(pidfile)])
    managed(tmp_path, {"mode": "command", "command": command})
    pids = []
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(lambda _: lifecycle.ensure(tmp_path, "test", "127.0.0.1", port, timeout=3), range(2))) == [True, True]
        pid = int(pidfile.read_text())
        pids.append(pid)
        assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", port, timeout=3)
        assert int(pidfile.read_text()) == pid
        os.kill(pid, signal.SIGTERM)
        import time
        deadline = time.monotonic() + 2
        while lifecycle.socks_ready("127.0.0.1", port) and time.monotonic() < deadline:
            time.sleep(.02)
        assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", port, timeout=3)
        pids.append(int(pidfile.read_text()))
        assert pids[-1] != pid
    finally:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def test_warp_connects_in_proxy_mode_and_does_not_reconnect_ready_client(tmp_path, monkeypatch):
    managed(tmp_path, {"mode": "warp"})
    commands = []
    ready = False
    monkeypatch.setattr(lifecycle.shutil, "which", lambda *a, **k: "/usr/local/bin/warp-cli")
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a: ready)
    def run(args, **kwargs):
        nonlocal ready
        commands.append(args[1:])
        if args[1:] == ["connect"]:
            ready = True
        return subprocess.CompletedProcess(args, 0, json.dumps({"status": "Connected" if ready else "Disconnected"}).encode())
    monkeypatch.setattr(subprocess, "run", run)
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 2181)
    assert commands[:3] == [["mode", "proxy"], ["proxy", "port", "2181"], ["connect"]]
    commands.clear()
    assert lifecycle.ensure(tmp_path, "test", "127.0.0.1", 2181)
    assert commands == [["--json", "status"]]


def test_only_routed_providers_start(tmp_path, monkeypatch):
    import router
    calls = []
    monkeypatch.setattr(router, "ROOT", tmp_path)
    monkeypatch.setattr(router, "_providers", {
        "used": {"socks5": {"host": "127.0.0.1", "port": 1234}},
        "unused": {"socks5": {"host": "127.0.0.1", "port": 1235}},
    })
    monkeypatch.setattr(lifecycle, "ensure", lambda root, name, host, port: calls.append(name))
    lifecycle.ensure_routed(tmp_path, {
        "outbounds": [{"tag": "used"}, {"tag": "unused"}],
        "route": {"rules": [{"type": "logical", "rules": [{"outbound": "used"}]}], "final": "direct"},
    }, router._providers, router.proxy_upstream)
    assert calls == ["used"]


def test_failed_command_is_bounded_and_does_not_claim_ready(tmp_path, monkeypatch):
    managed(tmp_path, {"mode": "command", "command": shlex.join([sys.executable, "-c", "raise SystemExit(7)"])})
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a: False)
    with pytest.raises(lifecycle.StartupError, match="exited with code 7"):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 12345, timeout=2)


def test_failed_startup_has_short_cooldown(tmp_path, monkeypatch):
    managed(tmp_path, {"mode": "command", "command": "missing-proxy"})
    monkeypatch.setattr(lifecycle, "socks_ready", lambda *a: False)
    calls = []
    def spawn(*a, **k):
        calls.append(a)
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(lifecycle.StartupError, match="Could not start"):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 12345)
    with pytest.raises(lifecycle.StartupError, match="recently failed"):
        lifecycle.ensure(tmp_path, "test", "127.0.0.1", 12345)
    assert len(calls) == 1


@pytest.mark.skipif(os.name == "nt", reason="Unix privilege drop")
def test_root_startup_drops_to_runtime_owner(tmp_path, monkeypatch):
    import pwd
    from types import SimpleNamespace
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=501, pw_gid=20, pw_dir="/Users/test", pw_name="test"))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:2080")
    monkeypatch.setenv("SECRET_TOKEN", "must-not-inherit")
    options = lifecycle._launch_options(tmp_path)
    assert options["user"] == 501 and options["group"] == 20
    assert options["extra_groups"] == []
    assert options["env"]["HOME"] == "/Users/test"
    assert "HTTPS_PROXY" not in options["env"]
    assert "SECRET_TOKEN" not in options["env"]


def test_disconnected_health_checks_never_start_provider(tmp_path, monkeypatch):
    import router
    config = tmp_path / "sing-box.json"
    config.write_text(json.dumps({"route": {"final": "test"}}))
    monkeypatch.setattr(router, "SING_BOX_CONFIG", config)
    monkeypatch.setattr(router, "is_proxy_provider", lambda name: True)
    monkeypatch.setattr(router, "engine_alive", lambda: False)
    monkeypatch.setattr(router, "probe_url_for", lambda name: None)
    monkeypatch.setattr(lifecycle, "ensure", lambda *a, **k: pytest.fail("disconnected startup"))
    assert router.check_egress_live("test", tmp_path / "unused") == ("alive", None)
