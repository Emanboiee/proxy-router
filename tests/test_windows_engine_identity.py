import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def windows_router(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "windows_router", Path(__file__).resolve().parents[1] / "router.py"
    )
    router = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(router)
    monkeypatch.setattr(router, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(router, "resolve_sing_box", lambda: r"C:\Program Files\Router\sing-box.exe")
    monkeypatch.setattr(router, "SING_BOX_CONFIG", r"C:\Users\Gaming PC\router\sing-box.json")
    return router


def test_windows_scan_matches_exact_argv_with_spaces(windows_router, monkeypatch):
    router = windows_router
    command = router.subprocess.list2cmdline(router._expected_engine_argv())
    rows = [
        {"ProcessId": 101, "Name": "sing-box.exe", "CommandLine": command},
        {"ProcessId": 102, "Name": "sing-box.exe", "CommandLine": command + ".evil"},
        {"ProcessId": 103, "Name": "sing-box.exe", "CommandLine": command + " --extra"},
        {"ProcessId": 104, "Name": "other.exe", "CommandLine": command},
    ]
    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps(rows)))
    assert router._find_our_engine_pids() == [101]
    assert router._command_is_our_engine(command)
    assert not router._command_is_our_engine(command.replace("sing-box.json", "foreign.json"))


@pytest.mark.parametrize("stdout,returncode", [
    ("[]", 1), ("not JSON", 0), ("null", 0), ("{}", 0),
    (json.dumps([{"Name": "sing-box.exe", "ProcessId": 101, "CommandLine": None}]), 0),
    (json.dumps([{"Name": "sing-box.exe", "ProcessId": True, "CommandLine": "x"}]), 0),
])
def test_windows_scan_fails_closed(windows_router, monkeypatch, stdout, returncode):
    monkeypatch.setattr(windows_router.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=returncode, stdout=stdout))
    with pytest.raises(windows_router.EngineIdentityError):
        windows_router._find_our_engine_pids()


def test_windows_empty_process_table_is_not_an_orphan(windows_router, monkeypatch):
    monkeypatch.setattr(windows_router.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout="[]"))
    assert windows_router._find_our_engine_pids() == []
