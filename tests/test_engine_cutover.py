"""E1 PR 2 cutover contract: router keeps signature-identical trampolines that
delegate to engine.py, passing router-owned values at CALL TIME so monkeypatch
sites keep working. These tests fail on base (PR 1) and pass after the cutover.
"""
from pathlib import Path
from unittest import mock

import engine
import router


def test_error_class_is_shared_identity():
    assert router.EngineIdentityError is engine.EngineIdentityError


def test_expected_command_delegates_with_router_values():
    with mock.patch.object(engine, "expected_engine_command", return_value="CMD") as spy, \
         mock.patch.object(router, "resolve_sing_box", return_value="/fake/sing-box") as resolver, \
         mock.patch.object(router, "SING_BOX_CONFIG", "/fake/sing-box.json") as config:
        got = router._expected_engine_command()
    assert got == "CMD"
    # The trampoline must read router globals at CALL TIME, so the patched
    # objects are exactly what reach engine. That is the monkeypatch contract.
    spy.assert_called_once_with(resolver, config)


def test_expected_argv_delegates_with_router_command():
    with mock.patch.object(engine, "expected_engine_argv", return_value=["CMD"]) as spy, \
         mock.patch.object(router, "_expected_engine_command", return_value="CMD"):
        got = router._expected_engine_argv()
    assert got == ["CMD"]
    spy.assert_called_once_with("CMD")


def test_command_is_our_engine_delegates_with_router_argv():
    with mock.patch.object(engine, "command_is_our_engine", return_value=True) as spy, \
         mock.patch.object(router, "_expected_engine_argv", return_value=["CMD"]):
        got = router._command_is_our_engine("CMD")
    assert got is True
    spy.assert_called_once_with("CMD", ["CMD"])


def test_find_pids_delegates_with_full_chain():
    with mock.patch.object(engine, "find_our_engine_pids", return_value=[42]) as spy, \
         mock.patch.object(router, "_expected_engine_argv", return_value=["CMD"]), \
         mock.patch.object(router, "resolve_sing_box", return_value="/fake/sing-box") as resolver, \
         mock.patch.object(router, "_command_is_our_engine", return_value=True) as matcher:
        got = router._find_our_engine_pids()
    assert got == [42]
    spy.assert_called_once_with(["CMD"], resolver, matcher)


def test_pid_matches_delegates_with_full_chain():
    with mock.patch.object(engine, "pid_matches", return_value=True) as spy, \
         mock.patch.object(router, "_expected_engine_command", return_value="CMD"), \
         mock.patch.object(router, "_command_is_our_engine", return_value=True) as matcher:
        got = router._pid_matches(42)
    assert got is True
    spy.assert_called_once_with(42, "CMD", matcher)


def test_terminate_pid_delegates_with_router_matcher():
    with mock.patch.object(engine, "terminate_pid", return_value=True) as spy, \
         mock.patch.object(router, "_pid_matches", return_value=True) as matcher:
        got = router._terminate_pid(42)
    assert got is True
    spy.assert_called_once_with(42, matcher)


def test_engine_in_all_runtime_manifests():
    root = Path(engine.__file__).resolve().parent
    for rel in ("install.sh", "install.ps1", ".github/scripts/assemble-release-bundle.sh",
                ".github/workflows/release.yml"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "engine.py" in text, f"engine.py missing from {rel}"
    install = (root / "install.sh").read_text(encoding="utf-8")
    assert install.count("engine.py") >= 2, "install.sh needs engine.py in both lists"
