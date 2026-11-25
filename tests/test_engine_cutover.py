"""E1 PR 2 cutover contract: router keeps signature-identical trampolines that
delegate to engine.py, passing router-owned values at CALL TIME so monkeypatch
sites keep working. These tests fail on base (PR 1) and pass after the cutover.
"""
from pathlib import Path
from unittest import mock

import engine
import router


def test_error_class_is_shared_identity():
    # router callers raise/catch this class; engine raises the moved one.
    # They MUST be the same object or except/catch silently breaks.
    assert router.EngineIdentityError is engine.EngineIdentityError


def test_expected_command_delegates_with_router_values():
    with mock.patch.object(engine, "expected_engine_command", return_value="CMD") as spy, \
         mock.patch.object(router, "resolve_sing_box", return_value="/fake/sing-box"), \
         mock.patch.object(router, "SING_BOX_CONFIG", "/fake/sing-box.json"):
        got = router._expected_engine_command()
    assert got == "CMD"
    spy.assert_called_once_with(router.resolve_sing_box, router.SING_BOX_CONFIG)


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
         mock.patch.object(router, "resolve_sing_box", return_value="/fake/sing-box"), \
         mock.patch.object(router, "_command_is_our_engine", return_value=True):
        got = router._find_our_engine_pids()
    assert got == [42]
    spy.assert_called_once_with(["CMD"], router.resolve_sing_box, router._command_is_our_engine)


def test_pid_matches_delegates_with_full_chain():
    with mock.patch.object(engine, "pid_matches", return_value=True) as spy, \
         mock.patch.object(router, "_expected_engine_command", return_value="CMD"), \
         mock.patch.object(router, "_command_is_our_engine", return_value=True):
        got = router._pid_matches(42)
    assert got is True
    spy.assert_called_once_with(42, "CMD", router._command_is_our_engine)


def test_terminate_pid_delegates_with_router_matcher():
    with mock.patch.object(engine, "terminate_pid", return_value=True) as spy, \
         mock.patch.object(router, "_pid_matches", return_value=True):
        got = router._terminate_pid(42)
    assert got is True
    spy.assert_called_once_with(42, router._pid_matches)


def test_engine_in_all_runtime_manifests():
    root = Path(engine.__file__).resolve().parent
    for rel in ("install.sh", "install.ps1", ".github/scripts/assemble-release-bundle.sh",
                ".github/workflows/release.yml"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "engine.py" in text, f"engine.py missing from {rel}"
    # install.sh has two lists (required-file check + copy list)
    install = (root / "install.sh").read_text(encoding="utf-8")
    assert install.count("engine.py") >= 2, "install.sh needs engine.py in both lists"
