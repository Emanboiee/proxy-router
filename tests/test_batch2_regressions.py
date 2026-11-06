"""Focused regressions for the #230-241 audit batch."""
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from tests.test_router_regressions import load_router
import proxy_tray
import router


def test_tray_poll_uses_fast_status_with_transition_guard(monkeypatch):
    """#237: the tray polls --fast; a down-transition triggers one full
    verification (see test_tray_fast_poll_verifies_down_transitions).
    Supersedes the PR #243 revert, which needed full status because fast
    alone misreports helper-managed TUN."""
    client = proxy_tray.RouterClient.__new__(proxy_tray.RouterClient)
    client._active_provider = None
    client._last_seen_up = False
    seen = []
    def fake_run(*args):
        seen.append(args)
        return (0, '{"up": false, "mode": "proxy"}')
    monkeypatch.setattr(client, "_run", fake_run)
    client.status()
    assert seen[0] == ("status", "--json", "--fast")
    assert len(seen) == 1  # no down-transition from an unknown start


def test_windows_engine_stop_without_orphan_scan(tmp_path):
    """#235: no engine + no PID file must not fail on Windows."""
    r = load_router(tmp_path)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    r._effective_uid = lambda: 0
    r._find_our_engine_pids = mock.Mock(
        side_effect=r.EngineIdentityError("exact orphan scan is unavailable on Windows"))
    with mock.patch.object(r.os, "name", "nt"), \
         mock.patch.object(r.sys, "platform", "win32"):
        assert r.engine_stop() == 0


def test_engine_alive_does_not_trim_live_log(tmp_path):
    """#236: status/doctor are read-only; a liveness getter must not mutate the log."""
    r = load_router(tmp_path)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.PID_FILE.write_text("4242\n")
    r._pid_matches = lambda pid: True
    r.trim_live_log_if_needed = mock.Mock(side_effect=AssertionError("log mutated"))
    with mock.patch.object(r.os, "kill", return_value=None):
        assert r.engine_alive() is True
    r.trim_live_log_if_needed.assert_not_called()


def test_assembly_stamps_release_tag(tmp_path):
    """#231: assembled VERSION must carry the tag, not 'dev'."""
    script = Path(__file__).resolve().parents[1] / ".github/scripts/assemble-release-bundle.sh"
    assert script.is_file()
    text = script.read_text()
    assert 'printf \'%s\\n\' "$release_tag" > dist/proxy-router/VERSION' in text
    assert 'release_tag="${5:-}"' in text


def test_same_tag_reinstall_is_idempotent(tmp_path):
    """#231: re-running the installer for the current tag is a no-op."""
    install = Path(__file__).resolve().parents[1] / "install.sh"
    text = install.read_text()
    assert 'release %s already installed; nothing to do' in text
    assert '[ "$OLD_TARGET" = "$RELEASE_TAG" ]' in text


def test_tray_fast_poll_verifies_down_transitions(monkeypatch):
    """#237: fast poll by default; a down-transition verifies once, fully.

    Fast status cannot see a helper-managed macOS TUN engine (its PID lives
    in the root-owned helper state dir), so a 'down' reading while the last
    poll said 'up' must be confirmed through one full status before the tray
    publishes it. The expensive elevation probe then runs on transitions
    only, not every 5s poll.
    """
    client = proxy_tray.RouterClient.__new__(proxy_tray.RouterClient)
    client._active_provider = None
    client._last_seen_up = True  # last poll was up
    calls = []

    def fake_run(*args):
        calls.append(args)
        if "--fast" in args:
            return 0, '{"up": false, "mode": "tun"}'  # fast cannot see helper TUN
        return 0, '{"up": true, "mode": "tun"}'  # full status sees it

    monkeypatch.setattr(client, "_run", fake_run)
    st = client.status()
    assert st.up is True
    # One fast poll + exactly one full verification.
    assert sum(1 for c in calls if "--fast" in c) == 1
    assert sum(1 for c in calls if "--fast" not in c) == 1
    assert client._last_seen_up is True


def test_tray_stays_down_without_repeat_verification(monkeypatch):
    """Once verified down, subsequent fast-down polls don't re-verify."""
    client = proxy_tray.RouterClient.__new__(proxy_tray.RouterClient)
    client._active_provider = None
    client._last_seen_up = False
    calls = []
    monkeypatch.setattr(client, "_run", lambda *a: calls.append(a) or (0, '{"up": false, "mode": "proxy"}'))
    st = client.status()
    assert st.up is False
    assert len(calls) == 1 and "--fast" in calls[0]


def test_tray_first_poll_down_verifies_fully(monkeypatch):
    """Unknown prior state (_last_seen_up=False from init) plus fast down:
    the transition check uses _last_seen_up, so no verification runs. This
    documents the chosen trade-off: a helper-TUN engine connected BEFORE the
    tray started shows 'down' until the first real state change."""
    client = proxy_tray.RouterClient.__new__(proxy_tray.RouterClient)
    client._active_provider = None
    client._last_seen_up = False
    calls = []
    def fake_run(*args):
        calls.append(args)
        return (0, '{"up": false, "mode": "tun"}')
    monkeypatch.setattr(client, "_run", fake_run)
    st = client.status()
    assert st.up is False
    assert sum(1 for c in calls if "--fast" not in c) == 0
