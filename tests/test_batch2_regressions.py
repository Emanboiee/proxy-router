"""Focused regressions for the #230-241 audit batch."""
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from tests.test_router_regressions import load_router
import proxy_tray
import router


def test_tray_poll_uses_fast_status(monkeypatch):
    """#237: the 5s tray poll must not spawn sudo/launchctl probes."""
    client = proxy_tray.RouterClient.__new__(proxy_tray.RouterClient)
    seen = []
    monkeypatch.setattr(client, "_run", lambda *args: (seen.append(args), (0, "{}"))[1])
    client.status()
    assert seen and seen[0] == ("status", "--json", "--fast")


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
