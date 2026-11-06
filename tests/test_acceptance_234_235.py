"""Acceptance evidence for #234 and #235 (fixes merged in #242/#244)."""
from pathlib import Path
from unittest import mock

from tests.test_router_regressions import load_router


def test_234_degraded_reload_boots_the_chosen_candidate(tmp_path, monkeypatch):
    """#234 acceptance: a SIGHUP-timeout restart must use the caller's config,
    not rebuild from stale <name>.active markers."""
    r = load_router(tmp_path)
    chosen = tmp_path / "chosen.conf"
    stale = tmp_path / "stale.conf"
    chosen.write_text("x"); stale.write_text("x")
    r.resolve_sing_box = lambda: Path("/bin/true")
    r.sing_box_at_least = lambda v: True
    # Markers point at STALE; the caller built CHOSEN via active_overrides.
    r.set_active("proton", stale)
    builds = []
    def fake_build(overrides=None):
        builds.append(dict(overrides or {}))
        return ({"endpoints": [{"type": "wireguard"}]}, {"proton": chosen})
    r.build_singbox_config = fake_build
    def fake_publish(config):
        # A real publish leaves the candidate on disk; write_last_good reads it.
        r.SING_BOX_CONFIG.write_text(config and "chosen-config")
        return True
    r.publish_sing_box = fake_publish
    r.validate_config = lambda path=None: True
    # SIGHUP fails to come up...
    monkeypatch.setattr(r, "wait_engine", lambda *a, **k: False)
    # ...then the full restart succeeds.
    monkeypatch.setattr(r, "engine_start", lambda **k: 0)
    monkeypatch.setattr(r.os, "kill", lambda pid, sig: None)
    assert r.engine_reload({"proton": chosen}) == 0
    # The fallback start must NOT have rebuilt from markers: the only build
    # is the caller's chosen config.
    assert len(builds) == 1
    assert r.LAST_GOOD_FILE.exists()  # candidate snapshotted as last-good


def test_234_failed_restart_returns_nonzero(tmp_path, monkeypatch):
    r = load_router(tmp_path)
    chosen = tmp_path / "chosen.conf"
    chosen.write_text("x")
    r.resolve_sing_box = lambda: Path("/bin/true")
    r.sing_box_at_least = lambda v: True
    r.build_singbox_config = lambda overrides=None: ({"endpoints": [{"type": "wireguard"}]}, {"proton": chosen})
    r.publish_sing_box = lambda config: True
    monkeypatch.setattr(r, "wait_engine", lambda *a, **k: False)
    monkeypatch.setattr(r, "engine_start", lambda **k: 1)
    monkeypatch.setattr(r.os, "kill", lambda pid, sig: None)
    r.LAST_GOOD_FILE.write_text("{}")
    assert r.engine_reload({"proton": chosen}) != 0


def test_235_windows_stop_no_pid_file_returns_zero(tmp_path):
    """#235 acceptance: hermetic os.name=nt, no PID file -> engine_stop() == 0."""
    r = load_router(tmp_path)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    r._effective_uid = lambda: 0
    r._find_our_engine_pids = mock.Mock(
        side_effect=r.EngineIdentityError("exact orphan scan is unavailable on Windows"))
    with mock.patch.object(r.os, "name", "nt"), \
         mock.patch.object(r.sys, "platform", "win32"):
        assert r.engine_stop() == 0


def test_235_windows_stop_with_matching_pid_terminates_and_returns_zero(tmp_path):
    r = load_router(tmp_path)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.PID_FILE.write_text("4242\n")
    r.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    r._effective_uid = lambda: 0
    r._pid_matches = lambda pid: True
    terminated = []
    r._terminate_pid = lambda pid: terminated.append(pid) or None
    r._find_our_engine_pids = mock.Mock(
        side_effect=r.EngineIdentityError("exact orphan scan is unavailable on Windows"))
    with mock.patch.object(r.os, "name", "nt"), \
         mock.patch.object(r.sys, "platform", "win32"):
        assert r.engine_stop() == 0
    assert terminated == [4242]
    assert not r.PID_FILE.exists()
