"""#236 acceptance: read-only commands never mutate the live engine log.

With an oversized log containing a tail FATAL, status/doctor reads must
leave log bytes, mtime and inode unchanged; bounding happens only in
engine_start's rotation path.
"""
import os
import stat
from unittest import mock

from tests.test_router_regressions import load_router

FATAL_LOG = ("x" * 4096 + "\n") * 2000 + "FATAL: engine crashed\n"


def _seed_log(r):
    r.LOG_DIR.mkdir(parents=True, exist_ok=True)
    r.LOG_FILE.write_text(FATAL_LOG)
    before = r.LOG_FILE.stat()
    return (before.st_size, before.st_mtime_ns, before.st_ino)


def test_engine_alive_does_not_mutate_oversized_log(tmp_path):
    r = load_router(tmp_path)
    fingerprint = _seed_log(r)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.PID_FILE.write_text("4242\n")
    r._pid_matches = lambda pid: True
    with mock.patch.object(r.os, "kill", return_value=None):
        assert r.engine_alive() is True
    after = r.LOG_FILE.stat()
    assert (after.st_size, after.st_mtime_ns, after.st_ino) == fingerprint


def test_status_report_does_not_mutate_the_log(tmp_path):
    r = load_router(tmp_path)
    fingerprint = _seed_log(r)
    r.PID_FILE = tmp_path / "sing-box.pid"
    r.PID_FILE.write_text("4242\n")
    r._pid_matches = lambda pid: True
    r.current_mode = lambda: "tun"
    r.engine_mode_consistent = lambda skip_helper=False: True
    with mock.patch.object(r.os, "kill", return_value=None):
        rc, _line = r._status_report(fast=False)
    after = r.LOG_FILE.stat()
    assert (after.st_size, after.st_mtime_ns, after.st_ino) == fingerprint
    assert "trimmed" not in r.LOG_FILE.read_text()


def test_trim_helper_still_exists_for_explicit_use(tmp_path):
    """The trim helper is not deleted - only unreachable from status paths."""
    r = load_router(tmp_path)
    assert callable(r.trim_live_log_if_needed)


# ---------------------------------------------------------------------------
# #233 boot-behavior acceptance: kill between write and validate, and kill
# mid-publish. The merged transactional publish must leave the live config
# validated and candidate-free so the next boot cannot load garbage.
# ---------------------------------------------------------------------------

def test_233_kill_between_write_and_validate_leaves_live_validated(tmp_path):
    from tests.test_router_regressions import load_router
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("ORIGINAL")
    def die(path=None):
        raise KeyboardInterrupt("killed between write and validate")
    r.validate_config = die
    try:
        r.publish_sing_box({"endpoints": [{"type": "wireguard"}]})
    except KeyboardInterrupt:
        pass
    assert r.SING_BOX_CONFIG.read_text() == "ORIGINAL"
    assert not [p for p in tmp_path.iterdir() if "candidate" in p.name]


def test_233_kill_mid_publish_leaves_no_candidate(tmp_path):
    import state as state_module
    from tests.test_router_regressions import load_router
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("ORIGINAL")
    real = state_module.atomic_write
    calls = {"n": 0}
    def kill_on_publish(path, text, mode=0o600, on_commit=None, publish=None):
        calls["n"] += 1
        if calls["n"] == 2:  # the publish write, after validation passed
            raise KeyboardInterrupt("killed mid-publish")
        return real(path, text, mode, on_commit=on_commit)
    with mock.patch.object(r.state, "atomic_write", kill_on_publish):
        try:
            r.publish_sing_box({"endpoints": [{"type": "wireguard"}]})
        except KeyboardInterrupt:
            pass
    # Either the old or the new validated config is on disk; the invariant is
    # that it was validated and no candidate file lingers.
    assert r.SING_BOX_CONFIG.read_text() in ("ORIGINAL", '{"endpoints": [{"type": "wireguard"}]}')
    assert not [p for p in tmp_path.iterdir() if "candidate" in p.name]
