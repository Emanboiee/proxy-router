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
