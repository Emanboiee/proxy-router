"""#184 item 2: bounded engine-log retention must report write failures
explicitly instead of silently swallowing them (no retry storm).
"""
import errno
from unittest import mock

from tests.test_router_regressions import load_router


def test_rotate_log_reports_oserror(tmp_path, capsys, monkeypatch):
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 20)
    r.LOG_MAX_BYTES = 1  # force rotation path
    def no_space(*a, **k):
        raise OSError(errno.ENOSPC, "No space left")
    monkeypatch.setattr(r.os, "chmod", no_space)
    r.rotate_log_if_needed()
    err = capsys.readouterr().err
    assert "log retention failed" in err, err


def test_trim_live_log_reports_oserror(tmp_path, capsys, monkeypatch):
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 400)
    r.LOG_MAX_BYTES = 10  # force trim path
    def no_space(*a, **k):
        raise OSError(errno.ENOSPC, "No space left")
    monkeypatch.setattr(r.os, "chmod", no_space)
    r.trim_live_log_if_needed()
    err = capsys.readouterr().err
    assert "log retention failed" in err, err


def test_rotate_log_success_is_silent(tmp_path, capsys):
    """Council P1: a successful rotation must not print a false failure. After
    rename the live path no longer exists, so chmod-ing it always ENOENTs."""
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 20)
    r.LOG_MAX_BYTES = 1
    r.rotate_log_if_needed()
    assert "log retention failed" not in capsys.readouterr().err
    # the archive exists with the log content
    assert (tmp_path / "sing-box.log.1").read_text() == "x" * 20


def test_trim_live_log_success_is_silent(tmp_path, capsys):
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 400)
    r.LOG_MAX_BYTES = 10
    r.trim_live_log_if_needed()
    assert "log retention failed" not in capsys.readouterr().err
