"""#184 item 2: bounded engine-log retention must report write failures
explicitly instead of silently swallowing them (no retry storm).
"""
import errno
from pathlib import Path
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


def test_rotate_log_unlink_failure_is_reported_not_raised(tmp_path, capsys, monkeypatch):
    """#184 item 2: an OSError while clearing the old archive must be reported,
    never escape. This call runs inside engine_start; an escaped exception
    aborts the engine start it was meant to protect."""
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 20)
    r.LOG_MAX_BYTES = 1

    real_unlink = Path.unlink

    def deny_archive(self, *a, **k):
        if str(self).endswith("sing-box.log.1"):
            raise OSError(errno.EACCES, "Permission denied")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", deny_archive)
    try:
        r.rotate_log_if_needed()
    except OSError as exc:
        raise AssertionError(f"retention error escaped engine_start: {exc}") from exc
    err = capsys.readouterr().err
    assert "log retention failed" in err, err


def test_rotate_log_missing_is_silent(tmp_path, capsys):
    """#184: a first start has no log yet (engine_start creates it with 'ab').
    ENOENT on the size check is legitimate, not a retention failure; printing
    one here is a false failure on every clean first start."""
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "logs" / "sing-box.log"  # intentionally absent
    r.LOG_MAX_BYTES = 1
    r.rotate_log_if_needed()
    assert "log retention failed" not in capsys.readouterr().err


def test_rotate_log_stat_failure_is_reported(tmp_path, capsys, monkeypatch):
    """#184 item 2: a failing size check must not be silently swallowed."""
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 20)
    r.LOG_MAX_BYTES = 1

    def deny_stat(self, *a, **k):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "stat", deny_stat)
    try:
        r.rotate_log_if_needed()
    except OSError as exc:
        raise AssertionError(f"retention error escaped engine_start: {exc}") from exc
    err = capsys.readouterr().err
    assert "log retention failed" in err, err


def test_trim_live_log_success_is_silent(tmp_path, capsys):
    r = load_router(tmp_path)
    r.LOG_FILE = tmp_path / "sing-box.log"
    r.LOG_FILE.write_text("x" * 400)
    r.LOG_MAX_BYTES = 10
    r.trim_live_log_if_needed()
    assert "log retention failed" not in capsys.readouterr().err
