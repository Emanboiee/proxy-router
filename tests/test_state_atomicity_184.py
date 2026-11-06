"""#184: lifecycle state writes must be atomic (no partial/truncated files)."""
import json
import os
import stat
from unittest import mock

from tests.test_router_regressions import load_router


def test_set_mode_write_is_atomic(tmp_path):
    """A crash mid-write must not leave a truncated/partial mode file."""
    r = load_router(tmp_path)
    r.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    r.MODE_FILE.write_text("proxy")
    with mock.patch.object(r.state, "tempfile") as tf:
        # Inject ENOSPC at file creation: the old write_text would leave a
        # partial file only if it truncated; atomic_write never opens the target.
        tf.NamedTemporaryFile.side_effect = OSError(28, "ENOSPC")
        try:
            r.set_mode("tun")
        except OSError:
            pass
    assert r.MODE_FILE.read_text() == "proxy"  # unchanged on failure


def test_set_mode_uses_atomic_helper(tmp_path):
    r = load_router(tmp_path)
    r.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with mock.patch.object(r, "_atomic_write") as aw:
        r.set_mode("tun")
    aw.assert_called_once()
    assert aw.call_args.args[0] == r.MODE_FILE


def test_pid_file_write_survives_enospc(tmp_path):
    """A truncated PID file orphans a running engine; the write must be atomic."""
    r = load_router(tmp_path)
    r.PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    r.PID_FILE.write_text("9999")
    with mock.patch.object(r.state, "tempfile") as tf:
        tf.NamedTemporaryFile.side_effect = OSError(28, "ENOSPC")
        try:
            r._atomic_write(r.PID_FILE, "4242")
        except OSError:
            pass
    assert r.PID_FILE.read_text() == "9999"


def test_set_active_uses_atomic_helper(tmp_path):
    r = load_router(tmp_path)
    profile = tmp_path / "proton-a.conf"
    profile.write_text("x")
    with mock.patch.object(r, "_atomic_write") as aw:
        r.set_active("proton", profile)
    aw.assert_called_once()
    assert aw.call_args.args[0] == tmp_path / "state" / "proton.active"
    assert aw.call_args.args[1] == "proton-a"


def test_manual_off_marker_is_atomic(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "_atomic_write") as aw:
        r._write_manual_off()
    aw.assert_called_once()
    assert aw.call_args.args[0] == r.MANUAL_OFF_FILE
    assert "manual stop" in aw.call_args.args[1]


def test_mode_file_ownership_handed_back(tmp_path):
    """atomic_write's on_commit handles ownership; no separate chmod needed."""
    r = load_router(tmp_path)
    r.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    calls = []
    with mock.patch.object(r.state, "atomic_write",
                           side_effect=lambda path, text, mode, on_commit=None: calls.append(on_commit)):
        r.set_mode("tun")
    assert calls and calls[0] is not None  # on_commit (ownership) supplied
