"""#322: state writes reach stable storage before they become visible."""
from __future__ import annotations

import errno
import os

import pytest

import network_control
import state


def test_atomic_write_fsyncs_before_replace(tmp_path, monkeypatch):
    target = tmp_path / "state" / "marker"
    real_fsync, real_replace = os.fsync, os.replace
    order = []

    def watched_fsync(fd):
        order.append("fsync")
        return real_fsync(fd)

    def watched_replace(source, destination):
        order.append("replace")
        return real_replace(source, destination)

    monkeypatch.setattr(state.os, "fsync", watched_fsync)
    monkeypatch.setattr(state.os, "replace", watched_replace)

    state.atomic_write(target, "ready\n", on_commit=lambda path: order.append("commit"))

    assert order == ["fsync", "replace", "commit"]
    assert target.read_text() == "ready\n"


def test_network_write_bytes_fsyncs_before_replace(tmp_path, monkeypatch):
    target = tmp_path / "state" / "marker"
    real_fsync, real_replace = os.fsync, os.replace
    order = []

    def watched_fsync(fd):
        order.append("fsync")
        return real_fsync(fd)

    def watched_replace(source, destination):
        order.append("replace")
        return real_replace(source, destination)

    monkeypatch.setattr(state.os, "fsync", watched_fsync)
    monkeypatch.setattr(state.os, "replace", watched_replace)

    network_control.write_bytes(target, b"ready\n")

    assert order == ["fsync", "replace"]
    assert target.read_bytes() == b"ready\n"


@pytest.mark.parametrize("writer", ["state", "network_control"])
def test_fsync_failure_leaves_previous_file_and_no_commit(tmp_path, monkeypatch, writer):
    target = tmp_path / "marker"
    target.write_text("old")
    committed = []

    def fail_fsync(_fd):
        raise OSError(errno.EIO, "fsync failed")

    monkeypatch.setattr(state.os, "fsync", fail_fsync)
    with pytest.raises(OSError):
        if writer == "state":
            state.atomic_write(target, "new", on_commit=committed.append)
        else:
            network_control.write_bytes(target, b"new")

    assert target.read_text() == "old"
    assert committed == []
    assert [path for path in tmp_path.iterdir() if path != target] == []
