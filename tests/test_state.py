"""Hermetic contracts for the dependency-free state-file leaf."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import state


def test_atomic_write_replaces_content_and_sets_mode(tmp_path: Path):
    target = tmp_path / "state" / "marker"
    state.atomic_write(target, "ready\n", 0o640)

    assert target.read_text() == "ready\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert list(target.parent.glob(".*.tmp")) == []


def test_atomic_write_calls_commit_after_replace(tmp_path: Path):
    target = tmp_path / "marker"
    seen: list[tuple[Path, str]] = []

    state.atomic_write(
        target,
        "new",
        on_commit=lambda path: seen.append((path, path.read_text())),
    )

    assert seen == [(target, "new")]


def test_atomic_write_cleans_temporary_file_when_write_fails(tmp_path: Path, monkeypatch):
    target = tmp_path / "marker"
    real_replace = os.replace

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr(state.os, "replace", fail_replace)
    try:
        state.atomic_write(target, "new")
    except OSError as exc:
        assert str(exc) == "replace failed"
    else:  # pragma: no cover - defensive assertion for the contract
        raise AssertionError("atomic_write unexpectedly succeeded")
    finally:
        monkeypatch.setattr(state.os, "replace", real_replace)

    assert not target.exists()
    assert list(tmp_path.glob(".*.tmp")) == []
