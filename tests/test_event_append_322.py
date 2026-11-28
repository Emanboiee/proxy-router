"""#322: concurrent lifecycle events keep every line and stay private."""
from __future__ import annotations

import json
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import state


class _SplitWriter:
    """Expose an interleaving window inside a single append."""

    def __init__(self, handle):
        self._handle = handle

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *args):
        return self._handle.__exit__(*args)

    def write(self, text):
        middle = len(text) // 2
        self._handle.write(text[:middle])
        self._handle.flush()
        time.sleep(0.02)
        self._handle.write(text[middle:])

    def __getattr__(self, name):
        return getattr(self._handle, name)


def _slow_event_writes(monkeypatch):
    real_open = Path.open

    def open_with_split(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        return _SplitWriter(handle) if self.name == "events.jsonl" else handle

    monkeypatch.setattr(state.Path, "open", open_with_split)


def test_concurrent_appends_keep_every_line(tmp_path, monkeypatch):
    _slow_event_writes(monkeypatch)
    barrier = threading.Barrier(2, timeout=5)
    total = 12

    def emit(worker):
        barrier.wait()
        for index in range(total):
            state.log_event(tmp_path, "rotation", worker=worker, index=index)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(emit, range(2)))

    path = tmp_path / "state" / "events.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 2 * total
    events = [json.loads(line) for line in lines]
    assert sorted((event["worker"], event["index"]) for event in events) == sorted(
        (worker, index) for worker in range(2) for index in range(total)
    )
    assert all(set(event) == {"kind", "at", "worker", "index"} for event in events)


def test_event_log_is_private(tmp_path):
    state.log_event(tmp_path, "rotation", provider="proton")

    path = tmp_path / "state" / "events.jsonl"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["provider"] == "proton"
