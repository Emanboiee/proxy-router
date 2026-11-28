"""PR #332 P1: events.jsonl rewrites must be serialized across writers.

``route_watcher.append_event`` trims the line count with a non-atomic
``read_text`` -> ``write_text``. Two watcher processes (start/stop locking only
guards the spawn window) can interleave an append into that window and lose it.
Both the watcher and the router's ``state.log_event`` therefore hold one shared
lock on ``state/events.lock`` around their write sequences.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import route_watcher as watcher
import state


def test_line_cap_rewrite_cannot_clobber_a_concurrent_append(tmp_path, monkeypatch):
    cap = 4
    monkeypatch.setattr(watcher, "EVENT_MAX_LINES", cap)
    path = watcher.events_file(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps({"kind": "old", "n": i}, separators=(",", ":")) + "\n"
            for i in range(cap + 2)
        ),
        encoding="utf-8",
    )

    window = threading.Event()
    started = threading.Event()
    appended = threading.Event()
    fired = threading.Event()
    real_write_text = Path.write_text

    def write_text_with_interleave(self, data, *args, **kwargs):
        if (
            not fired.is_set()
            and self == path
            and isinstance(data, str)
            and data.count("\n") >= cap
        ):
            # Force the other writer into the first trim's read -> write window.
            fired.set()
            window.set()
            assert started.wait(2.0), "second writer never reached the interleave"
            appended.wait(2.0)  # bounded deadline: when both writers hold the
            # shared lock, the append lands after the trim, not inside it.
        return real_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", write_text_with_interleave)

    def second_writer():
        if not window.wait(2.0):
            return
        started.set()
        watcher.append_event(tmp_path, {"kind": "rotation", "marker": "SENTINEL"})
        appended.set()

    writer = threading.Thread(target=second_writer)
    writer.start()
    try:
        watcher.append_event(tmp_path, {"kind": "new", "host": "opencode.ai"})
    finally:
        writer.join(3.0)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert any('"marker":"SENTINEL"' in line for line in lines), lines


def test_log_event_and_watcher_append_share_one_lock(tmp_path):
    assert hasattr(state, "events_lock"), "state.events_lock is missing"
    locked = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def holder():
        with state.events_lock(tmp_path):
            locked.set()
            release.wait(3.0)

    def writer():
        state.log_event(tmp_path, "rotation")
        watcher.append_event(tmp_path, {"kind": "probe"})
        finished.set()

    holder_thread = threading.Thread(target=holder)
    writer_thread = threading.Thread(target=writer)
    holder_thread.start()
    assert locked.wait(2.0)
    writer_thread.start()
    try:
        assert not finished.wait(0.3), "a writer ignored the shared events lock"
    finally:
        release.set()
        writer_thread.join(3.0)
        holder_thread.join(3.0)
    assert finished.is_set()
