"""PR #332 P1: two watcher workers must not lose an event to a line-cap trim.

``state/route-watcher/events.jsonl`` has one writer function,
``route_watcher.append_event``. Start/stop locking guards only the spawn
window, so two workers can overlap briefly during cleanup. Its
``_enforce_event_line_cap`` non-atomic read_text -> write_text can then discard
the other worker's append. A local persistent lock serializes the whole append
sequence; ``state.log_event`` writes a different file and is unrelated.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import route_watcher as watcher


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
            appended.wait(2.0)  # bounded deadline: with the lock, the append
            # lands after the trim, not inside it.
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


def test_append_event_holds_the_local_events_lock(tmp_path):
    assert hasattr(watcher, "_events_lock"), "route_watcher._events_lock is missing"
    locked = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def holder():
        with watcher._events_lock(tmp_path):
            locked.set()
            release.wait(3.0)

    def writer():
        watcher.append_event(tmp_path, {"kind": "probe"})
        finished.set()

    holder_thread = threading.Thread(target=holder)
    writer_thread = threading.Thread(target=writer)
    holder_thread.start()
    assert locked.wait(2.0)
    writer_thread.start()
    try:
        assert not finished.wait(0.3), "append_event ignored the events lock"
    finally:
        release.set()
        writer_thread.join(3.0)
        holder_thread.join(3.0)
    assert finished.is_set()
