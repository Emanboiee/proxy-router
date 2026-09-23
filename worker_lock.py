"""Cross-process start lock for optional background workers.

A tiny leaf module on purpose: monitor.py and route_watcher.py are both
stdlib-only single files that must stay importable without the engine, and
both need the same short-lived exclusive lock around their check-then-spawn
window so two concurrent ``monitor on`` / ``watcher on`` calls cannot each
spawn a worker and clobber the pid record.

The lock guards only the start/stop transaction, never the worker lifetime.
The lock file is intentionally persistent: unlinking it on release would let
a waiter hold the lock on an orphaned inode while a fresh opener locks a new
file at the same path (the classic unlink-on-release flock race).
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path


@contextlib.contextmanager
def exclusive(path: Path, *, timeout: float = 5.0):
    """Hold an exclusive lock on ``path`` for the duration of the block.

    Raises TimeoutError when another holder does not release within the
    budget. The file's content is never read; it is pure bookkeeping.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            handle.write("0")
            handle.flush()
            handle.seek(0)
            _spin(lambda: _try_nt_lock(handle), timeout, path)
        else:
            import fcntl

            _spin(lambda: _try_flock(handle, fcntl), timeout, path)
        yield handle
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            handle.close()


def _try_flock(handle, fcntl) -> bool:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _try_nt_lock(handle) -> bool:
    import msvcrt

    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def _spin(attempt, timeout: float, path: Path) -> None:
    deadline = time.monotonic() + timeout
    while True:
        if attempt():
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"worker lock busy: {path}")
        time.sleep(0.05)
