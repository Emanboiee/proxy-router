"""Small, dependency-free primitives for durable router state.

This module is intentionally a leaf.  It knows how to replace a state file
atomically, but it does not know anything about providers, engines, or the
router's module-level configuration.  It imports only the stdlib.  Callers can
supply an ownership callback for platforms where an elevated write must be
handed back to the invoking user.
"""

from __future__ import annotations

import contextlib
import os
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable


def atomic_write(
    path: Path,
    text: str,
    mode: int = 0o600,
    *,
    on_commit: Callable[[Path], None] | None = None,
) -> None:
    """Replace ``path`` with ``text`` without exposing a partial file.

    The temporary file is created beside the destination so ``os.replace``
    remains atomic on the same filesystem.  Its bytes are flushed and fsynced
    before the replacement, so a crash after commit cannot expose an empty or
    partial state file.  ``on_commit`` runs only after the replacement succeeds;
    a failed write never reports a successful state transition to the caller.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
        if on_commit is not None:
            on_commit(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_json(path: Path, default: object | None = None) -> object | None:
    """Read a JSON state value, returning ``default`` for missing/bad data."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return default


def write_json(
    path: Path,
    value: object,
    mode: int = 0o600,
    *,
    on_commit: Callable[[Path], None] | None = None,
) -> None:
    """Serialize ``value`` and persist it through :func:`atomic_write`."""
    atomic_write(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        mode,
        on_commit=on_commit,
    )


def publish_validated(path: Path, text: str, validate: Callable[[Path], bool],
                      mode: int = 0o600,
                      on_commit: Callable[[Path], None] | None = None,
                      publish: Callable[[str], bool] | None = None) -> bool:
    """Write ``text`` to a candidate, validate it, then publish atomically.

    #233: the live path is never exposed to an unvalidated or partially
    written config. OSError (e.g. ENOSPC) propagates like ``atomic_write``;
    the candidate is always removed, and a failed validation returns False
    without touching the live file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = path.with_name(f".{path.name}.candidate")
    try:
        atomic_write(candidate, text, mode)
        if not validate(candidate):
            return False
        # Publish the already-validated bytes. Callers may supply their own
        # writer (router.write_sing_box) to preserve ownership/ENOSPC hooks.
        if publish is not None:
            return bool(publish(text))
        atomic_write(path, text, mode, on_commit=on_commit)
        return True
    finally:
        candidate.unlink(missing_ok=True)


def publish_sing_box(config: dict, live_path: Path, validate: Callable[[Path], bool],
                     on_commit: Callable[[Path], None] | None = None,
                     publish: Callable[[str], None] | None = None) -> bool:
    """#233: validate a generated config as a candidate, then publish it.

    The egress check, candidate write, validation, and publish all happen
    before the live file is touched. False leaves it byte-identical.
    """
    text = json.dumps(config, indent=2) + "\n"
    return publish_validated(live_path, text, validate, on_commit=on_commit,
                             publish=publish)


EVENTS_LOG_MAX_BYTES = 1_000_000
_LOCK_ATTEMPTS = 100
_LOCK_PAUSE_SECONDS = 0.05


@contextlib.contextmanager
def _append_lock(path: Path):
    """Serialize writers with a fixed retry budget, not a clock.

    ``worker_lock.exclusive`` reads ``time.monotonic`` before it tries the
    lock. Recovery callers patch that clock, so log_event needs a lock that
    does not consume their scheduled values. The retry cap still keeps a
    stuck writer from blocking an event for more than about five seconds.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            handle.write("0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            for _ in range(_LOCK_ATTEMPTS):
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(_LOCK_PAUSE_SECONDS)
            else:
                raise OSError("event log lock busy")
        yield
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


def log_event(root: Path, kind: str, **fields) -> None:
    """Append one bounded, secret-free lifecycle event (#184 item 1).

    JSONL at ``<root>/state/events.jsonl``: kind, epoch, caller-supplied
    fields (reason, duration_seconds, provider, config revision...). Appends
    hold an exclusive lock against other writers and keep the file at 0600.
    Best effort: a failing write is reported to stderr and never raises, so
    event logging cannot break the action it describes. Bounded by truncation
    from the oldest half once the file passes EVENTS_LOG_MAX_BYTES.
    """
    path = Path(root) / "state" / "events.jsonl"
    event = {"kind": str(kind), "at": int(time.time())}
    event.update({key: value for key, value in fields.items() if value is not None})
    line = json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # One lock per log: trimming and appending share the same writer, so
        # two processes cannot interleave halves of a JSON line.
        with _append_lock(path.with_suffix(".lock")):
            try:
                if path.is_file() and path.stat().st_size > EVENTS_LOG_MAX_BYTES:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    keep = lines[len(lines) // 2:]
                    path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
            except OSError:
                pass  # bounding is best effort; the append below still tries
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            os.chmod(path, 0o600)
    except OSError as exc:
        print(f"router: event log write failed ({kind}): {exc}", file=sys.stderr)
