"""Small, dependency-free primitives for durable router state.

This module is intentionally a leaf.  It knows how to replace a state file
atomically, but it does not know anything about providers, engines, or the
router's module-level configuration.  Callers can supply an ownership
callback for platforms where an elevated write must be handed back to the
invoking user.
"""

from __future__ import annotations

import os
import json
import tempfile
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
    remains atomic on the same filesystem.  ``on_commit`` runs only after the
    replacement succeeds; a failed write never reports a successful state
    transition to the caller.
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
