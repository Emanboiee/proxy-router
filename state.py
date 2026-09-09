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
