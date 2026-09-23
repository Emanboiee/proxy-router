"""Freshness contracts for the read-only cached network diagnostic."""

from __future__ import annotations

import json
import datetime
from pathlib import Path

import router


def test_cached_network_diagnostic_marks_recent_result_fresh(tmp_path: Path, monkeypatch):
    """A recent ISO timestamp remains usable and reports its age."""
    path = tmp_path / "network-diagnostic.json"
    path.write_text(json.dumps({
        "checked_at": "2026-09-09T12:00:00+00:00",
        "status": "ok",
    }))
    monkeypatch.setattr(router, "NETWORK_DIAGNOSTIC_FILE", path)

    checked = datetime.datetime.fromisoformat("2026-09-09T12:00:00+00:00").timestamp()
    result = router._cached_network_diagnostic(now=checked + 120)

    assert result["stale"] is False
    assert result["age_seconds"] == 120.0
    assert result["status"] == "ok"


def test_cached_network_diagnostic_marks_old_result_stale(tmp_path: Path, monkeypatch):
    """An old green result is retained for context but cannot claim freshness."""
    path = tmp_path / "network-diagnostic.json"
    path.write_text(json.dumps({
        "checked_at": "2026-09-09T12:00:00+00:00",
        "status": "ok",
    }))
    monkeypatch.setattr(router, "NETWORK_DIAGNOSTIC_FILE", path)

    checked = datetime.datetime.fromisoformat("2026-09-09T12:00:00+00:00").timestamp()
    result = router._cached_network_diagnostic(now=checked + 301)

    assert result["stale"] is True
    assert result["age_seconds"] == 301.0


def test_cached_network_diagnostic_treats_bad_timestamp_as_stale(tmp_path: Path, monkeypatch):
    """A malformed timestamp never becomes implicit current health evidence."""
    path = tmp_path / "network-diagnostic.json"
    path.write_text(json.dumps({"checked_at": "not-a-time", "status": "ok"}))
    monkeypatch.setattr(router, "NETWORK_DIAGNOSTIC_FILE", path)

    result = router._cached_network_diagnostic(now=0)

    assert result["stale"] is True
    assert result["age_seconds"] is None
