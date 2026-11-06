"""#184 item 1: structured lifecycle events with reason/provider/context."""
import json
from unittest import mock

from tests.test_router_regressions import load_router
import state


def _events(tmp_path):
    path = tmp_path / "state" / "events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_rotation_event_records_provider_and_profile(tmp_path):
    r = load_router(tmp_path)
    profile = tmp_path / "proton-a.conf"
    profile.write_text("x")
    r.record_rotation("proton", profile)
    events = _events(tmp_path)
    assert any(e["kind"] == "rotation" and e["provider"] == "proton"
               and e["profile"] == "proton-a" and "at" in e for e in events)


def test_fallback_activation_event_carries_reason(tmp_path):
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"]}, "proton": {}}
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda p: None
    conf = tmp_path / "proton.conf"
    conf.write_text("x")
    r.provider_files = lambda n: [conf] if n == "proton" else []
    assert r.activate_fallback("warp", target="proton") == 0
    events = _events(tmp_path)
    assert any(e["kind"] == "fallback_activated" and e["provider"] == "warp"
               and e["target"] == "proton" and e["reason"] for e in events)


def test_deactivation_and_restore_events(tmp_path):
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda p: None
    conf = tmp_path / "proton.conf"
    conf.write_text("x")
    r.provider_files = lambda n: [conf] if n == "proton" else []
    assert r.activate_fallback("warp", target="proton") == 0
    assert r.deactivate_fallback("warp", automatic=True) == 0
    events = _events(tmp_path)
    kinds = [e["kind"] for e in events]
    assert "fallback_deactivated" in kinds


def test_event_log_is_bounded(tmp_path):
    import time as time_mod
    root = tmp_path
    state.EVENTS_LOG_MAX_BYTES = 2000
    try:
        for i in range(100):
            state.log_event(root, "rotation", provider="proton", seq=i)
        path = root / "state" / "events.jsonl"
        assert path.stat().st_size <= 2000 + 200  # bounded after truncation
        lines = path.read_text().splitlines()
        assert len(lines) < 100  # oldest half dropped
        assert all(json.loads(line)["kind"] == "rotation" for line in lines)
    finally:
        state.EVENTS_LOG_MAX_BYTES = 1_000_000


def test_event_write_failure_never_raises(tmp_path):
    """A failing event log must not break the action it describes (#184)."""
    with mock.patch.object(state.Path, "open", side_effect=OSError(28, "ENOSPC")):
        state.log_event(tmp_path, "rotation", provider="proton")  # must not raise
