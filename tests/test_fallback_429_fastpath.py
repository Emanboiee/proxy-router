"""#219 items 3+6: a quota-dead serving fallback must restore a healthy primary
in the same request budget, bypassing the two-win/cooldown gate (force path).
"""
import json
import time
from unittest import mock

from tests.test_router_regressions import load_router


def _setup(tmp_path, monkeypatch):
    r = load_router(tmp_path)
    conf = {"providers": {"proton": {"fallback_providers": ["cloudflare"]},
                          "cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}},
            "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}]}
    r.CONFIG_FILE.write_text(json.dumps(conf))
    assert r.load_config() == 0
    monkeypatch.setattr(r, "_profile_error", lambda p: None)
    monkeypatch.setattr(r, "engine_reload", lambda *a, **k: 0)
    monkeypatch.setattr(r, "current_mode", lambda: "proxy")
    monkeypatch.setattr(r, "_automatic_proxy_mode", lambda: True)
    monkeypatch.setattr(r, "response_provider_for_host", lambda h: "proton")
    monkeypatch.setattr(r, "_diagnostic_host_is_routed", lambda h: True)
    monkeypatch.setattr(r, "probe_egress",
                        lambda **kw: {"status": 200, "error": None, "latency_ms": 5.0,
                                      "block_reason": None})
    fb = r._fallback_state_path("proton")
    fb.parent.mkdir(parents=True, exist_ok=True)
    fb.write_text(json.dumps({"provider": "cloudflare", "reason": "confirmed-stall"}))
    return r


def _marker(tmp_path, *, successes=0, age=1000):
    marker = tmp_path / "state" / "recovery" / "proton-restore.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"attempted_at": int(time.time()) - age, "successes": successes}))
    return marker


def test_force_restore_commits_on_first_probe(tmp_path, monkeypatch):
    r = _setup(tmp_path, monkeypatch)
    marker = _marker(tmp_path)
    rc = r.restore_fallback("proton", "opencode.ai", automatic=True, force=True)
    assert rc == 0, "force restore must commit on a single healthy primary probe"
    assert not r.active_fallback("proton")
    assert not marker.exists()


def test_normal_restore_still_requires_two_wins(tmp_path, monkeypatch):
    r = _setup(tmp_path, monkeypatch)
    _marker(tmp_path, successes=0)
    rc = r.restore_fallback("proton", "opencode.ai", automatic=True)
    assert rc == 1, "normal restore must still require a second win"
    assert r.active_fallback("proton") == "cloudflare"


def test_force_restore_works_for_429_reason_fallback(tmp_path, monkeypatch):
    """Council P1: the relay creates reason='429' fallbacks, not 'confirmed-stall'.
    Force restore must clear those too, or the fast path is inert."""
    r = _setup(tmp_path, monkeypatch)
    fb = r._fallback_state_path("proton")
    fb.write_text(json.dumps({"provider": "cloudflare", "reason": "429"}))
    marker = _marker(tmp_path)
    rc = r.restore_fallback("proton", "opencode.ai", automatic=True, force=True)
    assert rc == 0, f"force restore must clear a reason=429 fallback, got {rc}"
    assert not r.active_fallback("proton")


def test_force_restore_bypasses_cooldown(tmp_path, monkeypatch):
    r = _setup(tmp_path, monkeypatch)
    marker = _marker(tmp_path, age=0)  # just attempted -> normal path returns 3
    assert r.restore_fallback("proton", "opencode.ai", automatic=True) == 3
    # re-set the fallback that the normal attempt reinstated, then force
    fb = r._fallback_state_path("proton")
    fb.write_text(json.dumps({"provider": "cloudflare", "reason": "confirmed-stall"}))
    assert r.restore_fallback("proton", "opencode.ai", automatic=True, force=True) == 0
