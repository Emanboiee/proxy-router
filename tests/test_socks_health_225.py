"""#225: a SOCKS listener accepting TCP is not evidence of a usable exit.

The status contract must distinguish engine liveness from routed egress:
a proxy provider whose egress record is stale, exhausted, or records a
recent failure is degraded even while the listener is up.
"""
import json
import time
from unittest import mock

from tests.test_router_regressions import load_router


def _controller(tmp_path, provider="cloudflare"):
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": [provider], "fail_open_direct": False},
                    provider: {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": provider}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._system_proxy_status_readonly = lambda: ("ok", None)
    return r, provider


def _record(r, name, *, ok=True, checked_at=None, exhausted=False):
    path = r.egress_record_path(name, r.proxy_profile_key(name))
    path.parent.mkdir(parents=True, exist_ok=True)
    checked = int(time.time()) if checked_at is None else checked_at
    path.write_text(json.dumps({
        "ok": ok, "exhausted": exhausted, "checked_at": checked,
        "last_ok_at": checked if ok else None, "status": 200 if ok else None,
    }))


def test_stale_clean_record_reports_degraded(tmp_path):
    """The #225 incident: ok=true from weeks ago must not read healthy."""
    r, cf = _controller(tmp_path)
    _record(r, cf, checked_at=int(time.time()) - 29 * 86400)
    lanes = r._degraded_lanes()
    assert any("stale" in lane and cf in lane for lane in lanes), lanes


def test_fresh_ok_record_is_not_degraded(tmp_path):
    r, cf = _controller(tmp_path)
    _record(r, cf, ok=True)
    assert r._degraded_lanes() == []


def test_exhausted_record_reports_degraded(tmp_path):
    r, cf = _controller(tmp_path)
    path = r.egress_record_path(cf, r.proxy_profile_key(cf))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "ok": False, "exhausted": True, "checked_at": int(time.time()),
        "exhausted_until": r._iso_ts(int(time.time()) + 900)}))
    lanes = r._degraded_lanes()
    assert any("quota exhausted" in lane for lane in lanes), lanes


def test_no_record_reads_unknown_not_healthy(tmp_path):
    """Absent evidence is UNKNOWN, not a green light (#225 item 4)."""
    r, cf = _controller(tmp_path)
    lanes = r._degraded_lanes()
    assert any("stale or unknown" in lane for lane in lanes), lanes


def test_fail_open_direct_lane_still_reported(tmp_path):
    """The pre-existing fail-open contract must survive the #225 extension."""
    r, cf = _controller(tmp_path)
    r._providers["warp"]["fail_open_direct"] = True
    r._effective_route_provider = lambda name: "direct"
    r.active_fallback = lambda name: "direct"
    lanes = r._degraded_lanes()
    assert any("failing open to direct" in lane for lane in lanes), lanes


def test_healthy_provider_does_not_mask_another(tmp_path):
    """A fresh OK provider must not hide a stale one's lane (#225 item 6)."""
    r, cf = _controller(tmp_path)
    r._providers["proton"] = {"socks5": {"host": "127.0.0.1", "port": 2182}}
    r._routes = [
        {"id": "school", "domains": ["discord.com"], "provider": cf},
        {"id": "other", "domains": ["x.com"], "provider": "proton"},
    ]
    _record(r, cf, ok=True)
    _record(r, "proton", checked_at=int(time.time()) - 40 * 86400)
    lanes = r._degraded_lanes()
    assert any("proton" in lane for lane in lanes), lanes
    # cloudflare's record is fresh: no cloudflare lane
    assert not any(cf in lane for lane in lanes), lanes
