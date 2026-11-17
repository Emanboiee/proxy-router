"""Issue #225: a SOCKS listener can accept TCP and the greeting, yet reject
CONNECT. A local port that answers is not a usable egress. These tests use only
loopback fixtures: no production tunnel, system proxy or WARP service is touched.
"""
import json
import socket
import threading
import time

import pytest

import egress
import provider_lifecycle as lifecycle
from tests.test_router_regressions import load_router


pytestmark = [pytest.mark.enable_socket, pytest.mark.allow_hosts(["127.0.0.1"])]


class FakeSocks:
    """Bounded loopback SOCKS5 server with a configurable CONNECT reply."""

    def __init__(self, *, connect_rep=0, greeting=True, blackhole=False, fragment=False,
                 reject_first=0):
        self.connect_rep = connect_rep
        self.greeting = greeting
        self.blackhole = blackhole
        self.fragment = fragment
        self.reject_first = reject_first  # reject the first N CONNECTs, then accept
        self.connect_count = 0
        self.connect_requests = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.port = self._server.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            conn.settimeout(1.5)
            try:
                if len(conn.recv(3)) < 3:
                    return
                greet = b"\x05\x00" if self.greeting else b"\x05\xff"
                if self.fragment:
                    for byte in greet:
                        conn.sendall(bytes([byte]))
                else:
                    conn.sendall(greet)
                if not self.greeting or self.blackhole:
                    return
                head = conn.recv(4)
                if len(head) < 4 or head[0] != 0x05:
                    return
                if head[3] == 0x03:  # DOMAINNAME
                    length = conn.recv(1)[0]
                    conn.recv(length + 2)
                self.connect_requests.append(head[1])
                self.connect_count += 1
                rep = 5 if self.connect_count <= self.reject_first else self.connect_rep
                rep &= 0xFF
                reply = bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                if self.fragment:
                    for byte in reply:
                        conn.sendall(bytes([byte]))
                else:
                    conn.sendall(reply)
            except OSError:
                pass

    def close(self):
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=2)


@pytest.fixture
def socks_factory():
    servers = []

    def make(**kwargs):
        server = FakeSocks(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


# --- bounded CONNECT probe -------------------------------------------------

def test_connect_rejected_rep5_is_not_usable(socks_factory):
    server = socks_factory(connect_rep=5)
    result = lifecycle.socks_connect_result("127.0.0.1", server.port, "example.com", timeout=1.0)
    assert result["ok"] is False
    assert result["code"] == 5
    assert server.connect_requests == [0x01]  # a CONNECT verb really went out


def test_connect_rejected_rep4_is_not_usable(socks_factory):
    server = socks_factory(connect_rep=4)
    result = lifecycle.socks_connect_result("127.0.0.1", server.port, "example.com", timeout=1.0)
    assert result["ok"] is False
    assert result["code"] == 4


def test_successful_connect_is_usable(socks_factory):
    server = socks_factory(connect_rep=0)
    result = lifecycle.socks_connect_result("127.0.0.1", server.port, "example.com", timeout=1.0)
    assert result["ok"] is True
    assert result["code"] == 0


def test_missing_upstream_is_not_usable():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    result = lifecycle.socks_connect_result("127.0.0.1", port, "example.com", timeout=0.5)
    assert result["ok"] is False
    assert result["code"] is None


def test_blackhole_is_bounded(socks_factory):
    server = socks_factory(blackhole=True)
    started = time.monotonic()
    result = lifecycle.socks_connect_result("127.0.0.1", server.port, "example.com", timeout=0.4)
    assert result["ok"] is False
    assert time.monotonic() - started < 2.0


# --- evidence classification ------------------------------------------------

def test_fresh_failed_evidence_is_unusable():
    record = {"ok": False, "checked_at": int(time.time())}
    assert egress.fresh_failure(record, int(time.time()), 86400) is True
    assert egress.usable_evidence(record, int(time.time()), 86400) is False


def test_fresh_success_is_usable():
    record = {"ok": True, "socks_connect_ok": True, "checked_at": int(time.time())}
    assert egress.usable_evidence(record, int(time.time()), 86400) is True


def test_stale_success_is_not_usable():
    record = {"ok": True, "checked_at": int(time.time()) - 90_000}
    assert egress.usable_evidence(record, int(time.time()), 86400) is False


# --- degraded-lane reporting -------------------------------------------------

def _controller(tmp_path, *providers):
    r = load_router(tmp_path)
    r._providers = {name: {"socks5": {"host": "127.0.0.1", "port": 2181 + i}}
                    for i, name in enumerate(providers)}
    r._routes = [{"id": f"route-{name}", "provider": name} for name in providers]
    r.current_mode = lambda: "proxy"
    r.active_fallback = lambda name: None
    r.is_proxy_provider = lambda name: name in r._providers
    r._effective_route_provider = lambda name: name
    return r


def _write_record(r, provider, **fields):
    profile = r.proxy_profile_key(provider)
    path = r.egress_record_path(provider, profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"checked_at": int(time.time())}
    record.update(fields)
    path.write_text(json.dumps(record))


def test_connect_rejection_marks_only_the_affected_route(tmp_path):
    r = _controller(tmp_path, "warp", "proton")
    _write_record(r, "warp", ok=False, socks_connect_ok=False, socks_connect_code=5)
    _write_record(r, "proton", ok=True, socks_connect_ok=True)

    lanes = r._degraded_lanes()
    assert any("route-warp" in lane and "connect rejected" in lane for lane in lanes)
    assert not any("route-proton" in lane for lane in lanes)


def test_missing_upstream_lane_is_degraded(tmp_path):
    r = _controller(tmp_path, "warp")
    _write_record(r, "warp", ok=False, error="connection refused", socks_connect_ok=False)

    lanes = r._degraded_lanes()
    assert any("route-warp" in lane for lane in lanes)


def test_reconnect_success_clears_degradation(tmp_path):
    r = _controller(tmp_path, "warp")
    _write_record(r, "warp", ok=False, socks_connect_ok=False, socks_connect_code=5)
    assert r._degraded_lanes()

    _write_record(r, "warp", ok=True, socks_connect_ok=True, socks_connect_code=0)
    assert r._degraded_lanes() == []


def test_connect_rejection_is_degraded_not_dead_without_http_corroboration(tmp_path, monkeypatch):
    """Council: a CONNECT rejection must be capped at 'degraded' and the HTTP
    probe given the final word. A working tunnel whose routed CONNECT target
    is whitelisted must not be dead-marked into the fail-open/direct path."""
    r = load_router(tmp_path)
    from pathlib import Path as _P
    r._providers = {"warp": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r._routes = [{"id": "r", "domains": ["school.example"], "provider": "warp"}]
    r._port = 2080
    r.is_proxy_provider = lambda name: True
    r.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    r.SING_BOX_CONFIG.write_text(json.dumps({"route": {"final": "warp"}}))
    r.engine_alive = lambda: True
    r.proxy_upstream = lambda name: ("127.0.0.1", 2181)
    r.probe_url_for = lambda name: "https://school.example/"
    r._write_proxy_egress = lambda name, record: None
    r.record_egress = lambda name, profile, **kw: kw
    r._clear_cooldown = lambda name, profile: None

    rejection = {"ok": False, "checked_at": int(time.time()),
                 "socks_connect_ok": False, "socks_connect_code": 5,
                 "error": "socks connect rejected (rep=5)"}
    monkeypatch.setattr(lifecycle, "recover_routed", lambda *a, **k: rejection)
    # HTTP probe succeeds — the tunnel carries traffic despite the CONNECT rejection.
    r.probe_egress = lambda **kw: {"ok": True, "latency_ms": 5.0, "status": 200,
                                    "error": None, "block_reason": None}
    monkeypatch.setattr(r, "provider_lifecycle", lifecycle)
    status, _ = r.check_egress_live("warp", _P("socks"))
    assert status == "alive", f"HTTP-corroborated tunnel must be alive, got {status}"


def test_recover_routed_retries_a_transient_connect_rejection(socks_factory, tmp_path,
                                                              monkeypatch):
    """Council: a single transient CONNECT rejection must not dead-mark an
    exit. recover_routed retries once before persisting a failure."""
    server = socks_factory(connect_rep=0, reject_first=1)
    config = tmp_path / "sing-box.json"
    config.write_text(json.dumps({"route": {"rules": [{"outbound": "warp",
                                                        "domain_suffix": ["school.example"]}]}}))
    monkeypatch.setattr(lifecycle, "ensure", lambda *a, **k: True)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)
    written = {}

    def endpoint(_name):
        return "127.0.0.1", server.port

    result = lifecycle.recover_routed(tmp_path, "warp", config, endpoint,
                                      lambda n, r: written.__setitem__(n, r))
    assert result is None, "a single rejection then success must not persist failure"
    assert written == {}, "no rejection record should be written on transient blip"
    assert server.connect_count == 2, "CONNECT must be attempted twice"


def test_egress_check_surfaces_connect_rejection_reason(tmp_path, capsys):
    """Deploy council: egress probe must surface the rep= evidence, not a
    generic 'probe connection' that hides why the SOCKS exit is dead."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r.is_proxy_provider = lambda name: True
    r.proxy_upstream = lambda name: ("127.0.0.1", 2181)
    r.listener_up = lambda: True
    r.active_fallback = lambda name: None
    r.check_egress_live = lambda name, profile: ("dead", {
        "socks_connect_ok": False, "socks_connect_code": 5,
        "error": "socks connect rejected (rep=5)"})
    r.egress_check("warp", as_json=True)
    out = capsys.readouterr().out
    assert "socks connect rejected (rep=5)" in out, out
    assert '"detail": "probe connection"' not in out


def test_later_http_probe_clears_connect_rejection_reason(tmp_path):
    """CodeRabbit: REP=5, then HTTP 200, then HTTP 403 must report the 403 as
    the cause, not reuse the old REP=5 from a superseded CONNECT check."""
    r = load_router(tmp_path)
    from pathlib import Path
    profile = Path("socks")
    r._write_proxy_egress("warp", {"ok": False, "checked_at": int(time.time()),
                                   "socks_connect_ok": False, "socks_connect_code": 5,
                                   "error": "socks connect rejected (rep=5)"})
    # A fresh HTTP probe (200 then 403) supersedes the CONNECT evidence.
    r.record_egress("warp", profile, ok=True, status=200)
    r.record_egress("warp", profile, ok=False, status=403)
    rec = r.read_egress("warp", profile)
    assert rec.get("socks_connect_ok") is None
    assert "connect rejected" not in r.egress.degraded_detail(rec, int(time.time()), 86400)


def test_fragmented_socks_replies_are_read_fully(socks_factory):
    """CodeRabbit: recv(n) can return fewer bytes; a reply sent one byte at a
    time must still be parsed as a successful CONNECT."""
    server = socks_factory(connect_rep=0, fragment=True)
    result = lifecycle.socks_connect_result("127.0.0.1", server.port, "example.com", timeout=1.0)
    assert result["ok"] is True, result
    assert result["code"] == 0


def test_connect_target_uses_routed_domain_not_fixed_host():
    """#225: probe a domain the provider actually routes, so a whitelist-only
    proxy isn't false-deaded for rejecting an arbitrary external host."""
    cfg = {"route": {"rules": [
        {"outbound": "other", "domain_suffix": ["unrelated.example"]},
        {"outbound": "warp", "domain_suffix": [".school.example"]},
    ]}}
    assert lifecycle.connect_target_for(cfg, "warp") == ("school.example", 443)
    assert lifecycle.connect_target_for(cfg, "missing") == ("example.com", 443)


def test_recover_routed_persists_connect_rejection(socks_factory, tmp_path):
    server = socks_factory(connect_rep=5)
    name = "warp"
    config = tmp_path / "sing-box.json"
    config.write_text(json.dumps({"route": {"rules": [{"outbound": name}]}}))
    written = {}

    def endpoint(_name):
        return "127.0.0.1", server.port

    def writer(provider, record):
        written[provider] = record

    monkeypatch_ensure = getattr(lifecycle, "ensure")
    lifecycle.ensure = lambda *a, **k: True
    try:
        result = lifecycle.recover_routed(tmp_path, name, config, endpoint, writer)
    finally:
        lifecycle.ensure = monkeypatch_ensure

    assert result is not None
    assert result["socks_connect_ok"] is False
    assert result["socks_connect_code"] == 5
    assert written[name]["socks_connect_code"] == 5
    assert written[name]["checked_at"] > 0


def test_recovered_http_probe_clears_stale_connect_rejection(tmp_path):
    """A fresh successful HTTP probe through the tunnel means the exit carries
    traffic now; a lingering socks_connect_ok=false must not keep the lane
    degraded forever (#225 deploy review finding)."""
    r = load_router(tmp_path)
    from pathlib import Path
    profile = Path("socks")
    # Production shape after a rejection then a successful HTTP probe.
    r.record_egress("warp", profile, ok=True, status=200)
    rec = r.read_egress("warp", profile)
    rec["socks_connect_ok"] = False
    rec["socks_connect_code"] = 5
    path = r.egress_record_path("warp", profile)
    path.write_text(json.dumps(rec))

    now = int(time.time())
    # The observable verdict, not the internal field: a fresh ok=true exit is usable.
    assert r.egress.fresh_failure(rec, now, 86400) is False
    assert r.egress.usable_evidence(rec, now, 86400) is True
    # And the actual user-visible status path: no degraded lane after recovery.
    r._providers = {"warp": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r._routes = [{"id": "route-warp", "provider": "warp"}]
    r.active_fallback = lambda name: None
    r.is_proxy_provider = lambda name: True
    assert r._degraded_lanes() == []


def test_connect_rejection_merges_into_existing_egress_record(tmp_path):
    """A CONNECT-rejection record must not wipe quota/block/fail-streak fields
    from the existing egress record (council deploy P1): clearing a reputation
    block would make provider_quota_exhausted report the exit eligible again."""
    r = load_router(tmp_path)
    from pathlib import Path
    profile = Path("socks")
    # Pre-existing record with an active block + fail streak + quota marker.
    r.record_egress("warp", profile, ok=False, status=403)
    existing = r.read_egress("warp", profile)
    existing.update({"blocked": True, "block_reason": "1010",
                     "exhausted": True, "exhausted_until": "2099-01-01T00:00:00+00:00",
                     "fails": 3, "tls_fails": 2})
    path = r.egress_record_path("warp", profile)
    path.write_text(json.dumps(existing))

    # Production path: recover_routed writes a rejection via the proxy adapter.
    r._write_proxy_egress("warp", {"ok": False, "checked_at": int(time.time()),
                                   "socks_connect_ok": False,
                                   "error": "socks connect rejected (rep=5)",
                                   "socks_connect_code": 5})
    merged = r.read_egress("warp", profile)
    assert merged["blocked"] is True, "reputation block must survive the merge"
    assert merged["exhausted"] is True, "quota marker must survive the merge"
    assert merged["fails"] == 3, "fail streak must survive the merge"
    assert merged["socks_connect_ok"] is False, "new rejection evidence is recorded"
