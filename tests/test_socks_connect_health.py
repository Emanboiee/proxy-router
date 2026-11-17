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

    def __init__(self, *, connect_rep=0, greeting=True, blackhole=False):
        self.connect_rep = connect_rep
        self.greeting = greeting
        self.blackhole = blackhole
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
                conn.sendall(b"\x05\x00" if self.greeting else b"\x05\xff")
                if not self.greeting or self.blackhole:
                    return
                head = conn.recv(4)
                if len(head) < 4 or head[0] != 0x05:
                    return
                if head[3] == 0x03:  # DOMAINNAME
                    length = conn.recv(1)[0]
                    conn.recv(length + 2)
                self.connect_requests.append(head[1])
                rep = self.connect_rep & 0xFF
                conn.sendall(bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
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
