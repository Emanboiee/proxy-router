"""#140: a dead WARP SOCKS listener while warp-cli claims Connected needs an
actionable doctor hint. Loopback-only, hermetic — no WARP service touched.
"""
import socket
import threading

import pytest

import provider_lifecycle as lifecycle
from tests.test_router_regressions import load_router

pytestmark = [pytest.mark.allow_hosts(["127.0.0.1"])]


def test_warp_hint_normalizes_loopback_variants(monkeypatch):
    """Council P3: LOCALHOST / whitespace / expanded IPv6 must be recognized
    as loopback, matching config-load normalization."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    seen = []
    def fake_hint(host, p, **kw):
        seen.append(host)
        return "hint"
    monkeypatch.setattr(lifecycle, "warp_socks_hint", fake_hint)
    providers = {
        "upper": {"socks5": {"host": "LOCALHOST", "port": port}},
        "space": {"socks5": {"host": " 127.0.0.1 ", "port": port}},
        "v6": {"socks5": {"host": "0:0:0:0:0:0:0:1", "port": port}},
    }
    assert lifecycle.warp_hint_for_providers(providers) is not None
    assert all(h in ("127.0.0.1", "::1") for h in seen), seen


def test_warp_hint_does_not_crash_on_launch_options_error(monkeypatch):
    """Deploy seat: _launch_options can raise under root-owned cwd; never crash doctor."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    def boom(*a, **k):
        raise RuntimeError("root-owned cwd")
    monkeypatch.setattr(lifecycle, "_launch_options", boom)
    monkeypatch.setattr(lifecycle, "_warp_binary", lambda env: "/fake/warp-cli")
    # no warp_status injected -> would hit _launch_options; must not raise
    assert lifecycle.warp_socks_hint("127.0.0.1", port) is None


def test_warp_hint_for_providers_scans_local_socks():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    providers = {"cloudflare": {"socks5": {"host": "127.0.0.1", "port": port}}}
    hint = lifecycle.warp_hint_for_providers(providers)
    # warp_status() will find no warp-cli here -> no hint, but no crash
    assert hint is None or "warp-cli" in hint


def test_warp_hint_when_refused_and_warp_connected():
    # bind then close -> guaranteed connection-refused port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    hint = lifecycle.warp_socks_hint("127.0.0.1", port, warp_status=lambda: "Connected")
    assert hint is not None
    assert "warp-cli disconnect" in hint and "warp-cli connect" in hint


def test_no_hint_when_warp_disconnected():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert lifecycle.warp_socks_hint("127.0.0.1", port, warp_status=lambda: "Disconnected") is None


def test_no_hint_when_listener_alive():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert lifecycle.warp_socks_hint("127.0.0.1", port, warp_status=lambda: "Connected") is None
    finally:
        srv.close()
