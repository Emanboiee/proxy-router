"""#140: a dead WARP SOCKS listener while warp-cli claims Connected needs an
actionable doctor hint. Loopback-only, hermetic — no WARP service touched.
"""
import socket
import threading

import pytest

import provider_lifecycle as lifecycle
from tests.test_router_regressions import load_router

pytestmark = [pytest.mark.allow_hosts(["127.0.0.1"])]


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
