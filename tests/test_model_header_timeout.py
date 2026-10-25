"""Exercise production header timing against an isolated loopback upstream."""
import contextlib
import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from model_relay import ModelRelay, RouterRecovery
from tests.test_model_relay import setup_router

pytestmark = [pytest.mark.enable_socket, pytest.mark.allow_hosts(["127.0.0.1"])]


@pytest.fixture
def header_path(monkeypatch):
    delays = []
    attempts = []
    tunnels = []
    result = b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\ndata: [DONE]\n\n'

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            attempts.append(self.rfile.read(int(self.headers["Content-Length"])))
            header_delay, body_delay = delays.pop(0)
            time.sleep(header_delay)
            with contextlib.suppress(OSError):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(result)))
                self.end_headers()
                time.sleep(body_delay)
                self.wfile.write(result)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    upstream = Server(("127.0.0.1", 0), Upstream)

    class LocalConnection(http.client.HTTPConnection):
        # Keep production connect/request/getresponse/socket handling, replacing
        # only the CONNECT/TLS boundary with a local cleartext test upstream.
        def __init__(self, host, port, *, timeout):
            super().__init__(*upstream.server_address, timeout=timeout)

        def set_tunnel(self, host, port):
            tunnels.append((host, port))

    monkeypatch.setattr(http.client, "HTTPSConnection", LocalConnection)
    recovery = Mock()
    recovery.snapshot.return_value = ("primary", "primary", "first")
    recovery.recover_transport.return_value = True
    relay = ModelRelay(("127.0.0.1", 0), "https://model.test/v1", 1234, recovery,
                       header_timeout=0.05, timeout=1, retry_window=0.3, max_retries=2)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, relay)]
    for thread in threads:
        thread.start()

    def request(model="test-free", cancel=False):
        conn = http.client.HTTPConnection(*relay.server_address, timeout=2)
        conn.request("POST", "/v1/chat/completions", json.dumps({
            "model": model, "messages": [{"role": "user", "content": "SECRET-PROMPT"}],
            "stream": True}), {"Content-Type": "application/json", "Authorization": "Bearer SECRET-TOKEN"})
        if cancel:
            conn.close()
            return None
        response = conn.getresponse()
        output = response.status, response.read(), response.getheader("X-Proxy-Router-Retries")
        conn.close()
        return output

    yield request, delays, attempts, recovery, relay, result, tunnels
    for server in (relay, upstream):
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=3)


def test_hanging_headers_rotate_before_retry_window_without_replaying_output(header_path, caplog):
    request, delays, attempts, recovery, relay, result, tunnels = header_path
    delays.extend([(0.2, 0), (0, 0)])
    started = time.monotonic()
    assert request() == (200, result, "1")
    assert time.monotonic() - started < 0.3
    assert len(attempts) == 2
    assert attempts[0] == attempts[1]
    recovery.recover_transport.assert_called_once()
    recovery.recover.assert_not_called()
    assert tunnels == [("model.test", 443)] * 2
    assert "SECRET-PROMPT" not in caplog.text
    assert "SECRET-TOKEN" not in caplog.text


def test_delayed_headers_restore_longer_stream_idle_timeout(header_path):
    request, delays, attempts, recovery, relay, result, _ = header_path
    delays.append((0.01, 0.15))
    assert request() == (200, result, "0")
    assert len(attempts) == 1
    recovery.recover_transport.assert_not_called()


@pytest.mark.parametrize("available", [True, False])
def test_failed_headers_close_and_bound_attempts(header_path, available):
    request, delays, attempts, recovery, relay, _, _ = header_path
    recovery.recover_transport.return_value = available
    delays.extend([(0.2, 0)] * 3)
    started = time.monotonic()
    status, body, _ = request()
    assert status == 504
    assert json.loads(body)["error"]["code"] == "upstream_header_timeout"
    assert len(attempts) == (3 if available else 1)
    assert time.monotonic() - started < 0.3


def test_remaining_window_caps_a_single_header_wait(header_path):
    request, delays, attempts, recovery, relay, _, _ = header_path
    relay.header_timeout = 1
    relay.retry_window = 0.04
    delays.append((0.2, 0))
    started = time.monotonic()
    assert request()[0] == 504
    assert time.monotonic() - started < 0.2
    assert len(attempts) == 1
    recovery.recover_transport.assert_not_called()


def test_paid_model_is_not_automatically_replayed(header_path):
    request, delays, attempts, recovery, *_ = header_path
    delays.append((0.2, 0))
    assert request(model="paid-model")[0] == 504
    recovery.recover_transport.assert_not_called()


def test_cancelled_client_does_not_rotate_or_retry(header_path):
    request, delays, attempts, recovery, *_ = header_path
    delays.append((0.2, 0))
    request(cancel=True)
    time.sleep(0.3)
    assert len(attempts) <= 1
    recovery.recover_transport.assert_not_called()


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_header_budget_rejected_before_binding(timeout):
    with pytest.raises(ValueError, match="header timeout"):
        ModelRelay(("127.0.0.1", 0), "https://model.test/v1", 1234, Mock(), header_timeout=timeout)


def test_transport_recovery_does_not_record_quota_exhaustion(tmp_path, monkeypatch):
    router, paths = setup_router(tmp_path, monkeypatch)
    monkeypatch.setattr(router, "response_provider_for_host", lambda host: "proton")
    monkeypatch.setattr(router, "_automatic_proxy_mode", lambda: True)
    recovery = RouterRecovery(router, "model.test")
    snapshot = recovery.snapshot()
    assert recovery.recover_transport(snapshot, timeout=1)
    assert recovery.snapshot() != snapshot
    assert router.is_cooled_down("proton", paths[0])
    assert not router.egress_is_exhausted("proton", paths[0])
