"""429 recovery belongs below model clients; no prompts or model changes on retry."""
from __future__ import annotations

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from model_relay import ModelRelay, RouterRecovery
from tests.test_proxy_provider import load_router, proxy_config, write_conf

pytestmark = [pytest.mark.enable_socket, pytest.mark.allow_hosts(['127.0.0.1'])]


@pytest.fixture
def relay_path():
    attempts = []
    statuses = []
    body = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\ndata: [DONE]\n\n'

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            attempts.append((self.path, self.rfile.read(int(self.headers['Content-Length'])),
                             self.headers.get('Authorization')))
            status = statuses.pop(0)
            if isinstance(status, tuple):
                status, response = status
            else:
                response = b'{"error":{"type":"RateLimitError"}}' if status == 429 else body
            self.send_response(status)
            self.send_header('Content-Type', 'text/event-stream' if status == 200 else 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    class Recovery:
        def __init__(self):
            self.exit = 0
            self.switches = 0
            self.available = True

        def snapshot(self):
            return self.exit

        def recover(self, expected):
            assert expected == self.exit
            self.switches += 1
            if self.available:
                self.exit += 1
            return self.available

    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    recovery = Recovery()
    relay = ModelRelay(('127.0.0.1', 0), 'https://example.test/zen/v1', 1, recovery, max_retries=3)

    def open_upstream(method, path, data, headers):
        conn = http.client.HTTPConnection(*upstream.server_address, timeout=3)
        conn.request(method, '/zen/v1' + path, data, headers)
        return conn, conn.getresponse()

    relay.open_upstream = open_upstream
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, relay)]
    for t in threads:
        t.start()

    def request(model='test-free'):
        payload = json.dumps({'model': model, 'messages': [{'role': 'user', 'content': 'unchanged'}],
                              'stream': True}).encode()
        conn = http.client.HTTPConnection(*relay.server_address, timeout=5)
        conn.request('POST', '/v1/chat/completions', payload,
                     {'Content-Type': 'application/json', 'Authorization': 'Bearer test-only'})
        response = conn.getresponse()
        result = response.status, response.read(), response.getheader('X-Proxy-Router-Retries')
        conn.close()
        return result

    yield request, statuses, attempts, recovery, body
    for s in (relay, upstream):
        s.shutdown()
        s.server_close()
    for t in threads:
        t.join(timeout=3)


def test_429s_rotate_and_replay_same_model_before_streaming(relay_path):
    request, statuses, attempts, recovery, body = relay_path
    statuses.extend([429, 429, 200])
    assert request() == (200, body, '2')
    assert recovery.switches == 2
    assert attempts[0] == attempts[1] == attempts[2]
    assert attempts[0][0] == '/zen/v1/chat/completions'


def test_exhaustion_exposes_final_429_and_bounds_retries(relay_path):
    request, statuses, attempts, recovery, _ = relay_path
    statuses.extend([429, 429, 429, 429])
    assert request()[0::2] == (429, '3')
    assert len(attempts) == 4
    recovery.available = False
    statuses.append(429)
    assert request()[0::2] == (429, '0')


def test_paid_model_generic_429_does_not_rotate(relay_path):
    request, statuses, attempts, recovery, _ = relay_path
    statuses.append(429)
    assert request('paid-model')[0] == 429
    assert recovery.switches == 0


def test_http_200_raw_free_limit_recovers_before_adapter_translation(relay_path):
    request, statuses, attempts, recovery, body = relay_path
    statuses.extend([(200, b'{"error":{"type":"FreeUsageLimitError"}}'), 200])
    assert request() == (200, body, '1')
    assert recovery.switches == 1
    assert attempts[0] == attempts[1]


def test_normal_json_success_is_preserved_without_recovery(relay_path):
    request, statuses, _, recovery, _ = relay_path
    body = b'{"choices":[{"message":{"content":"FreeUsageLimitError is a word"}}]}'
    statuses.append((200, body))
    assert request() == (200, body, '0')
    assert recovery.switches == 0


def test_fragmented_json_limit_preamble_is_detected(relay_path, monkeypatch):
    request, statuses, attempts, recovery, body = relay_path
    read1 = http.client.HTTPResponse.read1
    # Force byte-sized reads so whitespace arrives separately from the JSON.
    monkeypatch.setattr(http.client.HTTPResponse, 'read1', lambda response, size=-1: read1(response, 1))
    statuses.extend([(200, b' \n {"error":{"type":"FreeUsageLimitError"}}'), 200])
    assert request() == (200, body, '1')
    assert recovery.switches == 1
    assert attempts[0] == attempts[1]


def setup_router(tmp_path, monkeypatch):
    r = load_router(tmp_path)
    conf = proxy_config()
    conf['providers']['proton']['fallback_providers'] = ['warp-proxy']
    conf['providers']['warp-proxy'].pop('fallback_providers')
    paths = [write_conf(tmp_path / 'providers/proton', stem) for stem in ('a', 'b')]
    r.CONFIG_FILE.write_text(json.dumps(conf))
    assert r.load_config() == 0
    monkeypatch.setattr(r, '_profile_error', lambda p: None)
    monkeypatch.setattr(r, 'engine_alive', lambda: False)
    monkeypatch.setattr(r, 'listener_up', lambda: False)
    monkeypatch.setattr(r, 'engine_reload', lambda *a, **k: 0)
    monkeypatch.setattr(r, 'current_mode', lambda: 'proxy')
    r.set_active('proton', paths[0])
    return r, paths


def test_router_cooldown_fallback_and_late_response_attribution(tmp_path, monkeypatch):
    r, paths = setup_router(tmp_path, monkeypatch)
    recovery = RouterRecovery(r, 'opencode.ai')
    first = recovery.snapshot()
    assert recovery.recover(first)
    second = recovery.snapshot()
    assert first != second
    assert r.is_cooled_down('proton', paths[0])
    assert recovery.recover(first)  # concurrent response from old exit
    assert recovery.snapshot() == second
    assert not r.is_cooled_down('proton', paths[1])
    assert recovery.recover(second)
    assert recovery.snapshot()[1:] == ('warp-proxy', 'socks')
    assert not recovery.recover(recovery.snapshot())
    assert r.is_cooled_down('warp-proxy', r.proxy_profile_key('warp-proxy'))


def test_routing_allow_list_controls_response_attribution(tmp_path, monkeypatch):
    r, _ = setup_router(tmp_path, monkeypatch)
    config = json.loads(r.CONFIG_FILE.read_text())
    config['routing'] = {'mode': 'vpn-list', 'vpn_domains': ['school.example']}
    r.CONFIG_FILE.write_text(json.dumps(config))
    assert RouterRecovery(r, 'opencode.ai').snapshot() is None
    config['routing']['vpn_domains'].append('opencode.ai')
    r.CONFIG_FILE.write_text(json.dumps(config))
    assert RouterRecovery(r, 'opencode.ai').snapshot()[0] == 'proton'


def test_lock_failure_never_reports_success(tmp_path, monkeypatch):
    r, _ = setup_router(tmp_path, monkeypatch)
    recovery = RouterRecovery(r, 'opencode.ai')
    monkeypatch.setattr(r, '_with_lock', lambda *a, **k: 1)
    assert recovery.recover(recovery.snapshot()) is False


@pytest.mark.parametrize('host', ['host.ts.net', 'host.local', 'magicdns', '100.64.1.2', 'fd7a:115c:a1e0::1'])
def test_private_bypass_is_never_charged_to_safe_list_default(tmp_path, monkeypatch, host):
    r, _ = setup_router(tmp_path, monkeypatch)
    r._vpn = {'public_dns': {'server': '1.1.1.1'}, 'tailscale_bypass': True}
    r._routing = {'mode': 'safe-list', 'default_provider': 'proton'}
    assert r.response_provider_for_host(host) is None


def test_missing_provider_route_does_not_hide_later_live_route(tmp_path, monkeypatch):
    r, _ = setup_router(tmp_path, monkeypatch)
    r._providers['missing'] = {'directory': 'providers/missing'}
    r._routes.insert(0, {'id': 'missing', 'provider': 'missing', 'domains': ['opencode.ai']})
    assert r.response_provider_for_host('opencode.ai') == 'proton'
