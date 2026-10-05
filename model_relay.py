"""Local OpenAI-compatible relay; retry IP-scoped free-model 429s below clients."""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from types import SimpleNamespace

log = logging.getLogger("proxy-router.model-relay")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"}
MAX_BODY = 32 * 1024 * 1024


def route_provider(namespace: dict, host: str) -> str | None:
    """Return the enabled route provider responsible for ``host``."""
    router = SimpleNamespace(**namespace)
    routing = router.routing_state()
    if routing["mode"] == "safe-list" and any(
        router._response_host_matches(host, d) for d in routing["direct_domains"]
    ):
        return None
    public_dns = router._vpn.get("public_dns")
    private = public_dns.get("private_domains", ["local", "ts.net"]) if public_dns else []
    if public_dns and "." not in host.rstrip("."):
        return None
    bypass = list(private) + (router._TAILSCALE_DOMAINS if router._vpn.get("tailscale_bypass") else [])
    if any(router._response_host_matches(host, d) for d in bypass):
        return None
    if router._vpn.get("tailscale_bypass"):
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if any(address in ipaddress.ip_network(cidr) for cidr in router._TAILSCALE_CIDRS):
                return None
    routes = router._routes_with_autodetected_domains(router._routes)
    selected = {n: p for n in router._providers if not router.is_proxy_provider(n)
                and not router.active_fallback(n) and (p := router._usable_profile(n)) is not None}
    proxy_live = router.active_proxy_providers()

    def available(provider):
        leaf = router._effective_route_provider(provider)
        return leaf == "direct" or leaf in selected or leaf in proxy_live

    if routing.get("health_order") and selected:
        routes = router._routes_by_health_order(routes, selected)
    for route in routes:
        provider = route.get("provider")
        if not isinstance(provider, str) or not available(provider):
            continue
        domains = route.get("domains", [])
        if routing["mode"] == "vpn-list":
            domains = router._vpn_list_intersection(domains, router._effective_vpn_domains(routing))
        for domain in domains:
            if router._response_host_matches(host, domain):
                return provider
    default = routing["default_provider"]
    return default if routing["mode"] == "safe-list" and available(default) else None


class RouterRecovery:
    """Serialize response attribution and exit changes with the engine controller."""
    def __init__(self, router, host):
        self.router, self.host = router, host
        self.lock = threading.RLock()

    def _snapshot(self):
        r = self.router
        if r.load_config() != 0 or r.MANUAL_OFF_FILE.exists():
            return None
        primary = r.response_provider_for_host(self.host)
        if not primary:
            return None
        effective = r._effective_route_provider(primary)
        if effective == "direct":
            return primary, effective, "direct"
        if r.is_proxy_provider(effective):
            return primary, effective, r._PROXY_PROFILE_STEM
        profile = r.persisted_active(effective) or r.resolve_active(effective)
        return (primary, effective, profile.stem) if profile else None

    def snapshot(self):
        with self.lock:
            return self._snapshot()

    def recover(self, expected):
        with self.lock:
            def apply():
                current = self._snapshot()
                if not expected or not current:
                    return False
                if current != expected:
                    # Another request already switched this exit. Never charge its
                    # late 429 to the newly selected server.
                    return True
                r = self.router
                _, effective, _ = current
                if effective == "direct":
                    return False
                if r.is_proxy_provider(effective):
                    r._apply_upstream_failure(effective, r.proxy_profile_key(effective), "429", 60)
                    rotated = False
                else:
                    rotated = r.rotate(effective, reason="429") == 0
                if not rotated:
                    # Follow the live leaf, including nested provider fallbacks.
                    switched = False
                    for candidate in r.configured_fallbacks(effective):
                        leaf = r._effective_route_provider(candidate)
                        profile = (r.proxy_profile_key(leaf) if r.is_proxy_provider(leaf)
                                   else r._usable_profile(leaf))
                        if leaf != "direct" and (profile is None or r.is_cooled_down(leaf, profile)
                                                  or r.egress_is_blocked(leaf, profile)):
                            continue
                        if r.activate_fallback(effective, target=candidate, reason="429") == 0:
                            switched = True
                            break
                    if not switched:
                        return False
                return self._snapshot() not in (None, current)
            return self.router._with_lock(apply, timeout=45) is True


class ModelRelay(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream, proxy_port, recovery, *, max_retries=32,
                 timeout=180, retry_window=180, free_models=()):
        parsed = urlsplit(upstream)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("upstream must be an HTTPS API base URL")
        if address[0] != "127.0.0.1":
            raise ValueError("model relay must listen on 127.0.0.1")
        self.upstream = parsed
        self.proxy_port = proxy_port
        self.recovery = recovery
        self.max_retries, self.timeout, self.retry_window = max_retries, timeout, retry_window
        self.free_models = set(free_models)
        super().__init__(address, RelayHandler)

    def open_upstream(self, method, path, body, headers):
        # Explicit CONNECT ignores ambient proxy/no_proxy settings. TLS verifies
        # the upstream hostname; this relay needs no interception certificate.
        conn = http.client.HTTPSConnection("127.0.0.1", self.proxy_port, timeout=self.timeout)
        conn.set_tunnel(self.upstream.hostname, self.upstream.port or 443)
        try:
            conn.request(method, self.upstream.path.rstrip("/") + path, body, headers)
            return conn, conn.getresponse()
        except Exception:
            conn.close()
            raise


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        # Model requests, credentials, and prompts never enter access logs.
        pass

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"service": "proxy-router-model-relay", "ok": True})
        self._relay()

    def do_POST(self):
        self._relay()

    def _json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def _relay(self):
        server = self.server
        path = urlsplit(self.path)
        allowed = {("GET", "/v1/models"), ("POST", "/v1/chat/completions")}
        if path.scheme or path.netloc or path.query or (self.command, path.path) not in allowed:
            return self._json(404, {"error": {"message": "Unknown model endpoint"}})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if self.headers.get("Transfer-Encoding") or not 0 <= length <= MAX_BODY:
            return self._json(413, {"error": {"message": "Invalid or oversized request body"}})
        self.connection.settimeout(server.timeout)
        body = self.rfile.read(length) if length else None
        model = ""
        if self.command == "POST":
            try:
                payload = json.loads(body or b"")
                model = payload.get("model", "")
                if not isinstance(model, str):
                    raise ValueError("model must be a string")
            except (ValueError, AttributeError):
                return self._json(400, {"error": {"message": "Invalid model request"}})
        free = model.endswith(("-free", ":free")) or model in server.free_models
        blocked = HOP_HEADERS | {h.strip().lower() for h in self.headers.get("Connection", "").split(",")}
        headers = {k: v for k, v in self.headers.items() if k.lower() not in blocked}
        headers["Accept-Encoding"] = "identity"
        deadline = time.monotonic() + server.retry_window
        retries = 0
        headers_sent = False
        try:
            while True:
                exit_before = server.recovery.snapshot()
                conn, response = server.open_upstream(self.command, path.path[3:], body, headers)
                try:
                    prefix = b""
                    failed_body = response.read(MAX_BODY + 1) if response.status == 429 else None
                    status = response.status
                    if status == 200 and self.command == "POST":
                        # Some Zen rejections arrive as raw JSON under HTTP 200,
                        # even with an SSE content type. Inspect the first
                        # meaningful byte before committing headers; normal SSE
                        # stays live even when its first chunk is fragmented.
                        prefix = response.read1(64 * 1024)
                        while prefix and not prefix.strip():
                            if len(prefix) >= 64 * 1024:
                                raise http.client.HTTPException("oversized response preamble")
                            chunk = response.read1(64 * 1024 - len(prefix))
                            if not chunk:
                                break
                            prefix += chunk
                        if prefix.lstrip().startswith(b"{"):
                            prefix += response.read(MAX_BODY + 1 - len(prefix))
                            if len(prefix) > MAX_BODY:
                                raise http.client.HTTPException("oversized JSON response")
                            try:
                                error = json.loads(prefix).get("error", {})
                                kind = error.get("type") if isinstance(error, dict) else None
                            except (ValueError, AttributeError):
                                kind = None
                            if kind == "FreeUsageLimitError" or free and kind == "RateLimitError":
                                status, failed_body = 429, prefix
                                prefix = b""
                    semantic_free = failed_body is not None and b"freeusagelimiterror" in failed_body.lower()
                    if (status == 429 and (free or semantic_free)
                            and retries < server.max_retries and time.monotonic() < deadline):
                        # Close rejected sockets before reloading the network engine.
                        response.close()
                        conn.close()
                        if server.recovery.recover(exit_before):
                            retries += 1
                            log.info("free-model 429: exit changed; retry %d", retries)
                            if time.monotonic() < deadline:
                                continue
                    self.send_response(status)
                    blocked = HOP_HEADERS | {h.strip().lower() for h in response.getheader("Connection", "").split(",")}
                    for k, v in response.getheaders():
                        if k.lower() not in blocked:
                            self.send_header(k, v)
                    self.send_header("X-Proxy-Router-Retries", str(retries))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    headers_sent = True
                    self.close_connection = True
                    if failed_body is not None:
                        self.wfile.write(failed_body)
                    else:
                        if prefix:
                            self.wfile.write(prefix)
                            self.wfile.flush()
                        # Once success/SSE headers are sent, never replay a partial
                        # completion or tool call. Only rejected 429s are retryable.
                        while chunk := response.read1(64 * 1024):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    return
                finally:
                    response.close()
                    conn.close()
        except (OSError, http.client.HTTPException) as exc:
            log.warning("model upstream connection failed (%s)", type(exc).__name__)
            if not headers_sent:
                self._json(502, {"error": {"message": "Model upstream connection failed"}})


def serve(router, args):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    host = urlsplit(args.upstream).hostname
    recovery = RouterRecovery(router, host)
    with ModelRelay(("127.0.0.1", args.port), args.upstream, router._port, recovery,
                    max_retries=args.max_retries, free_models=args.free_model,
                    timeout=args.timeout, retry_window=args.retry_window) as server:
        log.info("listening on 127.0.0.1:%d; upstream %s", args.port, host)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0
