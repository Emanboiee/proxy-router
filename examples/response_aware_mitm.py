#!/usr/bin/env python3
"""Response-aware mitmproxy addon for routed OpenCode traffic.

Run only in the opt-in response-aware mode. The addon observes matching 429
responses, asks proxy-router to rotate the effective egress, and retries one
fully buffered request through the existing sing-box HTTP proxy. It deliberately
never logs request headers or bodies.
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http


DEFAULT_HOSTS = ("opencode.ai",)
DEFAULT_UPSTREAM = "http://127.0.0.1:2080"
DEFAULT_MAX_RETRY_BYTES = 4 * 1024 * 1024
DEFAULT_EVENT_TIMEOUT = 120.0
DEFAULT_RETRY_TIMEOUT = 120.0
HOP_BY_HOP_REQUEST_HEADERS = frozenset({
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})
HOP_BY_HOP_RESPONSE_HEADERS = frozenset({
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return max(1.0, float(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _host_matches(host: str, domain: str) -> bool:
    host = str(host or "").strip().lower().rstrip(".")
    domain = str(domain or "").strip().lower().lstrip("*.").rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


class ResponseAwareOpenCode:
    """Observe configured upstream errors and perform one safe retry."""

    def __init__(self) -> None:
        configured = os.environ.get("RESPONSE_AWARE_HOSTS", "opencode.ai")
        self.hosts = tuple(item.strip().lower() for item in configured.split(",") if item.strip()) or DEFAULT_HOSTS
        self.upstream = os.environ.get("RESPONSE_AWARE_UPSTREAM", DEFAULT_UPSTREAM)
        self.max_retry_bytes = _env_int("RESPONSE_AWARE_MAX_RETRY_BYTES", DEFAULT_MAX_RETRY_BYTES)
        self.event_timeout = _env_float("RESPONSE_AWARE_EVENT_TIMEOUT", DEFAULT_EVENT_TIMEOUT)
        self.retry_timeout = _env_float("RESPONSE_AWARE_RETRY_TIMEOUT", DEFAULT_RETRY_TIMEOUT)
        self.router_root = Path(os.environ.get("PROXY_ROUTER_ROOT", str(Path(__file__).resolve().parents[1])))
        self.router_bin = Path(os.environ.get("PROXY_ROUTER_BIN", str(self.router_root / "router.py")))

    def _is_target(self, host: str) -> bool:
        return any(_host_matches(host, domain) for domain in self.hosts)

    def _router_command(self, host: str, status: int) -> list[str]:
        return [
            sys.executable,
            str(self.router_bin),
            "response-event",
            "--host",
            host,
            "--status",
            str(status),
        ]

    def _rotate(self, host: str, status: int) -> bool:
        env = dict(os.environ)
        env["PROXY_ROUTER_ROOT"] = str(self.router_root)
        try:
            result = subprocess.run(
                self._router_command(host, status),
                cwd=str(self.router_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.event_timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            ctx.log.error(f"response-aware rotation failed: {type(exc).__name__}")
            return False
        if result.returncode != 0:
            ctx.log.error(f"response-aware rotation returned {result.returncode}")
            return False
        ctx.log.info("response-aware rotation completed")
        return True

    def _retry_request(self, flow: http.HTTPFlow) -> http.Response | None:
        request_body = flow.request.raw_content or b""
        if len(request_body) > self.max_retry_bytes:
            ctx.log.warn("response-aware retry skipped: request body exceeds configured limit")
            return None
        headers: dict[str, str] = {}
        for key, value in flow.request.headers.items():
            if key.lower() not in HOP_BY_HOP_REQUEST_HEADERS:
                headers[str(key)] = str(value)
        method = str(flow.request.method or "GET").upper()
        data = request_body if method not in {"GET", "HEAD"} else None
        request = urllib.request.Request(
            flow.request.pretty_url,
            data=data,
            headers=headers,
            method=method,
        )
        proxy_handler = urllib.request.ProxyHandler(
            {} if not self.upstream or self.upstream.lower() == "direct"
            else {"http": self.upstream, "https": self.upstream}
        )
        opener = urllib.request.build_opener(proxy_handler)
        try:
            response = opener.open(request, timeout=self.retry_timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        except (OSError, urllib.error.URLError) as exc:
            ctx.log.error(f"response-aware retry failed: {type(exc).__name__}")
            return None
        try:
            body = response.read(self.max_retry_bytes + 1)
            if len(body) > self.max_retry_bytes:
                ctx.log.warn("response-aware retry skipped: response body exceeds configured limit")
                return None
            response_headers = {
                str(key): str(value)
                for key, value in response.headers.items()
                if key.lower() not in HOP_BY_HOP_RESPONSE_HEADERS
            }
            return http.Response.make(int(response.status), body, response_headers)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def response(self, flow: http.HTTPFlow) -> None:
        response = flow.response
        host = str(flow.request.host or "")
        if response is None or response.status_code != 429 or not self._is_target(host):
            return
        if flow.metadata.get("response_aware_retried"):
            return
        flow.metadata["response_aware_retried"] = True
        if not self._rotate(host, int(response.status_code)):
            return
        replacement = self._retry_request(flow)
        if replacement is not None:
            flow.response = replacement
            ctx.log.info("response-aware retry replaced upstream 429")


addons = [ResponseAwareOpenCode()]
