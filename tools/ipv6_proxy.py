#!/usr/bin/env python3
"""IPv6-preferring CONNECT proxy.

opencode-zen's free tier is quota'd per source IP. The home IPv4 address is
burned (429 FreeUsageLimitError) while the IPv6 lane still has quota — the
opencode CLI works because Node dials IPv6 first, hermes fails because Python
dials IPv4 first. This proxy lets any client (hermes) reach https endpoints
over IPv6, with IPv4 as fallback for hosts without AAAA records.

Usage: ipv6_proxy.py [port]   (default 2081, binds 127.0.0.1)
Point https_proxy at it; add NO_PROXY=127.0.0.1,localhost so local providers
(freellm, lami, zcode) bypass it.
"""

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2081
BUFSIZE = 65536


class Ipv6ConnectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep stdout quiet
        pass

    def _dial(self, host: str, port: int) -> socket.socket | None:
        """Connect to host:port preferring IPv6 (zen quota is per-IP; the
        IPv4 lane is burned). Falls back to IPv4 only when no AAAA exists."""
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
        except OSError:
            return None
        v6 = [i for i in infos if i[0] == socket.AF_INET6]
        candidates = v6 + [i for i in infos if i[0] == socket.AF_INET]
        for family, stype, proto, _, addr in candidates:
            sock = None
            try:
                sock = socket.socket(family, stype, proto)
                sock.settimeout(10)
                sock.connect(addr)
                sock.settimeout(None)
                return sock
            except OSError:
                if sock is not None:
                    sock.close()
        return None

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(BUFSIZE)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        try:
            port = int(port)
        except ValueError:
            self.send_error(400)
            return
        upstream = self._dial(host, port)
        if upstream is None:
            self.send_error(502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        # client -> upstream in a thread; upstream -> client inline
        threading.Thread(target=self._pump,
                         args=(self.connection, upstream), daemon=True).start()
        self._pump(upstream, self.connection)
        for s in (upstream, self.connection):
            try:
                s.close()
            except OSError:
                pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Ipv6ConnectHandler)
    print(f"ipv6-proxy on 127.0.0.1:{PORT}")
    server.serve_forever()
