"""F09: probe targets are validated at the connection, across every resolved
address and every redirect hop."""
from __future__ import annotations

import importlib.util
import socket
import sys
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load(name: str):
    modname = f"f09_{name}"
    spec = importlib.util.spec_from_file_location(modname, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


def _addrinfo(count: int):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"93.184.216.{i}", 0))
        for i in range(1, count + 1)
    ]


class ResolverCoverageTests(unittest.TestCase):
    def test_router_resolver_examines_every_address(self):
        router = _load("router")
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo(12)):
            addresses = router.resolve_target_addresses("https://example.com/")
        self.assertEqual(len(addresses), 12)

    def test_monitor_resolver_examines_every_address_and_dedupes(self):
        monitor = _load("monitor")
        entries = _addrinfo(12) + _addrinfo(12)
        with mock.patch("socket.getaddrinfo", return_value=entries):
            addresses = monitor.resolve_target_addresses("https://example.com/")
        self.assertEqual(len(addresses), 12)


class RedirectHopTests(unittest.TestCase):
    def setUp(self):
        self.monitor = _load("monitor")
        self.handler = self.monitor._ValidatedRedirectHandler()
        self.request = urllib.request.Request("https://example.com/")

    def _redirect(self, target: str):
        return self.handler.redirect_request(
            self.request, None, 302, "Found", {}, target
        )

    def test_private_hop_is_refused(self):
        with mock.patch.object(self.monitor, "resolve_target_addresses", return_value=[]):
            self.assertIsNone(self._redirect("http://127.0.0.1:2080/"))

    def test_metadata_hop_is_refused(self):
        with mock.patch.object(self.monitor, "resolve_target_addresses", return_value=[]):
            self.assertIsNone(self._redirect("http://169.254.169.254/latest/meta-data/"))

    def test_dns_rebinding_hop_is_refused(self):
        target = "https://rebind.example/"
        with mock.patch.object(
            self.monitor, "resolve_target_addresses", return_value=["10.0.0.8"]
        ) as resolve:
            self.assertIsNone(self._redirect(target))
        resolve.assert_called_once_with(target)

    def test_public_hop_still_follows(self):
        target = "https://example.org/"
        with mock.patch.object(
            self.monitor, "resolve_target_addresses", return_value=["93.184.216.34"]
        ):
            redirected = self._redirect(target)
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.full_url, target)

if __name__ == "__main__":
    unittest.main()
