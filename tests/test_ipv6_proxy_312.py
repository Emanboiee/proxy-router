"""Issue #312: ipv6 CONNECT proxy must parse bracketed IPv6 and gate targets."""

import importlib.util
import ipaddress
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "ipv6_proxy.py"


def _load_module():
    # ipv6_proxy computes PORT from sys.argv at import; pin argv so pytest
    # arguments do not blow up int() during load.
    with patch.object(sys, "argv", ["ipv6_proxy.py"]):
        spec = importlib.util.spec_from_file_location("ipv6_proxy_312", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class ParseTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_bracketed_ipv6_literal(self):
        self.assertEqual(self.mod.parse_target("[::1]:443"), ("::1", 443))

    def test_plain_hostname(self):
        self.assertEqual(self.mod.parse_target("example.com:443"),
                         ("example.com", 443))

    def test_plain_ipv4(self):
        self.assertEqual(self.mod.parse_target("127.0.0.1:8080"),
                         ("127.0.0.1", 8080))

    def test_malformed_target_rejected(self):
        for bad in ("", "example.com", "example.com:notaport", "[::1]"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.mod.parse_target(bad)


class AllowlistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_loopback_rejected_by_default(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            with self.subTest(host=host):
                self.assertFalse(self.mod.is_allowed(host))

    def test_alternate_loopback_spellings_rejected_by_default(self):
        # #312 R1: numeric/legacy/trailing-dot spellings still resolve to
        # loopback; the gate must deny them, not fail open.
        for host in ("127.1", "2130706433", "0x7f000001", "127.0.0.1.",
                     "0177.0.0.1"):
            with self.subTest(host=host):
                self.assertFalse(self.mod.is_allowed(host))

    def test_public_host_allowed_by_default(self):
        self.assertTrue(self.mod.is_allowed("example.com"))

    def test_allowlist_limits_destinations(self):
        with patch.dict(os.environ, {self.mod.ALLOW_ENV: "example.com"}):
            self.assertTrue(self.mod.is_allowed("example.com"))
            self.assertTrue(self.mod.is_allowed("api.example.com"))
            self.assertFalse(self.mod.is_allowed("evil.test"))

    def test_explicit_allowlist_can_permit_loopback(self):
        with patch.dict(os.environ, {self.mod.ALLOW_ENV: "127.0.0.1"}):
            self.assertTrue(self.mod.is_allowed("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
