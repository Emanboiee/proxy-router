"""Tests for explicit provider health-route selection and validation."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import router


class ProbeRouteSelectionTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            name: getattr(router, name)
            for name in ("_providers", "_routes", "_routing", "_egress_settings")
        }
        router._providers = {
            "proton": {
                "probe_url": "https://api.ipify.org",
                "probe_route_id": "opencode-zen",
            }
        }
        # Roblox is intentionally first: the explicit route must win.
        router._routes = [
            {"id": "roblox", "domains": ["roblox.com"], "provider": "proton"},
            {"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"},
        ]
        router._routing = {"mode": "default"}
        router._egress_settings = {}

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(router, name, value)

    def test_explicit_route_wins_over_route_order_and_pinned_url(self):
        self.assertEqual(
            router.probe_url_for("proton"),
            "https://opencode.ai/zen/v1/models",
        )

    def test_explicit_route_fails_closed_when_not_tunneled(self):
        router._routing = {"mode": "vpn-list", "vpn_domains": ["roblox.com"]}
        self.assertIsNone(router.probe_url_for("proton"))

    def test_provider_without_explicit_route_preserves_first_route_fallback(self):
        router._providers["proton"].pop("probe_route_id")
        self.assertEqual(router.probe_url_for("proton"), "https://roblox.com")


class ProbeRouteConfigValidationTests(unittest.TestCase):
    def _load(self, config):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name).resolve()
        (root / "providers" / "proton").mkdir(parents=True)
        old = {
            name: getattr(router, name)
            for name in ("ROOT", "CONFIG_FILE", "SING_BOX_CONFIG", "LAST_GOOD_FILE",
                         "PID_FILE", "LOG_FILE", "LOCK_FILE", "MODE_FILE",
                         "MANUAL_OFF_FILE")
        }
        router.ROOT = root
        router.CONFIG_FILE = root / "router.json"
        router.SING_BOX_CONFIG = root / "sing-box.json"
        router.LAST_GOOD_FILE = root / "sing-box.json.last-good"
        router.PID_FILE = root / "sing-box.pid"
        router.LOG_FILE = root / "sing-box.log"
        router.LOCK_FILE = root / "state" / "engine.lock"
        router.MODE_FILE = root / "state" / "mode"
        router.MANUAL_OFF_FILE = root / "state" / "manual-off"
        router.CONFIG_FILE.write_text(json.dumps(config))
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                return router.load_config()
        finally:
            for name, value in old.items():
                setattr(router, name, value)
            temp.cleanup()

    def _base(self, provider_entry, routes):
        return {
            "providers": {"proton": provider_entry},
            "routes": routes,
        }

    def test_valid_probe_route_is_accepted(self):
        config = self._base(
            {"directory": "providers/proton", "probe_route_id": "opencode-zen"},
            [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        )
        self.assertEqual(self._load(config), 0)

    def test_unknown_probe_route_is_rejected(self):
        config = self._base(
            {"directory": "providers/proton", "probe_route_id": "missing"},
            [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        )
        self.assertEqual(self._load(config), 1)

    def test_probe_route_owned_by_another_provider_is_rejected(self):
        config = {
            "providers": {
                "proton": {"directory": "providers/proton", "probe_route_id": "opencode-zen"},
                "cloudflare": {"directory": "providers/cloudflare"},
            },
            "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "cloudflare"}],
        }
        self.assertEqual(self._load(config), 1)

    def test_probe_route_without_domains_is_rejected(self):
        config = self._base(
            {"directory": "providers/proton", "probe_route_id": "opencode-zen"},
            [{"id": "opencode-zen", "domains": [], "provider": "proton"}],
        )
        self.assertEqual(self._load(config), 1)


if __name__ == "__main__":
    unittest.main()
