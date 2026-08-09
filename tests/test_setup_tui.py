"""Tests for setup_tui.py (stdlib only, no network, no private keys printed)."""
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import setup_tui


def _relocate(module, root: Path) -> None:
    module.ROOT = root


def _write_valid_conf(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Interface]\n"
        "Address = 10.2.0.2/32\n"
        "PrivateKey = aaaabbbbccccdddd\n"
        "DNS = 10.2.0.1\n"
        "[Peer]\n"
        "PublicKey = xbbzzww\n"
        "Endpoint = 1.2.3.4:51820\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
    )


class GuideTextTests(unittest.TestCase):
    """guide_text returns the content of the bundled markdown guide."""

    def test_proton_guide_loads(self):
        text = setup_tui.guide_text("proton")
        self.assertIn("Proton VPN", text)
        self.assertIn("WireGuard", text)

    def test_warp_guide_loads(self):
        text = setup_tui.guide_text("warp")
        self.assertIn("WARP", text)
        self.assertIn("wgcf", text)

    def test_all_returns_combined_guides(self):
        text = setup_tui.guide_text("all")
        self.assertIn("Proton VPN", text)
        self.assertIn("WARP", text)

    def test_unknown_provider_returns_empty(self):
        text = setup_tui.guide_text("nonexistent")
        self.assertEqual(text, "")


class ImportProfilesTests(unittest.TestCase):
    """import_profiles copies valid .conf files, rejects invalid, sets mode 0600."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(setup_tui, self.root)
        self.dest = self.root / "providers" / "proton"
        self.dest.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_import_single_conf(self):
        src = self.root / "test.conf"
        _write_valid_conf(src)
        result = setup_tui.import_profiles(src, self.dest)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["rejected"], 0)
        dest_file = self.dest / "test.conf"
        self.assertTrue(dest_file.exists())
        mode = stat.S_IMODE(dest_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_import_directory_of_confs(self):
        src_dir = self.root / "downloads"
        src_dir.mkdir()
        _write_valid_conf(src_dir / "a.conf")
        _write_valid_conf(src_dir / "b.conf")
        result = setup_tui.import_profiles(src_dir, self.dest)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["rejected"], 0)

    def test_reject_missing_file(self):
        result = setup_tui.import_profiles(self.root / "nope.conf", self.dest)
        self.assertEqual(result["imported"], 0)
        self.assertEqual(result["rejected"], 1)

    def test_reject_invalid_conf(self):
        src = self.root / "bad.conf"
        src.write_text("not a wireguard config\n")
        result = setup_tui.import_profiles(src, self.dest)
        self.assertEqual(result["imported"], 0)
        self.assertEqual(result["rejected"], 1)

    def test_does_not_print_private_key(self):
        src = self.root / "secret.conf"
        _write_valid_conf(src)
        with mock.patch("builtins.print") as mock_print:
            setup_tui.import_profiles(src, self.dest)
        for call in mock_print.call_args_list:
            self.assertNotIn("aaaabbbbccccdddd", str(call))

    def test_safe_name_sanitizes(self):
        src = self.root / "my server (1).conf"
        _write_valid_conf(src)
        result = setup_tui.import_profiles(src, self.dest)
        self.assertEqual(result["imported"], 1)
        # Should be sanitized to a safe filename
        files = list(self.dest.glob("*.conf"))
        self.assertEqual(len(files), 1)
        self.assertNotIn(" ", files[0].name)
        self.assertNotIn("(", files[0].name)


class ApplyPresetsTests(unittest.TestCase):
    """apply_presets is idempotent and preserves unrelated routes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(setup_tui, self.root)
        self.config = self.root / "router.json"
        self.config.write_text(json.dumps({
            "port": 2080,
            "providers": {
                "proton": {"directory": "providers/proton", "cooldown_seconds": 60}
            },
            "routes": [
                {"id": "existing", "domains": ["existing.com"], "provider": "proton"}
            ],
            "vpn": {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"}
        }, indent=2) + "\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_adds_opencode_route(self):
        result = setup_tui.apply_presets(self.config)
        self.assertEqual(result["added"], ["opencode-zen", "roblox"])
        data = json.loads(self.config.read_text())
        route = next(r for r in data["routes"] if r["id"] == "opencode-zen")
        self.assertEqual(route["domains"], ["opencode.ai"])
        self.assertEqual(route["provider"], "proton")

    def test_adds_roblox_route(self):
        result = setup_tui.apply_presets(self.config)
        self.assertIn("roblox", [r["id"] for r in json.loads(self.config.read_text())["routes"]])

    def test_idempotent_does_not_duplicate(self):
        setup_tui.apply_presets(self.config)
        result = setup_tui.apply_presets(self.config)
        self.assertEqual(result["added"], [])
        data = json.loads(self.config.read_text())
        opencode_routes = [r for r in data["routes"] if r["id"] == "opencode-zen"]
        self.assertEqual(len(opencode_routes), 1)

    def test_preserves_existing_routes(self):
        setup_tui.apply_presets(self.config)
        data = json.loads(self.config.read_text())
        self.assertIn({"id": "existing", "domains": ["existing.com"], "provider": "proton"}, data["routes"])

    def test_adds_cloudflare_provider_if_missing(self):
        setup_tui.apply_presets(self.config)
        data = json.loads(self.config.read_text())
        self.assertIn("cloudflare", data["providers"])

    def test_preserves_existing_providers(self):
        setup_tui.apply_presets(self.config)
        data = json.loads(self.config.read_text())
        self.assertEqual(data["providers"]["proton"]["cooldown_seconds"], 60)


class CheckTests(unittest.TestCase):
    """check reports provider profile availability without network."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(setup_tui, self.root)
        self.config = self.root / "router.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_check_passes_with_valid_profiles(self):
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_valid_conf(self.root / "providers" / "proton" / "a.conf")
        self.config.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": []
        }))
        result = setup_tui.check(self.root)
        self.assertEqual(result["ok"], True)

    def test_check_fails_without_profiles(self):
        (self.root / "providers" / "proton").mkdir(parents=True)
        self.config.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": []
        }))
        result = setup_tui.check(self.root)
        self.assertEqual(result["ok"], False)
        self.assertIn("proton", result["issues"][0].lower())


if __name__ == "__main__":
    unittest.main()
