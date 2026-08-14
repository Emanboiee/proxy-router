"""Tests for setup_tui.py (stdlib only, no network, no private keys printed)."""
import io
import json
import os
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


class CustomPresetTests(unittest.TestCase):
    """Named presets: listing, apply-by-name, and custom preset creation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(setup_tui, self.root)
        self.config = self.root / "router.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_builtin_names_listed(self):
        names = setup_tui.preset_names(self.root)
        self.assertIn("school-warp", names)
        self.assertIn("default", names)

    def test_apply_school_warp_sets_vpn_list(self):
        result = setup_tui.apply_preset_by_name(self.root, "school-warp")
        self.assertEqual(result["mode"], "vpn-list")
        data = json.loads(self.config.read_text())
        self.assertEqual(data["routing"]["mode"], "vpn-list")
        self.assertIn("discord.com", data["routing"]["vpn_domains"])
        school = next(r for r in data["routes"] if r["id"] == "school")
        self.assertEqual(school["provider"], "cloudflare")
        self.assertIn("cloudflare", data["providers"])

    def test_apply_preset_idempotent(self):
        setup_tui.apply_preset_by_name(self.root, "school-warp")
        result = setup_tui.apply_preset_by_name(self.root, "school-warp")
        self.assertEqual(result["added"], [])
        data = json.loads(self.config.read_text())
        self.assertEqual(len([r for r in data["routes"] if r["id"] == "school"]), 1)

    def test_custom_preset_roundtrip(self):
        path = setup_tui.add_custom_preset(
            self.root, "mygames", "cloudflare", ["game.com", "play.net"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.name, "mygames.json")
        names = setup_tui.preset_names(self.root)
        self.assertIn("mygames", names)
        result = setup_tui.apply_preset_by_name(self.root, "mygames")
        self.assertEqual(result["mode"], "vpn-list")
        data = json.loads(self.config.read_text())
        self.assertIn("game.com", data["routing"]["vpn_domains"])
        route = next(r for r in data["routes"] if r["id"] == "mygames")
        self.assertEqual(route["provider"], "cloudflare")

    def test_custom_preset_safe_list_default_provider(self):
        path = setup_tui.add_custom_preset(
            self.root, "work", "proton", ["gmail.com", "drive.google.com"],
            mode="safe-list", default_provider="proton")
        preset = json.loads(path.read_text())
        self.assertEqual(preset["routing"]["mode"], "safe-list")
        self.assertEqual(preset["routing"]["default_provider"], "proton")
        self.assertIn("gmail.com", preset["routing"]["direct_domains"])

    def test_invalid_preset_name_rejected(self):
        with self.assertRaises(ValueError):
            setup_tui.add_custom_preset(self.root, "../evil", "proton", ["x.com"])

    def test_unknown_preset_raises(self):
        with self.assertRaises(ValueError):
            setup_tui.apply_preset_by_name(self.root, "nope-not-a-preset")


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


class BridgeTests(unittest.TestCase):
    """Hermes OpenCode auto-rotation bridge: installs/checks go to env paths only."""

    @staticmethod
    def _env(vpn_root: Path, tmp: Path) -> dict:
        return {
            "OPENCODE_ZEN_VPN_ROOT": str(vpn_root),
            "HERMES_CONFIG": str(tmp / "no-such-hermes.yaml"),
        }

    def test_bridge_check_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            vpn_root = Path(tmp) / "vpn"
            vpn_root.mkdir()
            out = io.StringIO()
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", out):
                rc = setup_tui._cmd_bridge_check()
            self.assertEqual(rc, 1)
            text = out.getvalue()
            self.assertIn("bridge: manager missing", text)
            for line in text.splitlines():
                self.assertTrue(line.startswith("bridge:"), line)

    def test_bridge_install_copies_and_validates(self):
        expected = (
            Path(setup_tui.__file__).resolve().parent / "examples" / "proxy-manager.sh"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            vpn_root = Path(tmp) / "vpn"
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", io.StringIO()), \
                 mock.patch("sys.stderr", io.StringIO()):
                rc = setup_tui._cmd_bridge_install(Path(tmp))
            self.assertEqual(rc, 0)
            target = vpn_root / "proxy-manager.sh"
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(vpn_root.stat().st_mode), 0o700)

    def test_bridge_install_idempotent(self):
        expected = (
            Path(setup_tui.__file__).resolve().parent / "examples" / "proxy-manager.sh"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            vpn_root = Path(tmp) / "vpn"
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", io.StringIO()), \
                 mock.patch("sys.stderr", io.StringIO()):
                first = setup_tui._cmd_bridge_install(Path(tmp))
            self.assertEqual(first, 0)
            target = vpn_root / "proxy-manager.sh"
            mtime = target.stat().st_mtime_ns
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", io.StringIO()), \
                 mock.patch("sys.stderr", io.StringIO()):
                second = setup_tui._cmd_bridge_install(Path(tmp))
            self.assertEqual(second, 0)
            self.assertEqual(target.stat().st_mtime_ns, mtime)
            self.assertEqual(target.read_bytes(), expected)

    def test_bridge_force_overwrites(self):
        expected = (
            Path(setup_tui.__file__).resolve().parent / "examples" / "proxy-manager.sh"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            vpn_root = Path(tmp) / "vpn"
            vpn_root.mkdir()
            target = vpn_root / "proxy-manager.sh"
            target.write_text("#!/bin/sh\necho stale\n")
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", io.StringIO()), \
                 mock.patch("sys.stderr", io.StringIO()):
                rc = setup_tui._cmd_bridge_install(Path(tmp), force=True)
            self.assertEqual(rc, 0)
            self.assertEqual(target.read_bytes(), expected)

    def test_bridge_flag_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            vpn_root = Path(tmp) / "vpn"
            vpn_root.mkdir()
            out = io.StringIO()
            with mock.patch.dict(os.environ, self._env(vpn_root, Path(tmp))), \
                 mock.patch("sys.stdout", out):
                rc = setup_tui.main(["setup", "--bridge-check"])
            self.assertEqual(rc, 1)
            self.assertIn("bridge:", out.getvalue())

    def test_tui_item_9_records_bridge_action(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "9")
        self.assertEqual(state.action, ("bridge_install",))
        self.assertFalse(state.quit)


class FullScreenTuiTests(unittest.TestCase):
    """Pure render/apply_key functions and wizard entry paths (no real TTY)."""

    def test_render_menu_frame_has_borders_and_items(self):
        state = setup_tui.TuiState()
        frame = setup_tui.render_frame(state)
        joined = "\n".join(frame)
        self.assertIn("\u250c", joined)
        self.assertIn("\u2514", joined)
        self.assertIn("\u2502", joined)
        self.assertIn("proxy-router setup", joined)
        self.assertIn("Start proxy-router", joined)
        self.assertIn("Stop proxy-router", joined)
        self.assertIn("Add a VPN provider", joined)
        self.assertIn("TUN mode toggle", joined)
        self.assertIn("rotation & autoroute", joined)
        self.assertIn("Check provider health", joined)
        self.assertIn("Quit", joined)
        self.assertIn("\u2191\u2193 navigate", joined)

    def test_apply_key_moves_cursor_and_returns_new_state(self):
        state = setup_tui.TuiState()
        down = setup_tui.apply_key(state, "\x1b[B")
        self.assertEqual(down.cursor, 1)
        self.assertEqual(state.cursor, 0)  # original state untouched (pure)
        self.assertNotEqual(id(down), id(state))
        j = setup_tui.apply_key(down, "j")
        self.assertEqual(j.cursor, 2)
        up = setup_tui.apply_key(j, "\x1b[A")
        self.assertEqual(up.cursor, 1)
        k = setup_tui.apply_key(up, "k")
        self.assertEqual(k.cursor, 0)
        wrapped = setup_tui.apply_key(state, "\x1b[A")
        self.assertEqual(wrapped.cursor, len(setup_tui.TUI_MENU) - 1)

    def test_enter_on_guide_builds_pager_with_guide_text(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")  # provider wizard
        state = setup_tui.apply_key(state, "1")  # proton guide
        self.assertEqual(state.view, "guide")
        self.assertEqual(state.guide_provider, "proton")
        self.assertTrue(state.guide_lines)
        self.assertTrue(state.provider_wizard_import)
        frame = setup_tui.render_frame(state)
        joined = "\n".join(frame)
        self.assertIn("Show Proton VPN guide", joined)
        self.assertIn("i import", joined)
        self.assertIn("q back", joined)
        self.assertIn("WireGuard", joined)  # guide body is visible inside the pager

    def test_guide_scroll_and_back_to_menu(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")  # provider wizard
        state = setup_tui.apply_key(state, "2")  # warp guide
        self.assertEqual(state.view, "guide")
        self.assertEqual(state.guide_provider, "warp")
        scrolled = setup_tui.apply_key(state, "\x1b[B")
        self.assertEqual(scrolled.guide_scroll, 1)
        scrolled = setup_tui.apply_key(scrolled, "\x1b[A")
        self.assertEqual(scrolled.guide_scroll, 0)
        back = setup_tui.apply_key(scrolled, "q")
        self.assertEqual(back.view, "provider")  # wizard continuation
        back = setup_tui.apply_key(back, "q")
        self.assertEqual(back.view, "menu")

    def test_q_esc_ctrl_c_and_zero_quit(self):
        for key in ("q", "Q", "\x1b", "\x03", "0"):
            state = setup_tui.apply_key(setup_tui.TuiState(), key)
            self.assertTrue(state.quit, repr(key))

    def test_import_editing_and_enter_records_action(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")  # provider wizard
        state = setup_tui.apply_key(state, "1")  # proton guide
        state = setup_tui.apply_key(state, "i")  # jump to import
        self.assertEqual(state.view, "import")
        self.assertEqual(state.import_provider, "proton")
        for ch in "/tmp/conf.d":
            state = setup_tui.apply_key(state, ch)
        self.assertEqual(state.import_text, "/tmp/conf.d")
        state = setup_tui.apply_key(state, "\x7f")
        self.assertEqual(state.import_text, "/tmp/conf.")
        state = setup_tui.apply_key(state, "\r")
        self.assertEqual(state.view, "menu")
        self.assertEqual(state.action, ("import", "proton", "/tmp/conf."))

    def test_import_escape_cancels(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")  # provider wizard
        state = setup_tui.apply_key(state, "2")  # warp guide
        state = setup_tui.apply_key(state, "i")  # jump to import
        self.assertEqual(state.import_provider, "cloudflare")
        state = setup_tui.apply_key(state, "/some/path")
        state = setup_tui.apply_key(state, "\x1b")
        self.assertEqual(state.view, "provider")  # wizard continuation
        self.assertIsNone(state.action)

    def test_non_tty_falls_back_to_plain_line_menu(self):
        root = Path(tempfile.mkdtemp())
        fake_in = io.StringIO("q\n")
        fake_out = io.StringIO()
        with mock.patch("sys.stdin", fake_in), mock.patch("sys.stdout", fake_out):
            rc = setup_tui.wizard(root)
        self.assertEqual(rc, 0)
        text = fake_out.getvalue()
        self.assertIn("proxy-router setup wizard", text)  # old plain banner
        self.assertNotIn("\x1b[?1049h", text)  # alternate screen never opened
        self.assertNotIn("\x1b[?25l", text)

    def test_tui_session_renders_frames_and_restores_screen(self):
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

            def fileno(self):
                return 1

        root = Path(tempfile.mkdtemp())
        fake_in = FakeTTY()
        fake_out = FakeTTY()
        events = iter(["3", "1", "\x1b[B", "q", "q", "q"])  # provider wizard, proton guide, scroll, back, back, quit
        with mock.patch("sys.stdin", fake_in), \
             mock.patch("sys.stdout", fake_out), \
             mock.patch("setup_tui._read_key", side_effect=lambda: next(events)), \
             mock.patch("setup_tui.tty.setraw"), \
             mock.patch("setup_tui.termios.tcgetattr", return_value=[1, 2, 3, 4, 5, 6]), \
             mock.patch("setup_tui.termios.tcsetattr"):
            rc = setup_tui.wizard(root)
        self.assertEqual(rc, 0)
        text = fake_out.getvalue()
        self.assertTrue(text.startswith("\x1b[?1049h"))  # entered alternate screen
        self.assertIn("Start proxy-router", text)         # frame rendered
        self.assertIn("Show Proton VPN guide", text)      # guide pager rendered
        self.assertIn("\u250c", text)
        self.assertTrue(text.rstrip().endswith("\x1b[?25h\x1b[?1049l"))  # restored
    def test_provider_tint_keeps_guide_frame_width(self):
        state = setup_tui.TuiState(view="guide", guide_provider="proton", cols=40, rows=18)
        state.guide_lines = ["guide"]
        with mock.patch.object(setup_tui, "ANSI", True):
            frame = setup_tui.render_frame(state)
        self.assertEqual(len(setup_tui._strip_ansi(frame[1])), state.cols)
        self.assertIn("Proton", setup_tui._strip_ansi(frame[1]))


class ControlCenterTuiTests(unittest.TestCase):
    """Control-center menu: engine start/stop, VPN toggle, provider wizard and
    rotation settings record actions; the wizard loop executes them."""

    def test_menu_lists_engine_and_vpn_items(self):
        keys = {key for key, _ in setup_tui.TUI_MENU}
        for key in ("1", "2", "3", "4", "5"):
            self.assertIn(key, keys)

    def test_engine_start_records_action(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "1")
        self.assertEqual(state.action, ("engine_start",))
        self.assertEqual(state.view, "menu")

    def test_engine_stop_records_action(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "2")
        self.assertEqual(state.action, ("engine_stop",))

    def test_vpn_toggle_records_action(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "4")
        self.assertEqual(state.action, ("vpn_toggle",))

    def test_provider_wizard_opens_and_esc_returns(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")
        self.assertEqual(state.view, "provider")
        esc = setup_tui.apply_key(state, "\x1b")
        self.assertEqual(esc.view, "menu")

    def test_provider_wizard_guide_then_import(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "3")
        state = setup_tui.apply_key(state, "2")  # warp guide
        self.assertEqual(state.view, "guide")
        self.assertEqual(state.guide_provider, "warp")
        state = setup_tui.apply_key(state, "i")
        self.assertEqual(state.view, "import")
        self.assertEqual(state.import_provider, "cloudflare")

    def test_rotation_view_opens_and_esc_returns(self):
        state = setup_tui.apply_key(setup_tui.TuiState(), "5")
        self.assertEqual(state.view, "rotation")
        joined = "\n".join(setup_tui.render_frame(state))
        self.assertIn("interval_seconds", joined)
        esc = setup_tui.apply_key(state, "\x1b")
        self.assertEqual(esc.view, "menu")

    def test_rotation_interval_prompt_returns_to_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({"port": 2080}))
            state = setup_tui.apply_key(setup_tui.TuiState(root=root), "5")
            state = setup_tui.apply_key(state, "1")
            self.assertEqual(state.view, "routing_prompt")
            self.assertEqual(state.prompt_return_view, "rotation")
            for ch in "3600":
                state = setup_tui.apply_key(state, ch)
            state = setup_tui.apply_key(state, "\r")
            self.assertEqual(state.action, ("rotation_set", "interval_seconds", "3600"))
            self.assertEqual(state.view, "rotation")
            prompt = setup_tui.apply_key(setup_tui.TuiState(root=root), "5")
            prompt = setup_tui.apply_key(prompt, "2")
            prompt = setup_tui.apply_key(prompt, "\x1b")
            self.assertEqual(prompt.view, "rotation")
            self.assertIsNone(prompt.action)

    def test_rotation_policy_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({"rotation": {"policy": "latency"}}))
            state = setup_tui.apply_key(setup_tui.TuiState(root=root), "5")
            state = setup_tui.apply_key(state, "3")
            self.assertEqual(state.action, ("rotation_set", "policy", "least-recent"))

    def test_rotation_set_executes_and_writes_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "router.json").write_text(json.dumps({"port": 2080}))
            text, rc = setup_tui._execute_action(
                ("rotation_set", "interval_seconds", "3600"), root)
            self.assertEqual(rc, 0, text)
            data = json.loads((root / "router.json").read_text())
            self.assertEqual(data["rotation"]["interval_seconds"], 3600)
            text, rc = setup_tui._execute_action(("rotation_set", "policy", "bogus"), root)
            self.assertEqual(rc, 1, text)

    def test_read_vpn_mode_defaults_to_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(setup_tui._read_vpn_mode(root), "proxy")
            mode = root / "state" / "mode"
            mode.parent.mkdir(parents=True)
            mode.write_text("tun")
            self.assertEqual(setup_tui._read_vpn_mode(root), "tun")


class RoutingTuiTests(unittest.TestCase):
    """TUI surface for routing modes: menu item, read-only view, and routing
    changes executed through the single ``router.py routing`` CLI writer."""

    def _seed(self, root: Path, routing=None) -> None:
        (root / "providers" / "proton").mkdir(parents=True)
        data = {"port": 2080, "providers": {"proton": {"directory": "providers/proton"}}, "routes": []}
        if routing is not None:
            data["routing"] = routing
        (root / "router.json").write_text(json.dumps(data))

    def test_menu_lists_routing_modes(self):
        self.assertIn(("r", "Routing modes (show / switch / add-remove domain)"), setup_tui.TUI_MENU)
        self.assertIn(("s", "Presets: apply by name / create custom (built-in + custom)"), setup_tui.TUI_MENU)

    def test_routing_actions_include_preset_by_name(self):
        self.assertEqual(setup_tui._ROUTING_ACTIONS[-1][0], "7")

    def test_routing_view_opens_and_reflects_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seed(root, {"mode": "safe-list", "direct_domains": ["youtube.com"],
                              "default_provider": "proton"})
            state = setup_tui.apply_key(setup_tui.TuiState(root=root), "r")
            self.assertEqual(state.view, "routing")
            joined = "\n".join(setup_tui.render_frame(state))
            self.assertIn("mode: safe-list", joined)
            self.assertIn("youtube.com", joined)
            esc = setup_tui.apply_key(state, "\x1b")
            self.assertEqual(esc.view, "menu")

    def test_routing_prompt_records_cli_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seed(root)
            state = setup_tui.apply_key(setup_tui.TuiState(root=root), "r")
            state = setup_tui.apply_key(state, "3")  # add direct domain
            self.assertEqual(state.view, "routing_prompt")
            for ch in "youtube.com":
                state = setup_tui.apply_key(state, ch)
            state = setup_tui.apply_key(state, "\r")
            self.assertEqual(state.action,
                             ("routing", "add", "--mode", "safe-list", "--domain", "youtube.com"))
            # empty input cancels instead of recording an action
            state = setup_tui.apply_key(setup_tui.TuiState(root=root), "r")
            state = setup_tui.apply_key(state, "3")
            state = setup_tui.apply_key(state, "\r")
            self.assertIsNone(state.action)
            self.assertFalse(state.status_ok)

    def test_routing_change_goes_through_router_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seed(root)
            text, rc = setup_tui._execute_action(
                ("routing", "set", "--mode", "safe-list", "--default-provider", "proton"), root)
            self.assertEqual(rc, 0, text)
            data = json.loads((root / "router.json").read_text())
            self.assertEqual(data["routing"]["mode"], "safe-list")
            text, rc = setup_tui._execute_action(
                ("routing", "add", "--mode", "safe-list", "--domain", "youtube.com"), root)
            self.assertEqual(rc, 0, text)
            data = json.loads((root / "router.json").read_text())
            self.assertEqual(data["routing"]["direct_domains"], ["youtube.com"])
            self.assertIn("NOT reloaded", text)


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
