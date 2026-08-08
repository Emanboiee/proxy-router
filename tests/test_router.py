"""Unit tests for router.py (stdlib only, no third-party deps, no network)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router


def _relocate(module, root: Path) -> None:
    """Point every module-level runtime path at ``root`` for test isolation."""
    module.ROOT = Path(root).resolve()
    module.CONFIG_FILE = module.ROOT / "router.json"
    module.SING_BOX_CONFIG = module.ROOT / "sing-box.json"
    module.PID_FILE = module.ROOT / "sing-box.pid"
    module.LOG_FILE = module.ROOT / "sing-box.log"
    module.LOCK_FILE = module.ROOT / "state" / "engine.lock"
    module.MODE_FILE = module.ROOT / "state" / "mode"


def _write_conf(path: Path, *, psk: bool = True, mtu: bool = True, keepalive: bool = True) -> None:
    lines = [
        "[Interface]",
        "Address = 10.2.0.2/32",
        "PrivateKey = aaaabbbbccccdddd",
        "DNS = 10.2.0.1",
    ]
    if mtu:
        lines.append("MTU = 1420")
    lines += ["", "[Peer]", "PublicKey = xbbzzww", "Endpoint = 1.2.3.4:51820", "AllowedIPs = 0.0.0.0/0, ::/0"]
    if psk:
        lines.append("PresharedKey = pskpskpskpsk")
    if keepalive:
        lines.append("PersistentKeepalive = 25")
    path.write_text("\n".join(lines) + "\n")


class WireGuardParseTests(unittest.TestCase):
    def test_parse_wireguard_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "profile.conf"
            _write_conf(conf)
            endpoint = router.parse_wireguard(conf)
            self.assertEqual(endpoint["type"], "wireguard")
            self.assertEqual(endpoint["address"], ["10.2.0.2/32"])
            self.assertEqual(endpoint["private_key"], "aaaabbbbccccdddd")
            peer = endpoint["peers"][0]
            self.assertEqual(peer["address"], "1.2.3.4")  # literal IP, no DNS lookup
            self.assertEqual(peer["port"], 51820)
            self.assertEqual(peer["public_key"], "xbbzzww")
            self.assertEqual(peer["allowed_ips"], ["0.0.0.0/0", "::/0"])
            self.assertEqual(peer["pre_shared_key"], "pskpskpskpsk")
            self.assertEqual(peer["persistent_keepalive_interval"], 25)
            self.assertEqual(endpoint["mtu"], 1420)

    def test_parse_wireguard_optional_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "profile.conf"
            _write_conf(conf, psk=False, mtu=False, keepalive=False)
            endpoint = router.parse_wireguard(conf)
            self.assertNotIn("pre_shared_key", endpoint["peers"][0])
            self.assertNotIn("persistent_keepalive_interval", endpoint["peers"][0])
            self.assertNotIn("mtu", endpoint)


class ConfigBuildTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        (self.root / "providers" / "cloudflare").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        router._providers = {
            "proton": {"directory": "providers/proton", "cooldown_seconds": 60},
            "cloudflare": {"directory": "providers/cloudflare", "cooldown_seconds": 60},
        }
        router._routes = [
            {"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"},
            {"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"},
        ]
        router._port = 2080

    def tearDown(self):
        self._tmp.cleanup()

    def test_build_config_maps_routes_and_skips_empty_provider(self):
        config, active = router.build_singbox_config()
        self.assertEqual(active, {"proton"})
        self.assertEqual([e["tag"] for e in config["endpoints"]], ["proton"])
        dns_tags = [s["tag"] for s in config["dns"]["servers"]]
        self.assertIn("dns-proton", dns_tags)
        self.assertNotIn("dns-cloudflare", dns_tags)
        self.assertIn("dns-local", dns_tags)
        self.assertEqual(
            next(s for s in config["dns"]["servers"] if s["tag"] == "dns-proton")["server"],
            "10.2.0.1",
        )
        self.assertEqual(config["dns"]["rules"], [{"domain_suffix": ["opencode.ai"], "server": "dns-proton"}])
        self.assertEqual(config["dns"]["strategy"], "ipv4_only")
        rules = config["route"]["rules"]
        self.assertIn({"outbound": "proton", "domain_suffix": ["opencode.ai"]}, rules)
        self.assertNotIn({"outbound": "cloudflare", "domain_suffix": ["roblox.com"]}, rules)


class RoutesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}],
        }))
        self.assertEqual(router.load_config(), 0)

    def tearDown(self):
        self._tmp.cleanup()

    def test_routes_add_writes_id_and_roundtrips(self):
        key, id_ = router._routes_add_entry("example.com", "domains", None, "proton")
        self.assertEqual((key, id_), ("domains", "example-com"))
        self.assertEqual(router.save_config(), 0)
        data = json.loads(router.CONFIG_FILE.read_text())
        self.assertIn({"id": "example-com", "domains": ["example.com"], "provider": "proton"}, data["routes"])

    def test_routes_add_rejects_unknown_provider(self):
        self.assertIsNone(router._routes_add_entry("example.com", "domains", None, "nope"))

    def test_routes_remove_roundtrip(self):
        self.assertTrue(router._routes_remove_entry("opencode"))
        self.assertEqual(router.save_config(), 0)
        data = json.loads(router.CONFIG_FILE.read_text())
        self.assertEqual(data["routes"], [])
        self.assertFalse(router._routes_remove_entry("opencode"))


class RotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        for name in ("a", "b"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}

    def tearDown(self):
        self._tmp.cleanup()

    def test_fresh_profile_chosen_when_active_is_hot(self):
        a = self.root / "providers" / "proton" / "a.conf"
        router.set_active("proton", a)
        router.mark_cooldown("proton", a, 60)
        self.assertEqual(router.resolve_active("proton").name, "b.conf")

    def test_active_profile_kept_when_not_cooled(self):
        b = self.root / "providers" / "proton" / "b.conf"
        router.set_active("proton", b)
        self.assertEqual(router.resolve_active("proton").name, "b.conf")

    def test_all_cooled_returns_none(self):
        for name in ("a", "b"):
            router.mark_cooldown("proton", self.root / "providers" / "proton" / f"{name}.conf", 60)
        self.assertIsNone(router.resolve_active("proton"))


class VpnModeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"}

    def tearDown(self):
        self._tmp.cleanup()

    def test_mode_defaults_to_proxy(self):
        self.assertEqual(router.current_mode(), "proxy")

    def test_set_mode_roundtrips(self):
        router.set_mode("tun")
        self.assertEqual(router.current_mode(), "tun")
        router.set_mode("proxy")
        self.assertEqual(router.current_mode(), "proxy")

    def test_tun_mode_builds_tun_inbound(self):
        router.set_mode("tun")
        config, _ = router.build_singbox_config()
        inbounds = config["inbounds"]
        self.assertEqual(len(inbounds), 1)
        self.assertEqual(inbounds[0]["type"], "tun")
        self.assertEqual(inbounds[0]["address"], ["172.19.0.1/30"])
        self.assertEqual(inbounds[0]["stack"], "system")
        self.assertTrue(inbounds[0]["auto_route"])
        self.assertEqual(config["route"]["final"], "direct")

    def test_proxy_mode_builds_mixed_inbound(self):
        router.set_mode("proxy")
        config, _ = router.build_singbox_config()
        self.assertEqual(config["inbounds"], [
            {"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": 2080}
        ])

    def test_vpn_custom_stack_from_config(self):
        router._vpn = {"stack": "gvisor"}
        router.set_mode("tun")
        config, _ = router.build_singbox_config()
        self.assertEqual(config["inbounds"][0]["stack"], "gvisor")


class InitTests(unittest.TestCase):
    def test_init_writes_config_matching_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            _relocate(router, Path(tmp))
            router.write_default_config()
            written = json.loads(router.CONFIG_FILE.read_text())
            example = json.loads(
                (Path(__file__).resolve().parent.parent / "router.example.json").read_text()
            )
            self.assertEqual(written, example)


class RootEnvTests(unittest.TestCase):
    def test_proxy_router_root_env_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = tmp
            result = subprocess.run(
                [sys.executable, "-c", "import router; print(router.ROOT)"],
                cwd=Path(__file__).resolve().parent.parent,
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(result.stdout.strip()), Path(tmp).resolve())


if __name__ == "__main__":
    unittest.main()
