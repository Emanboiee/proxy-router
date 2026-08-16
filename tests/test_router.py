"""Unit tests for router.py (stdlib only, no third-party deps, no network)."""
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router


def _relocate(module, root: Path) -> None:
    """Point every module-level runtime path at ``root`` for test isolation."""
    module.ROOT = Path(root).resolve()
    module.CONFIG_FILE = module.ROOT / "router.json"
    module.SING_BOX_CONFIG = module.ROOT / "sing-box.json"
    module.LAST_GOOD_FILE = module.ROOT / "sing-box.json.last-good"
    module.PID_FILE = module.ROOT / "sing-box.pid"
    module.LOG_FILE = module.ROOT / "sing-box.log"
    module.LOCK_FILE = module.ROOT / "state" / "engine.lock"
    module.MODE_FILE = module.ROOT / "state" / "mode"
    module.MANUAL_OFF_FILE = module.ROOT / "state" / "manual-off"


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
            old_vpn, router._vpn = router._vpn, {}
            try:
                endpoint = router.parse_wireguard(conf)
            finally:
                router._vpn = old_vpn
            self.assertNotIn("pre_shared_key", endpoint["peers"][0])
            self.assertNotIn("persistent_keepalive_interval", endpoint["peers"][0])
            self.assertEqual(endpoint["mtu"], router.DEFAULT_ENDPOINT_MTU)

    def test_parse_wireguard_mtu_fallback_uses_vpn_mtu(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "profile.conf"
            _write_conf(conf, mtu=False)
            old_vpn, router._vpn = router._vpn, {"mtu": 1420}
            try:
                endpoint = router.parse_wireguard(conf)
            finally:
                router._vpn = old_vpn
            self.assertEqual(endpoint["mtu"], 1420)

    def test_dns_server_for_avoids_private_proton_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "profile.conf"
            _write_conf(conf)
            self.assertEqual(router.dns_server_for(conf), "1.1.1.1")
            conf.write_text(conf.read_text().replace("DNS = 10.2.0.1", "DNS = 2a07:b944::2:1"))
            self.assertEqual(router.dns_server_for(conf), "1.1.1.1")


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
            {"id": "example-com", "domains": ["example.com"], "provider": "proton"},
            {"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"},
        ]
        router._port = 2080

    def tearDown(self):
        self._tmp.cleanup()

    def test_build_config_maps_routes_and_skips_empty_provider(self):
        config, active = router.build_singbox_config()
        self.assertEqual(set(active), {"proton"})
        self.assertEqual(active["proton"].name, "a.conf")
        self.assertEqual([e["tag"] for e in config["endpoints"]], ["proton"])
        dns_tags = [s["tag"] for s in config["dns"]["servers"]]
        self.assertIn("dns-proton", dns_tags)
        self.assertNotIn("dns-cloudflare", dns_tags)
        self.assertIn("dns-local", dns_tags)
        self.assertEqual(
            next(s for s in config["dns"]["servers"] if s["tag"] == "dns-proton")["server"],
            "1.1.1.1",
        )
        # DNS must resolve over the direct physical path, not ride the tunnel:
        # a WireGuard blip must not take down resolution (seen as upstream
        # "Connection error" storms) before the dial is even attempted. No
        # detour key = sing-box default dials via the system path; detouring
        # to the "direct" outbound is rejected at start ("detour to an empty
        # direct outbound makes no sense", sing-box 1.13).
        for server in config["dns"]["servers"]:
            if server["tag"].startswith("dns-") and server["tag"] != "dns-local":
                self.assertNotIn("detour", server, server["tag"])
        self.assertEqual(config["dns"]["rules"], [{"domain_suffix": ["example.com"], "server": "dns-proton"}])
        self.assertEqual(config["dns"]["strategy"], "ipv4_only")
        rules = config["route"]["rules"]
        self.assertIn({"outbound": "proton", "domain_suffix": ["example.com"]}, rules)
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
            "routes": [{"id": "example-org", "domains": ["example.org"], "provider": "proton"}],
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
        self.assertTrue(router._routes_remove_entry("example-org"))
        self.assertEqual(router.save_config(), 0)
        data = json.loads(router.CONFIG_FILE.read_text())
        self.assertEqual(data["routes"], [])
        self.assertFalse(router._routes_remove_entry("example-org"))

    def test_save_config_restores_private_mode(self):
        os.chmod(router.CONFIG_FILE, 0o644)
        self.assertEqual(router.save_config(), 0)
        self.assertEqual(stat.S_IMODE(router.CONFIG_FILE.stat().st_mode), 0o600)


class ConfigValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _relocate(router, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_config_rejects_invalid_port_without_throwing(self):
        router.CONFIG_FILE.write_text(json.dumps({"port": 70000, "providers": {"proton": {}}, "routes": []}))
        self.assertEqual(router.load_config(), 1)

    def test_load_config_rejects_non_object_routes(self):
        router.CONFIG_FILE.write_text(json.dumps({"port": 2080, "providers": {"proton": {}}, "routes": ["bad"]}))
        self.assertEqual(router.load_config(), 1)

    def test_load_config_rejects_provider_path_escape(self):
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080, "providers": {"proton": {"directory": "../outside"}}, "routes": []
        }))
        self.assertEqual(router.load_config(), 1)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        for name in ("a", "b"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        # Pin rotation to the default policy: RotationPolicyTests runs before
        # this class (alphabetical order) and leaves "least-recent" behind.
        router._rotation = dict(router.DEFAULT_ROTATION_SETTINGS)
        # rotate() probes egress through the tunnel; tests never touch the network.
        self._probe = mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True}))
        self._probe.start()

    def tearDown(self):
        self._probe.stop()
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

    def test_rotate_walks_forward_through_pool_before_wrapping(self):
        _write_conf(self.root / "providers" / "proton" / "c.conf")
        router.set_active("proton", self.root / "providers" / "proton" / "b.conf")
        with mock.patch.object(router, "engine_reload", return_value=0), \
                mock.patch.object(router, "engine_switch", return_value=0):
            self.assertEqual(router.rotate("proton"), 0)
            self.assertEqual((self.root / "state" / "proton.active").read_text(), "c")
            self.assertEqual(router.rotate("proton"), 0)
            self.assertEqual((self.root / "state" / "proton.active").read_text(), "a")


class VpnModeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
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
        # Mixed proxy listener stays alongside the TUN so apps pinned to
        # 127.0.0.1:PORT keep working while TUN captures everything else.
        self.assertEqual(len(inbounds), 2)
        self.assertEqual(inbounds[0]["type"], "tun")
        self.assertEqual(inbounds[0]["address"], ["172.19.0.1/30"])
        self.assertEqual(inbounds[0]["stack"], "system")
        self.assertTrue(inbounds[0]["auto_route"])
        self.assertEqual(inbounds[1], {
            "type": "mixed", "tag": "local-proxy",
            "listen": "127.0.0.1", "listen_port": 2080,
        })
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

    def test_tun_mode_hijacks_dns(self):
        router.set_mode("tun")
        config, _ = router.build_singbox_config()
        self.assertIn({"protocol": "dns", "action": "hijack-dns"}, config["route"]["rules"])

    def test_tun_hijack_rule_precedes_route_rules(self):
        # The dns hijack must come FIRST: domain/outbound rules also match DNS
        # queries and would route them out of the DNS module (M7).
        router.set_mode("tun")
        config, _ = router.build_singbox_config()
        self.assertEqual(config["route"]["rules"][0], {"protocol": "dns", "action": "hijack-dns"})

    def test_proxy_mode_has_no_hijack_rule(self):
        router.set_mode("proxy")
        config, _ = router.build_singbox_config()
        self.assertNotIn({"protocol": "dns", "action": "hijack-dns"}, config["route"]["rules"])

    def test_mode_consistency_checks_config_inbounds(self):
        router.set_mode("tun")
        config, _ = router.build_singbox_config()
        router.write_sing_box(config)
        self.assertTrue(router.engine_mode_consistent())
        router.set_mode("proxy")
        # config still says tun, mode says proxy => inconsistent
        self.assertFalse(router.engine_mode_consistent())


class ParseEndpointTests(unittest.TestCase):
    def test_ipv4_endpoint(self):
        self.assertEqual(router.parse_endpoint("1.2.3.4:51820"), ("1.2.3.4", "51820"))

    def test_ipv6_bracketed_endpoint(self):
        self.assertEqual(router.parse_endpoint("[2606:4700::1]:51820"), ("2606:4700::1", "51820"))

    def test_bad_endpoint_raises(self):
        with self.assertRaises(SystemExit):
            router.parse_endpoint("nocolons")


class InitTests(unittest.TestCase):
    def test_init_writes_config_matching_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            _relocate(router, Path(tmp))
            self.assertEqual(router.write_default_config(), 0)
            written = json.loads(router.CONFIG_FILE.read_text())
            example = json.loads(
                (Path(__file__).resolve().parent.parent / "router.example.json").read_text()
            )
            self.assertEqual(written, example)

    def test_init_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            _relocate(router, Path(tmp))
            self.assertEqual(router.write_default_config(), 0)
            written = router.CONFIG_FILE.read_text()
            self.assertNotEqual(router.write_default_config(), 0)
            # untouched on refusal
            self.assertEqual(router.CONFIG_FILE.read_text(), written)
            self.assertEqual(router.write_default_config(force=True), 0)


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

class SingBoxVersionTests(unittest.TestCase):
    """M8: the generated config needs sing-box >= 1.12 (dialer
    domain_resolver, route.default_domain_resolver, hijack-dns rule action)."""

    FAKE_BIN = "/nonexistent/for-tests/sing-box"

    def setUp(self):
        router._sing_box_version_resolved = False
        router._sing_box_version_cache = None
        router._sing_box_resolved = False
        router._sing_box_cache = None
        self._rsb = mock.patch.object(router, "resolve_sing_box", return_value=self.FAKE_BIN)
        self._rsb.start()

    def tearDown(self):
        self._rsb.stop()
        router._sing_box_version_resolved = False

    def _run(self, stdout):
        return mock.patch.object(
            router.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=stdout, stderr=""),
        )

    def test_parses_stable_version(self):
        with self._run("sing-box version 1.13.16\n\nEnvironment: go1.26.5 darwin/arm64\n"):
            self.assertEqual(router.sing_box_version(), (1, 13, 16))

    def test_1_12_meets_minimum(self):
        with self._run("sing-box version 1.12.0\n"):
            self.assertEqual(router.sing_box_version(), (1, 12, 0))
            self.assertTrue(router.sing_box_at_least(router.MIN_SING_BOX_VERSION))

    def test_1_11_rejected(self):
        with self._run("sing-box version 1.11.8\n"):
            self.assertFalse(router.sing_box_at_least(router.MIN_SING_BOX_VERSION))

    def test_unparseable_version_falls_open(self):
        with self._run("weird banner without a version\n"):
            self.assertIsNone(router.sing_box_version())
            self.assertTrue(router.sing_box_at_least(router.MIN_SING_BOX_VERSION))

    def test_engine_start_rejects_old_binary_before_writing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            _relocate(router, Path(tmp))
            (Path(tmp) / "providers" / "proton").mkdir(parents=True)
            _write_conf(Path(tmp) / "providers" / "proton" / "a.conf")
            router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
            router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
            router._port = 2080
            with self._run("sing-box version 1.11.8\n"):
                self.assertEqual(router.engine_start(), 1)
            self.assertFalse(router.PID_FILE.exists())
            self.assertFalse(router.SING_BOX_CONFIG.exists())


class ResolveHostTests(unittest.TestCase):
    """M10: peer endpoint resolution prefers IPv6 but is tunable and never
    hits the network in tests (getaddrinfo is mocked)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        router._vpn = {}

    def tearDown(self):
        self._tmp.cleanup()

    def test_ipv4_literal_passthrough(self):
        self.assertEqual(router.resolve_host("1.2.3.4"), "1.2.3.4")

    def test_ipv6_literal_passthrough(self):
        self.assertEqual(router.resolve_host("2606:4700::1"), "2606:4700::1")
        self.assertEqual(router.resolve_host("[2606:4700::1]"), "2606:4700::1")

    def test_prefers_ipv6_when_both_present(self):
        infos = [(socket.AF_INET, 0, 0, "", ("1.2.3.4", 0)),
                 (socket.AF_INET6, 0, 0, "", ("2606:4700::1", 0))]
        with mock.patch.object(router.socket, "getaddrinfo", return_value=infos):
            self.assertEqual(router.resolve_host("peer.example"), "2606:4700::1")

    def test_falls_back_to_ipv4_when_no_aaaa(self):
        infos = [(socket.AF_INET, 0, 0, "", ("1.2.3.4", 0))]
        with mock.patch.object(router.socket, "getaddrinfo", return_value=infos):
            self.assertEqual(router.resolve_host("peer.example"), "1.2.3.4")

    def test_prefer_ipv6_off_prefers_ipv4(self):
        router._vpn = {"prefer_ipv6_peers": False}
        infos = [(socket.AF_INET6, 0, 0, "", ("2606:4700::1", 0)),
                 (socket.AF_INET, 0, 0, "", ("1.2.3.4", 0))]
        with mock.patch.object(router.socket, "getaddrinfo", return_value=infos):
            self.assertEqual(router.resolve_host("peer.example"), "1.2.3.4")

    def test_gaierror_passthrough(self):
        import socket as _socket
        with mock.patch.object(router.socket, "getaddrinfo", side_effect=_socket.gaierror):
            self.assertEqual(router.resolve_host("no.such.host.example"), "no.such.host.example")


class DnsStrategyTests(unittest.TestCase):
    """M10: dns.strategy (routed *destinations*) defaults to ipv4_only because
    the tunnels are IPv4-only, and is configurable via router.json vpn."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        router._vpn = {}

    def tearDown(self):
        self._tmp.cleanup()

    def test_defaults_to_ipv4_only(self):
        self.assertEqual(router.dns_strategy(), "ipv4_only")

    def test_configured_strategy_used(self):
        router._vpn = {"dns_strategy": "ipv6_prefer"}
        self.assertEqual(router.dns_strategy(), "ipv6_prefer")

    def test_invalid_strategy_falls_back(self):
        router._vpn = {"dns_strategy": "bogus"}
        self.assertEqual(router.dns_strategy(), "ipv4_only")

    def test_build_uses_configured_strategy(self):
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {"dns_strategy": "ipv4_prefer"}
        config, _ = router.build_singbox_config()
        self.assertEqual(config["dns"]["strategy"], "ipv4_prefer")


class ParseEndpointEdgeTests(unittest.TestCase):
    def test_bracketed_v6_requires_port(self):
        with self.assertRaises(SystemExit):
            router.parse_endpoint("[2606:4700::1]")

    def test_port_range_rejected(self):
        for endpoint in ("host.example:0", "host.example:65536", "host.example:-1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(SystemExit):
                router.parse_endpoint(endpoint)

    def test_non_numeric_port_rejected(self):
        with self.assertRaises(SystemExit):
            router.parse_endpoint("host.example:notaport")

    def test_empty_port_rejected(self):
        with self.assertRaises(SystemExit):
            router.parse_endpoint("host.example:")


class StatusReportTests(unittest.TestCase):
    """M13: `status` and `vpn status` must agree on up/down and exit code."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        router._port = 2080
        router._vpn = {}

    def tearDown(self):
        self._tmp.cleanup()

    def test_proxy_mode_without_engine_is_down(self):
        with mock.patch.object(router, "listener_up", return_value=False):
            rc, line = router._status_report()
        self.assertEqual(rc, 1)
        self.assertIn("down", line)

    def test_tun_mode_without_engine_is_down(self):
        router.set_mode("tun")
        rc, line = router._status_report()
        self.assertEqual(rc, 1)
        self.assertIn("tun", line)

    def test_tun_mode_with_mismatched_engine_is_down(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_mode_consistent", return_value=False):
            rc, line = router._status_report()
        self.assertEqual(rc, 1)
        self.assertIn("does not match tun", line)

    def test_tun_mode_up(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_mode_consistent", return_value=True):
            rc, line = router._status_report()
        self.assertEqual(rc, 0)
        self.assertIn("up (tun)", line)

    def test_proxy_mode_up(self):
        with mock.patch.object(router, "listener_up", return_value=True), \
             mock.patch.object(router, "engine_alive", return_value=True):
            rc, line = router._status_report()
        self.assertEqual(rc, 0)
        self.assertIn("up", line)

    def test_vpn_status_uses_shared_report(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_mode_consistent", return_value=True), \
             mock.patch("sys.stdout.write") as write:
            rc = router.vpn_status()
        self.assertEqual(rc, 0)
        self.assertTrue(any("up (tun)" in str(c) for c in write.call_args_list))


class EngineEnsureConsistencyTests(unittest.TestCase):
    """M13: ensure must not declare a tun-mode system healthy when the running
    engine does not match the persisted mode."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_proxy_listener_up_returns_without_start(self):
        with mock.patch.object(router, "listener_up", return_value=True), \
             mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_start", side_effect=AssertionError("must not start")):
            self.assertEqual(router.engine_ensure(), 0)

    def test_tun_alive_and_consistent_is_healthy(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_mode_consistent", return_value=True), \
             mock.patch.object(router, "engine_start", side_effect=AssertionError("must not start")):
            self.assertEqual(router.engine_ensure(), 0)

    def test_tun_alive_but_inconsistent_restarts(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=True), \
             mock.patch.object(router, "engine_mode_consistent", return_value=False), \
             mock.patch.object(router, "engine_start", return_value=77) as start:
            self.assertEqual(router.engine_ensure(), 77)
        start.assert_called_once()

    def test_tun_down_starts(self):
        router.set_mode("tun")
        with mock.patch.object(router, "engine_alive", return_value=False), \
             mock.patch.object(router, "engine_start", return_value=0) as start:
            self.assertEqual(router.engine_ensure(), 0)
        start.assert_called_once()


class VpnOnRollbackTests(unittest.TestCase):
    """H5: vpn on pre-flights, and on engine failure restores the previous
    mode AND brings the proxy engine back so the user keeps connectivity."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"}

    def tearDown(self):
        self._tmp.cleanup()

    def test_failed_vpn_on_restores_proxy_mode_and_engine(self):
        with mock.patch.object(router, "resolve_sing_box", return_value="/bin/echo"), \
             mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "engine_start", return_value=1) as start, \
             mock.patch.object(router, "listener_up", return_value=False):
            rc = router.vpn_on()
        self.assertEqual(rc, 1)
        self.assertEqual(router.current_mode(), "proxy")
        # original failed engine_start + proxy restore
        self.assertEqual(start.call_count, 2)

    def test_successful_vpn_on_keeps_tun(self):
        with mock.patch.object(router, "resolve_sing_box", return_value="/bin/echo"), \
             mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "engine_start", return_value=0) as start:
            rc = router.vpn_on()
        self.assertEqual(rc, 0)
        self.assertEqual(router.current_mode(), "tun")
        start.assert_called_once()


class WaitEngineTests(unittest.TestCase):
    """H2: start must not claim success when a foreign process answers our
    port while the engine we launched died."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_proxy_readiness_requires_our_process(self):
        with mock.patch.object(router, "listener_up", return_value=True), \
             mock.patch.object(router, "engine_alive", return_value=False):
            self.assertFalse(router.wait_engine(timeout=0.4))

    def test_proxy_readiness_with_our_process(self):
        with mock.patch.object(router, "listener_up", return_value=True), \
             mock.patch.object(router, "engine_alive", return_value=True):
            self.assertTrue(router.wait_engine(timeout=2.0))

    def test_proxy_readiness_false_without_listener(self):
        with mock.patch.object(router, "listener_up", return_value=False), \
             mock.patch.object(router, "engine_alive", return_value=True):
            self.assertFalse(router.wait_engine(timeout=0.4))


class EngineReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        (self.root / "sing-box.pid").write_text("1234")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}

    def tearDown(self):
        self.tmp.cleanup()

    def test_reload_ignores_historical_fatal_log_lines(self):
        with mock.patch.object(router, "resolve_sing_box", return_value="/bin/sing-box"), \
             mock.patch.object(router, "sing_box_at_least", return_value=True), \
             mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "_pid_matches", return_value=True), \
             mock.patch.object(router, "log_offset", return_value=987), \
             mock.patch.object(router, "wait_engine", return_value=True) as wait_engine, \
             mock.patch.object(router.os, "kill"):
            self.assertEqual(router.engine_reload(), 0)
        wait_engine.assert_called_once_with(2.0, log_from=987)


class CliStatusAgreementTests(unittest.TestCase):
    """M13 at the CLI boundary: status and vpn status exit 1 with "down" when
    nothing is running, in a throwaway PROXY_ROUTER_ROOT."""

    def test_both_report_down_with_exit_1(self):
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = tmp
            env["SING_BOX"] = ""  # do not depend on this machine's binary
            for cmd in (["status"], ["vpn", "status"]):
                result = subprocess.run(
                    [sys.executable, str(repo / "router.py"), *cmd],
                    cwd=repo, env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 1, (cmd, result.stdout, result.stderr))
                self.assertIn("down", result.stdout.lower(), (cmd, result.stdout))


if __name__ == "__main__":
    unittest.main()


class EgressRecordTests(unittest.TestCase):
    """state/egress/<provider>/<profile>.json persistence, atomic 0600."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        self.profile = self.root / "providers" / "proton" / "a.conf"
        _write_conf(self.profile)
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}

    def tearDown(self):
        self._tmp.cleanup()

    def test_roundtrip_and_private_mode(self):
        router.write_egress("proton", self.profile, {"ok": True, "latency_ms": 12.5})
        self.assertEqual(router.read_egress("proton", self.profile)["latency_ms"], 12.5)
        self.assertEqual(stat.S_IMODE((self.root / "state" / "egress" / "proton" / "a.json").stat().st_mode), 0o600)

    def test_invalid_stem_rejected(self):
        with self.assertRaises(ValueError):
            router.egress_record_path("proton", Path("a!.conf"))
        with self.assertRaises(ValueError):
            router.egress_record_path("proton", Path("a b.conf"))

    def test_record_fail_then_ok_clears_streak(self):
        first = router.record_egress("proton", self.profile, ok=False, error="connection refused")
        self.assertEqual(first["fails"], 1)
        self.assertFalse(first["ok"])
        second = router.record_egress("proton", self.profile, ok=True, latency_ms=12.5, status=200)
        self.assertEqual(second["fails"], 0)
        self.assertEqual(second["latency_ms"], 12.5)
        self.assertIsNone(second["error"])
        self.assertTrue(int(second["last_ok_at"]) > 0)

    def test_mark_blocked_expiry_and_clear(self):
        now = int(time.time())
        router.mark_blocked("proton", self.profile, "cloudflare-1010", seconds=60)
        self.assertTrue(router.egress_is_blocked("proton", self.profile, now=now))
        self.assertFalse(router.egress_is_blocked("proton", self.profile, now=now + 61))
        router.clear_blocked("proton", self.profile)
        self.assertFalse(router.egress_is_blocked("proton", self.profile, now=now))

    def test_blocked_without_expiry_stays_blocked(self):
        router.write_egress("proton", self.profile, {"blocked": True})
        self.assertTrue(router.egress_is_blocked("proton", self.profile, now=10 ** 12))

    def test_default_block_seconds_used(self):
        router.mark_blocked("proton", self.profile, "403")
        record = router.read_egress("proton", self.profile)
        self.assertGreaterEqual(record["blocked_until"], int(time.time()) + router.egress_settings()["block_seconds"] - 1)


class EgressRankTests(unittest.TestCase):
    """Rotation preference: fast+recent OK < unknown < slow-but-OK < failing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        router._egress_settings = dict(router.DEFAULT_EGRESS_SETTINGS)

    def tearDown(self):
        self._tmp.cleanup()

    def test_rank_order(self):
        now = 1_000_000
        ok_fast = {"ok": True, "last_ok_at": now, "latency_ms": 40}
        ok_slow = {"ok": True, "last_ok_at": now, "latency_ms": 9000}
        unknown = {}
        failing = {"ok": False, "fails": 3}
        ranked = sorted([unknown, failing, ok_slow, ok_fast], key=lambda r: router._egress_rank(r, now=now))
        self.assertEqual(ranked, [ok_fast, unknown, ok_slow, failing])

    def test_single_failure_not_deprioritized(self):
        self.assertEqual(router._egress_rank({"ok": False, "fails": 1}),
                         router._egress_rank({}))

    def test_stale_ok_deprioritized(self):
        window = router.egress_settings()["ok_window"]
        record = {"ok": True, "last_ok_at": 1_000_000 - int(window) - 1, "latency_ms": 40}
        self.assertNotEqual(router._egress_rank(record, now=1_000_000)[0], 0)


class ProbeEgressTests(unittest.TestCase):
    """probe_egress/probe_profile: parsing, block detection, error redaction."""

    class _FakeClock:
        def __init__(self, values):
            self._values = list(values)

        def __call__(self):
            return self._values.pop(0)

    class _FakeResponse:
        def __init__(self, body, status=200):
            self._body = body
            self.status = status
            self.closed = False

        def read(self, n):
            return self._body

        def close(self):
            self.closed = True

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        self.profile = self.root / "providers" / "proton" / "a.conf"
        _write_conf(self.profile)
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}

    def tearDown(self):
        self._tmp.cleanup()

    def test_probe_ok_parses_latency(self):
        fake = self._FakeResponse(b"fl=flXXX\r\nip=1.2.3.4\r\n")
        clock = self._FakeClock([0.0, 0.123])
        result = router.probe_egress(port=2080, url="https://example.com",
                                     opener=lambda req, timeout: fake, clock=clock)
        self.assertTrue(result["ok"])
        self.assertEqual(result["latency_ms"], 123.0)
        self.assertEqual(result["status"], 200)
        self.assertTrue(fake.closed)

    def test_probe_detects_1010_block(self):
        fake = self._FakeResponse(b"<html>error code: 1010</html>", status=403)
        result = router.probe_egress(port=2080, url="https://example.com",
                                     opener=lambda req, timeout: fake)
        self.assertFalse(result["ok"])
        self.assertEqual(result["block_reason"], "cloudflare-1010")

    def test_probe_detects_403_cloudflare_page(self):
        fake = self._FakeResponse(b"Cloudflare Ray ID ... Access denied", status=403)
        result = router.probe_egress(port=2080, url="https://example.com",
                                     opener=lambda req, timeout: fake)
        self.assertEqual(result["block_reason"], "cloudflare-403")

    def test_probe_network_error_redacts_urls(self):
        def failing_opener(req, timeout):
            raise urllib.error.URLError("boom https://secret.invalid/path")

        result = router.probe_egress(port=2080, url="https://secret.invalid/path", opener=failing_opener)
        self.assertFalse(result["ok"])
        self.assertIn("URLError", result["error"])
        self.assertNotIn("secret.invalid", result["error"])

    def test_probe_profile_writes_and_blocks(self):
        with mock.patch.object(router, "probe_egress", return_value={
                "ok": False, "latency_ms": None, "status": 403,
                "error": "cloudflare-1010", "block_reason": "cloudflare-1010"}) as probe:
            ok, record = router.probe_profile("proton", self.profile)
        self.assertFalse(ok)
        self.assertEqual(record["fails"], 1)
        self.assertTrue(router.egress_is_blocked("proton", self.profile))
        probe.assert_called_once()

    def test_probe_profile_ok_clears_existing_block(self):
        router.mark_blocked("proton", self.profile, "cloudflare-1010")
        with mock.patch.object(router, "probe_egress", return_value={
                "ok": True, "latency_ms": 80.0, "status": 200,
                "error": None, "block_reason": None}):
            ok, record = router.probe_profile("proton", self.profile)
        self.assertTrue(ok)
        self.assertFalse(router.egress_is_blocked("proton", self.profile))
        self.assertEqual(record["fails"], 0)

    def test_probe_profile_skips_without_routed_domain(self):
        router._routes = []
        with mock.patch.object(router, "probe_egress", side_effect=AssertionError("must not probe")):
            ok, record = router.probe_profile("proton", self.profile)
        self.assertTrue(ok)
        self.assertIsNone(record)

    def test_probe_url_for_strips_wildcard(self):
        router._routes = [{"id": "w", "domains": ["*.example.com", "opencode.ai"], "provider": "proton"},
                          {"id": "other", "domains": ["roblox.com"], "provider": "cloudflare"}]
        self.assertEqual(router.probe_url_for("proton"), "https://example.com")
        self.assertEqual(router.probe_url_for("cloudflare"), "https://roblox.com")
        self.assertIsNone(router.probe_url_for("ghost"))


class RotationEgressTests(unittest.TestCase):
    """Egress-aware rotation: blocked skip, latency ranking, --reason smart
    cooldown, --force override, last-good rollback."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        for name in ("a", "b", "c"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        self.reload_patch = mock.patch.object(router, "engine_reload", return_value=0)
        self.engine_reload = self.reload_patch.start()
        self.switch_patch = mock.patch.object(router, "engine_switch", return_value=0)
        self.engine_switch = self.switch_patch.start()
        self.probe_patch = mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True}))
        self.probe = self.probe_patch.start()

    def tearDown(self):
        self.probe_patch.stop()
        self.switch_patch.stop()
        self.reload_patch.stop()
        self._tmp.cleanup()

    def _profile(self, stem):
        return self.root / "providers" / "proton" / f"{stem}.conf"

    def _active(self):
        return (self.root / "state" / "proton.active").read_text()

    def test_rotate_skips_blocked_profile(self):
        router.set_active("proton", self._profile("a"))
        router.mark_blocked("proton", self._profile("b"), "cloudflare-1010")
        self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "c")

    def test_rotate_prefers_low_latency_ok_profile(self):
        router.set_active("proton", self._profile("a"))
        router.record_egress("proton", self._profile("b"), ok=True, latency_ms=200)
        router.record_egress("proton", self._profile("c"), ok=True, latency_ms=50)
        self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "c")

    def test_rotate_unknown_pool_order_kept(self):
        router.set_active("proton", self._profile("a"))
        self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "b")
        self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "c")

    def test_rotate_force_overrides_blocked_and_clears_marker(self):
        router.set_active("proton", self._profile("a"))
        router.mark_blocked("proton", self._profile("b"), "cloudflare-1010")
        self.assertEqual(router.rotate("proton", force=True), 0)
        self.assertEqual(self._active(), "b")
        self.assertFalse(router.egress_is_blocked("proton", self._profile("b")))

    def test_rotate_reason_marks_current_with_upstream_cooldown(self):
        router.set_active("proton", self._profile("a"))
        self.assertEqual(router.rotate("proton", reason="503"), 0)
        self.assertEqual(self._active(), "b")
        record = router.read_egress("proton", self._profile("a"))
        self.assertEqual(record["upstream_error"], "503")
        until = int((self.root / "state" / "cooldowns" / "proton" / "a.until").read_text().strip())
        self.assertGreaterEqual(until, int(time.time()) + 110)  # 503 default = cooldown 120s

    def test_rotate_reason_block_marks_current_blocked(self):
        router.set_active("proton", self._profile("a"))
        self.assertEqual(router.rotate("proton", reason="1010"), 0)
        self.assertTrue(router.egress_is_blocked("proton", self._profile("a")))
        self.assertEqual(self._active(), "b")

    def test_rotate_probe_failure_rolls_back(self):
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "listener_up", return_value=True), \
                mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})) as probe:
            # rollback restores service but still reports the failed rotation
            # (non-zero) so callers can activate the configured fallback
            self.assertEqual(router.rotate("proton"), 1)
        self.assertEqual(self._active(), "a")
        self.assertTrue(router.is_cooled_down("proton", self._profile("b")))
        probe.assert_called_once()
        # first hard switch for the rotation, second for the rollback
        self.assertEqual(self.engine_switch.call_count, 2)

    def test_rotate_reason_probe_failure_keeps_reason_cooldown(self):
        # A --reason rotation marks the current profile FAILED upstream; the
        # rollback restore must NOT clear that mark (ping-pong A->B->A->C->A).
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "listener_up", return_value=True), \
                mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            # rollback restores service but reports the failed rotation (1)
            self.assertEqual(router.rotate("proton", reason="503"), 1)
        self.assertEqual(self._active(), "a")  # rolled back to previous
        self.assertTrue(router.is_cooled_down("proton", self._profile("a")))  # mark survived
        self.assertTrue(router.is_cooled_down("proton", self._profile("b")))  # failed switch also cooled
        record = router.read_egress("proton", self._profile("a"))
        self.assertEqual(record["upstream_error"], "503")

    def test_rotate_plain_probe_failure_clears_previous_cooldown(self):
        # Plain rotations only mildly cool the previous profile as preference;
        # restoring it on rollback MUST undo that so last-good is usable now.
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "listener_up", return_value=True), \
                mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            self.assertEqual(router.rotate("proton"), 1)
        self.assertEqual(self._active(), "a")
        self.assertFalse(router.is_cooled_down("proton", self._profile("a")))

    def test_rotate_probe_failure_without_previous_keeps_switch(self):
        with mock.patch.object(router, "listener_up", return_value=True), \
                mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            # no previous profile to restore: the failed switch stays put
            # and the failure is reported so callers can fall back
            self.assertEqual(router.rotate("proton"), 1)
        self.assertEqual(self._active(), "a")

    def test_rotate_no_probe_skips_probe(self):
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "probe_profile", side_effect=AssertionError("must not probe")):
            self.assertEqual(router.rotate("proton", probe=False), 0)
        self.assertEqual(self._active(), "b")

    def test_rotate_tun_mode_does_not_probe(self):
        router.set_mode("tun")
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "probe_profile", side_effect=AssertionError("must not probe")):
            self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "b")

    def test_rotate_records_last_rotation(self):
        router.set_active("proton", self._profile("a"))
        self.assertEqual(router.rotate("proton"), 0)
        rotation = json.loads((self.root / "state" / "proton.rotation").read_text())
        self.assertEqual(rotation["profile"], "b")
        self.assertIsInstance(rotation["at"], int)

    def test_all_blocked_fails_with_force_hint(self):
        router.set_active("proton", self._profile("a"))
        router.mark_blocked("proton", self._profile("b"), "cloudflare-1010")
        router.mark_blocked("proton", self._profile("c"), "cloudflare-1010")
        self.assertEqual(router.rotate("proton"), 1)


class EgressSettingsTests(unittest.TestCase):
    def test_load_bounds_supplied_values(self):
        router._load_egress_settings({"egress": {
            "probe_timeout": 999, "block_seconds": -5, "fail_threshold": 99,
            "probe_url": "not a url", "upstream_cooldown_seconds": "x",
        }})
        settings = router.egress_settings()
        self.assertEqual(settings["probe_timeout"], 60.0)
        self.assertEqual(settings["block_seconds"], 0)
        self.assertEqual(settings["fail_threshold"], 20)
        self.assertEqual(settings["probe_url"], router.DEFAULT_PROBE_URL)
        self.assertEqual(settings["upstream_cooldown_seconds"], router.DEFAULT_EGRESS_SETTINGS["upstream_cooldown_seconds"])

    def test_load_keeps_valid_url(self):
        router._load_egress_settings({"egress": {"probe_url": "https://opencode.ai"}})
        self.assertEqual(router.egress_settings()["probe_url"], "https://opencode.ai")


class StatusJsonTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        (self.root / "providers" / "cloudflare").mkdir(parents=True)
        self.profile = self.root / "providers" / "proton" / "a.conf"
        _write_conf(self.profile)
        router._providers = {
            "proton": {"directory": "providers/proton", "cooldown_seconds": 60},
            "cloudflare": {"directory": "providers/cloudflare", "cooldown_seconds": 60},
        }
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        self.report = mock.patch.object(router, "_status_report", return_value=(0, "up (proxy 127.0.0.1:2080)"))
        self.report.start()

    def tearDown(self):
        self.report.stop()
        self._tmp.cleanup()

    def test_status_json_shape(self):
        router.set_active("proton", self.profile)
        router.mark_cooldown("proton", self.profile, 60)
        router.record_egress("proton", self.profile, ok=True, latency_ms=88.5, status=200)
        router.record_rotation("proton", self.profile)
        data = router.status_json()
        self.assertTrue(data["up"])
        self.assertEqual(data["mode"], "proxy")
        self.assertEqual(data["port"], 2080)
        proton = data["providers"]["proton"]
        self.assertEqual(proton["active"], "a")
        self.assertIn("a", proton["cooldown_until"])
        self.assertEqual(proton["last_rotation"]["profile"], "a")
        self.assertTrue(proton["egress"]["a"]["ok"])
        self.assertEqual(proton["egress"]["a"]["latency_ms"], 88.5)
        self.assertEqual(data["routes"], [{"id": "example-com", "provider": "proton",
                                           "domains": ["example.com"], "ip_cidr": []}])
        self.assertEqual(data["providers"]["cloudflare"]["active"], None)

    def test_status_json_down(self):
        with mock.patch.object(router, "_status_report", return_value=(1, "down (proxy mode)")):
            data = router.status_json()
        self.assertFalse(data["up"])
        self.assertIn("down", data["state"])


class LogRotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_rotates_oversized_log(self):
        router.LOG_FILE.write_text("x" * (router.LOG_MAX_BYTES + 10))
        router.rotate_log_if_needed()
        self.assertFalse(router.LOG_FILE.exists())
        self.assertTrue(Path(str(router.LOG_FILE) + ".1").exists())

    def test_leaves_small_log_alone(self):
        router.LOG_FILE.write_text("small")
        router.rotate_log_if_needed()
        self.assertTrue(router.LOG_FILE.exists())
        self.assertFalse(Path(str(router.LOG_FILE) + ".1").exists())

    def test_missing_log_is_noop(self):
        router.rotate_log_if_needed()  # must not raise


class CliStatusJsonTests(unittest.TestCase):
    def test_status_json_down_with_exit_1(self):
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = tmp
            env["SING_BOX"] = ""
            result = subprocess.run(
                [sys.executable, str(repo / "router.py"), "status", "--json"],
                cwd=repo, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            data = json.loads(result.stdout)
            self.assertFalse(data["up"])
            self.assertIn("down", data["state"])

    def test_status_json_unusable_config(self):
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "router.json").write_text(json.dumps({"port": 99999}))
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = tmp
            env["SING_BOX"] = ""
            result = subprocess.run(
                [sys.executable, str(repo / "router.py"), "status", "--json"],
                cwd=repo, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            data = json.loads(result.stdout)
            self.assertFalse(data["up"])
            self.assertIn("unusable config", data["state"])

    def test_egress_show_empty_json(self):
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_dir = root / "providers" / "proton"
            provider_dir.mkdir(parents=True)
            _write_conf(provider_dir / "a.conf")
            root.joinpath("router.json").write_text(json.dumps({
                "port": 2080,
                "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
                "routes": [],
            }))
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = tmp
            env["SING_BOX"] = ""
            result = subprocess.run(
                [sys.executable, str(repo / "router.py"), "egress", "show"],
                cwd=repo, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data, {"proton": {}})

class EgressDnsProbeTests(unittest.TestCase):
    """Feature 3: the tunnel-DNS companion signal records dns_ok and
    distinguishes a dead DNS path from a repo-block HTTP status."""

    class _FakeResponse:
        def __init__(self, body=b"ok", status=200):
            self._body = body
            self.status = status

        def read(self, n):
            return self._body

        def close(self):
            pass

    def _probe(self, *, ok=False, status=None, error=None):
        result = {"ok": ok, "latency_ms": None, "status": status, "error": error,
                  "block_reason": None}
        return result

    def test_direct_resolve_failure_is_inconclusive(self):
        with mock.patch.object(router, "_bounded_getaddrinfo", return_value=None):
            self.assertIsNone(router.egress_dns_probe("example.com"))

    def test_response_through_tunnel_means_dns_ok(self):
        with mock.patch.object(router, "_bounded_getaddrinfo", return_value=["1.2.3.4"]), \
             mock.patch.object(router, "probe_egress", return_value=self._probe(ok=True, status=200)):
            self.assertTrue(router.egress_dns_probe("example.com"))

    def test_dns_marked_error_means_tunnel_dns_dead(self):
        with mock.patch.object(router, "_bounded_getaddrinfo", return_value=["1.2.3.4"]), \
             mock.patch.object(router, "probe_egress", return_value=self._probe(
                 error="URLError: <urlopen error [Errno 8] nodename nor servname provided, or not known>")):
            self.assertFalse(router.egress_dns_probe("example.com"))

    def test_transport_error_is_inconclusive(self):
        with mock.patch.object(router, "_bounded_getaddrinfo", return_value=["1.2.3.4"]), \
             mock.patch.object(router, "probe_egress", return_value=self._probe(
                 error="TimeoutError: timed out")):
            self.assertIsNone(router.egress_dns_probe("example.com"))


class EgressLiveCheckTests(unittest.TestCase):
    """check_egress_live classification: alive / degraded / dead + dns_ok."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        self.profile = self.root / "providers" / "proton" / "a.conf"
        _write_conf(self.profile)
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}

    def tearDown(self):
        self._tmp.cleanup()

    def _probe(self, *, ok=False, status=None, error=None, block_reason=None):
        return {"ok": ok, "latency_ms": None, "status": status, "error": error,
                "block_reason": block_reason}

    def test_probe_ok_is_alive_and_records_dns_ok(self):
        with mock.patch.object(router, "probe_egress",
                               return_value=self._probe(ok=True, status=200)):
            status, record = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "alive")
        self.assertTrue(record["ok"])
        self.assertIs(record["dns_ok"], True)

    def test_http_status_failure_is_degraded_not_dead(self):
        # 403 from Cloudflare = reputation block: tunnel path works, so the
        # exit must NOT be classified dead (keepalive must not rotate).
        with mock.patch.object(router, "probe_egress",
                               return_value=self._probe(status=403, error="cloudflare-403",
                                                        block_reason="cloudflare-403")):
            status, record = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "degraded")
        self.assertFalse(record["ok"])
        self.assertIs(record["dns_ok"], True)
        self.assertTrue(router.egress_is_blocked("proton", self.profile))

    def test_transport_failure_with_dead_tunnel_dns_is_dead(self):
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                error="URLError: tunnel down")), \
             mock.patch.object(router, "egress_dns_probe", return_value=False):
            status, record = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "dead")
        self.assertFalse(record["ok"])
        self.assertIs(record["dns_ok"], False)

    def test_transport_failure_alone_is_still_dead(self):
        # no HTTP status at all = the tunnel path is broken even when the DNS
        # companion check cannot be determined - never leave it unhealed.
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                error="TimeoutError: timed out")), \
             mock.patch.object(router, "egress_dns_probe", return_value=None):
            status, record = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "dead")
        self.assertFalse(record["ok"])
        self.assertNotIn("dns_ok", record)  # only persisted when determined

    def test_transport_death_applies_cooldown(self):
        # TLS/transport failure (no HTTP status) must cool the exit so
        # resolve_active/rotation stop re-picking it for the cooldown window.
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                error="URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>")), \
             mock.patch.object(router, "egress_dns_probe", return_value=None):
            status, _ = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "dead")
        self.assertTrue(router.is_cooled_down("proton", self.profile))

    def test_degraded_http_status_does_not_cooldown(self):
        # A 403/1010 reputation block marks blocked (stronger than cooldown);
        # a plain 5xx means the tunnel path works and must NOT be cooled.
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                status=503, error="HTTP 503")):
            status, _ = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "degraded")
        self.assertFalse(router.is_cooled_down("proton", self.profile))

    def test_alive_probe_does_not_cooldown(self):
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                ok=True, status=200)):
            status, _ = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "alive")
        self.assertFalse(router.is_cooled_down("proton", self.profile))

    def test_probe_profile_transport_failure_cools_exit(self):
        # Same rule through the probe_profile path (used by egress probe and
        # rotate's post-switch verification).
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                error="URLError: <urlopen error [SSL: TLSV1_ALERT_INTERNAL_ERROR]>")), \
             mock.patch.object(router, "record_egress", wraps=router.record_egress):
            ok, record = router.probe_profile("proton", self.profile)
        self.assertFalse(ok)
        self.assertTrue(router.is_cooled_down("proton", self.profile))
        self.assertNotIn("block_reason", record or {})

    def test_probe_profile_http_failure_does_not_cooldown(self):
        # HTTP-status failure (reputation/5xx) is NOT a dead tunnel: only the
        # blocked marker applies for 1010/403, and plain 5xx cools nothing.
        with mock.patch.object(router, "probe_egress", return_value=self._probe(
                status=500, error="HTTP 500")):
            ok, _ = router.probe_profile("proton", self.profile)
        self.assertFalse(ok)
        self.assertFalse(router.is_cooled_down("proton", self.profile))

    def test_no_routed_domain_counts_as_alive(self):
        router._routes = []
        with mock.patch.object(router, "probe_egress", side_effect=AssertionError("must not probe")):
            status, record = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "alive")
        self.assertIsNone(record)

    def test_record_egress_omits_dns_ok_when_unspecified(self):
        record = router.record_egress("proton", self.profile, ok=True, latency_ms=10.0)
        self.assertNotIn("dns_ok", record)
        record = router.record_egress("proton", self.profile, ok=False, error="boom", dns_ok=False)
        self.assertIs(record["dns_ok"], False)


class EgressCheckCommandTests(unittest.TestCase):
    """egress check CLI semantics: exit codes, dead: line, json shape, and
    all-provider checking (records refresh even after a dead-first exit)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        (self.root / "providers" / "cloudflare").mkdir(parents=True)
        _write_conf(self.root / "providers" / "proton" / "a.conf")
        _write_conf(self.root / "providers" / "cloudflare" / "b.conf")
        router._providers = {
            "proton": {"directory": "providers/proton", "cooldown_seconds": 60},
            "cloudflare": {"directory": "providers/cloudflare", "cooldown_seconds": 60},
        }
        router._routes = [
            {"id": "example-com", "domains": ["example.com"], "provider": "proton"},
            {"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"},
        ]
        router._port = 2080
        router._vpn = {}
        self.listener = mock.patch.object(router, "listener_up", return_value=True)
        self.listener.start()
        self.live_patch = mock.patch.object(router, "check_egress_live",
                                            return_value=("alive", {"ok": True, "dns_ok": True}))
        self.live = self.live_patch.start()

    def tearDown(self):
        self.live_patch.stop()
        self.listener.stop()
        self._tmp.cleanup()

    def _live(self, *results):
        self.live_patch.stop()
        self.live_patch = mock.patch.object(router, "check_egress_live", side_effect=list(results))
        self.live = self.live_patch.start()

    def test_works_in_tun_mode_via_mixed_listener(self):
        # TUN capture keeps the 127.0.0.1 mixed listener alongside the TUN
        # inbound, so the check no longer refuses tun mode.
        router.set_mode("tun")
        with mock.patch("sys.stdout.write"):
            rc = router.egress_check()
        self.assertEqual(rc, 0)

    def test_requires_listener(self):
        self.listener.stop()
        with mock.patch.object(router, "listener_up", return_value=False), \
             mock.patch("sys.stdout.write"):
            rc = router.egress_check()
        self.assertEqual(rc, 1)

    def test_unknown_provider_fails(self):
        rc = router.egress_check("ghost")
        self.assertEqual(rc, 1)

    def test_all_alive_exit_zero(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        rc = router.egress_check(as_json=True)
        self.assertEqual(rc, 0)

    def test_dead_exit_one_and_dead_line(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        self._live(("dead", {"ok": False, "dns_ok": False}), ("dead", {"ok": False}))
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check()
        self.assertEqual(rc, 1)
        joined = "".join(str(c) for c in write.call_args_list)
        self.assertIn("dead: proton", joined)
        # both providers are checked so records refresh; only the first dead
        # provider is named so keepalive rotates exactly one exit
        self.assertEqual(self.live.call_count, 2)
        self.assertNotIn("dead: cloudflare", joined)

    def test_records_refresh_after_first_dead(self):
        # regression: a dead-first provider must not freeze the follow-on
        # provider's record at its last failure (status UIs showed stale
        # "timed out" labels while the tunnel actually worked)
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        self.live_patch.stop()  # exercise the real check_egress_live/record path
        probes = [
            {"ok": False, "latency_ms": None, "status": None,
             "error": "URLError: timeout", "block_reason": None},
            {"ok": True, "latency_ms": 42.0, "status": 200,
             "error": None, "block_reason": None},
        ]
        with mock.patch.object(router, "probe_egress", side_effect=probes) as probe, \
             mock.patch.object(router, "egress_dns_probe", return_value=False), \
             mock.patch("sys.stdout.write") as write:
            rc = router.egress_check()
        self.assertEqual(rc, 1)
        self.assertEqual(probe.call_count, 2)
        joined = "".join(str(c) for c in write.call_args_list)
        self.assertIn("dead: proton", joined)
        self.assertNotIn("dead: cloudflare", joined)
        record = router.read_egress("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        self.assertTrue(record["ok"])
        self.assertEqual(record["fails"], 0)
        self.assertEqual(record["latency_ms"], 42.0)

    def test_degraded_exit_zero_not_dead(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        self._live(("degraded", {"ok": False, "status": 403, "dns_ok": True}),
                   ("alive", {"ok": True, "dns_ok": True}))
        rc = router.egress_check()
        self.assertEqual(rc, 0)

    def test_json_shape(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        self._live(("dead", {"ok": False, "dns_ok": False}),
                   ("alive", {"ok": True, "dns_ok": True}))
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check(as_json=True)
        self.assertEqual(rc, 1)
        text = "".join(c.args[0] for c in write.call_args_list)
        data = json.loads(text)
        self.assertEqual(data["dead"], ["proton"])
        self.assertEqual(data["results"]["proton"]["status"], "dead")
        self.assertEqual(data["results"]["cloudflare"]["status"], "alive")

    def test_provider_filter(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        rc = router.egress_check("proton")
        self.assertEqual(rc, 0)
        self.assertEqual(self.live.call_count, 1)

    def test_active_fallback_is_not_probed_as_primary(self):
        router._providers["proton"]["fallback_provider"] = "cloudflare"
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.set_active("cloudflare", self.root / "providers" / "cloudflare" / "b.conf")
        marker = self.root / "state" / "fallback"
        marker.mkdir(parents=True)
        (marker / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check(as_json=True)
        self.assertEqual(rc, 0)
        # one probe through the fallback marker, one for cloudflare as itself
        self.assertEqual(self.live.call_count, 2)
        data = json.loads("".join(c.args[0] for c in write.call_args_list))
        self.assertEqual(data["results"]["proton"]["status"], "fallback")
        self.assertEqual(data["results"]["proton"]["fallback_provider"], "cloudflare")
        self.assertEqual(data["results"]["cloudflare"]["status"], "alive")

    def test_provider_without_profiles_is_skipped_not_dead(self):
        # empty provider dir: no active profile, nothing to probe, so it must
        # be skipped rather than counted as a dead tunnel.
        (self.root / "providers" / "proton" / "a.conf").unlink()
        self._live()
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check("proton")
        self.assertEqual(rc, 0)
        joined = "".join(c.args[0] for c in write.call_args_list)
        self.assertIn("skipped", joined)
        self.assertEqual(self.live.call_count, 0)

    def test_check_attributes_to_persisted_active_even_when_cooled(self):
        # Cooldown marks never reload the engine: the tunnel still routes via
        # the persisted active profile, so egress check must probe THAT exit
        # and not resolve_active's preferred non-cooled pick (which would
        # blame a different profile for the tunnel's health).
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.mark_cooldown("proton", self.root / "providers" / "proton" / "a.conf", 300)
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check("proton")
        self.assertEqual(rc, 0)
        _, kwargs = self.live.call_args
        self.assertEqual(self.live.call_args[0][1].stem, "a")
        persisted = router.persisted_active("proton")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.stem, "a")

    def test_probe_attributes_to_persisted_active_even_when_cooled(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        router.mark_cooldown("proton", self.root / "providers" / "proton" / "a.conf", 300)
        with mock.patch.object(router, "probe_profile",
                               return_value=(True, {"ok": True})) as probe:
            rc = router.egress_probe("proton")
        self.assertEqual(rc, 0)
        _, kwargs = probe.call_args
        self.assertEqual(probe.call_args[0][1].stem, "a")


class EgressSweepTests(unittest.TestCase):
    """egress sweep: full-pool probing in wrap order, best-alive end state,
    dead-pool exit code, and configurable probe targets."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        for name in ("a", "b", "c"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        self.listener = mock.patch.object(router, "listener_up", return_value=True)
        self.listener.start()
        self.rotate_patch = mock.patch.object(router, "rotate", return_value=0)
        self.rotate = self.rotate_patch.start()
        self.probe_patch = mock.patch.object(router, "probe_profile",
                                             return_value=(True, {"ok": True, "latency_ms": 10.0,
                                                                 "status": 200}))
        self.probe = self.probe_patch.start()
        self.reload_patch = mock.patch.object(router, "engine_reload", return_value=0)
        self.engine_reload = self.reload_patch.start()
        self.switch_patch = mock.patch.object(router, "engine_switch", return_value=0)
        self.engine_switch = self.switch_patch.start()
        self.sleep_patch = mock.patch.object(router.time, "sleep")
        self.sleep_patch.start()

    def tearDown(self):
        self.sleep_patch.stop()
        self.switch_patch.stop()
        self.reload_patch.stop()
        self.probe_patch.stop()
        self.rotate_patch.stop()
        self.listener.stop()
        self._tmp.cleanup()

    def _profile(self, stem):
        return self.root / "providers" / "proton" / f"{stem}.conf"

    def _probe(self, *results):
        self.probe_patch.stop()
        self.probe_patch = mock.patch.object(router, "probe_profile", side_effect=list(results))
        self.probe = self.probe_patch.start()

    def test_works_in_tun_mode_via_mixed_listener(self):
        # TUN capture keeps the 127.0.0.1 mixed listener, so the sweep can
        # probe through it in either mode.
        router.set_mode("tun")
        with mock.patch("sys.stdout.write"):
            rc = router.egress_sweep()
        self.assertEqual(rc, 0)

    def test_probes_every_profile_once_in_wrap_order(self):
        router.set_active("proton", self._profile("a"))
        rc = router.egress_sweep("proton")
        self.assertEqual(rc, 0)
        stems = [call.args[1].stem for call in self.probe.call_args_list]
        self.assertEqual(stems, ["a", "b", "c"])
        # hops are direct hard switches (a->b, b->c, then back to the best);
        # sweep never routes through rotate()
        self.rotate.assert_not_called()
        self.assertEqual(self.engine_switch.call_count, 3)

    def test_does_not_probe_unactivated_profiles_after_hop_failure(self):
        router.set_active("proton", self._profile("a"))
        # hop a->b succeeds, hop b->c fails, restore-to-original is a third switch
        self.engine_switch.side_effect = [0, 1, 0]
        self._probe(
            (True, {"ok": True, "latency_ms": 10.0, "status": 200}),
            (True, {"ok": True, "latency_ms": 20.0, "status": 200}),
        )
        rc = router.egress_sweep("proton")
        self.assertEqual(rc, 1)
        self.assertEqual([call.args[1].stem for call in self.probe.call_args_list], ["a", "b"])
        active = router.persisted_active("proton")
        self.assertIsNotNone(active)
        assert active is not None
        self.assertEqual(active.stem, "a")

    def test_ends_on_best_alive_profile(self):
        router.set_active("proton", self._profile("a"))
        self._probe(
            (True, {"ok": True, "latency_ms": 100.0, "status": 200}),
            (True, {"ok": True, "latency_ms": 50.0, "status": 200}),
            (True, {"ok": True, "latency_ms": 200.0, "status": 200}),
        )
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_sweep("proton")
        self.assertEqual(rc, 0)
        self.assertEqual(router.persisted_active("proton").stem, "b")
        # a->b, b->c, then back to the best (b)
        self.assertEqual(self.engine_switch.call_count, 3)
        joined = "".join(c.args[0] for c in write.call_args_list)
        self.assertIn("switched proton -> b (sweep)", joined)

    def test_keeps_current_when_already_best(self):
        # all profiles alive at the same latency: first tested (the current
        # one) wins, so the sweep must NOT reload the engine.
        router.set_active("proton", self._profile("a"))
        rc = router.egress_sweep("proton")
        self.assertEqual(rc, 0)
        self.assertEqual(router.persisted_active("proton").stem, "a")
        self.engine_reload.assert_not_called()

    def test_all_profiles_dead_exit_one_no_switch(self):
        router.set_active("proton", self._profile("a"))
        self._probe(
            (False, {"ok": False, "latency_ms": None, "status": None}),
            (False, {"ok": False, "latency_ms": None, "status": None}),
            (False, {"ok": False, "latency_ms": None, "status": None}),
        )
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_sweep("proton")
        self.assertEqual(rc, 1)
        # every exit is probed via a hard switch, then the original restored
        self.assertEqual(self.engine_switch.call_count, 3)
        self.assertEqual(router.persisted_active("proton").stem, "a")  # restored
        joined = "".join(c.args[0] for c in write.call_args_list)
        self.assertIn("0/3 alive", joined)

    def test_unknown_provider_is_an_error(self):
        rc = router.egress_sweep("ghost")
        self.assertEqual(rc, 1)
        self.probe.assert_not_called()
        self.rotate.assert_not_called()

    def test_uses_provider_pinned_probe_url(self):
        # the pinned probe_url from router.json wins over the route-domain
        # pick, so the sweep rides the tunnel to the configured target
        config = {
            "port": 2080,
            "providers": {
                "proton": {"directory": "providers/proton",
                           "probe_url": "https://example.com/probe"},
            },
            "routes": [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}],
        }
        (self.root / "router.json").write_text(json.dumps(config))
        self.assertEqual(router.load_config(), 0)
        router.set_active("proton", self._profile("a"))
        self.probe_patch.stop()  # exercise the real probe_profile/probe_url_for path
        urls = []

        def fake_probe_egress(*, port=None, url=None, timeout=None, opener=None, clock=None):
            urls.append(url)
            return {"ok": True, "latency_ms": 5.0, "status": 200, "error": None, "block_reason": None}

        with mock.patch.object(router, "probe_egress", side_effect=fake_probe_egress), \
             mock.patch("sys.stdout.write"):
            rc = router.egress_sweep("proton")
        self.assertEqual(rc, 0)
        self.assertEqual(urls, ["https://example.com/probe"] * 3)


class LastGoodConfigTests(unittest.TestCase):
    """Feature 2: sing-box.json.last-good snapshot + one-step restore when a
    reload's new config fails validation or the engine fails to come up."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        self.profile = self.root / "providers" / "proton" / "a.conf"
        _write_conf(self.profile)
        (self.root / "sing-box.pid").write_text("1234")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        self.patches = [
            mock.patch.object(router, "resolve_sing_box", return_value="/bin/sing-box"),
            mock.patch.object(router, "sing_box_at_least", return_value=True),
            mock.patch.object(router, "_pid_matches", return_value=True),
            mock.patch.object(router, "log_offset", return_value=0),
            mock.patch.object(router.os, "kill"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self._tmp.cleanup()

    def test_start_writes_last_good_after_success(self):
        class _Proc:
            pid = 4242
        with mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "wait_engine", return_value=True), \
             mock.patch.object(router.subprocess, "Popen", return_value=_Proc()):
            self.assertEqual(router.engine_start(), 0)
        self.assertTrue(router.LAST_GOOD_FILE.is_file())
        self.assertEqual(router.LAST_GOOD_FILE.read_text(), router.SING_BOX_CONFIG.read_text())
        self.assertEqual(stat.S_IMODE(router.LAST_GOOD_FILE.stat().st_mode), 0o600)

    def test_start_failure_never_writes_last_good(self):
        class _Proc:
            pid = 4242
        with mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "wait_engine", return_value=False), \
             mock.patch.object(router.subprocess, "Popen", return_value=_Proc()):
            self.assertEqual(router.engine_start(), 1)
        self.assertFalse(router.LAST_GOOD_FILE.exists())

    def test_reload_invalid_config_restores_last_good_and_reloads(self):
        known_good = json.dumps({"inbounds": [], "known": True})
        router.LAST_GOOD_FILE.write_text(known_good)
        with mock.patch.object(router, "validate_config", side_effect=[False, True]), \
             mock.patch.object(router, "wait_engine", side_effect=[True]) as wait:
            self.assertEqual(router.engine_reload(), 0)
        # restored file == last-good content
        self.assertEqual(router.SING_BOX_CONFIG.read_text(), known_good)
        seen_kills = [c for c in router.os.kill.mock_calls]  # noqa: F841
        # engine was hot-reloaded onto the restore
        self.assertEqual(wait.call_count, 1)

    def test_reload_restore_without_last_good_fails_cleanly(self):
        router.LAST_GOOD_FILE.unlink(missing_ok=True)
        with mock.patch.object(router, "validate_config", return_value=False), \
             mock.patch("sys.stderr.write") as err:
            rc = router.engine_reload()
        self.assertEqual(rc, 1)
        joined = "".join(str(c) for c in err.call_args_list)
        self.assertIn("no sing-box.json.last-good", joined)

    def test_restored_last_good_also_failing_stops_with_message(self):
        router.LAST_GOOD_FILE.write_text(json.dumps({"inbounds": []}))
        with mock.patch.object(router, "validate_config", return_value=False), \
             mock.patch("sys.stderr.write") as err:
            rc = router.engine_reload()
        self.assertEqual(rc, 1)
        joined = "".join(str(c) for c in err.call_args_list)
        self.assertIn("restored sing-box.json.last-good failed sing-box check", joined)

    def test_reload_start_failure_restores_and_starts_from_last_good(self):
        known_good = json.dumps({"inbounds": [], "known": True})
        router.LAST_GOOD_FILE.write_text(known_good)
        with mock.patch.object(router, "validate_config", side_effect=[True, True]), \
             mock.patch.object(router, "engine_start", return_value=1), \
             mock.patch.object(router, "restore_last_good", return_value=0) as restore:
            # no pid file -> reload must start the engine
            router.PID_FILE.unlink(missing_ok=True)
            rc = router.engine_reload()
        self.assertEqual(rc, 0)
        restore.assert_called_once()

    def test_successful_reload_refreshes_last_good(self):
        with mock.patch.object(router, "validate_config", return_value=True), \
             mock.patch.object(router, "wait_engine", return_value=True) as wait:
            self.assertEqual(router.engine_reload(), 0)
        self.assertTrue(router.LAST_GOOD_FILE.is_file())
        self.assertEqual(router.LAST_GOOD_FILE.read_text(), router.SING_BOX_CONFIG.read_text())
        self.assertEqual(wait.call_count, 1)

    def test_restore_starts_engine_with_existing_config_when_engine_gone(self):
        known_good = json.dumps({"inbounds": [], "known": True})
        router.LAST_GOOD_FILE.write_text(known_good)
        router.PID_FILE.unlink(missing_ok=True)
        with mock.patch.object(router, "validate_config", side_effect=[False, True]), \
             mock.patch.object(router, "engine_start", return_value=0) as start:
            rc = router.engine_reload()
        self.assertEqual(rc, 0)
        start.assert_called_once_with(use_existing_config=True)


class ErrorPolicyTests(unittest.TestCase):
    """error_policy table: merge precedence (provider > global > built-in),
    action+seconds overrides honored by rotate, exhaust marker in egress +
    status --json, block marker, tls/connection defaults matching the merged
    300s rule, missing-reason fallback, config validation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        for stem in ("a", "b", "c"):
            _write_conf(self.root / "providers" / "proton" / f"{stem}.conf")
        self.profile = self.root / "providers" / "proton" / "a.conf"
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        router._error_policy = None
        router._egress_settings = dict(router.DEFAULT_EGRESS_SETTINGS)
        self.reload_patch = mock.patch.object(router, "engine_reload", return_value=0)
        self.reload_patch.start()
        self.switch_patch = mock.patch.object(router, "engine_switch", return_value=0)
        self.switch_patch.start()

    def tearDown(self):
        self.switch_patch.stop()
        self.reload_patch.stop()
        router._error_policy = None
        self._tmp.cleanup()

    def _cooldown_until(self, stem="a"):
        return int((self.root / "state" / "cooldowns" / "proton" / f"{stem}.until").read_text().strip())

    def test_builtin_defaults_applied_without_config(self):
        self.assertEqual(router.policy_action("proton", "429"), ("exhaust", 900))
        self.assertEqual(router.policy_action("proton", "503"), ("cooldown", 120))
        self.assertEqual(router.policy_action("proton", "timeout"), ("cooldown", 60))
        self.assertEqual(router.policy_action("proton", "tls"), ("cooldown", 300))
        self.assertEqual(router.policy_action("proton", "connection"), ("cooldown", 300))
        self.assertEqual(router.policy_action("proton", "1010"), ("block", 3600))
        self.assertEqual(router.policy_action("proton", "403"), ("block", 3600))

    def test_merge_precedence_default_vs_global_vs_provider(self):
        router._error_policy = {
            "503": {"action": "exhaust", "seconds": 600},
            "timeout": {"action": "cooldown", "seconds": 30},
        }
        # global overrides built-in defaults
        self.assertEqual(router.policy_action("proton", "503"), ("exhaust", 600))
        self.assertEqual(router.policy_action("proton", "timeout"), ("cooldown", 30))
        # untouched keys keep their built-in defaults
        self.assertEqual(router.policy_action("proton", "429"), ("exhaust", 900))
        # per-provider beats global
        router._providers["proton"]["error_policy"] = {"503": {"action": "cooldown", "seconds": 90}}
        self.assertEqual(router.policy_action("proton", "503"), ("cooldown", 90))
        self.assertEqual(router.policy_action("proton", "timeout"), ("cooldown", 30))
        self.assertEqual(router.policy_action("proton", "429"), ("exhaust", 900))

    def test_reason_normalization_maps_transport_and_http(self):
        self.assertEqual(router.policy_action("proton", "cloudflare-1010"), ("block", 3600))
        self.assertEqual(router.policy_action("proton", "cloudflare-403"), ("block", 3600))
        self.assertEqual(router.policy_action("proton", "HTTP 503 Service Unavailable"), ("cooldown", 120))
        self.assertEqual(router.policy_action("proton", "[SSL: TLSV1_ALERT_INTERNAL_ERROR]"), ("cooldown", 300))
        self.assertEqual(router.policy_action("proton", "TimeoutError: timed out"), ("cooldown", 60))
        self.assertEqual(router.policy_action("proton", "Connection reset by peer"), ("cooldown", 300))

    def test_missing_reason_falls_back_to_default(self):
        router._error_policy = {"default": {"action": "exhaust", "seconds": 45}}
        self.assertEqual(router.policy_action("proton", "some-custom-reason"), ("exhaust", 45))
        router._error_policy = None
        self.assertEqual(router.policy_action("proton", "some-custom-reason"), ("cooldown", 300))

    def test_seconds_override_honored_by_rotate_reason(self):
        router.set_active("proton", self.profile)
        router._providers["proton"]["error_policy"] = {"503": {"action": "cooldown", "seconds": 45}}
        with mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True})):
            self.assertEqual(router.rotate("proton", reason="503"), 0)
        self.assertEqual(self._cooldown_until(), int(time.time()) + 45)  # exact policy seconds
        record = router.read_egress("proton", self.profile)
        self.assertEqual(record["upstream_error"], "503")
        self.assertFalse(record.get("exhausted"))

    def test_exhaust_writes_marker_visible_in_status_json(self):
        router._error_policy = {"429": {"action": "exhaust", "seconds": 900}}
        router.set_active("proton", self.profile)
        router._apply_upstream_failure("proton", self.profile, "429", 60)
        record = router.read_egress("proton", self.profile)
        self.assertTrue(record["exhausted"])
        self.assertIsInstance(record["exhausted_until"], str)
        self.assertTrue(router.is_cooled_down("proton", self.profile))
        with mock.patch.object(router, "_status_report", return_value=(0, "up (proxy 127.0.0.1:2080)")):
            data = router.status_json()
        egress = data["providers"]["proton"]["egress"]["a"]
        self.assertTrue(egress["exhausted"])
        self.assertEqual(egress["exhausted_until"], record["exhausted_until"])
        # status --json echoes the effective policy per provider
        self.assertEqual(data["error_policy"]["proton"]["429"], {"action": "exhaust", "seconds": 900})

    def test_block_action_marks_blocked(self):
        router.set_active("proton", self.profile)
        router._apply_upstream_failure("proton", self.profile, "1010", 60)
        self.assertTrue(router.egress_is_blocked("proton", self.profile))
        record = router.read_egress("proton", self.profile)
        self.assertEqual(record["block_reason"], "1010")
        self.assertGreaterEqual(record["blocked_until"], int(time.time()) + 3599)

    def test_tls_reason_matches_merged_300s_rule(self):
        # A TLS transport death through probe_profile cools for the policy's
        # tls seconds; the built-in 300s must match the merged TLS rule.
        with mock.patch.object(router, "probe_egress", return_value={
                "ok": False, "latency_ms": None, "status": None,
                "error": "URLError: <urlopen error [SSL: TLSV1_ALERT_INTERNAL_ERROR]>",
                "block_reason": None}):
            ok, _ = router.probe_profile("proton", self.profile)
        self.assertFalse(ok)
        until = self._cooldown_until()
        self.assertGreaterEqual(until, int(time.time()) + 290)
        self.assertLess(until, int(time.time()) + 310)
        self.assertFalse(router.egress_is_blocked("proton", self.profile))
        # a configured tls override is honored by the probe path too
        router._clear_cooldown("proton", self.profile)
        router._error_policy = {"tls": {"action": "cooldown", "seconds": 45}}
        with mock.patch.object(router, "probe_egress", return_value={
                "ok": False, "latency_ms": None, "status": None,
                "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
                "block_reason": None}):
            router.probe_profile("proton", self.profile)
        self.assertGreaterEqual(self._cooldown_until(), int(time.time()) + 40)

    def test_check_egress_live_dead_uses_connection_seconds(self):
        router._error_policy = {"connection": {"action": "cooldown", "seconds": 20}}
        with mock.patch.object(router, "probe_egress", return_value={
                "ok": False, "latency_ms": None, "status": None,
                "error": "URLError: <urlopen error timed out>",
                "block_reason": None}), \
             mock.patch.object(router, "egress_dns_probe", return_value=None):
            status, _ = router.check_egress_live("proton", self.profile)
        self.assertEqual(status, "dead")
        self.assertGreaterEqual(self._cooldown_until(), int(time.time()) + 15)

    def test_load_config_validates_and_merges_error_policy(self):
        (self.root / "router.json").write_text(json.dumps({
            "port": 2080,
            "providers": {
                "proton": {"directory": "providers/proton",
                           "error_policy": {"429": {"action": "cooldown", "seconds": 11}}},
            },
            "routes": [{"id": "r", "domains": ["example.com"], "provider": "proton"}],
            "error_policy": {"503": {"action": "exhaust", "seconds": 222}},
        }))
        self.assertEqual(router.load_config(), 0)
        self.assertEqual(router.policy_action("proton", "503"), ("exhaust", 222))
        self.assertEqual(router.policy_action("proton", "429"), ("cooldown", 11))
        self.assertEqual(router.policy_action("proton", "1010"), ("block", 3600))
        # malformed policy fails the config load instead of silently guessing
        (self.root / "router.json").write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton"}},
            "routes": [{"id": "r", "domains": ["example.com"], "provider": "proton"}],
            "error_policy": {"503": {"action": "nope", "seconds": 5}},
        }))
        self.assertEqual(router.load_config(), 1)


class RoutingModeTests(unittest.TestCase):
    """Feature: routing modes (safe-list / vpn-list) adjust route.final and
    prepend direct-domain pins; default mode stays byte-compatible."""

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
        router._routes = [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}]
        router._port = 2080
        router._vpn = {}
        router._routing = {}
        router.set_mode("proxy")  # never inherit tun from another test

    def tearDown(self):
        router._routing = {}  # never leak a routing mode into later classes
        self._tmp.cleanup()

    def test_default_mode_byte_compatible(self):
        config, active = router.build_singbox_config()
        self.assertEqual(set(active), {"proton"})
        self.assertEqual(active["proton"].name, "a.conf")
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["route"]["rules"], [
            {"outbound": "proton", "domain_suffix": ["example.com"]},
            {"domain": ["localhost"], "outbound": "direct"},
            {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
        ])
        self.assertEqual(config["dns"]["rules"], [
            {"domain_suffix": ["example.com"], "server": "dns-proton"},
        ])

    def test_explicit_default_mode_is_accepted(self):
        router._routing = {"mode": "default"}
        config, _ = router.build_singbox_config()
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["route"]["rules"][0], {"outbound": "proton", "domain_suffix": ["example.com"]})

    def test_safe_list_final_and_direct_pins_first(self):
        router._routing = {"mode": "safe-list", "direct_domains": ["youtube.com", "google.com"],
                           "default_provider": "proton"}
        config, _ = router.build_singbox_config()
        self.assertEqual(config["route"]["final"], "proton")
        rules = config["route"]["rules"]
        # direct-domain pins come FIRST, before every provider route
        self.assertEqual(rules[0], {"domain_suffix": ["youtube.com", "google.com"], "outbound": "direct"})
        self.assertEqual(rules[1], {"outbound": "proton", "domain_suffix": ["example.com"]})
        # loopback/localhost direct pins still present at the end
        self.assertEqual(rules[-2], {"domain": ["localhost"], "outbound": "direct"})
        self.assertEqual(rules[-1], {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"})

    def test_safe_list_direct_domains_resolve_via_dns_local(self):
        # youtube.com is direct-only; example.com is ALSO in a provider route.
        router._routing = {"mode": "safe-list", "direct_domains": ["youtube.com", "example.com"],
                           "default_provider": "proton"}
        config, _ = router.build_singbox_config()
        # direct domains pin to dns-local FIRST, never to a provider resolver
        self.assertEqual(config["dns"]["rules"][0],
                         {"domain_suffix": ["youtube.com", "example.com"], "server": "dns-local"})
        # example.com lives in a provider route too; that route must still pin
        # it to dns-proton (but the direct pin wins in rule order).
        self.assertIn({"domain_suffix": ["example.com"], "server": "dns-proton"}, config["dns"]["rules"])

    def test_probe_url_for_skips_direct_whitelisted_domains_in_safe_list(self):
        # Probe must ride the TUNNEL: a direct-whitelisted host measures the
        # direct path and false-alives a dead exit. probe_url_for must skip
        # it and pick the next tunneled route domain.
        router._routing = {"mode": "safe-list", "direct_domains": ["example.com"],
                           "default_provider": "proton"}
        # safe-list default provider carries all unrouted traffic, so the
        # generic egress probe URL is a valid tunneled target
        default_probe = router.egress_settings()["probe_url"]
        self.assertEqual(router.probe_url_for("proton"), default_probe)
        # a pinned probe_url whose host is direct-whitelisted measures the
        # direct path and must be rejected in favor of the default target
        router._providers["proton"]["probe_url"] = "https://example.com/pinned"
        self.assertEqual(router.probe_url_for("proton"), default_probe)

    def test_probe_url_for_does_not_skip_in_default_or_vpn_list(self):
        # direct_domains only pin direct in safe-list mode; in default/vpn-list
        # the list is ignored, so the normal first-domain probe must remain.
        router._routing = {"mode": "vpn-list", "vpn_domains": ["example.com"],
                           "direct_domains": ["example.com"]}
        self.assertEqual(router.probe_url_for("proton"), "https://example.com")
        router._routing = {}
        self.assertEqual(router.probe_url_for("proton"), "https://example.com")

    def test_probe_url_for_uses_provider_pinned_probe_url_first(self):
        # roblox.com's bot-protection landing hangs even on a healthy tunnel;
        # a pinned per-provider probe_url (a light target) must win over the
        # first-routed-domain pick so egress checks don't false-mark the exit.
        router._providers["cloudflare"] = {
            "directory": "providers/cloudflare",
            "cooldown_seconds": 60,
            "probe_url": "https://www.roblox.com/robots.txt",
        }
        router._routes = router._routes + [
            {"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"}]
        self.assertEqual(router.probe_url_for("cloudflare"),
                         "https://www.roblox.com/robots.txt")
        # provider without a pin still uses the route pick
        self.assertEqual(router.probe_url_for("proton"), "https://example.com")

    def test_probe_url_for_ignores_invalid_pinned_probe_url(self):
        # invalid pin falls back to the first routed domain, not to garbage
        router._providers["cloudflare"] = {
            "directory": "providers/cloudflare",
            "cooldown_seconds": 60,
            "probe_url": "not-a-url",
        }
        router._routes = router._routes + [{"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"}]
        self.assertEqual(router.probe_url_for("cloudflare"), "https://roblox.com")

    def test_safe_list_tun_keeps_hijack_first(self):
        router.set_mode("tun")
        router._routing = {"mode": "safe-list", "direct_domains": ["youtube.com"], "default_provider": "proton"}
        config, _ = router.build_singbox_config()
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"protocol": "dns", "action": "hijack-dns"})
        # sniff recovers hostnames for the raw-IP TUN flows before routing
        self.assertEqual(rules[1], {"action": "sniff"})
        self.assertEqual(rules[2], {"domain_suffix": ["youtube.com"], "outbound": "direct"})
        self.assertEqual(config["route"]["final"], "proton")

    def test_safe_list_bad_default_provider_fails_build(self):
        # 'cloudflare' is a known provider but has no usable profile: the
        # build must fail loudly instead of emitting a dangling final.
        router._routing = {"mode": "safe-list", "direct_domains": [], "default_provider": "cloudflare"}
        with self.assertRaises(SystemExit) as ctx:
            router.build_singbox_config()
        self.assertIn("cloudflare", str(ctx.exception))
        self.assertIn("no active profile", str(ctx.exception))

    def test_safe_list_unknown_default_provider_fails_load(self):
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [],
            "routing": {"mode": "safe-list", "default_provider": "banana"},
        }))
        self.assertEqual(router.load_config(), 1)
        self.assertEqual(router._routing, {})  # nothing silently accepted

    def test_safe_list_missing_default_provider_fails_load(self):
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [],
            "routing": {"mode": "safe-list", "direct_domains": ["youtube.com"]},
        }))
        self.assertEqual(router.load_config(), 1)

    def test_vpn_list_final_direct_and_pins_intact(self):
        router._routing = {"mode": "vpn-list", "vpn_domains": ["example.com"]}
        config, _ = router.build_singbox_config()
        self.assertEqual(config["route"]["final"], "direct")
        # tunnel pins intact and no direct-pin/dns rules were added
        self.assertEqual(config["route"]["rules"], [
            {"outbound": "proton", "domain_suffix": ["example.com"]},
            {"domain": ["localhost"], "outbound": "direct"},
            {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
        ])
        self.assertEqual(config["dns"]["rules"], [
            {"domain_suffix": ["example.com"], "server": "dns-proton"},
        ])

    def test_bad_mode_fails_load(self):
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [],
            "routing": {"mode": "banana"},
        }))
        self.assertEqual(router.load_config(), 1)

    def test_non_list_domains_fail_load(self):
        router.CONFIG_FILE.write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [],
            "routing": {"mode": "safe-list", "direct_domains": "youtube.com", "default_provider": "proton"},
        }))
        self.assertEqual(router.load_config(), 1)


class RoutingCliTests(unittest.TestCase):
    """CLI surface for routing modes: atomic 0600 writes, no engine reload."""

    REPO = Path(__file__).resolve().parent.parent

    def _run(self, tmp: str, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PROXY_ROUTER_ROOT"] = tmp
        env["SING_BOX"] = ""
        return subprocess.run(
            [sys.executable, str(self.REPO / "router.py"), *args],
            cwd=self.REPO, env=env, capture_output=True, text=True,
        )

    def _seed(self, tmp: str) -> None:
        root = Path(tmp)
        (root / "providers" / "proton").mkdir(parents=True)
        _write_conf(root / "providers" / "proton" / "a.conf")
        root.joinpath("router.json").write_text(json.dumps({
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [{"id": "example-com", "domains": ["example.com"], "provider": "proton"}],
        }))

    def test_routing_set_add_remove_roundtrip_with_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed(tmp)
            result = self._run(tmp, "routing", "set", "--mode", "safe-list", "--default-provider", "proton")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("engine was NOT reloaded", result.stderr)
            config_path = Path(tmp) / "router.json"
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            data = json.loads(config_path.read_text())
            self.assertEqual(data["routing"]["mode"], "safe-list")
            self.assertEqual(data["routing"]["default_provider"], "proton")
            self.assertEqual(self._run(tmp, "routing", "add", "--mode", "safe-list", "--domain", "youtube.com").returncode, 0)
            self.assertEqual(json.loads(config_path.read_text())["routing"]["direct_domains"], ["youtube.com"])
            self.assertEqual(self._run(tmp, "routing", "remove", "--mode", "safe-list", "--domain", "youtube.com").returncode, 0)
            self.assertEqual(json.loads(config_path.read_text())["routing"]["direct_domains"], [])
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)

    def test_routing_show_echoes_effective_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed(tmp)
            self.assertEqual(self._run(tmp, "routing", "set", "--mode", "vpn-list").returncode, 0)
            self.assertEqual(self._run(tmp, "routing", "add", "--mode", "vpn-list", "--domain", "blocked.example").returncode, 0)
            result = self._run(tmp, "routing", "show")
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)  # stdout is pure JSON
            self.assertEqual(data["mode"], "vpn-list")
            self.assertEqual(data["vpn_domains"], ["blocked.example"])
            self.assertEqual(data["direct_domains"], [])

    def test_status_json_includes_routing_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed(tmp)
            self.assertEqual(self._run(tmp, "routing", "set", "--mode", "safe-list", "--default-provider", "proton").returncode, 0)
            # engine is not running in the tmp root, so status exits 1 with
            # "down" - the routing echo must still be in the JSON.
            result = self._run(tmp, "status", "--json")
            self.assertEqual(result.returncode, 1)
            data = json.loads(result.stdout)
            self.assertEqual(data["routing"]["mode"], "safe-list")
            self.assertEqual(data["routing"]["default_provider"], "proton")
            self.assertEqual(data["routing"]["direct_domains"], [])

    def test_routing_set_rejects_unknown_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed(tmp)
            result = self._run(tmp, "routing", "set", "--mode", "safe-list", "--default-provider", "banana")
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a known provider", result.stderr)
            data = json.loads((Path(tmp) / "router.json").read_text())
            self.assertNotIn("routing", data)  # rejected config never written

    def test_routing_set_default_resets_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed(tmp)
            self.assertEqual(self._run(tmp, "routing", "set", "--mode", "safe-list", "--default-provider", "proton").returncode, 0)
            result = self._run(tmp, "routing", "set", "--mode", "default")
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((Path(tmp) / "router.json").read_text())
            self.assertEqual(data["routing"]["mode"], "default")


class ScheduledRotationTests(unittest.TestCase):
    """rotate_due / next_rotation_at / _load_rotation_settings (scheduled rotation)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        (self.root / "state").mkdir(parents=True)
        for name in ("a", "b"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._rotation = {"interval_seconds": 3600, "jitter_seconds": 300}
        router._routes = []

    def tearDown(self):
        self._tmp.cleanup()

    def _rotation_record(self) -> int:
        path = self.root / "state" / "proton.rotation"
        self.assertTrue(path.is_file(), "rotation record was not written")
        return int(json.loads(path.read_text())["at"])

    def test_load_rotation_settings_rejects_negative(self):
        with self.assertRaises(ValueError):
            router._load_rotation_settings({"rotation": {"interval_seconds": -1, "jitter_seconds": 0}})

    def test_load_rotation_settings_defaults_when_absent(self):
        router._load_rotation_settings({})
        self.assertEqual(router.scheduled_interval(), 0)
        self.assertEqual(router._rotation["jitter_seconds"], 300)

    def test_rotate_due_disabled_returns_3(self):
        router._rotation = {"interval_seconds": 0, "jitter_seconds": 300}
        self.assertEqual(router.rotate_due("proton"), 3)

    def test_rotate_due_seeds_missing_record(self):
        # No rotation record yet: the first pass seeds "rotated now" (returns 0)
        # so a fresh install waits a full interval before the first switch.
        router.set_active("proton", self.root / "providers" / "proton" / "b.conf")
        self.assertEqual(router.rotate_due("proton"), 0)
        record = json.loads((self.root / "state" / "proton.rotation").read_text())
        self.assertEqual(record["profile"], "b")

    def test_rotate_due_not_due_returns_3(self):
        (self.root / "state" / "proton.rotation").write_text(
            json.dumps({"profile": "a", "at": int(time.time())}), encoding="utf-8")
        with mock.patch.object(router, "rotate", side_effect=AssertionError("must not rotate when not due")):
            self.assertEqual(router.rotate_due("proton"), 3)

    def test_rotate_due_rotates_when_interval_elapsed(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        backdated = int(time.time()) - 7200  # two full intervals ago
        (self.root / "state" / "proton.rotation").write_text(
            json.dumps({"profile": "a", "at": backdated}), encoding="utf-8")
        with mock.patch.object(router, "engine_reload", return_value=0), \
                mock.patch.object(router, "engine_switch", return_value=0), \
                mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True})):
            self.assertEqual(router.rotate_due("proton"), 0)
        self.assertGreater(self._rotation_record(), backdated)

    def test_next_rotation_at_is_deterministic(self):
        at = int(time.time()) - 3600
        (self.root / "state" / "proton.rotation").write_text(
            json.dumps({"profile": "a", "at": at}), encoding="utf-8")
        self.assertEqual(router.next_rotation_at("proton"), router.next_rotation_at("proton"))

    def test_status_json_reports_rotation(self):
        (self.root / "state" / "proton.rotation").write_text(
            json.dumps({"profile": "b", "at": int(time.time()) - 7200}), encoding="utf-8")
        with mock.patch.object(router, "_status_report", return_value=(0, "ok")):
            data = router.status_json()
        self.assertEqual(data["rotation"]["interval_seconds"], 3600)
        self.assertIn("next_at", data["rotation"])


class RotationPolicyTests(unittest.TestCase):
    """Autoroute: rotation policy 'latency' (default) vs 'least-recent'."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        (self.root / "state").mkdir(parents=True)
        for name in ("a", "b", "c"):
            _write_conf(self.root / "providers" / "proton" / f"{name}.conf")
        router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
        router._rotation = {"interval_seconds": 0, "jitter_seconds": 300, "policy": "latency"}
        router._routes = []

    def tearDown(self):
        self._tmp.cleanup()

    def _profile(self, stem):
        return self.root / "providers" / "proton" / f"{stem}.conf"

    def _set_policy(self, policy):
        router._load_rotation_settings({"rotation": {"policy": policy}})

    def _seed_ok(self, stem, last_ok_at, latency_ms=None):
        record = {"last_ok_at": last_ok_at, "checked_at": last_ok_at, "fails": 0}
        if latency_ms is not None:
            record["latency_ms"] = latency_ms
        router.write_egress("proton", self._profile(stem), record)

    def _active_stem(self):
        return (self.root / "state" / "proton.active").read_text()

    def test_default_policy_is_latency(self):
        self.assertEqual(router.rotation_policy(), "latency")

    def test_least_recent_policy_loaded(self):
        self._set_policy("least-recent")
        self.assertEqual(router.rotation_policy(), "least-recent")

    def test_invalid_policy_rejected(self):
        with self.assertRaises(ValueError):
            self._set_policy("round-robin")

    def _cool(self, stem):
        path = self.root / "state" / "cooldowns" / "proton" / f"{stem}.until"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(int(time.time()) + 3600))

    def _rotate_ranked(self):
        with mock.patch.object(router, "engine_reload", return_value=0), \
                mock.patch.object(router, "engine_switch", return_value=0), \
                mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True})):
            return router.rotate("proton")

    def test_lru_key_oldest_ok_wins(self):
        self._set_policy("least-recent")
        router.set_active("proton", self._profile("a"))
        self._cool("a")
        self._seed_ok("b", int(time.time()) - 1 * 3600)
        self._seed_ok("c", int(time.time()) - 2 * 3600)
        self.assertEqual(self._rotate_ranked(), 0)
        self.assertEqual(self._active_stem(), "c")

    def test_least_recent_never_used_wins(self):
        self._set_policy("least-recent")
        router.set_active("proton", self._profile("a"))
        self._cool("a")
        self._seed_ok("b", int(time.time()) - 3600)
        self.assertEqual(self._rotate_ranked(), 0)
        self.assertEqual(self._active_stem(), "c")

    def test_least_recent_skips_recently_failed(self):
        self._set_policy("least-recent")
        router.set_active("proton", self._profile("a"))
        self._cool("a")
        self._seed_ok("b", int(time.time()) - 3600)
        router.write_egress("proton", self._profile("c"), {
            "last_ok_at": None, "checked_at": int(time.time() - 100),
            "fails": 2, "latency_ms": None})
        self.assertEqual(self._rotate_ranked(), 0)
        self.assertEqual(self._active_stem(), "b")

    def test_least_recent_excludes_blocked(self):
        self._set_policy("least-recent")
        router.set_active("proton", self._profile("a"))
        self._cool("a")
        self._seed_ok("b", int(time.time()) - 3600)
        router.write_egress("proton", self._profile("c"), {
            "last_ok_at": int(time.time() - 1), "checked_at": int(time.time() - 1),
            "fails": 0, "blocked_until": int(time.time()) + 3600})
        self.assertEqual(self._rotate_ranked(), 0)
        self.assertEqual(self._active_stem(), "b")

    def test_latency_policy_prefers_fastest_over_oldest(self):
        router.set_active("proton", self._profile("a"))
        self._cool("a")
        self._seed_ok("a", int(time.time()) - 28800, latency_ms=200)
        self._seed_ok("b", int(time.time()) - 3600, latency_ms=40)
        self.assertEqual(self._rotate_ranked(), 0)
        self.assertEqual(self._active_stem(), "b")

    def test_status_json_exposes_policy(self):
        data = router.status_json()
        self.assertEqual(data["rotation"]["policy"], "latency")
        self._set_policy("least-recent")
        self.assertEqual(router.status_json()["rotation"]["policy"], "least-recent")


class WithProxyTests(unittest.TestCase):
    """with-proxy fail-open runner (listener probe + env set/strip)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        (self.root / "router.json").write_text(
            json.dumps({"port": self.port}), encoding="utf-8")

    def tearDown(self):
        self._srv.close()
        self._tmp.cleanup()

    def _exec_through(self, healthy: bool) -> dict:
        """Run with_proxy against a (possibly down) listener and capture the
        env the child would receive, using a fake execvpe that stops here."""
        caught = {}

        def fake_execvpe(file, argv, env):
            caught.update({"file": file, "argv": argv, "env": env})
            raise SystemExit(0)

        if not healthy:
            self._srv.close()
        with mock.patch.object(router.os, "execvpe", side_effect=fake_execvpe):
            with self.assertRaises(SystemExit):
                router.with_proxy(["/bin/echo", "hi"], timeout_ms=200)
        return caught

    def test_check_up_prints_url_and_exit_0(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(router.with_proxy([], check=True, timeout_ms=200), 0)
        self.assertEqual(out.getvalue().strip(), f"http://127.0.0.1:{self.port}")

    def test_check_down_exit_1(self):
        self._srv.close()
        self.assertEqual(router.with_proxy([], check=True, timeout_ms=200), 1)

    def test_force_proxy_refused_when_down(self):
        self._srv.close()
        self.assertEqual(router.with_proxy(["/bin/echo"], force_proxy=True, timeout_ms=200), 4)

    def test_force_proxy_and_direct_rejected(self):
        self.assertEqual(router.with_proxy(["/bin/echo"], force_proxy=True, force_direct=True, timeout_ms=200), 1)

    def test_missing_command_rejected(self):
        self.assertEqual(router.with_proxy([], timeout_ms=200), 1)

    def test_proxy_env_set_when_healthy(self):
        caught = self._exec_through(healthy=True)
        self.assertEqual(caught["env"].get("http_proxy"), f"http://127.0.0.1:{self.port}")
        self.assertEqual(caught["env"].get("HTTPS_PROXY"), f"http://127.0.0.1:{self.port}")

    def test_proxy_env_stripped_when_down(self):
        os.environ["http_proxy"] = "http://stale.example:8080"
        try:
            caught = self._exec_through(healthy=False)
            self.assertNotIn("http_proxy", caught["env"])
            self.assertNotIn("HTTPS_PROXY", caught["env"])
        finally:
            os.environ.pop("http_proxy", None)

    def test_force_direct_skips_probe_even_when_healthy(self):
        caught = self._exec_through_variant(force_direct=True)
        self.assertNotIn("http_proxy", caught["env"])

    def _exec_through_variant(self, force_direct: bool = False) -> dict:
        caught = {}

        def fake_execvpe(file, argv, env):
            caught.update({"env": env})
            raise SystemExit(0)

        with mock.patch.object(router.os, "execvpe", side_effect=fake_execvpe):
            with self.assertRaises(SystemExit):
                router.with_proxy(["/bin/echo"], force_direct=force_direct, timeout_ms=200)
        return caught

    def test_config_port_falls_back_to_default(self):
        (self.root / "router.json").unlink()
        self.assertEqual(router._config_port(), router.DEFAULT_PORT)


if __name__ == "__main__":
    unittest.main()
