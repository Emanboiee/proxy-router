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
        self.assertEqual(active, {"proton"})
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
        with mock.patch.object(router, "engine_reload", return_value=0):
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
        self.probe_patch = mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True}))
        self.probe = self.probe_patch.start()

    def tearDown(self):
        self.probe_patch.stop()
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
        with mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})) as probe:
            self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "a")
        self.assertTrue(router.is_cooled_down("proton", self._profile("b")))
        probe.assert_called_once()
        # first reload for the switch, second for the rollback
        self.assertEqual(self.engine_reload.call_count, 2)

    def test_rotate_reason_probe_failure_keeps_reason_cooldown(self):
        # A --reason rotation marks the current profile FAILED upstream; the
        # rollback restore must NOT clear that mark (ping-pong A->B->A->C->A).
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            self.assertEqual(router.rotate("proton", reason="503"), 0)
        self.assertEqual(self._active(), "a")  # rolled back to previous
        self.assertTrue(router.is_cooled_down("proton", self._profile("a")))  # mark survived
        self.assertTrue(router.is_cooled_down("proton", self._profile("b")))  # failed switch also cooled
        record = router.read_egress("proton", self._profile("a"))
        self.assertEqual(record["upstream_error"], "503")

    def test_rotate_plain_probe_failure_clears_previous_cooldown(self):
        # Plain rotations only mildly cool the previous profile as preference;
        # restoring it on rollback MUST undo that so last-good is usable now.
        router.set_active("proton", self._profile("a"))
        with mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            self.assertEqual(router.rotate("proton"), 0)
        self.assertEqual(self._active(), "a")
        self.assertFalse(router.is_cooled_down("proton", self._profile("a")))

    def test_rotate_probe_failure_without_previous_keeps_switch(self):
        with mock.patch.object(router, "probe_profile", return_value=(False, {"ok": False})):
            self.assertEqual(router.rotate("proton"), 0)
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
    stop-at-first-dead."""

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

    def test_requires_proxy_mode(self):
        router.set_mode("tun")
        with mock.patch("sys.stdout.write"):
            rc = router.egress_check()
        self.assertEqual(rc, 1)

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
        # stop at first dead: cloudflare must not be checked
        self.assertEqual(self.live.call_count, 1)

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
        self._live(("dead", {"ok": False, "dns_ok": False}))
        with mock.patch("sys.stdout.write") as write:
            rc = router.egress_check(as_json=True)
        self.assertEqual(rc, 1)
        text = "".join(c.args[0] for c in write.call_args_list)
        data = json.loads(text)
        self.assertEqual(data["dead"], ["proton"])
        self.assertEqual(data["results"]["proton"]["status"], "dead")

    def test_provider_filter(self):
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        rc = router.egress_check("proton")
        self.assertEqual(rc, 0)
        self.assertEqual(self.live.call_count, 1)

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

    def tearDown(self):
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


if __name__ == "__main__":
    unittest.main()
