"""Unit tests for router.py (stdlib only, no third-party deps, no network)."""
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        with mock.patch.object(router, "listener_up", return_value=True):
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
