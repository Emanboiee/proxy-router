"""Isolated WARP-as-local-SOCKS5 routing tests (alternate-port worker).

Recommended integration contract for the core worker:

- Provider entry: ``providers["cloudflare"] = {"socks5": {"host":
  "127.0.0.1", "port": 2181}}`` (canonical key ``"socks5"``).
  Tests also exercise tolerant alias parsing separately.
- Helpers: ``router.proxy_upstream(name) -> (host, port)`` and the
  generated sing-box SOCKS5 outbound.
- ``build_singbox_config()``: emits ``{"type": "socks", "tag": name, ...}``
  in ``outbounds`` for proxy-backed providers (no WireGuard profile
  required), routes that provider's domains to the SOCKS5 tag, keeps
  ``route.final == "direct"``.
- Failure semantics: a dead upstream degrades to a bounded fallback
  (direct / probe failure), never a shared-engine teardown
  (``engine_stop`` must not run for one dead upstream).


Isolation: temp roots only (``load_router`` relocates ROOT/CONFIG/PID/STATE
into ``tmp_path``), fake runners / monkeypatched sockets (no real
listeners, no binding 2180/2181), never touches live 2080, system proxy,
TUN, YouTube, official WARP, or host machine state.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]

ALT_PORT = 2180
UPSTREAM_PORT = 2181
WARP_PROVIDER = "cloudflare"
# Fixture domains only; must never include media bypass targets.
WARP_DOMAINS = ["warp-only.example", "warp-cdn.example"]
FORBIDDEN_SUBSTRINGS = ("youtube.com", "googlevideo.com", "ytimg.com")


def load_router(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "warp_proxy_router_under_test", ROOT / "router.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.CONFIG_FILE = tmp_path / "router.json"
    module.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    module.LAST_GOOD_FILE = tmp_path / "sing-box.json.last-good"
    module.PID_FILE = tmp_path / "sing-box.pid"
    module.LOG_FILE = tmp_path / "sing-box.log"
    module.LOCK_FILE = tmp_path / "state" / "engine.lock"
    module.MODE_FILE = tmp_path / "state" / "mode"
    module.MANUAL_OFF_FILE = tmp_path / "state" / "manual-off"
    module.SYSTEM_PROXY_STATE_FILE = tmp_path / "state" / "system-proxy.json"
    module.NETWORK_DIAGNOSTIC_FILE = tmp_path / "state" / "network-diagnostic.json"
    return module


def _write_wg_conf(path: Path) -> None:
    path.write_text(
        "[Interface]\nAddress = 10.2.0.2/32\nPrivateKey = aaaabbbbccccdddd\n"
        "DNS = 10.2.0.1\nMTU = 1420\n\n"
        "[Peer]\nPublicKey = eeeeffffgggghhhh\nEndpoint = 192.0.2.1:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )


def _wg_profile(router, profile: Path) -> None:
    """Pin a provider to a temp WireGuard profile without touching disk state."""
    router._usable_profile = lambda name, preferred=None: profile  # noqa: E731
    router.parse_wireguard = lambda path: {  # noqa: E731
        "type": "wireguard", "tag": "", "address": ["10.2.0.2/32"],
        "private_key": "secret",
        "peers": [{"address": "192.0.2.1", "port": 51820,
                   "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
    }
    router.dns_server_for = lambda path: "1.1.1.1"  # noqa: E731


def _socks_outbounds(config: dict) -> list:
    return [o for o in config.get("outbounds", []) if o.get("type") == "socks"]




# 1. Alt-port listener/config must not assume 2080.
def test_listener_and_config_use_alt_port_without_2080(tmp_path):
    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    _write_wg_conf(profile)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": ALT_PORT,
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [{"id": "example", "domains": ["example.com"],
                    "provider": "proton"}],
    }))
    assert router._config_port() == ALT_PORT
    assert router.load_config() == 0
    assert router._port == ALT_PORT
    _wg_profile(router, profile)
    router._routing = {}
    router.current_mode = lambda: "proxy"  # noqa: E731
    config, _active = router.build_singbox_config()
    assert config["inbounds"] == [
        {"type": "mixed", "tag": "local-proxy",
         "listen": "127.0.0.1", "listen_port": ALT_PORT}
    ]
    blob = json.dumps(config)
    assert str(ALT_PORT) in blob
    assert "2080" not in blob


# 2. Proxy-backed WARP domains -> SOCKS5 outbound, default stays direct.
def test_warp_domains_route_to_socks5_while_default_stays_direct(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": ALT_PORT,
        "providers": {WARP_PROVIDER: {
            "socks5": {"host": "127.0.0.1", "port": UPSTREAM_PORT}}},
        "routes": [{"id": "warp-only", "domains": WARP_DOMAINS,
                    "provider": WARP_PROVIDER}],
    }))
    assert router.load_config() == 0
    router._port = ALT_PORT
    router.current_mode = lambda: "proxy"  # noqa: E731
    config, _active = router.build_singbox_config()
    socks = _socks_outbounds(config)
    host, port = router.proxy_upstream(WARP_PROVIDER)
    assert (host, port) == ("127.0.0.1", UPSTREAM_PORT)
    assert socks
    warp_out = next(o for o in socks if o["server_port"] == UPSTREAM_PORT)
    assert warp_out["tag"] == WARP_PROVIDER
    rules = config["route"]["rules"]
    assert {"outbound": WARP_PROVIDER,
            "domain_suffix": WARP_DOMAINS} in rules
    assert config["route"]["final"] == "direct"


# 3. WARP fixture must not introduce media bypass targets.
def test_warp_fixture_introduces_no_youtube_targets(tmp_path):
    for domain in WARP_DOMAINS:
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in domain
    router = load_router(tmp_path)
    profile = tmp_path / "warp.conf"
    _write_wg_conf(profile)
    router._providers = {WARP_PROVIDER: {}}
    router._routes = [{"id": "warp-only", "domains": list(WARP_DOMAINS),
                       "provider": WARP_PROVIDER}]
    router._routing = {}
    router._port = ALT_PORT
    router.current_mode = lambda: "proxy"  # noqa: E731
    _wg_profile(router, profile)
    config, _active = router.build_singbox_config()
    blob = json.dumps(config).lower()
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in blob


class _FakeProxyRunner:
    """Fake networksetup/scutil surface; records, never touches the host."""

    def __init__(self):
        self.commands: list = []
        self.http = {"enabled": False, "server": None, "port": None}
        self.https = {"enabled": False, "server": None, "port": None}

    def __call__(self, command, **kwargs):
        self.commands.append(list(command))
        if command[:3] == ["route", "-n", "get"]:
            return SimpleNamespace(returncode=0, stdout="interface: en0\n")
        if command[1] == "-listnetworkserviceorder":
            return SimpleNamespace(
                returncode=0,
                stdout="(1) Test Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n")
        if command[1] == "-listallnetworkservices":
            return SimpleNamespace(returncode=0, stdout="Test Wi-Fi\n")
        if command[:2] == ["scutil", "--nc"]:
            return SimpleNamespace(returncode=0, stdout="")
        if command[:2] == ["scutil", "--proxy"]:
            http_on = "1" if self.http["enabled"] else "0"
            https_on = "1" if self.https["enabled"] else "0"
            return SimpleNamespace(
                returncode=0,
                stdout=("<dictionary> {\n"
                        f"  HTTPEnable : {http_on}\n"
                        f"  HTTPProxy : {self.http['server'] or ''}\n"
                        f"  HTTPPort : {self.http['port'] or ''}\n"
                        f"  HTTPSEnable : {https_on}\n"
                        f"  HTTPSProxy : {self.https['server'] or ''}\n"
                        f"  HTTPSPort : {self.https['port'] or ''}\n"
                        "}\n"))
        if command[0] == "networksetup" and command[1] in {
                "-getwebproxy", "-getsecurewebproxy"}:
            state = self.http if command[1] == "-getwebproxy" else self.https
            enabled = "Yes" if state["enabled"] else "No"
            return SimpleNamespace(
                returncode=0,
                stdout=f"Enabled: {enabled}\nServer: {state['server'] or ''}\n"
                       f"Port: {state['port'] or ''}\n")
        if command[0] == "networksetup" and command[1] in {
                "-getautoproxyurl", "-getproxyautodiscovery",
                "-getproxybypassdomains"}:
            return SimpleNamespace(returncode=0, stdout="Enabled: No\n")
        if command[0] == "networksetup" and command[1] == "-setwebproxy":
            self.http = {"enabled": True, "server": command[3],
                         "port": int(command[4])}
        elif command[0] == "networksetup" and command[1] == "-setsecurewebproxy":
            self.https = {"enabled": True, "server": command[3],
                          "port": int(command[4])}
        elif command[0] == "networksetup" and command[1] == "-setwebproxystate":
            self.http["enabled"] = command[3] == "on"
        elif command[0] == "networksetup" and command[1] == "-setsecurewebproxystate":
            self.https["enabled"] = command[3] == "on"
        return SimpleNamespace(returncode=0, stdout="")


# 4. Harness mutates neither system proxy state nor the live router root.
def test_harness_mutates_neither_system_proxy_nor_live_root(tmp_path, monkeypatch):
    import router as live_router

    live_root = live_router.ROOT
    live_config = live_router.CONFIG_FILE
    live_config_before = live_config.read_bytes() if live_config.is_file() else None
    assert Path(tmp_path).resolve() != Path(live_root).resolve()
    monkeypatch.delenv("PROXY_ROUTER_ROOT", raising=False)

    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    _write_wg_conf(profile)
    router._providers = {"proton": {}}
    router._routes = [{"id": "example", "domains": ["example.com"],
                       "provider": "proton"}]
    router._routing = {}
    router._port = ALT_PORT
    router.current_mode = lambda: "proxy"  # noqa: E731
    _wg_profile(router, profile)
    router.build_singbox_config()

    runner = _FakeProxyRunner()
    assert router.system_proxy_on(runner=runner) == 0
    assert router.system_proxy_off(runner=runner) == 0
    state_file = tmp_path / "state" / "system-proxy.json"
    assert not state_file.exists()  # off cleans up its own tmp record

    assert "PROXY_ROUTER_ROOT" not in __import__("os").environ
    for cmd in runner.commands:
        assert str(live_root) not in " ".join(cmd)
    if live_config_before is None:
        assert not live_config.exists()
    else:
        assert live_config.read_bytes() == live_config_before


# 5. Dead SOCKS5 upstream -> bounded fallback, no shared-engine teardown.
def test_dead_socks5_upstream_falls_back_without_engine_teardown(
        tmp_path, monkeypatch):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": ALT_PORT,
        "providers": {WARP_PROVIDER: {
            "socks5": {"host": "127.0.0.1", "port": UPSTREAM_PORT}}},
        "routes": [{"id": "warp-only", "domains": WARP_DOMAINS,
                    "provider": WARP_PROVIDER}],
    }))
    assert router.load_config() == 0

    def _refused(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(router.socket, "create_connection", _refused)
    assert router._listener_healthy(UPSTREAM_PORT, 0.05) is False
    # --check path: bounded probe result, no raise, no teardown.
    assert router.with_proxy([], check=True) == 1

    teardown_calls: list = []
    monkeypatch.setattr(
        router, "engine_stop",
        lambda *a, **k: teardown_calls.append((a, k)) or 1)
    assert router._listener_healthy(UPSTREAM_PORT, 0.05) is False
    assert teardown_calls == []

    config, _active = router.build_singbox_config()
    assert config["route"]["final"] == "direct"
    assert teardown_calls == []


# 6. Existing WireGuard provider config still builds as before.
def test_wireguard_provider_build_unchanged(tmp_path):
    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    _write_wg_conf(profile)
    router._providers = {"proton": {}}
    router._routes = [{"id": "example", "domains": ["example.com"],
                       "provider": "proton"}]
    router._routing = {}
    router._port = ALT_PORT
    router.current_mode = lambda: "proxy"  # noqa: E731
    _wg_profile(router, profile)
    config, active = router.build_singbox_config()
    assert [e["tag"] for e in config["endpoints"]] == ["proton"]
    assert config["dns"]["rules"] == [
        {"domain_suffix": ["example.com"], "server": "dns-proton"}]
    assert config["dns"]["final"] == "dns-local"
    assert {"outbound": "proton",
            "domain_suffix": ["example.com"]} in config["route"]["rules"]
    assert config["route"]["final"] == "direct"
    assert _socks_outbounds(config) == []
    assert set(active) == {"proton"}


def test_proxy_schema_uses_public_upstream_helper(tmp_path):
    """Canonical SOCKS5 schema is validated through router's public API."""
    router = load_router(tmp_path)
    router._providers = {WARP_PROVIDER: {
        "socks5": {"host": "127.0.0.1", "port": UPSTREAM_PORT}}}
    assert router.proxy_upstream(WARP_PROVIDER) == ("127.0.0.1", UPSTREAM_PORT)

    for unsupported_key in ("proxy", "socks5_upstream"):
        router._providers = {WARP_PROVIDER: {
            unsupported_key: {"host": "127.0.0.1", "port": UPSTREAM_PORT}}}
        with pytest.raises(ValueError, match="not a proxy-backed"):
            router.proxy_upstream(WARP_PROVIDER)


def test_no_brittle_private_hooks_required(tmp_path):
    """New tests must pass without inventing private router internals."""
    router = load_router(tmp_path)
    for public in ("load_config", "build_singbox_config", "parse_wireguard",
                   "system_proxy_on", "system_proxy_off", "with_proxy",
                   "engine_stop"):
        assert callable(getattr(router, public, None)), public
