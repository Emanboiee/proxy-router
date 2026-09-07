"""Proxy-backed provider path: local SOCKS5 upstream (e.g. `warp-cli mode proxy`).

A proxy-backed provider routes its assigned domains through a local SOCKS5
hop instead of a WireGuard endpoint in the shared engine. These tests use
temporary roots and alternate ports 2180/2181 (never live 2080), in-memory
or tmp-file configs, and no real network destinations.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# A real 32-byte WireGuard key (base64) so `sing-box check` accepts mocked
# endpoints in the validation test. Not a secret: generated for tests only.
TEST_WG_KEY = "DpXK7bY67saB3wwJ2SAbUrqND0eFP4IkIFMjq/DCEKk="

WG_ENDPOINT = {
    "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
    "private_key": TEST_WG_KEY,
    "peers": [{"address": "192.0.2.1", "port": 51820,
               "public_key": TEST_WG_KEY, "allowed_ips": ["0.0.0.0/0"]}],
}


def load_router(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "proxy_router_proxy_under_test", ROOT / "router.py")
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


def write_conf(directory: Path, stem: str = "a") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    profile = directory / f"{stem}.conf"
    profile.write_text(
        "[Interface]\nAddress=10.0.0.2/32\nPrivateKey=x\nDNS=1.1.1.1\n\n"
        "[Peer]\nEndpoint=192.0.2.1:51820\nPublicKey=y\nAllowedIPs=0.0.0.0/0\n"
    )
    return profile


def mock_wireguard(router, live: dict[str, Path]):
    """Stub profile selection/parsing so builds need no real keys on disk."""
    router._usable_profile = lambda name, preferred=None: live.get(name)
    router.parse_wireguard = lambda path: dict(WG_ENDPOINT)
    router.dns_server_for = lambda path: "1.1.1.1"
    router.current_mode = lambda: "proxy"


def proxy_config(port=2180, upstream_port=2181):
    return {
        "port": port,
        "providers": {
            "proton": {"directory": "providers/proton"},
            "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": upstream_port},
                           "fallback_providers": ["proton"]},
        },
        "routes": [
            {"id": "zen", "domains": ["opencode.ai"], "provider": "proton"},
            {"id": "school", "domains": ["school.example"], "provider": "warp-proxy"},
        ],
    }


# ---------------------------------------------------------------------------
# parsing: accept explicit proxy providers, preserve legacy WireGuard entries
# ---------------------------------------------------------------------------

def test_load_config_accepts_proxy_provider_alongside_wireguard(tmp_path):
    router = load_router(tmp_path)
    write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))

    assert router.load_config() == 0
    assert router.is_proxy_provider("warp-proxy") is True
    assert router.is_proxy_provider("proton") is False
    assert router.proxy_upstream("warp-proxy") == ("127.0.0.1", 2181)
    assert router.fallback_chain("warp-proxy") == ["proton"]


def test_load_config_accepts_localhost_alias_and_bracketed_v6(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2180,
        "providers": {
            "warp-a": {"socks5": {"host": "localhost", "port": 2181}},
            "warp-b": {"socks5": {"host": "[::1]", "port": 2181}},
        },
        "routes": [],
    }))

    assert router.load_config() == 0
    assert router.proxy_upstream("warp-a") == ("127.0.0.1", 2181)
    assert router.proxy_upstream("warp-b") == ("::1", 2181)


@pytest.mark.parametrize("socks5", [
    {"host": "8.8.8.8", "port": 2181},          # remote proxy: unsafe
    {"host": "proxy.example", "port": 2181},    # hostname: ambiguous DNS
    {"host": "", "port": 2181},                 # empty host
    {"host": "127.0.0.1", "port": 0},           # port out of range
    {"host": "127.0.0.1", "port": 65536},       # port out of range
    {"host": "127.0.0.1", "port": "fast"},      # non-integer port
    {"host": "127.0.0.1"},                      # missing port
    {"port": 2181},                             # missing host
    "socks5://127.0.0.1:2181",                  # wrong shape entirely
])
def test_load_config_rejects_unsafe_or_malformed_upstream(tmp_path, socks5):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2180,
        "providers": {"warp-proxy": {"socks5": socks5}},
        "routes": [],
    }))

    assert router.load_config() == 1


def test_load_config_rejects_upstream_pointing_at_own_listener(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2180,
        "providers": {"warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2180}}},
        "routes": [],
    }))

    assert router.load_config() == 1


def test_load_config_rejects_directory_plus_socks5(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2180,
        "providers": {"warp-proxy": {"directory": "providers/warp",
                                     "socks5": {"host": "127.0.0.1", "port": 2181}}},
        "routes": [],
    }))

    assert router.load_config() == 1


def test_legacy_wireguard_config_loads_unchanged(tmp_path):
    """Backward compatibility: a pre-proxy router.json behaves as before."""
    router = load_router(tmp_path)
    write_conf(tmp_path / "providers" / "proton")
    write_conf(tmp_path / "providers" / "fallback")
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2181,
        "providers": {
            "proton": {"directory": "providers/proton",
                       "fallback_provider": "fallback"},
            "fallback": {"directory": "providers/fallback"},
        },
        "routes": [{"id": "zen", "domains": ["opencode.ai"], "provider": "proton"}],
    }))

    assert router.load_config() == 0
    assert router.is_proxy_provider("proton") is False
    assert router.fallback_chain("proton") == ["fallback"]


# ---------------------------------------------------------------------------
# generated config: SOCKS5 outbound, scoped rules, direct-by-default
# ---------------------------------------------------------------------------

def test_build_emits_socks_outbound_and_scoped_rules(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})

    config, _selected = router.build_singbox_config()

    socks = [o for o in config["outbounds"] if o.get("type") == "socks"]
    assert socks == [{"type": "socks", "tag": "warp-proxy", "server": "127.0.0.1",
                      "server_port": 2181, "version": "5"}]
    # No WireGuard endpoint is created for the proxy-backed provider.
    assert [e["tag"] for e in config["endpoints"]] == ["proton"]
    rules = config["route"]["rules"]
    assert {"outbound": "proton", "domain_suffix": ["opencode.ai"]} in rules
    assert {"outbound": "warp-proxy", "domain_suffix": ["school.example"]} in rules
    # Default traffic stays direct; only assigned domains ride the proxy.
    assert config["route"]["final"] == "direct"
    assert not any(r.get("outbound") == "warp-proxy" and "domain_suffix" not in r
                   for r in rules)
    # Proxy-routed domains resolve via the local resolver (no tunnel DNS).
    assert {"domain_suffix": ["school.example"], "server": "dns-local"} in config["dns"]["rules"]
    assert {"domain_suffix": ["opencode.ai"], "server": "dns-proton"} in config["dns"]["rules"]


def test_build_never_routes_loopback_to_proxy(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})

    config, _selected = router.build_singbox_config()

    proxy_rules = [r for r in config["route"]["rules"] if r.get("outbound") == "warp-proxy"]
    assert proxy_rules, "expected at least one proxy rule"
    for rule in proxy_rules:
        assert "ip_cidr" not in rule, f"proxy must not capture IP ranges: {rule}"
    tail = config["route"]["rules"][-2:]
    assert tail == [{"domain": ["localhost"], "outbound": "direct"},
                    {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"}]


def test_build_rejects_upstream_loop_set_programmatically(tmp_path):
    router = load_router(tmp_path)
    router._providers = {"warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2180}}}
    router._routes = [{"id": "school", "domains": ["school.example"],
                       "provider": "warp-proxy"}]
    router._routing = {}
    router._vpn = {}
    router._port = 2180
    router.current_mode = lambda: "proxy"

    with pytest.raises(SystemExit, match="proxy loop"):
        router.build_singbox_config()


# ---------------------------------------------------------------------------
# fallback: a dead proxy-backed provider fails over, others untouched
# ---------------------------------------------------------------------------

def test_dead_proxy_fails_over_without_disturbing_other_providers(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    reloads = []
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: reloads.append(True) or 0)

    assert router.activate_fallback("warp-proxy", target="proton", reason="connection") == 0
    marker = json.loads((tmp_path / "state" / "fallback" / "warp-proxy.json").read_text())
    assert marker["provider"] == "proton"
    assert reloads == [True]

    config, _selected = router.build_singbox_config()

    # The failed proxy lane is parked: its routes follow the fallback ...
    assert [e["tag"] for e in config["endpoints"]] == ["proton"]
    assert [o.get("tag") for o in config["outbounds"]] == ["direct"]
    rules = config["route"]["rules"]
    assert {"outbound": "proton", "domain_suffix": ["school.example"]} in rules
    assert {"outbound": "proton", "domain_suffix": ["opencode.ai"]} in rules
    assert not any(r.get("outbound") == "warp-proxy" for r in rules)
    # ... while the unrelated WireGuard endpoint is untouched.
    endpoint = next(e for e in config["endpoints"] if e["tag"] == "proton")
    assert endpoint["peers"][0]["address"] == "192.0.2.1"


def test_effective_mapping_follows_nested_chain_through_proxy(tmp_path):
    router = load_router(tmp_path)
    proton_conf = tmp_path / "proton.conf"
    proton2_conf = tmp_path / "proton2.conf"
    router._providers = {
        "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181},
                       "fallback_providers": ["proton"]},
        "proton": {"fallback_providers": ["proton2"]},
        "proton2": {},
    }
    router._routes = [{"id": "school", "domains": ["school.example"],
                       "provider": "warp-proxy"}]
    router._routing = {}
    router._vpn = {}
    router._port = 2180
    mock_wireguard(router, {"proton": proton_conf, "proton2": proton2_conf})
    fallback_dir = tmp_path / "state" / "fallback"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "warp-proxy.json").write_text(json.dumps({"provider": "proton"}))
    (fallback_dir / "proton.json").write_text(json.dumps({"provider": "proton2"}))

    assert router._effective_route_provider("warp-proxy") == "proton2"
    config, _selected = router.build_singbox_config()

    assert [e["tag"] for e in config["endpoints"]] == ["proton2"]
    assert {"outbound": "proton2", "domain_suffix": ["school.example"]} in config["route"]["rules"]


def test_activate_fallback_accepts_proxy_candidate(tmp_path, monkeypatch):
    """Failover works in the other direction too: a dead WireGuard lane can
    fall back onto a proxy-backed provider with no *.conf files."""
    router = load_router(tmp_path)
    write_conf(tmp_path / "providers" / "proton")
    router._providers = {
        "proton": {"directory": "providers/proton",
                   "fallback_providers": ["warp-proxy"]},
        "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181}},
    }
    router._port = 2180
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    reloads = []
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: reloads.append(True) or 0)

    assert router.activate_fallback("proton", reason="tls") == 0
    marker = json.loads((tmp_path / "state" / "fallback" / "proton.json").read_text())
    assert marker["provider"] == "warp-proxy"
    assert reloads == [True]


def test_rotate_refuses_proxy_backed_provider(tmp_path, capsys):
    router = load_router(tmp_path)
    router._providers = {"warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    router._port = 2180

    assert router.rotate("warp-proxy") == 1
    assert "proxy-backed" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# TUN boundary: SOCKS5 is TCP-only, so TUN builds fail closed
# ---------------------------------------------------------------------------

def test_tun_mode_fails_closed_for_proxy_routed_domains(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})
    router.current_mode = lambda: "tun"

    with pytest.raises(SystemExit, match="SOCKS5"):
        router.build_singbox_config()


def test_tun_mode_fails_closed_for_proxy_selective_provider(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    data = proxy_config()
    data["routes"] = [{"id": "zen", "domains": ["opencode.ai"], "provider": "proton"}]
    router.CONFIG_FILE.write_text(json.dumps(data))
    assert router.load_config() == 0
    router._vpn = {"selective": "warp-proxy"}
    mock_wireguard(router, {"proton": proton_conf})
    router.current_mode = lambda: "tun"

    with pytest.raises(SystemExit, match="warp-proxy"):
        router.build_singbox_config()


def test_proxy_mode_builds_same_config_fine(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})

    config, _selected = router.build_singbox_config()
    assert any(o.get("tag") == "warp-proxy" for o in config["outbounds"])


# ---------------------------------------------------------------------------
# validity surfaces
# ---------------------------------------------------------------------------

def test_providers_check_reports_proxy_upstream(tmp_path, capsys):
    router = load_router(tmp_path)
    router._providers = {
        "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181}},
    }
    router._port = 2180

    assert router.providers_check("warp-proxy") == 0
    result = router._check_provider_validity("warp-proxy")
    assert result["valid"] is True
    assert result["upstream"] == "127.0.0.1:2181"
    assert "warp-proxy: ok" in capsys.readouterr().out


def test_providers_check_flags_bad_proxy_upstream(tmp_path):
    router = load_router(tmp_path)
    router._providers = {
        "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 99999}},
    }
    router._port = 2180

    result = router._check_provider_validity("warp-proxy")
    assert result["valid"] is False
    assert any("65535" in issue for issue in result["issues"])


# ---------------------------------------------------------------------------
# generated config validates under the real engine
# ---------------------------------------------------------------------------

def test_generated_proxy_config_passes_sing_box_check(tmp_path):
    router = load_router(tmp_path)
    proton_conf = write_conf(tmp_path / "providers" / "proton")
    router.CONFIG_FILE.write_text(json.dumps(proxy_config()))
    assert router.load_config() == 0
    mock_wireguard(router, {"proton": proton_conf})
    router._port = 2180

    config, _selected = router.build_singbox_config()
    router.write_sing_box(config)

    assert router.SING_BOX_CONFIG.is_file()
    assert router.validate_config() is True


def test_proxy_only_config_writes_and_validates(tmp_path):
    """A WARP-proxy-only deployment has no WireGuard endpoints at all; the
    egress guard must still let the config through to `sing-box check`."""
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2180,
        "providers": {"warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181}}},
        "routes": [{"id": "school", "domains": ["school.example"],
                    "provider": "warp-proxy"}],
    }))
    assert router.load_config() == 0
    router._port = 2180
    router.current_mode = lambda: "proxy"

    config, selected = router.build_singbox_config()
    assert config["endpoints"] == []
    assert selected == {}
    router.write_sing_box(config)

    assert router.SING_BOX_CONFIG.is_file()
    assert router.validate_config() is True
