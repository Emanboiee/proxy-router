"""Public DNS must not steal MagicDNS or delegate blocked names to SOCKS."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tests.test_proxy_provider import load_router, mock_wireguard, proxy_config, write_conf


def configured_router(tmp_path):
    router = load_router(tmp_path)
    data = proxy_config()
    data["vpn"] = {
        "public_dns": {"server": "1.1.1.1", "private_domains": ["local", "ts.net", "corp.example"]},
        "tailscale_bypass": True,
    }
    router.CONFIG_FILE.write_text(json.dumps(data))
    assert router.load_config() == 0
    profile = write_conf(tmp_path / "providers" / "proton")
    mock_wireguard(router, {"proton": profile})
    router.active_proxy_providers = lambda: {"warp-proxy": ("127.0.0.1", 2181)}
    return router


def test_public_dns_preserves_private_resolution_and_wireguard_dns(tmp_path):
    router = configured_router(tmp_path)
    config, _ = router.build_singbox_config()

    assert config["dns"]["final"] == "dns-public"
    assert config["route"]["default_domain_resolver"] == "dns-public"
    private_dns = config["dns"]["rules"][0]
    assert private_dns["server"] == "dns-local"
    assert set(private_dns["domain_suffix"]) == {"local", "ts.net", "corp.example"}
    assert {"domain_suffix": ["opencode.ai"], "server": "dns-proton"} in config["dns"]["rules"]
    private = next(o for o in config["outbounds"] if o["tag"] == "direct-private")
    assert private["domain_resolver"] == "dns-local"
    assert any(r.get("domain_regex") == [r"^[^.]+$"] and r.get("outbound") == "direct-private"
               for r in config["route"]["rules"])
    # In proxy mode a physical-interface binding would break tailnet sockets.
    assert config["route"]["auto_detect_interface"] is False


def test_warp_names_are_resolved_before_the_socks_route(tmp_path):
    router = configured_router(tmp_path)
    config, _ = router.build_singbox_config()
    rules = config["route"]["rules"]
    socks_index = next(i for i, r in enumerate(rules) if r.get("outbound") == "warp-proxy")
    assert rules[socks_index - 1] == {
        "domain_suffix": ["school.example"], "action": "resolve", "server": "dns-public",
    }
    private_index = next(i for i, r in enumerate(rules) if "ts.net" in r.get("domain_suffix", []))
    assert private_index < socks_index - 1
    assert {"domain_suffix": ["school.example"], "server": "dns-public"} in config["dns"]["rules"]


def test_private_routes_override_conflicting_provider_domains(tmp_path):
    router = configured_router(tmp_path)
    router._routes.insert(0, {"id": "overlap", "provider": "warp-proxy", "domains": ["ts.net", "tailscale.com"]})
    config, _ = router.build_singbox_config()
    rules = config["route"]["rules"]
    provider_index = next(i for i, r in enumerate(rules) if r.get("outbound") == "warp-proxy")
    for domain in ("ts.net", "tailscale.com"):
        first = next(i for i, r in enumerate(rules) if domain in r.get("domain_suffix", []))
        assert first < provider_index
        assert rules[first]["outbound"].startswith("direct")
    cidr_rule = next(r for r in rules if "100.64.0.0/10" in r.get("ip_cidr", []))
    assert cidr_rule["outbound"] == "direct-private"


def test_safe_list_socks_default_also_resolves_unmatched_names(tmp_path):
    router = configured_router(tmp_path)
    router._routing = {"mode": "safe-list", "default_provider": "warp-proxy", "direct_domains": ["trusted.example"]}
    config, _ = router.build_singbox_config()
    assert config["route"]["final"] == "warp-proxy"
    assert config["route"]["rules"][-1] == {"action": "resolve", "server": "dns-public"}
    assert {"domain_suffix": ["trusted.example"], "server": "dns-public"} in config["dns"]["rules"]


def test_local_wireguard_override_uses_public_dns_when_enabled(tmp_path):
    router = configured_router(tmp_path)
    router._vpn["dns_resolver"] = "local"
    config, _ = router.build_singbox_config()
    assert {"domain_suffix": ["opencode.ai"], "server": "dns-public"} in config["dns"]["rules"]


@pytest.mark.parametrize("value", [
    "1.1.1.1", {}, {"server": "cloudflare-dns.com"}, {"server": True},
    {"server": "0.0.0.0"}, {"server": "224.0.0.1"},
    {"server": "1.1.1.1", "transport": "bogus"},
    {"server": "1.1.1.1", "private_domains": "ts.net"},
    {"server": "1.1.1.1", "private_domains": ["*"]},
    {"server": "1.1.1.1", "private_domains": [None]},
])
def test_bad_public_dns_fails_without_replacing_live_config(tmp_path, value):
    router = load_router(tmp_path)
    data = proxy_config()
    data["vpn"] = {"public_dns": value}
    router.CONFIG_FILE.write_text(json.dumps(data))
    router.SING_BOX_CONFIG.write_text('existing config')
    assert router.load_config() == 1
    assert router.SING_BOX_CONFIG.read_text() == 'existing config'


def test_generated_coexistence_config_passes_real_sing_box_check(tmp_path):
    router = configured_router(tmp_path)
    config, _ = router.build_singbox_config()
    router.write_sing_box(config)
    assert router.validate_config() is True


@pytest.mark.parametrize("original_domains", [["corp.example"], []])
def test_reconnect_preserves_and_restores_original_bypass(tmp_path, monkeypatch, original_domains):
    router = configured_router(tmp_path)
    current = {"domains": list(original_domains)}
    proxy = {"known": True, "enabled": True, "server": "127.0.0.1", "port": router._port}
    monkeypatch.setattr(router, "_proxy_target_services", lambda runner=None: ["Wi-Fi"])
    monkeypatch.setattr(router, "active_service_name", lambda runner=None: "Wi-Fi")
    monkeypatch.setattr(router, "_service_proxy_state", lambda *args: dict(proxy))
    monkeypatch.setattr(router, "_capture_proxy_aux", lambda *args: {"bypass": {"domains": list(current["domains"])}})
    monkeypatch.setattr(router, "_wait_effective_proxy", lambda *args: {"known": True, "http": dict(proxy), "https": dict(proxy)})

    def runner(command, **kwargs):
        if command[1] == "-setproxybypassdomains":
            assert command[3:], "networksetup requires a list or Empty"
            current["domains"] = [] if command[3:] == ["Empty"] else command[3:]
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    assert router.system_proxy_on(runner=runner) == 0
    assert "*.ts.net" in current["domains"]
    assert "100.64.0.0/10" in current["domains"]
    assert all(domain in current["domains"] for domain in original_domains)
    assert router.system_proxy_on(runner=runner) == 0
    # Disconnect must restore the recorded list even if the config changed.
    router._vpn = {}
    assert router.system_proxy_off(runner=runner) == 0
    assert current["domains"] == original_domains
