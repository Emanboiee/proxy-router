"""Gaming must capture raw-IP UDP destinations, not just game websites."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import setup_tui


@pytest.fixture
def gaming_router(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "gaming_router", Path(__file__).resolve().parents[1] / "router.py"
    )
    router = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(router)
    router.ROOT = tmp_path
    router.CONFIG_FILE = tmp_path / "router.json"
    router.MODE_FILE = tmp_path / "state" / "mode"
    # Simulate an existing selective setup: Gaming must remove the old
    # IP-only capture and direct-domain exceptions without losing providers.
    router.CONFIG_FILE.write_text(json.dumps({
        "providers": {"cloudflare": {"directory": "providers/cloudflare"}},
        "routes": [],
        "routing": {"mode": "safe-list", "direct_domains": ["steampowered.com"]},
        "vpn": {"capture": "routes", "selective": "roblox", "network_auto": True},
    }))
    setup_tui.apply_preset_by_name(tmp_path, "gaming")
    profile = tmp_path / "providers" / "cloudflare" / "gaming.conf"
    profile.parent.mkdir(parents=True)
    profile.write_text(
        "[Interface]\nAddress = 10.2.0.2/32\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nDNS = 1.1.1.1\n"
        "[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Endpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
    )
    assert router.load_config() == 0
    router.set_mode("tun")
    return router


def test_gaming_captures_game_servers_and_tunnels_unmatched_udp(gaming_router):
    config, _ = gaming_router.build_singbox_config()
    tun = config["inbounds"][0]
    assert tun["auto_route"] is True
    assert tun["mtu"] == 1280
    assert "fdfe:dcba:9876::1/126" in tun["address"]
    assert "route_address_set" not in tun
    assert config["route"]["final"] == "cloudflare"
    assert not any(r.get("network") == "udp" and r.get("outbound") == "direct"
                   for r in config["route"]["rules"])
    assert any("100.64.0.0/10" in r.get("ip_cidr", [])
               and r.get("outbound") in {"direct", "direct-private"}
               for r in config["route"]["rules"])
    assert {"protocol": "dns", "action": "hijack-dns"} in config["route"]["rules"]
    assert {r["id"] for r in gaming_router._routes} == {"steam", "roblox", "reddit"}
    assert gaming_router._vpn["network_auto"] is False
    assert setup_tui.apply_preset_by_name(gaming_router.ROOT, "gaming")["added"] == []


def test_gaming_refuses_missing_vpn_instead_of_sending_games_direct(gaming_router):
    for path in gaming_router.ROOT.glob("providers/*/*.conf"):
        path.unlink()
    with pytest.raises(SystemExit, match="no active profile"):
        gaming_router.build_singbox_config()


@pytest.mark.parametrize("selective", [False, True])
def test_windows_strict_dns_applies_only_to_full_capture(gaming_router, monkeypatch, selective):
    router = gaming_router
    monkeypatch.setattr(router, "os", SimpleNamespace(**{**vars(router.os), "name": "nt"}))
    if selective:
        router._vpn["capture"] = "routes"
        monkeypatch.setattr(router, "_route_capture_cidrs", lambda *a: ["192.0.2.0/24"])
    config, _ = router.build_singbox_config()
    assert config["inbounds"][0]["strict_route"] is (not selective)
    dns_capture = {"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"}
    assert (dns_capture in config["route"]["rules"]) is (not selective)
