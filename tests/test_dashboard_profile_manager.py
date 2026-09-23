import json
import os
import stat

import pytest

import dashboard_profile_manager as manager


WIREGUARD = """[Interface]
PrivateKey = PRIVATE-TEST-KEY
Address = 10.20.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = PUBLIC-TEST-KEY
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
"""


def config_at(root, providers=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "router.json").write_text(json.dumps({
        "port": 2080,
        "providers": providers or {},
        "routes": [],
        "vpn": {"default_mode": "proxy"},
    }))


def add_provider(root, name="primary"):
    source = root.parent / f"{name}.conf"
    source.write_text(WIREGUARD)
    return manager.save_provider(root, {"name": name.title(), "kind": "custom"}, source_path=str(source))


def test_provider_save_keeps_wireguard_secret_out_of_dashboard_state(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    source = tmp_path / "picked.conf"
    source.write_text(WIREGUARD)

    result = manager.save_provider(root, {"name": "Home tunnel", "kind": "custom"}, source_path=str(source))
    provider = result["providers"][0]
    copied = root / "providers" / provider["id"] / "wireguard.conf"
    config_text = (root / "router.json").read_text()
    store_text = (root / "state" / manager.STORE_NAME).read_text()

    assert provider["name"] == "Home tunnel"
    assert provider["kind"] == "custom"
    assert provider["server"] == "vpn.example.test:51820"
    assert copied.read_text() == WIREGUARD
    assert stat.S_IMODE(copied.stat().st_mode) == 0o600
    assert "PRIVATE-TEST-KEY" not in config_text
    assert "PRIVATE-TEST-KEY" not in store_text
    assert "PRIVATE-TEST-KEY" not in json.dumps(result)


def test_profile_create_and_apply_persists_routes_without_connecting(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    provider_state = add_provider(root)
    primary_id = provider_state["providers"][0]["id"]
    fallback_source = tmp_path / "fallback.conf"
    fallback_source.write_text(WIREGUARD.replace("vpn.example.test", "backup.example.test"))
    provider_state = manager.save_provider(root, {"name": "Backup tunnel", "kind": "wireguard"}, source_path=str(fallback_source))
    fallback_id = next(item["id"] for item in provider_state["providers"] if item["name"] == "Backup tunnel")

    manager.save_profile(root, {
        "name": "Work sites", "description": "A few work sites", "providerId": primary_id,
        "fallbackProviderId": fallback_id, "routeMode": "selective", "fallback": "retry",
        "domains": ["example.com", "api.example.com"], "autoSubdomains": False,
    })
    saved_store = json.loads((root / "state" / manager.STORE_NAME).read_text())
    profile = manager.state(root)["profiles"][0]
    assert saved_store["active_profile_id"] is None
    applied = manager.apply_profile(root, profile["id"])
    config = json.loads((root / "router.json").read_text())
    saved_store = json.loads((root / "state" / manager.STORE_NAME).read_text())

    assert applied["activeProfileId"] == profile["id"]
    assert saved_store["active_profile_id"] == profile["id"]
    assert config["routes"] == [{
        "id": profile["id"], "domains": ["example.com", "api.example.com"],
        "provider": primary_id, "auto_subdomains": False, "on_unavailable": "direct",
    }]
    assert config["providers"][primary_id]["fallback_providers"] == [fallback_id]
    assert not (root / "state" / "manual-off").exists()
    assert not (root / "sing-box.json").exists()


def test_apply_full_and_direct_modes_map_to_engine_config(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    provider = add_provider(root)["providers"][0]
    manager.save_profile(root, {
        "name": "Everything", "providerId": provider["id"], "routeMode": "full",
        "fallback": "block", "domains": [], "autoSubdomains": False,
    })
    profile = manager.state(root)["profiles"][0]
    manager.apply_profile(root, profile["id"])
    config = json.loads((root / "router.json").read_text())
    assert config["routing"] == {"mode": "safe-list", "default_provider": provider["id"], "direct_domains": []}

    manager.save_profile(root, {
        "name": "Direct", "providerId": "", "routeMode": "direct", "fallback": "direct",
        "domains": [], "autoSubdomains": False,
    })
    direct = next(item for item in manager.state(root)["profiles"] if item["name"] == "Direct")
    manager.apply_profile(root, direct["id"])
    config = json.loads((root / "router.json").read_text())
    assert config["routes"] == []
    assert config["routing"]["mode"] == "default"



def test_direct_profile_normalizes_retry_fallback_before_apply(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    add_provider(root, "primary")
    fallback_source = tmp_path / "fallback.conf"
    fallback_source.write_text(WIREGUARD.replace("vpn.example.test", "backup.example.test"))
    fallback_id = manager.save_provider(
        root, {"name": "Backup tunnel", "kind": "wireguard"}, source_path=str(fallback_source)
    )["providers"][0]["id"]

    saved = manager.save_profile(root, {
        "name": "Direct with imported retry", "providerId": "", "routeMode": "direct",
        "fallback": "retry", "fallbackProviderId": fallback_id,
        "domains": [], "autoSubdomains": False,
    })
    profile = saved["profiles"][0]
    manager.apply_profile(root, profile["id"])

    config = json.loads((root / "router.json").read_text())
    assert profile["fallback"] == "direct"
    assert profile["fallbackProviderId"] == ""
    assert "" not in config["providers"]
    assert config["routing"] == {"mode": "default"}

def test_invalid_profile_or_provider_save_preserves_saved_files(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    add_provider(root)
    before_config = (root / "router.json").read_text()
    before_store = (root / "state" / manager.STORE_NAME).read_text()

    with pytest.raises(manager.DashboardError, match="valid domain"):
        manager.save_profile(root, {
            "name": "Bad domain", "providerId": manager.state(root)["providers"][0]["id"],
            "routeMode": "selective", "domains": ["not a domain"],
        })
    bad_source = tmp_path / "invalid.conf"
    bad_source.write_text("[Interface]\nPrivateKey = secret\n")
    with pytest.raises(manager.DashboardError, match="WireGuard config needs"):
        manager.save_provider(root, {"name": "Broken", "kind": "custom"}, source_path=str(bad_source))

    assert (root / "router.json").read_text() == before_config
    assert (root / "state" / manager.STORE_NAME).read_text() == before_store


def test_provider_cannot_be_deleted_while_profile_uses_it(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    provider = add_provider(root)["providers"][0]
    manager.save_profile(root, {
        "name": "Work", "providerId": provider["id"], "routeMode": "selective",
        "fallback": "direct", "domains": ["example.com"],
    })

    with pytest.raises(manager.DashboardError, match="used by a saved profile"):
        manager.delete_provider(root, provider["id"])

    profile = manager.state(root)["profiles"][0]
    manager.delete_profile(root, profile["id"])
    assert manager.delete_provider(root, provider["id"])["providers"] == []
    assert not (root / "providers" / provider["id"]).exists()


def test_deleting_last_profile_keeps_empty_dashboard_instead_of_reimporting_old_config(tmp_path):
    root = tmp_path / "router"
    config_at(root, {"warp": {"directory": "providers/warp"}})
    config = json.loads((root / "router.json").read_text())
    config["routes"] = [{"id": "old", "provider": "warp", "domains": ["old.example"]}]
    (root / "router.json").write_text(json.dumps(config))
    profile = manager.state(root)["profiles"][0]

    result = manager.delete_profile(root, profile["id"])
    config = json.loads((root / "router.json").read_text())

    assert result["profiles"] == []
    assert result["activeProfileId"] is None
    assert config["routes"] == []
    assert config["routing"] == {"mode": "default"}
    assert manager.state(root)["profiles"] == []


def test_deleting_active_profile_applies_remaining_config_without_engine_actions(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    primary = add_provider(root)["providers"][0]
    first = manager.save_profile(root, {
        "name": "First", "providerId": primary["id"], "routeMode": "selective", "domains": ["first.example"],
    })["profiles"][-1]
    second = manager.save_profile(root, {
        "name": "Second", "providerId": primary["id"], "routeMode": "selective", "domains": ["second.example"],
    })["profiles"][-1]
    manager.apply_profile(root, first["id"])

    state = manager.delete_profile(root, first["id"])
    config = json.loads((root / "router.json").read_text())

    assert state["activeProfileId"] == second["id"]
    assert config["routes"][0]["domains"] == ["second.example"]
    assert not (root / "state" / "manual-off").exists()
    assert not (root / "state" / "connected").exists()


def test_profile_and_provider_identifiers_and_modes_are_validated(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    provider = add_provider(root)["providers"][0]

    with pytest.raises(manager.DashboardError, match="valid connection"):
        manager.save_profile(root, {
            "name": "Bad ID", "providerId": "../outside", "routeMode": "selective", "domains": ["example.com"],
        })
    with pytest.raises(manager.DashboardError, match="routing mode"):
        manager.save_profile(root, {"name": "Bad mode", "providerId": provider["id"], "routeMode": [], "domains": ["example.com"]})
    with pytest.raises(manager.DashboardError, match="Connection ID"):
        manager.delete_provider(root, "../router.json")
    with pytest.raises(manager.DashboardError, match="Profile ID"):
        manager.apply_profile(root, "../router.json")


def test_provider_used_as_routing_default_cannot_be_deleted(tmp_path):
    root = tmp_path / "router"
    config_at(root)
    provider = add_provider(root)["providers"][0]
    config = json.loads((root / "router.json").read_text())
    config["routing"] = {"mode": "vpn-list", "default_provider": provider["id"]}
    (root / "router.json").write_text(json.dumps(config))

    with pytest.raises(manager.DashboardError, match="routing default"):
        manager.delete_provider(root, provider["id"])
