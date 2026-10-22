import json

import pytest

import dashboard_profile_manager as manager


def write_config(root):
    config = {
        "port": 2080, "preset": "opencode-only", "vpn": {"default_mode": "proxy"},
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [
            {"id": "roblox", "provider": "proton", "domains": ["roblox.com"]},
            {"id": "opencode", "provider": "proton", "domains": ["opencode.ai"]},
        ],
        "routing": {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]},
    }
    (root / "router.json").write_text(json.dumps(config))
    (root / "presets").mkdir()
    for name, domain, route_id in [("opencode-only", "opencode.ai", "opencode"),
                                   ("roblox", "roblox.com", "roblox")]:
        (root / "presets" / f"{name}.json").write_text(json.dumps({
            "routes": [{"id": route_id, "provider": "proton", "domains": [domain]}],
            "routing": {"mode": "vpn-list", "vpn_domains": [domain]},
        }))
    return config


def test_discovers_existing_presets_and_actual_active_scope_without_writes(tmp_path):
    write_config(tmp_path)
    before = (tmp_path / "router.json").read_bytes()
    state = manager.state(tmp_path)
    assert [p["name"] for p in state["profiles"]] == ["opencode-only", "roblox"]
    assert state["activeProfileId"] == "preset-opencode-only"
    assert state["profiles"][0]["domains"] == ["opencode.ai"]
    assert (tmp_path / "router.json").read_bytes() == before
    assert not (tmp_path / "state").exists()
    assert "_preset_name" not in json.dumps(state)


def test_stale_preset_marker_does_not_claim_that_preset_is_active(tmp_path):
    config = write_config(tmp_path)
    config["routing"]["vpn_domains"] = ["roblox.com"]
    (tmp_path / "router.json").write_text(json.dumps(config))
    state = manager.state(tmp_path)
    active = next(p for p in state["profiles"] if p["id"] == state["activeProfileId"])
    assert active["name"] == "Custom routing"
    assert active["domains"] == ["roblox.com"]


def test_selecting_discovered_preset_preserves_vpn_options_and_never_starts_engine(tmp_path):
    write_config(tmp_path)
    path = tmp_path / "presets/roblox.json"
    preset = json.loads(path.read_text())
    preset["vpn"] = {"default_mode": "tun", "mtu": 1280}
    path.write_text(json.dumps(preset))
    state = manager.apply_profile(tmp_path, "preset-roblox")
    config = json.loads((tmp_path / "router.json").read_text())
    assert state["activeProfileId"] == "preset-roblox"
    assert config["preset"] == "roblox"
    assert config["routes"] == preset["routes"]
    assert config["vpn"]["default_mode"] == "tun"
    assert config["vpn"]["mtu"] == 1280
    assert not (tmp_path / "sing-box.json").exists()


def test_unavailable_preset_provider_does_not_modify_live_config(tmp_path):
    write_config(tmp_path)
    (tmp_path / "presets/school.json").write_text(json.dumps({
        "routes": [{"id": "discord", "provider": "missing", "domains": ["discord.com"]}],
    }))
    before = (tmp_path / "router.json").read_bytes()
    with pytest.raises(manager.DashboardError):
        manager.apply_profile(tmp_path, "preset-school")
    assert (tmp_path / "router.json").read_bytes() == before
    assert not (tmp_path / "state" / manager.STORE_NAME).exists()


def test_removing_inactive_preset_keeps_original_file_and_hides_it_on_refresh(tmp_path):
    write_config(tmp_path)
    state = manager.delete_profile(tmp_path, "preset-roblox")
    assert [p["name"] for p in state["profiles"]] == ["opencode-only"]
    assert (tmp_path / "presets/roblox.json").exists()
    assert manager.state(tmp_path) == state
    with pytest.raises(manager.DashboardError, match="Choose another"):
        manager.delete_profile(tmp_path, "preset-opencode-only")


def test_mixed_preset_keeps_missing_cloudflare_routes_and_metadata_edit(tmp_path):
    write_config(tmp_path)
    routes = [
        {"id": "school", "provider": "cloudflare", "domains": ["discord.com"]},
        {"id": "opencode", "provider": "proton", "domains": ["opencode.ai"]},
    ]
    (tmp_path / "presets/school.json").write_text(json.dumps({
        "routes": routes,
        "routing": {"mode": "vpn-list", "vpn_domains": ["discord.com", "opencode.ai"]},
    }))
    school = next(p for p in manager.state(tmp_path)["profiles"] if p["id"] == "preset-school")
    assert school["providerId"] == "cloudflare"
    assert school["presetRoutes"] == [
        {"id": "school", "providerId": "cloudflare", "domains": ["discord.com"], "available": False},
        {"id": "opencode", "providerId": "proton", "domains": ["opencode.ai"], "available": True},
    ]
    manager.save_profile(tmp_path, {**school, "name": "School access"}, school["id"])
    before = (tmp_path / "router.json").read_bytes()
    with pytest.raises(manager.DashboardError):
        manager.apply_profile(tmp_path, school["id"])
    assert (tmp_path / "router.json").read_bytes() == before
    manager.save_provider(tmp_path, {"name": "Cloudflare WARP", "kind": "warp",
                                     "host": "127.0.0.1", "port": 2181})
    state = manager.apply_profile(tmp_path, school["id"])
    school = next(p for p in state["profiles"] if p["id"] == "preset-school")
    assert school["name"] == "School access"
    assert all(route["available"] for route in school["presetRoutes"])
    assert json.loads((tmp_path / "router.json").read_text())["routes"] == routes
    assert not (tmp_path / "sing-box.json").exists()


def test_edit_mixed_routes_preserves_advanced_fields_and_source_preset(tmp_path):
    config = write_config(tmp_path)
    config["providers"]["cloudflare"] = {"socks5": {"host": "127.0.0.1", "port": 2181}}
    (tmp_path / "router.json").write_text(json.dumps(config))
    source = tmp_path / "presets/opencode-only.json"
    preset = json.loads(source.read_text())
    preset["routes"].append({"id": "inactive", "provider": "proton", "domains": ["inactive.example"]})
    preset["routes"][0]["ip_cidr"] = ["198.51.100.0/24"]
    source.write_text(json.dumps(preset))
    original = source.read_bytes()
    profile = next(p for p in manager.state(tmp_path)["profiles"] if p["id"] == "preset-opencode-only")
    rules = profile["routeRules"]
    assert rules[1]["enabled"] is False
    rules[0]["providerId"] = "cloudflare"
    rules[0]["domains"] = ["opencode.ai", "new.example"]
    rules.append({"id": "extra", "providerId": "proton", "domains": ["extra.example"], "autoSubdomains": True, "fallback": "block", "enabled": True})
    edited = {**profile, "routeRules": rules, "domains": ["opencode.ai", "new.example", "extra.example"]}
    manager.save_profile(tmp_path, edited, profile["id"])
    state = manager.apply_profile(tmp_path, profile["id"])
    actual = json.loads((tmp_path / "router.json").read_text())
    assert actual["routes"][0]["ip_cidr"] == ["198.51.100.0/24"]
    assert actual["routes"][0]["provider"] == "cloudflare"
    assert actual["routing"]["vpn_domains"] == ["opencode.ai", "new.example", "extra.example"]
    assert source.read_bytes() == original
    assert state["activeProfileId"] == profile["id"]
    saved = next(p for p in state["profiles"] if p["id"] == profile["id"])
    assert saved["routeRules"][0]["providerId"] == "cloudflare"
    saved["routeRules"] = [row for row in saved["routeRules"] if row["id"] != "extra"]
    manager.save_profile(tmp_path, saved, profile["id"])
    manager.apply_profile(tmp_path, profile["id"])
    assert len(json.loads((tmp_path / "router.json").read_text())["routes"]) == 2


def test_invalid_route_edit_keeps_previous_store_and_config(tmp_path):
    write_config(tmp_path)
    profile = manager.state(tmp_path)["profiles"][0]
    manager.save_profile(tmp_path, profile, profile["id"])
    before = (tmp_path / "state" / manager.STORE_NAME).read_bytes()
    config_before = (tmp_path / "router.json").read_bytes()
    profile["routeRules"][0]["domains"] = ["not a domain"]
    with pytest.raises(manager.DashboardError):
        manager.save_profile(tmp_path, profile, profile["id"])
    assert (tmp_path / "state" / manager.STORE_NAME).read_bytes() == before
    assert (tmp_path / "router.json").read_bytes() == config_before


def test_removing_route_removes_only_its_autodetect_source(tmp_path):
    config = write_config(tmp_path)
    config["autodetect"] = {"sources": {
        "youtube": {"route_id": "opencode", "enabled": True},
    }}
    (tmp_path / "router.json").write_text(json.dumps(config))
    profile = manager.state(tmp_path)["profiles"][0]
    profile["routeRules"] = [{
        "id": "replacement", "providerId": "proton", "domains": ["replacement.example"],
        "autoSubdomains": True, "fallback": "direct", "enabled": True,
    }]
    profile["domains"] = ["replacement.example"]
    manager.save_profile(tmp_path, profile, profile["id"])
    manager.apply_profile(tmp_path, profile["id"])
    actual = json.loads((tmp_path / "router.json").read_text())
    assert actual["autodetect"]["sources"] == {}
    assert actual["routes"][0]["id"] == "replacement"


def test_full_routing_default_connection_can_change_without_route_edits(tmp_path):
    config = write_config(tmp_path)
    config["providers"]["second"] = {"directory": "providers/second"}
    (tmp_path / "router.json").write_text(json.dumps(config))
    profile = manager.state(tmp_path)["profiles"][0]
    profile["routeMode"] = "full"
    manager.save_profile(tmp_path, profile, profile["id"])
    profile = next(p for p in manager.state(tmp_path)["profiles"] if p["id"] == profile["id"])
    profile["providerId"] = "second"
    manager.save_profile(tmp_path, profile, profile["id"])
    manager.apply_profile(tmp_path, profile["id"])
    assert json.loads((tmp_path / "router.json").read_text())["routing"]["default_provider"] == "second"
