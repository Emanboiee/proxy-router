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
