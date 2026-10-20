import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import dashboard_profile_manager as manager


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "router.json").write_text(
        json.dumps({
            "port": 2080,
            "providers": {"p": {"directory": "providers/p"}},
            "routes": [],
            "vpn": {"default_mode": "proxy"},
        }),
        encoding="utf-8",
    )
    (tmp_path / "presets").mkdir()
    return tmp_path


def write_preset(root: Path, name: str, value: dict) -> None:
    (root / "presets" / f"{name}.json").write_text(
        json.dumps(value), encoding="utf-8"
    )


def test_state_skips_malformed_preset_but_keeps_good(root: Path) -> None:
    write_preset(root, "goodroute", {
        "routing": {"mode": "vpn-list", "vpn_domains": ["good.example"]},
        "routes": [{"id": "good", "domains": ["good.example"], "provider": "p"}],
    })
    write_preset(root, "zbad", {
        "routing": {"mode": "vpn-list", "vpn_domains": ["matched.example"]},
        "routes": [
            {"id": "matched", "domains": ["matched.example"], "provider": "p"},
            {"id": "bad", "domains": None, "provider": "p"},
        ],
    })

    profiles = manager.state(root)["profiles"]
    ids = {profile["id"] for profile in profiles}

    assert "preset-goodroute" in ids
    assert "preset-zbad" not in ids


@pytest.mark.parametrize(
    "domains",
    [None, "example.com", 7, ["ok.example", 7]],
)
def test_load_local_preset_rejects_bad_route_domains(
    root: Path, domains: object
) -> None:
    write_preset(root, "bad", {
        "routes": [{"id": "bad", "provider": "p", "domains": domains}],
    })

    with pytest.raises(manager.DashboardError):
        manager._load_local_preset(root, "bad")


def test_load_local_preset_allows_absent_route_domains(root: Path) -> None:
    preset = {"routes": [{"id": "plain", "provider": "p"}]}
    write_preset(root, "nodomains", preset)

    assert manager._load_local_preset(root, "nodomains") == preset
