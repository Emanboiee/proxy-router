from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path):
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("proxy_router_under_test", ROOT / "router.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.CONFIG_FILE = tmp_path / "router.json"
    module.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    return module


def _write_config(tmp_path, *, preset="default", network_auto=True, mappings=None):
    config = {
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        "preset": preset,
        "vpn": {
            "default_mode": "tun",
            "capture": "routes",
            "network_auto": network_auto,
            "network_presets": mappings or {"SchoolWiFi": "school-warp"},
        },
    }
    (tmp_path / "router.json").write_text(json.dumps(config))


class _FakeComplete:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def test_current_ssid_parses_ipconfig_output(tmp_path):
    router = load_router(tmp_path)
    fake = _FakeComplete(stdout="\n  SSID : SchoolWiFi\n  BSSID : aa:bb\n")
    with mock.patch.object(router.subprocess, "run", return_value=fake):
        assert router.current_ssid() == "SchoolWiFi"


def test_current_ssid_none_when_unconnected(tmp_path):
    router = load_router(tmp_path)
    fake = _FakeComplete(stdout="\n  BSSID : aa:bb\n")
    with mock.patch.object(router.subprocess, "run", return_value=fake):
        assert router.current_ssid() is None


def test_current_ssid_skips_failed_interface(tmp_path):
    router = load_router(tmp_path)
    def _run(cmd, **kwargs):
        if cmd[2] == "en0":
            return _FakeComplete(stdout="", returncode=1)
        return _FakeComplete(stdout="  SSID : OtherNet\n")
    with mock.patch.object(router.subprocess, "run", side_effect=_run):
        assert router.current_ssid() == "OtherNet"


def test_network_preset_map_reads_vpn_section(tmp_path):
    router = load_router(tmp_path)
    router._vpn = {"network_presets": {"A": "school-warp", "B": "home"}}
    assert router.network_preset_map() == {"A": "school-warp", "B": "home"}


def test_network_preset_map_ignores_non_dict(tmp_path):
    router = load_router(tmp_path)
    router._vpn = {"network_presets": "nope"}
    assert router.network_preset_map() == {}


def test_preset_for_current_network_respects_auto_flag(tmp_path):
    router = load_router(tmp_path)
    router._vpn = {"network_auto": False, "network_presets": {"SchoolWiFi": "school-warp"}}
    with mock.patch.object(router, "current_ssid", return_value="SchoolWiFi"):
        assert router.preset_for_current_network() is None
    router._vpn["network_auto"] = True
    with mock.patch.object(router, "current_ssid", return_value="SchoolWiFi"):
        assert router.preset_for_current_network() == "school-warp"


def test_apply_network_preset_applies_and_reloads_when_changed(tmp_path):
    router = load_router(tmp_path)
    _write_config(tmp_path, preset="default")

    def fake_apply(root, name):
        path = root / "router.json"
        data = json.loads(path.read_text())
        data["preset"] = name
        path.write_text(json.dumps(data))
        return {"added": ["school"], "mode": "vpn-list", "preset": name}

    with (
        mock.patch.object(router, "preset_for_current_network", return_value="school-warp"),
        mock.patch.object(router, "_engine_runs_as_root", return_value=False),
        mock.patch.object(router, "engine_reload", return_value=0),
        mock.patch("setup_tui.apply_preset_by_name", side_effect=fake_apply),
    ):
        result = router.apply_network_preset()
    assert result["applied"] is True
    assert result["preset"] == "school-warp"
    assert result["reload_rc"] == 0
    marker = router.network_preset_marker(tmp_path)
    assert marker.is_file()
    assert json.loads(marker.read_text())["preset"] == "school-warp"
    applied = json.loads((tmp_path / "router.json").read_text())
    assert applied["preset"] == "school-warp"


def test_apply_network_preset_noop_when_already_active(tmp_path):
    router = load_router(tmp_path)
    _write_config(tmp_path, preset="school-warp")
    with (
        mock.patch.object(router, "preset_for_current_network", return_value="school-warp"),
        mock.patch("setup_tui.apply_preset_by_name") as apply_mock,
    ):
        result = router.apply_network_preset(reload_engine=False)
    assert result["applied"] is False
    assert result["reason"] == "already active"
    apply_mock.assert_not_called()


def test_apply_network_preset_noop_when_no_mapping(tmp_path):
    router = load_router(tmp_path)
    _write_config(tmp_path, preset="default", mappings={})
    with mock.patch.object(router, "preset_for_current_network", return_value=None):
        result = router.apply_network_preset(reload_engine=False)
    assert result["applied"] is False
    assert result["reason"] == "no network mapping"


def test_cmd_network_check_returns_zero_on_apply(tmp_path, capsys):
    router = load_router(tmp_path)
    _write_config(tmp_path, preset="default")
    with (
        mock.patch.object(router, "preset_for_current_network", return_value="school-warp"),
        mock.patch.object(router, "engine_reload", return_value=0),
        mock.patch.object(router, "_engine_runs_as_root", return_value=False),
        mock.patch("setup_tui.apply_preset_by_name", return_value={"added": [], "mode": "vpn-list", "preset": "school-warp"}),
    ):
        assert router.cmd_network_check() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applied"] is True


def test_network_status_reports_wifi_state(tmp_path):
    router = load_router(tmp_path)
    with mock.patch.object(router.sys, "platform", "darwin"), \
         mock.patch.object(router, "current_ssid", return_value="SchoolWiFi"):
        assert router.network_status()["connected"] is True
    with mock.patch.object(router.sys, "platform", "darwin"), \
         mock.patch.object(router, "current_ssid", return_value=None):
        result = router.network_status()
    assert result["connected"] is False
    assert result["supported"] is True


def test_network_disconnect_latches_and_tears_down_without_manual_off(tmp_path):
    router = load_router(tmp_path)
    router.MANUAL_OFF_FILE = tmp_path / "state" / "manual-off"
    with (
        mock.patch.object(router.sys, "platform", "darwin"),
        mock.patch.object(router, "route_watcher_stop"),
        mock.patch.object(router, "system_proxy_off", return_value=0),
        mock.patch.object(router, "_with_lock", return_value=0) as locked,
    ):
        assert router.cmd_network_disconnect() == 0
    assert router.network_off_marker().is_file()
    assert not router.MANUAL_OFF_FILE.exists()
    locked.assert_called_once()


def test_network_reconnect_clears_latch_after_engine_and_proxy_are_ready(tmp_path):
    router = load_router(tmp_path)
    router.MANUAL_OFF_FILE = tmp_path / "state" / "manual-off"
    marker = router.network_off_marker()
    marker.parent.mkdir(parents=True)
    marker.write_text("network unavailable\\n")
    with (
        mock.patch.object(router.sys, "platform", "darwin"),
        mock.patch.object(router, "current_ssid", return_value="HomeWiFi"),
        mock.patch.object(router, "load_config", return_value=0),
        mock.patch.object(router, "_with_lock", return_value=0) as locked,
        mock.patch.object(router, "route_watcher_start"),
        mock.patch.object(router, "system_proxy_on", return_value=0),
    ):
        assert router.cmd_network_reconnect() == 0
    assert not marker.exists()
    locked.assert_called_once()


def test_engine_ensure_stays_quiescent_while_network_latch_exists(tmp_path):
    router = load_router(tmp_path)
    router.MANUAL_OFF_FILE = tmp_path / "state" / "manual-off"
    router.network_off_marker().parent.mkdir(parents=True)
    router.network_off_marker().write_text("network unavailable\\n")
    assert router.engine_ensure() == 3


def test_cmd_network_check_serializes_preset_reload_under_engine_lock(tmp_path, capsys):
    router = load_router(tmp_path)
    _write_config(tmp_path, preset="default")
    calls = []

    def fake_lock(action):
        calls.append(action)
        return action()

    with (
        mock.patch.object(router, "_with_lock", side_effect=fake_lock),
        mock.patch.object(router, "apply_network_preset", return_value={
            "applied": False, "reason": "no network mapping", "checked_at": 1,
        }),
    ):
        assert router.cmd_network_check() == 0
    assert len(calls) == 1
    json.loads(capsys.readouterr().out)


class _SubprocessRun:
    """Simplest possible fake runner for route_watcher._network_check_hop."""

    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stderr = ""


def test_route_watcher_network_check_hop_runs_router_command(tmp_path):
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("route_watcher_under_test", ROOT / "route_watcher.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    calls = []
    with mock.patch.object(module.subprocess, "run", side_effect=lambda *a, **k: calls.append(a) or _SubprocessRun(0)):
        module._network_check_hop(tmp_path)
    assert calls
    assert calls[0][0][-1] == "network-check"
