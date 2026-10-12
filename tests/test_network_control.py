from unittest import mock
from types import SimpleNamespace
import json
import network_control as net


def test_history_caps_deduplicates_and_never_records_redaction(tmp_path):
    for i in range(7):
        net.remember(tmp_path, f"wifi-{i}", now=i + 1)
    rows = net.remember(tmp_path, "wifi-4", now=10)
    assert [r["ssid"] for r in rows] == [
        "wifi-4",
        "wifi-6",
        "wifi-5",
        "wifi-3",
        "wifi-2",
    ]
    assert net.remember(tmp_path, "<redacted>") == rows
    assert (tmp_path / "state/recent-networks.json").stat().st_mode & 0o777 == 0o600


def test_redacted_connected_is_not_lost_wifi(tmp_path):
    def run(args, **kwargs):
        output = (
            "Hardware Port: Wi-Fi\nDevice: en7\n"
            if args[0] == "networksetup"
            else "SSID : <redacted>\n"
        )
        return SimpleNamespace(returncode=0, stdout=output)

    result = net.probe(tmp_path, runner=run, platform="darwin")
    assert result["supported"] and result["connected"]
    assert result["ssid"] is None
    assert result["identity"] == "permission"


def test_failed_probe_is_unknown_not_disconnected(tmp_path):
    run = mock.Mock(side_effect=OSError("unavailable"))
    assert net.probe(tmp_path, runner=run, platform="darwin")["supported"] is False


def test_guard_debounce_unknown_and_manual_stop():
    guard = net.Guard()

    def action(connected, **options):
        return guard.action(
            {"connected": connected, "supported": True},
            enabled=True,
            manual_off=False,
            network_off=False,
            **options,
        )

    assert action(False) is None
    assert action(False) == "network-disconnect"
    assert (
        guard.action(
            {"connected": False, "supported": False},
            enabled=True,
            manual_off=False,
            network_off=False,
        )
        is None
    )
    assert action(False) is None
    assert (
        guard.action(
            {"connected": True, "supported": True},
            enabled=True,
            manual_off=True,
            network_off=True,
        )
        is None
    )
    assert (
        guard.action(
            {"connected": True, "supported": True},
            enabled=True,
            manual_off=False,
            network_off=True,
        )
        is None
    )
    assert (
        guard.action(
            {"connected": True, "supported": True},
            enabled=True,
            manual_off=False,
            network_off=True,
        )
        == "network-reconnect"
    )


def test_disconnect_disabled_does_not_disable_reconnect(tmp_path):
    net.set_disconnect(tmp_path, False)
    assert net.disconnect_enabled(tmp_path) is False
    guard = net.Guard()
    for _ in range(3):
        assert (
            guard.action(
                {"connected": False, "supported": True},
                enabled=False,
                manual_off=False,
                network_off=False,
            )
            is None
        )
    assert (
        guard.action(
            {"connected": True, "supported": True},
            enabled=False,
            manual_off=False,
            network_off=True,
        )
        is None
    )
    assert (
        guard.action(
            {"connected": True, "supported": True},
            enabled=False,
            manual_off=False,
            network_off=True,
        )
        == "network-reconnect"
    )
    assert "network_auto" not in net.preferences(tmp_path)


def test_stale_observation_never_used_for_matching(tmp_path):
    net.write_json(
        tmp_path / "state/native-network.json", {"ssid": "old-wifi", "checked_at": 1}
    )
    with mock.patch.object(net, "native_ssid", return_value=None):
        state = net.view(tmp_path, {"connected": True, "ssid": None})
    assert state["ssid"] is None
    assert state["recent"] == []


def test_failed_teardown_is_retried_despite_latch():
    guard = net.Guard()
    lost = {"connected": False, "supported": True}
    guard.action(lost, enabled=True, manual_off=False, network_off=False)
    action = guard.action(lost, enabled=True, manual_off=False, network_off=False)
    guard.completed(action, 1)
    assert (
        guard.action(lost, enabled=True, manual_off=False, network_off=True)
        == "network-disconnect"
    )
    guard.completed(action, 0)
    assert guard.action(lost, enabled=True, manual_off=False, network_off=True) is None


def test_worker_stays_alive_through_loss_and_applies_mapping_before_reconnect(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    observations = iter([False, False, False, True, True])
    commands = []
    ticks = 0

    def probe(root):
        return {"connected": next(observations), "supported": True, "ssid": None}

    def command(args, **kwargs):
        action = args[-1]
        commands.append(action)
        if action == "network-disconnect":
            (state / "network-off").touch()
        elif action == "network-reconnect":
            (state / "network-off").unlink()
        return SimpleNamespace(returncode=0)

    def sleep(seconds):
        nonlocal ticks
        ticks += 1
        if ticks == 5:
            (state / "manual-off").touch()

    with mock.patch.object(net, "probe", side_effect=probe), mock.patch.object(
        net, "native_ssid", return_value=None
    ), mock.patch.object(net.subprocess, "run", side_effect=command), mock.patch.object(
        net.time, "sleep", side_effect=sleep
    ):
        net.worker(tmp_path)
    assert commands.count("network-disconnect") == 1
    assert commands.count("network-reconnect") == 1
    assert commands[commands.index("network-reconnect") - 1] == "network-check"


def profile_fixture(root):
    import dashboard_profile_manager as manager

    net.write_json(
        root / "router.json",
        {
            "port": 2080,
            "providers": {"proton": {"directory": "providers/proton"}},
            "routes": [],
            "vpn": {"default_mode": "proxy", "network_auto": True},
        },
    )
    result = manager.save_profile(
        root,
        {
            "name": "Home routing",
            "providerId": "proton",
            "routeMode": "selective",
            "domains": ["example.net"],
            "autoSubdomains": True,
            "fallback": "direct",
        },
    )
    identifier = result["profiles"][0]["id"]
    router = SimpleNamespace(
        preset_for_current_network=mock.Mock(return_value="profile:" + identifier),
        engine_alive=mock.Mock(return_value=False),
        load_config=mock.Mock(return_value=0),
        engine_reload=mock.Mock(return_value=0),
        _engine_runs_as_root=mock.Mock(return_value=False),
        current_ssid=mock.Mock(return_value="Home WiFi"),
    )
    return router, identifier


def test_saved_profile_mapping_uses_real_routes_without_starting_engine(tmp_path):
    router, identifier = profile_fixture(tmp_path)
    assert net.profile_error(tmp_path, "profile:" + identifier) is None
    result = net.apply_mapping(router, tmp_path)
    assert result["applied"] is True
    assert net.read_json(tmp_path / "router.json")["routes"][0]["domains"] == [
        "example.net"
    ]
    router.engine_reload.assert_not_called()
    assert net.apply_mapping(router, tmp_path)["reason"] == "already active"


def test_failed_mapping_rolls_back_config_store_and_does_not_claim_applied(tmp_path):
    router, identifier = profile_fixture(tmp_path)
    before_config = net.read_json(tmp_path / "router.json")
    before_store = net.read_json(tmp_path / "state/dashboard_profiles.json")
    router.engine_alive.return_value = True
    router.engine_reload.return_value = 1
    result = net.apply_mapping(router, tmp_path)
    assert result["applied"] is False
    assert result["reload_rc"] == 1
    assert net.read_json(tmp_path / "router.json") == before_config
    assert net.read_json(tmp_path / "state/dashboard_profiles.json") == before_store
    assert not (tmp_path / "state/network-preset.json").exists()


def test_manual_off_never_applies_network_profile(tmp_path):
    router, identifier = profile_fixture(tmp_path)
    (tmp_path / "state/manual-off").touch()
    assert net.apply_mapping(router, tmp_path)["reason"] == "manually disconnected"
    router.engine_alive.assert_not_called()
    assert net.profile_error(tmp_path, "profile:missing") is not None


def test_exception_during_mapping_restores_exact_original_bytes(tmp_path):
    router, identifier = profile_fixture(tmp_path)
    path = tmp_path / "router.json"
    path.write_text(json.dumps(json.loads(path.read_text()), indent=4) + "\n")
    before = path.read_bytes()
    before_store = (tmp_path / "state/dashboard_profiles.json").read_bytes()
    router.engine_alive.return_value = True
    router.engine_reload.side_effect = RuntimeError("reload broke")
    import pytest

    with pytest.raises(RuntimeError, match="reload broke"):
        net.apply_mapping(router, tmp_path)
    assert path.read_bytes() == before
    assert (tmp_path / "state/dashboard_profiles.json").read_bytes() == before_store


def test_wifi_off_can_be_confirmed_without_ipconfig_summary(tmp_path):
    def run(args, **kwargs):
        if args[0] == "networksetup":
            return SimpleNamespace(
                returncode=0, stdout="Hardware Port: Wi-Fi\nDevice: en7\n"
            )
        if args[0] == "ipconfig":
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout="status: inactive\n")

    state = net.probe(tmp_path, runner=run, platform="darwin")
    assert state["supported"] is True
    assert state["connected"] is False
