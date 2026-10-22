"""Hermetic route recovery and explicit direct-fallback contracts."""
import json
from unittest import mock
import pytest
from tests.test_router_regressions import load_router
import route_watcher


@pytest.fixture
def controller(tmp_path):
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.probe_egress = mock.Mock(return_value={"status": None})
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda profile: None
    return r


def test_recovery_uses_vpn_before_direct(controller):
    r = controller
    r.probe_egress.side_effect = [{"status": None}, {"status": 200}]
    assert r.recover_route("warp", "discord.com") == 0
    assert r.active_fallback("warp") == "proton"
    r.engine_reload.assert_called_once()


def test_failed_vpn_falls_back_direct_and_reports_blocked_target(controller):
    r = controller
    assert r.recover_route("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"
    assert r.engine_reload.call_count == 2
    assert r.recover_route("warp", "discord.com") == 3
    assert r.engine_reload.call_count == 2


def test_direct_needs_explicit_opt_in(controller):
    r = controller
    r._providers["warp"].pop("fail_open_direct")
    assert r.recover_route("warp", "discord.com") == 1
    assert r.active_fallback("warp") is None
    assert "direct" not in r.configured_fallbacks("warp")


@pytest.mark.parametrize("dns", [False, None])
def test_dns_failure_does_not_change_route(controller, dns):
    r = controller
    r.egress_dns_probe.return_value = dns
    assert r.recover_route("warp", "discord.com") == 1
    r.engine_reload.assert_not_called()


@pytest.mark.parametrize("status", [200, 403, 429, 503])
def test_http_response_prevents_false_failover(controller, status):
    r = controller
    r.probe_egress.return_value = {"status": status}
    assert r.recover_route("warp", "discord.com") == 0
    r.engine_reload.assert_not_called()


def test_manual_off_and_tun_prevent_recovery(controller):
    r = controller
    r.MANUAL_OFF_FILE.parent.mkdir(parents=True)
    r.MANUAL_OFF_FILE.touch()
    assert r.recover_route("warp", "discord.com") == 3
    r.MANUAL_OFF_FILE.unlink()
    r._automatic_proxy_mode = lambda: False
    assert r.recover_route("warp", "discord.com") == 3
    r.probe_egress.assert_not_called()
    r.engine_reload.assert_not_called()


def test_unrouted_or_excluded_host_does_not_change_route(controller):
    r = controller
    assert r.recover_route("warp", "example.com") == 1
    r._routing = {"mode": "vpn-list", "vpn_domains": ["other.example"]}
    assert r.recover_route("warp", "discord.com") == 3
    r.engine_reload.assert_not_called()


def test_direct_marker_is_ignored_in_tun(controller):
    r = controller
    assert r.activate_fallback("warp", target="direct") == 0
    r.current_mode = lambda: "tun"
    assert r.active_fallback("warp") is None
    assert r.activate_fallback("warp", target="direct") != 0


def test_direct_rules_and_dns_preserve_route_precedence(controller, tmp_path):
    r = controller
    r._routing = {"mode": "safe-list", "default_provider": "proton", "direct_domains": []}
    r._routes.append({"id": "overlap", "domains": ["discord.com"], "provider": "proton"})
    r._usable_profile = lambda name, preferred=None: tmp_path / (name + ".conf")
    r.parse_wireguard = lambda path: {
        "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
        "private_key": "fixture", "peers": [{"address": "192.0.2.1", "port": 1,
        "public_key": "fixture", "allowed_ips": ["0.0.0.0/0"]}]}
    r.dns_server_for = lambda path: "1.1.1.1"
    assert r.activate_fallback("warp", target="direct") == 0
    config, _ = r.build_singbox_config()
    assert config["route"]["rules"][0] == {"outbound": "direct", "domain_suffix": ["discord.com"]}
    assert config["dns"]["rules"][0] == {"domain_suffix": ["discord.com"], "server": "dns-local"}
    assert config["route"]["final"] == "proton"


def test_watcher_passes_target_to_controller(tmp_path):
    runner = mock.Mock(return_value=mock.Mock(returncode=0, stderr="", stdout="recovered"))
    route_watcher.rotate_provider(tmp_path, "warp", host="discord.com", runner=runner)
    assert runner.call_args.args[0][2:] == ["failover", "warp", "recover", "--host", "discord.com"]


def test_watcher_probes_without_waiting_for_error_logs(tmp_path):
    w = route_watcher
    (tmp_path / "router.json").write_text(json.dumps({
        "routes": [{"domains": ["discord.com"], "provider": "warp"}]}))
    probe = mock.Mock(return_value={"ok": True})
    def stop(_seconds):
        w.enabled_file(tmp_path).unlink(missing_ok=True)
    with mock.patch.object(w, "engine_pid_alive", return_value=True), \
         mock.patch.object(w, "_read_new_lines", return_value=(0, [])), \
         mock.patch.object(w, "_network_check_hop"), \
         mock.patch.object(w, "probe_target", probe), \
         mock.patch.object(w, "restore_provider", return_value={"returncode": 3, "restored": False}) as restore, \
         mock.patch.object(w.signal, "signal"):
        assert w.worker(tmp_path, sleep=stop) == 0
    probe.assert_called_once_with(tmp_path.resolve(), "discord.com")
    restore.assert_called_once_with(tmp_path.resolve(), "warp", "discord.com")


def test_direct_fallback_returns_to_vpn_after_two_primary_checks(controller):
    r = controller
    assert r.activate_fallback("warp", target="direct") == 0
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"
    marker = r.ROOT / "state" / "recovery" / "warp-restore.json"
    marker.write_text(json.dumps({"attempted_at": 0, "successes": 1}))
    assert r.restore_fallback("warp", "discord.com") == 0
    assert r.active_fallback("warp") is None
    assert not marker.exists()


def test_restore_keeps_direct_when_primary_is_still_dead(controller):
    r = controller
    assert r.activate_fallback("warp", target="direct") == 0
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"
    marker = r.ROOT / "state" / "recovery" / "warp-restore.json"
    assert json.loads(marker.read_text())["successes"] == 0


def test_watcher_can_request_primary_restore(tmp_path):
    runner = mock.Mock(return_value=mock.Mock(returncode=0, stderr="", stdout="restored"))
    route_watcher.restore_provider(tmp_path, "warp", "discord.com", runner=runner)
    assert runner.call_args.args[0][2:] == [
        "failover", "warp", "restore", "--host", "discord.com"]


@pytest.fixture
def primary_controller(controller, tmp_path):
    r = controller
    profiles = [tmp_path / f"exit-{i}.conf" for i in range(6)]
    for profile in profiles:
        profile.touch()
    r.provider_files = lambda name: profiles
    r.resolve_active = lambda name: profiles[0]
    r.set_active("warp", profiles[0])
    return r, profiles


def test_primary_recovers_before_configured_fallback(primary_controller):
    r, profiles = primary_controller
    r.probe_egress.side_effect = [{"status": None}, {"status": 200}]
    assert r.recover_route("warp", "discord.com") == 0
    assert r.persisted_active("warp") == profiles[1]
    assert r.active_fallback("warp") is None
    r.engine_reload.assert_called_once_with({"warp": profiles[1]})


def test_three_distinct_primary_exits_before_fallback(primary_controller):
    r, profiles = primary_controller
    events = []
    r.engine_reload.side_effect = lambda *args: events.append(args) or 0
    r.probe_egress.side_effect = [{"status": None}] * 4 + [{"status": 200}]
    assert r.recover_route("warp", "discord.com") == 0
    assert events[:4] == [({"warp": p},) for p in profiles[1:4] + profiles[:1]]
    assert events[4:] == [()]
    assert r.persisted_active("warp") == profiles[0]
    assert r.active_fallback("warp") == "proton"
    assert all(r.is_cooled_down("warp", p) for p in profiles[:4])


def test_primary_skips_cooling_blocked_exhausted_and_malformed(primary_controller):
    r, profiles = primary_controller
    r.mark_cooldown("warp", profiles[1], 120)
    r.egress_is_blocked = lambda name, p: p == profiles[2]
    r.egress_is_exhausted = lambda name, p: p == profiles[3]
    r._profile_error = lambda p: "bad" if p == profiles[4] else None
    r.probe_egress.side_effect = [{"status": None}, {"status": 200}]
    assert r.recover_route("warp", "discord.com") == 0
    r.engine_reload.assert_called_once_with({"warp": profiles[5]})


def test_primary_budget_stops_starting_more_exits(primary_controller):
    r, profiles = primary_controller
    with mock.patch.object(r.time, "monotonic", side_effect=[0, 0, 31]):
        assert r._recover_primary_route("warp", lambda: False) == 1
    assert r.engine_reload.call_args_list == [mock.call({"warp": profiles[1]}),
                                             mock.call({"warp": profiles[0]})]
    assert r.persisted_active("warp") == profiles[0]


def test_primary_failed_reload_is_not_probed_or_retried(primary_controller):
    r, profiles = primary_controller
    r.engine_reload.return_value = 1
    reachable = mock.Mock(return_value=True)
    assert r._recover_primary_route("warp", reachable) == 1
    reachable.assert_not_called()
    assert r.engine_reload.call_args_list == [mock.call({"warp": p}) for p in profiles[1:4]]
    assert r.persisted_active("warp") == profiles[0]


def test_primary_rollback_failure_stops_fallback(primary_controller):
    r, profiles = primary_controller
    r.provider_files = lambda name: profiles[:2]
    r.engine_reload.side_effect = [0, 1]
    assert r.recover_route("warp", "discord.com") == 1
    assert r.active_fallback("warp") is None
    assert r.engine_reload.call_count == 2
    assert r.persisted_active("warp") == profiles[1]


@pytest.mark.parametrize("kind", ["proxy", "active-fallback"])
def test_primary_does_not_rotate_proxy_or_parked_provider(primary_controller, kind):
    r, profiles = primary_controller
    if kind == "proxy":
        r.is_proxy_provider = lambda name: True
    else:
        r.activate_fallback("warp", target="proton")
        r.engine_reload.reset_mock()
    assert r._recover_primary_route("warp", mock.Mock()) == 1
    r.engine_reload.assert_not_called()


def test_primary_stops_when_manual_off_appears(primary_controller):
    r, profiles = primary_controller
    def stop_after_reload(*args):
        r.MANUAL_OFF_FILE.parent.mkdir(parents=True, exist_ok=True)
        r.MANUAL_OFF_FILE.touch()
        return 0
    r.engine_reload.side_effect = stop_after_reload
    assert r.recover_route("warp", "discord.com") == 3
    assert r.active_fallback("warp") is None
    assert r.engine_reload.call_count == 1


def test_restore_rechecks_at_sixty_seconds_and_still_requires_two_wins(controller):
    r = controller
    r.activate_fallback("warp", target="direct")
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r.time, "time", return_value=1000):
        assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"
    with mock.patch.object(r.time, "time", return_value=1059):
        assert r.restore_fallback("warp", "discord.com") == 3
    assert r.active_fallback("warp") == "direct"
    with mock.patch.object(r.time, "time", return_value=1060):
        assert r.restore_fallback("warp", "discord.com") == 0
    assert r.active_fallback("warp") is None


def test_no_fallback_exhaustion_restores_original_primary(primary_controller):
    r, profiles = primary_controller
    r._providers["warp"] = {}
    assert r.recover_route("warp", "discord.com") == 1
    assert r.persisted_active("warp") == profiles[0]
    assert r.engine_reload.call_args_list == [mock.call({"warp": p})
                                             for p in profiles[1:4] + profiles[:1]]


def test_primary_recovery_honors_least_recent_policy(primary_controller):
    r, profiles = primary_controller
    r.rotation_policy = lambda: "least-recent"
    r.read_egress = lambda name, p: {"last_used": int(p.stem[-1])}
    r._egress_rank = lambda record: (0,)
    r._lru_key = lambda record: -record["last_used"]
    assert r._recover_primary_route("warp", lambda: True) == 0
    r.engine_reload.assert_called_once_with({"warp": profiles[-1]})


def test_primary_stops_when_mode_changes_after_probe(primary_controller):
    r, profiles = primary_controller
    mode = [True]
    r._automatic_proxy_mode = lambda: mode[0]
    def probe():
        mode[0] = False
        return False
    assert r._recover_primary_route("warp", probe) == 3
    assert r.engine_reload.call_count == 1
    assert r.active_fallback("warp") is None


def test_confirmed_stall_provider_fallback_is_restorable(controller):
    r = controller
    assert r.activate_fallback("warp", target="proton", reason="confirmed-stall",
                               automatic=True) == 0
    r.engine_reload.reset_mock()
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r.time, "time", return_value=1000):
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    # The SAME provider fallback is reinstated while one more win is pending.
    assert r.active_fallback("warp") == "proton"
    with mock.patch.object(r.time, "time", return_value=1060):
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 0
    assert r.active_fallback("warp") is None


def test_confirmed_stall_restore_reinstates_provider_on_failed_check(controller):
    r = controller
    assert r.activate_fallback("warp", target="proton", reason="confirmed-stall",
                               automatic=True) == 0
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    assert r.active_fallback("warp") == "proton"
    marker = r.ROOT / "state" / "recovery" / "warp-restore.json"
    assert json.loads(marker.read_text())["successes"] == 0


def test_automatic_restore_leaves_operator_fallback_selected(controller):
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    r.engine_reload.reset_mock()
    assert r.restore_fallback("warp", "discord.com", automatic=True) == 3
    assert r.active_fallback("warp") == "proton"
    r.engine_reload.assert_not_called()


def test_quota_exhaustion_uses_deadline_not_a_latch(primary_controller):
    r, profiles = primary_controller
    path = r.egress_record_path("warp", profiles[1])
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"exhausted": True,
                                "exhausted_until": r._iso_ts(1000)}))
    assert r.egress_is_exhausted("warp", profiles[1], now=999)
    assert not r.egress_is_exhausted("warp", profiles[1], now=1001)
    # A marker with no usable deadline stays active until cleared.
    path.write_text(json.dumps({"exhausted": True}))
    assert r.egress_is_exhausted("warp", profiles[1], now=999)
