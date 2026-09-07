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
         mock.patch.object(w.signal, "signal"):
        assert w.worker(tmp_path, sleep=stop) == 0
    probe.assert_called_once_with(tmp_path.resolve(), "discord.com")
