"""Hermetic coverage for the macOS proxy/DNS implementation in issue #124."""
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import router


SCUTIL_OK = """<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 2080
  HTTPSEnable : 1
  HTTPSProxy : 127.0.0.1
  HTTPSPort : 2080
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> { HTTPEnable : 0 }
  }
}
"""


def test_scutil_parser_uses_global_http_https_keys_only():
    parsed = router._parse_scutil_proxy(SCUTIL_OK)
    assert parsed["known"] is True
    assert parsed["http"] == {"enabled": True, "server": "127.0.0.1", "port": 2080}
    assert parsed["https"] == {"enabled": True, "server": "127.0.0.1", "port": 2080}


def test_connected_service_parser_has_no_hardcoded_vpn_names():
    def run(command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout='* (Connected) 42 : "Renamed VPN"\n')

    assert router._connected_network_services(run) == ["Renamed VPN"]


def test_active_service_comes_from_service_order_after_rename():
    def run(command, **_kwargs):
        if command[:3] == ["route", "-n", "get"]:
            return SimpleNamespace(returncode=0, stdout="interface: en0\n")
        if command[1] == "-listnetworkserviceorder":
            return SimpleNamespace(returncode=0, stdout=(
                "(1) Campus Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"))
        return SimpleNamespace(returncode=0, stdout="")

    assert router.active_service_name(run) == "Campus Wi-Fi"


class ProxyRunner:
    def __init__(self, *, foreign_https=False, converge=True):
        self.commands = []
        self.http = {"enabled": False, "server": None, "port": None}
        self.https = ({"enabled": True, "server": "10.0.0.2", "port": 8080}
                      if foreign_https else {"enabled": False, "server": None, "port": None})
        self.converge = converge

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[:3] == ["route", "-n", "get"]:
            return SimpleNamespace(returncode=0, stdout="interface: en0\n")
        if command[1] == "-listnetworkserviceorder":
            return SimpleNamespace(returncode=0, stdout="(1) Campus Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n")
        if command[1] == "-listallnetworkservices":
            return SimpleNamespace(returncode=0, stdout="Campus Wi-Fi\n")
        if command[:2] == ["scutil", "--nc"]:
            return SimpleNamespace(returncode=0, stdout="")
        if command[:2] == ["scutil", "--proxy"]:
            if not self.converge:
                return SimpleNamespace(returncode=0, stdout="<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n")
            return SimpleNamespace(returncode=0, stdout=SCUTIL_OK)
        if command[0] == "networksetup" and command[1] in {"-getwebproxy", "-getsecurewebproxy"}:
            state = self.http if command[1] == "-getwebproxy" else self.https
            enabled = "Yes" if state["enabled"] else "No"
            return SimpleNamespace(returncode=0, stdout=(
                f"Enabled: {enabled}\nServer: {state['server'] or ''}\nPort: {state['port'] or ''}\n"))
        if command[0] == "networksetup" and command[1] in {
                "-getautoproxyurl", "-getproxyautodiscovery", "-getproxybypassdomains"}:
            return SimpleNamespace(returncode=0, stdout="Enabled: No\n")
        if command[0] == "networksetup" and command[1] == "-setwebproxy":
            self.http = {"enabled": True, "server": command[3], "port": int(command[4])}
        elif command[0] == "networksetup" and command[1] == "-setsecurewebproxy":
            self.https = {"enabled": True, "server": command[3], "port": int(command[4])}
        elif command[0] == "networksetup" and command[1] == "-setwebproxystate" and command[3] == "off":
            self.http["enabled"] = False
        elif command[0] == "networksetup" and command[1] == "-setsecurewebproxystate" and command[3] == "off":
            self.https["enabled"] = False
        return SimpleNamespace(returncode=0, stdout="")


class FailingProxyRunner(ProxyRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fail_secure_set = False
        self.fail_secure_off = False

    def __call__(self, command, **kwargs):
        if (self.fail_secure_set and command[0] == "networksetup"
                and command[1] == "-setsecurewebproxy"):
            raise RuntimeError("secure proxy command failed")
        if (self.fail_secure_off and command[0] == "networksetup"
                and command[1] == "-setsecurewebproxystate"):
            raise RuntimeError("secure cleanup failed")
        return super().__call__(command, **kwargs)


class ConnectedOverrideRunner(ProxyRunner):
    """Physical proxy is set first; a connected extension overrides it until
    the extension service is reconciled."""

    def __init__(self):
        super().__init__()
        self.extension_enabled = False

    def __call__(self, command, **kwargs):
        if command[:2] == ["scutil", "--nc"]:
            return SimpleNamespace(returncode=0, stdout='* (Connected) 9 : "School VPN"\n')
        if command[:2] == ["scutil", "--proxy"] and not self.extension_enabled:
            return SimpleNamespace(returncode=0, stdout="<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n")
        if command[0] == "networksetup" and command[1] == "-setwebproxy" \
                and command[2] == "School VPN":
            self.extension_enabled = True
        return super().__call__(command, **kwargs)


def test_connect_records_ownership_and_disconnect_uses_recorded_port(tmp_path, monkeypatch):
    runner = ProxyRunner()
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    monkeypatch.setattr(router, "_port", 2080)
    assert router.system_proxy_on(runner=runner) == 0
    record = json.loads((tmp_path / "system-proxy.json").read_text())
    assert record["version"] == 1
    assert record["endpoint"] == {"server": "127.0.0.1", "port": 2080}
    assert "password" not in json.dumps(record).lower()

    monkeypatch.setattr(router, "_port", 2999)
    assert router.system_proxy_off(runner=runner) == 0
    assert runner.http["enabled"] is False and runner.https["enabled"] is False
    assert not (tmp_path / "system-proxy.json").exists()


def test_connected_extension_is_reconciled_after_physical_service(monkeypatch, tmp_path):
    runner = ConnectedOverrideRunner()
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    clock = iter([0.0, 3.0, 3.0])
    with mock.patch.object(router.time, "monotonic", side_effect=lambda: next(clock)):
        assert router.system_proxy_on(runner=runner) == 0
    set_services = [command[2] for command in runner.commands
                    if command[:2] == ["networksetup", "-setwebproxy"]]
    assert set_services[:2] == ["Campus Wi-Fi", "School VPN"]


def test_foreign_mixed_protocol_is_conflict_without_mutation(tmp_path, monkeypatch):
    runner = ProxyRunner(foreign_https=True)
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    assert router.system_proxy_on(runner=runner) == 1
    assert not any(command[1] == "-setwebproxy" for command in runner.commands)


def test_never_converging_effective_state_rolls_back_and_returns_failure(tmp_path, monkeypatch):
    runner = ProxyRunner(converge=False)
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    clock = iter([0.0, 3.0])
    with mock.patch.object(router.time, "monotonic", side_effect=lambda: next(clock)), \
         mock.patch.object(router.time, "sleep"):
        assert router.system_proxy_on(runner=runner) == 1
    assert runner.http["enabled"] is False and runner.https["enabled"] is False


def test_partial_connect_command_failure_rolls_back_owned_http(tmp_path, monkeypatch):
    runner = FailingProxyRunner()
    runner.fail_secure_set = True
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    assert router.system_proxy_on(runner=runner) == 1
    assert runner.http["enabled"] is False
    assert not (tmp_path / "system-proxy.json").exists()


def test_disconnect_cleanup_failure_is_nonzero_and_retains_record(tmp_path, monkeypatch):
    runner = FailingProxyRunner()
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "SYSTEM_PROXY_STATE_FILE", tmp_path / "system-proxy.json")
    assert router.system_proxy_on(runner=runner) == 0
    runner.fail_secure_off = True
    assert router.system_proxy_off(runner=runner) == 1
    assert (tmp_path / "system-proxy.json").exists()


def test_dns_timeout_with_routed_success_is_classified_without_side_effects(monkeypatch):
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "_providers", {"vpn": {}})
    monkeypatch.setattr(router, "_routes", [{"provider": "vpn", "domains": ["routed.example"]}])
    monkeypatch.setattr(router, "routing_state", lambda: {"mode": "default", "direct_domains": []})
    monkeypatch.setattr(router, "probe_url_for", lambda _name: "https://routed.example/")
    monkeypatch.setattr(router, "_bounded_getaddrinfo", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(router, "_effective_proxy_state", lambda *_args, **_kwargs: {
        "known": True,
        "http": {"enabled": True, "server": "127.0.0.1", "port": 2080},
        "https": {"enabled": True, "server": "127.0.0.1", "port": 2080},
    })
    calls = []
    monkeypatch.setattr(router, "probe_egress", lambda **kwargs: calls.append(kwargs) or {"ok": True})
    monkeypatch.setattr(router, "_macos_dns_snapshot", lambda *_args, **_kwargs: {
        "active_configured": ["1.1.1.1"], "dhcp": ["10.0.0.53"]})

    report = router._network_diagnostic(runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=""))
    assert report["status"] == "direct_dns_unavailable"
    assert report["direct_dns"]["status"] == "direct_dns_unavailable"
    assert report["routed"]["status"] == "ok"
    assert len(calls) == 1


def test_routed_http_403_is_reachable_not_dead_tunnel(monkeypatch):
    monkeypatch.setattr(router, "_port", 2080)
    monkeypatch.setattr(router, "_providers", {"vpn": {}})
    monkeypatch.setattr(router, "_routes", [{"provider": "vpn", "domains": ["routed.example"]}])
    monkeypatch.setattr(router, "routing_state", lambda: {"mode": "default", "direct_domains": []})
    monkeypatch.setattr(router, "probe_url_for", lambda _name: "https://routed.example/")
    monkeypatch.setattr(router, "_bounded_getaddrinfo", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(router, "_effective_proxy_state", lambda *_args, **_kwargs: {
        "known": True,
        "http": {"enabled": True, "server": "127.0.0.1", "port": 2080},
        "https": {"enabled": True, "server": "127.0.0.1", "port": 2080},
    })
    monkeypatch.setattr(router, "_direct_https_probe", lambda *args, **kwargs: {"status": "ok"})
    monkeypatch.setattr(router, "probe_egress", lambda **kwargs: {
        "ok": False, "status": 403, "error": "cloudflare-403"})
    report = router._network_diagnostic(
        runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=""))
    assert report["routed"]["status"] == "reachable_http_error"
    assert report["status"] == "ok"


def test_direct_http_429_is_reachable():
    def opener(_request, timeout):
        raise urllib.error.HTTPError("https://example.com/", 429, "rate limited", {}, None)

    result = router._direct_https_probe("https://example.com/", opener=opener)
    assert result["status"] == "ok"
    assert result["http_status"] == 429


def test_dhcp_dns_snapshot_is_read_only():
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        if command[:3] == ["route", "-n", "get"]:
            return SimpleNamespace(returncode=0, stdout="interface: en0\n")
        if command[1] == "-listallnetworkservices":
            return SimpleNamespace(returncode=0, stdout="Campus Wi-Fi\n")
        if command[1] == "-getdnsservers":
            return SimpleNamespace(returncode=0, stdout="1.1.1.1\n")
        if command[:2] == ["ipconfig", "getpacket"]:
            return SimpleNamespace(returncode=0, stdout="domain_name_server (ip_mult): (10.0.0.53)\n")
        if command[1] == "-listnetworkserviceorder":
            return SimpleNamespace(returncode=0, stdout="(1) Campus Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n")
        return SimpleNamespace(returncode=0, stdout="")

    snapshot = router._macos_dns_snapshot(run)
    assert snapshot["active_configured"] == ["1.1.1.1"]
    assert snapshot["dhcp"] == ["10.0.0.53"]
    assert not any(command[1] == "-setdnsservers" for command in commands)
