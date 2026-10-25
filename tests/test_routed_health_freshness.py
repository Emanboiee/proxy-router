"""A live engine and a prior check cannot stand in for current routed health."""
import json
import os

import pytest

import proxy_tray as tray
import router


@pytest.mark.parametrize("network", [None, {}, {"status": "unknown", "stale": False},
    {"status": "skipped", "stale": False}, {"status": "ok"},
    {"status": "ok", "stale": True}])
def test_unverified_health_is_not_connected_in_any_tray_surface(network):
    payload = {"up": True, "mode": "proxy", "system_proxy": {"status": "ok"},
               "providers": {"fixture": {"active": "a", "egress": {"a": {"ok": True}}}}}
    if network is not None:
        payload["network"] = network
    status = tray.RouterStatus.from_cli(0, json.dumps(payload))
    assert "connected" not in status.headline()
    assert tray._status_icon_color(status) != "#4caf50"
    assert tray._dashboard_indicator(status) != ("●", (77, 205, 139))
    model = tray.DashboardViewModel.from_status(status)
    assert model.title != "Connected"
    assert model.route_health != "Healthy"
    from types import SimpleNamespace
    app = tray.TrayApp(SimpleNamespace(root="/tmp"), None)
    app.latest = status
    labels = [item.text for item in app.build_menu()]
    assert "● Connected" not in labels
    assert "Check connectivity: router.py doctor --network" in labels


def test_fresh_success_is_connected_in_every_tray_surface():
    status = tray.RouterStatus.from_cli(0, json.dumps({
        "up": True, "mode": "proxy", "system_proxy": {"status": "ok"},
        "network": {"status": "ok", "stale": False},
        "providers": {"fixture": {"active": "a", "egress": {"a": {"ok": True}}}},
    }))
    assert "connected" in status.headline()
    assert tray._status_icon_color(status) == "#4caf50"
    assert tray.DashboardViewModel.from_status(status).title == "Connected"


@pytest.fixture
def generation_cache(tmp_path, monkeypatch):
    pid, config, cache = [tmp_path / name for name in ("pid", "engine.json", "health.json")]
    pid.write_text("4242")
    config.write_text("{}")
    monkeypatch.setattr(router, "PID_FILE", pid)
    monkeypatch.setattr(router, "SING_BOX_CONFIG", config)
    monkeypatch.setattr(router, "NETWORK_DIAGNOSTIC_FILE", cache)
    return pid, config, cache


@pytest.mark.parametrize("changed", [0, 1])
def test_prior_generation_success_is_stale(generation_cache, changed):
    import status_snapshot
    pid, config, cache = generation_cache
    cache.write_text(json.dumps({"checked_at": 100, "status": "ok",
                                "generation": status_snapshot.network_generation(pid, config)}))
    assert router._cached_network_diagnostic(now=101)["stale"] is False
    path = (pid, config)[changed]
    metadata = path.stat()
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000))
    assert router._cached_network_diagnostic(now=101)["stale"] is True


@pytest.mark.parametrize("timestamp", [101, float("nan"), float("inf"), True])
def test_future_or_nonfinite_time_cannot_prove_freshness(generation_cache, timestamp):
    import status_snapshot
    pid, config, cache = generation_cache
    cache.write_text(json.dumps({"checked_at": timestamp, "status": "ok",
                                "generation": status_snapshot.network_generation(pid, config)}))
    assert router._cached_network_diagnostic(now=100)["stale"] is True


def test_legacy_unbound_success_is_stale(generation_cache):
    _, _, cache = generation_cache
    cache.write_text(json.dumps({"checked_at": 100, "status": "ok"}))
    assert router._cached_network_diagnostic(now=101)["stale"] is True


@pytest.mark.parametrize("change_during_probe", [False, True])
def test_diagnostic_binds_generation_at_start(generation_cache, monkeypatch, change_during_probe):
    from types import SimpleNamespace
    _, config, cache = generation_cache
    monkeypatch.setattr(router, "_diagnostic_direct_url", lambda: "https://direct.example/")
    monkeypatch.setattr(router, "_effective_proxy_state", lambda *_: {"known": True})
    monkeypatch.setattr(router, "_effective_proxy_matches", lambda *_: True)
    monkeypatch.setattr(router, "_bounded_getaddrinfo", lambda *_, **__: ["192.0.2.1"])
    monkeypatch.setattr(router, "_direct_https_probe", lambda *_, **__: {"status": "ok"})
    monkeypatch.setattr(router, "_macos_dns_snapshot", lambda *_: {})
    monkeypatch.setattr(router, "_providers", {"fixture": {}})
    monkeypatch.setattr(router, "probe_url_for", lambda _: "https://routed.example/")
    monkeypatch.setattr(router, "unsafe_probe_target", lambda _: None)

    def probe(**_kwargs):
        if change_during_probe:
            metadata = config.stat()
            os.utime(config, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000))
        return {"ok": True}

    monkeypatch.setattr(router, "probe_egress", probe)
    result = router._network_diagnostic(runner=lambda *_, **__: SimpleNamespace())
    cache.write_text(json.dumps(result))
    assert result["status"] == "ok"
    assert router._cached_network_diagnostic()["stale"] is change_during_probe


def test_no_routed_target_does_not_report_success(generation_cache, monkeypatch):
    monkeypatch.setattr(router, "_diagnostic_direct_url", lambda: "https://direct.example/")
    monkeypatch.setattr(router, "_effective_proxy_state", lambda *_: {"known": True})
    monkeypatch.setattr(router, "_effective_proxy_matches", lambda *_: True)
    monkeypatch.setattr(router, "_bounded_getaddrinfo", lambda *_, **__: ["192.0.2.1"])
    monkeypatch.setattr(router, "_direct_https_probe", lambda *_, **__: {"status": "ok"})
    monkeypatch.setattr(router, "_macos_dns_snapshot", lambda *_: {})
    monkeypatch.setattr(router, "_providers", {})
    assert router._network_diagnostic(runner=object())["status"] == "routed_probe_skipped"
