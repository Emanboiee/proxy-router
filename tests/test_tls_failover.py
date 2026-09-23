"""Repeated no-HTTP TLS failures must eventually trigger failover."""
from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from tests.test_router_regressions import load_router


TLS = "curl(35): SSL_ERROR_SYSCALL"
EOF = "[SSL: UNEXPECTED_EOF_WHILE_READING] TLS EOF"
TARGET = "https://opencode.ai/zen/v1/models"


def outcome(error: str | None = TLS, status: int | None = None):
    return {
        "ok": status == 200,
        "latency_ms": 10 if status == 200 else None,
        "status": status,
        "error": error,
        "block_reason": None,
    }


@pytest.fixture
def lane(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    router._port = 49123
    router._providers = {
        "proton": {"directory": "providers/proton", "probe_url": TARGET},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    router._routes = [
        {"id": "proton", "provider": "proton", "domains": ["opencode.ai"]},
        {"id": "cloudflare", "provider": "cloudflare", "domains": ["discord.com"]},
    ]
    router._routing = {}
    router._vpn = {}
    router._egress_settings = {
        **router.DEFAULT_EGRESS_SETTINGS,
        "probe_settle_seconds": 0,
    }
    for provider in router._providers:
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        for stem in ("a", "b", "c"):
            (directory / f"{stem}.conf").write_text("synthetic profile")
        router.set_active(provider, directory / "a.conf")
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    monkeypatch.setattr(router, "listener_up", lambda: True)
    monkeypatch.setattr(router, "_automatic_proxy_mode", lambda: True)
    monkeypatch.setattr(router, "engine_reload", Mock(return_value=0))
    monkeypatch.setattr(router.time, "sleep", lambda _: None)
    monkeypatch.setattr(router.time, "time", lambda: 10000)
    monkeypatch.setattr(
        router,
        "egress_dns_probe",
        Mock(side_effect=AssertionError("TLS needs no DNS probe")),
    )
    return router, router.persisted_active("proton")


@pytest.mark.parametrize("method", ["probe_profile", "check_egress_live"])
@pytest.mark.parametrize("error", [TLS, EOF])
@pytest.mark.parametrize("seconds", [300, 777])
def test_repeated_tls_quarantines_and_rotation_skips(
    lane, monkeypatch, method, error, seconds
):
    router, profile = lane
    if seconds != 300:
        router._providers["proton"]["error_policy"] = {
            "tls": {"action": "cooldown", "seconds": seconds}
        }
    probe = Mock(return_value=outcome(error))
    monkeypatch.setattr(router, "probe_egress", probe)
    check = getattr(router, method)

    check("proton", profile)
    assert not router.is_cooled_down("proton", profile)
    verdict, record = check("proton", profile)

    assert router.is_cooled_down("proton", profile)
    assert record["tls_fails"] == 2
    if method == "check_egress_live":
        assert verdict == "dead"
    marker = router.ROOT / "state/cooldowns/proton/a.until"
    assert int(marker.read_text()) == 10000 + seconds
    assert all(call.kwargs["url"] == TARGET for call in probe.call_args_list)
    assert router.resolve_active("proton") != profile
    assert not router.is_cooled_down(
        "cloudflare", router.persisted_active("cloudflare")
    )

    monkeypatch.setattr(
        router, "probe_egress", Mock(return_value=outcome(None, 200))
    )
    assert router.rotate("proton", reason="timeout", automatic=True) == 0
    assert router.persisted_active("proton") != profile
    assert int(marker.read_text()) == 10000 + seconds
    assert router.rotate("proton", automatic=True) == 0
    assert router.persisted_active("proton") != profile
    assert router.persisted_active("cloudflare").stem == "a"


@pytest.mark.parametrize("status", [200, 401, 403, 429, 500, 503])
@pytest.mark.parametrize("method", ["probe_profile", "check_egress_live"])
def test_http_response_resets_tls_streak(
    lane, monkeypatch, status, method
):
    router, profile = lane
    check = getattr(router, method)
    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome()))
    check("proton", profile)

    monkeypatch.setattr(
        router, "probe_egress", Mock(return_value=outcome(TLS, status))
    )
    verdict, record = check("proton", profile)
    assert verdict != "dead"
    assert record["tls_fails"] == 0

    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome()))
    verdict, _ = check("proton", profile)
    if method == "check_egress_live":
        assert verdict == "degraded"
    assert not router.is_cooled_down("proton", profile)


def test_target_and_profile_changes_do_not_combine_tls_strikes(lane, monkeypatch):
    router, profile = lane
    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome()))

    for target in (TARGET, TARGET + "/other", TARGET):
        verdict, record = router.check_egress_live("proton", profile, url=target)
        assert verdict == "degraded"
        assert record["tls_fails"] == 1

    other = profile.with_name("b.conf")
    verdict, record = router.check_egress_live("proton", other)
    assert verdict == "degraded"
    assert record["tls_fails"] == 1
    assert not router.is_cooled_down("proton", other)


@pytest.mark.parametrize("recover", [True, False])
@pytest.mark.parametrize("threshold", [1, 2])
def test_settle_window_defers_tls_quarantine(
    lane, monkeypatch, recover, threshold
):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 2
    router._egress_settings["fail_threshold"] = threshold
    clock = [0.0]
    monkeypatch.setattr(router.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        router.time,
        "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    calls = []

    def probe(**kwargs):
        assert not router.is_cooled_down("proton", profile)
        calls.append(kwargs)
        return outcome(None, 200) if recover and len(calls) == 4 else outcome()

    monkeypatch.setattr(router, "probe_egress", probe)
    ok, _ = router._probe_with_settle("proton", profile)
    assert ok is recover
    assert len(calls) >= 4
    assert router.is_cooled_down("proton", profile) is (not recover)


def test_live_single_tls_blip_recovers_on_existing_retry(lane, monkeypatch):
    router, profile = lane
    probe = Mock(side_effect=[outcome(), outcome(None, 200)])
    monkeypatch.setattr(router, "probe_egress", probe)
    verdict, _ = router.check_egress_live("proton", profile)
    assert verdict == "alive"
    assert probe.call_count == 2
    assert not router.is_cooled_down("proton", profile)


@pytest.mark.parametrize("failed_provider", ["proton", "cloudflare"])
def test_automatic_check_reports_only_actual_dead_provider(
    lane, monkeypatch, capsys, failed_provider
):
    router, profile = lane
    failed_target = router.probe_url_for(failed_provider)

    def probe(*, url, **kwargs):
        return outcome() if url == failed_target else outcome(None, 200)

    monkeypatch.setattr(router, "probe_egress", probe)
    assert router.egress_check(as_json=True) == 0
    capsys.readouterr()
    assert router.egress_check(as_json=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["dead"] == [failed_provider]
    assert report["results"][failed_provider]["profile"] == profile.stem
    healthy = "cloudflare" if failed_provider == "proton" else "proton"
    assert report["results"][healthy]["status"] == "alive"
    assert not router.is_cooled_down(
        healthy, router.persisted_active(healthy)
    )
    assert router.egress_check(as_json=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["results"][failed_provider]["profile"] == "a"
    assert not router.read_egress(
        failed_provider, router.provider_dir(failed_provider) / "b.conf"
    )


@pytest.mark.parametrize("action", ["cooldown", "exhaust", "block"])
def test_tls_uses_configured_threshold_and_policy_action(
    lane, monkeypatch, action
):
    router, profile = lane
    router._egress_settings["fail_threshold"] = 3
    router._providers["proton"]["error_policy"] = {
        "tls": {"action": action, "seconds": 777}
    }
    router.write_egress("proton", profile, {"fails": 73})
    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome()))

    for strike in (1, 2, 3):
        verdict, record = router.check_egress_live("proton", profile)
        assert record["tls_fails"] == strike
        assert (verdict == "dead") is (strike == 3)
        assert router.is_cooled_down("proton", profile) is (strike == 3)

    persisted = router.read_egress("proton", profile)
    assert persisted["upstream_error"] == "tls"
    assert persisted.get("exhausted", False) is (action == "exhaust")
    assert router.egress_is_blocked("proton", profile) is (action == "block")


@pytest.mark.parametrize("mismatch", ["target", "provider", "newer-http-error"])
def test_automatic_timeout_does_not_borrow_unrelated_tls_policy(
    lane, monkeypatch, mismatch
):
    router, profile = lane
    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome()))
    router.check_egress_live("proton", profile)
    router.check_egress_live("proton", profile)

    provider = "proton"
    if mismatch == "target":
        router._providers["proton"]["probe_url"] = TARGET + "/other"
    elif mismatch == "provider":
        provider = "cloudflare"
    else:
        router._apply_upstream_failure("proton", profile, "429", 60)

    current = router.persisted_active(provider)
    monkeypatch.setattr(
        router, "probe_egress", Mock(return_value=outcome(None, 200))
    )
    assert router.rotate(provider, reason="timeout", automatic=True) == 0
    assert router.read_egress(provider, current)["upstream_error"] == "timeout"
