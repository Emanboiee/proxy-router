"""Cold exits get a grace window; HTTP policy outcomes remain immediate."""
from unittest.mock import Mock

import pytest

from tests.test_tls_failover import lane, outcome


def fake_clock(router, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(router.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(router.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    return clock


@pytest.mark.parametrize("error", ["curl(35): SSL_ERROR_SYSCALL", "curl(7): connection reset"])
@pytest.mark.parametrize("ready_at", [5.0, 16.0])
def test_cold_exit_recovers_without_a_premature_cooldown(lane, monkeypatch, error, ready_at):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 20
    clock = fake_clock(router, monkeypatch)
    monkeypatch.setattr(router, "egress_dns_probe", Mock(return_value=True))

    def probe(**kwargs):
        assert not router.is_cooled_down("proton", profile)
        clock[0] += .25
        return outcome(None, 200) if clock[0] >= ready_at else outcome(error)

    monkeypatch.setattr(router, "probe_egress", probe)
    ok, record = router._probe_with_settle("proton", profile)
    assert ok and record["ok"]
    assert ready_at <= clock[0] <= ready_at + 3
    assert not router.is_cooled_down("proton", profile)


@pytest.mark.parametrize("error", ["curl(35): SSL_ERROR_SYSCALL", "curl(7): connection reset"])
def test_persistent_transport_failure_cools_only_after_the_window(lane, monkeypatch, error):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 4
    clock = fake_clock(router, monkeypatch)
    monkeypatch.setattr(router, "egress_dns_probe", Mock(return_value=True))

    def probe(**kwargs):
        assert clock[0] < 4
        assert not router.is_cooled_down("proton", profile)
        return outcome(error)

    monkeypatch.setattr(router, "probe_egress", probe)
    ok, _ = router._probe_with_settle("proton", profile)
    assert not ok
    assert clock[0] == 4
    assert router.is_cooled_down("proton", profile)


@pytest.mark.parametrize("status,error", [(429, "rate-limit-429"), (503, "HTTP 503")])
def test_http_failure_does_not_spend_a_wireguard_settle_window(lane, monkeypatch, status, error):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 60
    clock = fake_clock(router, monkeypatch)
    probe = Mock(return_value=outcome(error, status))
    monkeypatch.setattr(router, "probe_egress", probe)
    ok, _ = router._probe_with_settle("proton", profile)
    assert not ok
    assert probe.call_count == 1
    assert clock[0] == 0
    if status == 429:
        assert router.is_cooled_down("proton", profile)
        assert router.read_egress("proton", profile)["exhausted"]


def test_retry_io_is_capped_and_no_probe_starts_at_the_deadline(lane, monkeypatch):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 3
    clock = fake_clock(router, monkeypatch)
    budgets = []

    def probe(**kwargs):
        budgets.append(kwargs["timeout"])
        assert clock[0] < 3
        clock[0] += min(1, kwargs["timeout"])
        return outcome()

    monkeypatch.setattr(router, "probe_egress", probe)
    ok, _ = router._probe_with_settle("proton", profile)
    assert not ok
    assert budgets == [3, 1.5]
    assert clock[0] == 3


def test_initial_probe_can_consume_the_entire_settle_budget(lane, monkeypatch):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 4
    clock = fake_clock(router, monkeypatch)
    calls = []

    def probe(**kwargs):
        calls.append(kwargs)
        clock[0] += kwargs.get("timeout", 8)
        return outcome()

    monkeypatch.setattr(router, "probe_egress", probe)
    ok, _ = router._probe_with_settle("proton", profile)
    assert not ok
    assert len(calls) == 1
    assert clock[0] == 4


def test_truncated_http_response_still_gets_a_transport_retry(lane, monkeypatch):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 4
    fake_clock(router, monkeypatch)
    probe = Mock(side_effect=[outcome("curl(18): incomplete response", 200), outcome(None, 200)])
    monkeypatch.setattr(router, "probe_egress", probe)
    assert router._probe_with_settle("proton", profile)[0]
    assert probe.call_count == 2


def test_settle_log_describes_polling_not_a_fixed_sleep(lane, monkeypatch, capsys):
    router, profile = lane
    router._egress_settings["probe_settle_seconds"] = 20
    fake_clock(router, monkeypatch)
    monkeypatch.setattr(router, "probe_egress", Mock(side_effect=[outcome(), outcome(None, 200)]))
    assert router._probe_with_settle("proton", profile)[0]
    message = capsys.readouterr().err
    assert "up to 20s" in message
    assert "retrying once after" not in message


@pytest.mark.parametrize("dns_ok", [None, False])
def test_old_dns_success_cannot_cool_an_inconclusive_connection_failure(lane, monkeypatch, dns_ok):
    router, profile = lane
    router.record_egress("proton", profile, ok=False, status=None,
                         error="connection reset", dns_ok=True)
    router._egress_settings["probe_settle_seconds"] = 2
    fake_clock(router, monkeypatch)
    monkeypatch.setattr(router, "probe_egress", Mock(return_value=outcome("connection reset")))
    monkeypatch.setattr(router, "egress_dns_probe", Mock(return_value=dns_ok))
    ok, record = router._probe_with_settle("proton", profile)
    assert not ok
    assert record.get("dns_ok") is dns_ok
    assert not router.is_cooled_down("proton", profile)
