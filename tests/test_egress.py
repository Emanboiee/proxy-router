"""Contract tests for the dependency-free egress classification seam."""

import egress


def test_transport_reason_distinguishes_tls_from_connection_failures():
    assert egress.transport_reason("curl(35): SSL connection reset") == "tls"
    assert egress.transport_reason("curl(7): connection refused") == "connection"


def test_probe_failure_reason_preserves_block_and_rate_limit_policy():
    assert egress.probe_failure_reason(403, "cloudflare error") == (
        "cloudflare-403",
        "cloudflare-403",
    )
    assert egress.probe_failure_reason(429, "upstream quota") == (
        "rate-limit-429",
        None,
    )
    assert egress.probe_failure_reason(200, "ok") == (None, None)


def test_dns_error_markers_are_case_insensitive_and_narrow():
    assert egress.dns_error_markers("Temporary failure in name resolution")
    assert egress.dns_error_markers("certificate verify failed") is False


def test_egress_rank_prefers_fast_fresh_ok_and_penalizes_live_failures():
    now = 1_000_000
    fresh = {"last_ok_at": now - 10, "checked_at": now - 10}
    limits = {"ok_window": 86400, "slow_latency_ms": 1200, "fail_threshold": 2}
    fast = dict(fresh, ok=True, latency_ms=120)
    slow = dict(fresh, ok=True, latency_ms=5000)
    failing = {"ok": False, "fails": 3, "checked_at": now - 10}
    assert egress.egress_rank(fast, now=now, **limits)[0] == 0
    assert egress.egress_rank(slow, now=now, **limits)[0] == 2
    assert egress.egress_rank(failing, now=now, **limits)[0] == 3
    assert egress.egress_rank({}, now=now, **limits) == (1, float("inf"))


def test_egress_rank_expires_stale_failure_streaks():
    now = 1_000_000
    stale = {"ok": False, "fails": 5, "checked_at": now - 200_000}
    assert egress.egress_rank(
        stale, now=now, ok_window=86400, slow_latency_ms=1200, fail_threshold=2
    )[0] == 1


def test_egress_rank_treats_malformed_persisted_values_as_unknown():
    now = 1_000_000
    limits = {"ok_window": 86400, "slow_latency_ms": 1200, "fail_threshold": 2}
    malformed_records = (
        {"ok": False, "fails": 3, "checked_at": "not-an-epoch"},
        {"ok": False, "fails": "not-a-count", "checked_at": now - 10},
        {"ok": True, "last_ok_at": "not-an-epoch", "checked_at": now - 10},
    )
    for record in malformed_records:
        assert egress.egress_rank(record, now=now, **limits) == (1, float("inf"))


def test_lru_key_prefers_oldest_and_treats_never_used_as_first():
    assert egress.lru_key({"last_ok_at": 100}) == 100
    assert egress.lru_key({"checked_at": 50}) == 50
    assert egress.lru_key({}) == 0
