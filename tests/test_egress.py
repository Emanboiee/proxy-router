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

