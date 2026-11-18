"""#216 item 1: a generic 200 must not hide a stalled model path. When the relay
recovers a response-header stall it writes upstream_error='timeout' on the exit;
that fresh evidence must mark the lane degraded even though ok=true.
"""
import time

import egress


def test_fresh_model_stall_timeout_is_degraded_even_when_ok():
    rec = {"ok": True, "status": 200, "checked_at": int(time.time()),
           "upstream_error": "timeout", "upstream_error_at": int(time.time())}
    assert egress.fresh_failure(rec, int(time.time()), 86400) is True
    assert egress.usable_evidence(rec, int(time.time()), 86400) is False


def test_stale_model_stall_timeout_is_not_degraded():
    old = int(time.time()) - 3 * 86400
    rec = {"ok": True, "status": 200, "checked_at": int(time.time()),
           "upstream_error": "timeout", "upstream_error_at": old}
    assert egress.fresh_failure(rec, int(time.time()), 86400) is False


def test_quota_429_upstream_error_unchanged():
    # A 429 upstream error stays on the quota axis, not a model-stall degrade.
    rec = {"ok": True, "status": 200, "checked_at": int(time.time()),
           "upstream_error": "429", "upstream_error_at": int(time.time())}
    assert egress.fresh_failure(rec, int(time.time()), 86400) is False


def test_degraded_detail_names_model_stall():
    rec = {"ok": True, "status": 200, "checked_at": int(time.time()),
           "upstream_error": "timeout", "upstream_error_at": int(time.time())}
    detail = egress.degraded_detail(rec, int(time.time()), 86400)
    assert "model" in detail.lower() or "stall" in detail.lower(), detail
