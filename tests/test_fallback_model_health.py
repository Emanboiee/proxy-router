"""#219: a generic HTTP 200 is not proof that the model path has quota.

The incident: recover_route()/restore_fallback() probed https://opencode.ai/
(root, 200) and declared the model lane recovered while the model endpoint
returned 429. A 429 must never count as model-path health.
"""
import json
from unittest import mock

import egress
from tests.test_router_regressions import load_router


def test_exhaust_marker_clears_stale_ok(tmp_path):
    """#219 item 4: a 429 quota exhaust must not leave ok=true alongside
    exhausted=true — status/scripts would read a dead lane as healthy."""
    from pathlib import Path
    r = load_router(tmp_path)
    prof = Path("socks")
    r.record_egress("cloudflare", prof, ok=True, status=200)
    r._providers = {"cloudflare": {"error_policy": {"429": {"action": "exhaust", "seconds": 900}}}}
    r._apply_upstream_failure("cloudflare", prof, "429", 900)
    rec = r.read_egress("cloudflare", prof)
    assert rec.get("exhausted") is True
    assert rec.get("ok") is False


def test_probe_healthy_rejects_429_even_with_200_status():
    """A probe result carrying a quota error is not healthy, regardless of status."""
    assert egress.probe_is_model_healthy({"status": 200, "error": "rate-limit-429"}) is False
    assert egress.probe_is_model_healthy({"status": 429, "error": "rate-limit-429"}) is False


def test_429_with_1010_label_is_not_model_healthy():
    """CodeRabbit: a 429 body with 'error code: 1010' classifies as cloudflare-1010
    but is still a quota signal; must be rejected independent of the label."""
    err, block = egress.probe_failure_reason(429, '{"error":"error code: 1010"}')
    assert err == "cloudflare-1010", (err, block)
    assert egress.probe_is_model_healthy({"status": 429, "error": err}) is False


def test_probe_healthy_accepts_clean_2xx():
    assert egress.probe_is_model_healthy({"status": 200, "error": None}) is True
    assert egress.probe_is_model_healthy({"status": 204, "error": None}) is True


def test_probe_healthy_rejects_no_status():
    assert egress.probe_is_model_healthy({"status": None, "error": "connection refused"}) is False
    assert egress.probe_is_model_healthy(None) is False


def test_recovery_probes_model_path_not_root(tmp_path):
    """#219: recovery must probe /zen/v1/models, not https://host/ root."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": False},
                    "proton": {}}
    r._routes = [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.response_provider_for_host = lambda host: "warp"
    r._diagnostic_host_is_routed = lambda host: True
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda p: None
    r.probe_egress = mock.Mock(return_value={"status": 200, "error": None,
                                             "latency_ms": 5.0, "block_reason": None})
    r.recover_route("warp", "opencode.ai")
    urls = [c.kwargs.get("url") for c in r.probe_egress.call_args_list]
    assert any(u and "/zen/v1/models" in u for u in urls), urls


def test_trailing_dot_host_still_probes_model_path(tmp_path):
    """Security seat: 'opencode.ai.' must normalize to the model path."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": False},
                    "proton": {}}
    r._routes = [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.response_provider_for_host = lambda host: "warp"
    r._diagnostic_host_is_routed = lambda host: True
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda p: None
    r.probe_egress = mock.Mock(return_value={"status": 429, "error": "rate-limit-429",
                                             "latency_ms": 5.0, "block_reason": None})
    r.recover_route("warp", "opencode.ai.")
    urls = [c.kwargs.get("url") for c in r.probe_egress.call_args_list]
    assert any(u and "/zen/v1/models" in u for u in urls), urls


def test_recover_route_does_not_confirm_recovery_on_model_429(tmp_path):
    """recover_route must not return 'already reachable' when the only HTTP
    response is a model-path 429 — that is the exact #219 incident shape."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": False},
                    "proton": {}}
    r._routes = [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.response_provider_for_host = lambda host: "warp"
    r._diagnostic_host_is_routed = lambda host: True
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda p: None
    # The probe returns a 200 status but the model path carries a 429 quota error.
    r.probe_egress = mock.Mock(return_value={"status": 200, "error": "rate-limit-429",
                                             "latency_ms": 5.0, "block_reason": None})
    result = r.recover_route("warp", "opencode.ai")
    # A model 429 is not recovery: must proceed past the immediate reachable() return.
    assert result != 0
