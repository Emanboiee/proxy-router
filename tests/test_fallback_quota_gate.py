"""Fallback activation must weigh live quota, not only static profile validity.

Issue #219: ``activate_fallback`` called ``provider_has_valid_exit`` only. For a
proxy-backed provider that is a static ``proxy_upstream()`` parse, so a provider
whose egress record was quota-exhausted still counted as a viable candidate. The
route then parked on an exit that could not serve traffic.
"""
import json
import time
from unittest import mock
import pytest
from tests.test_router_regressions import load_router


# Wall-clock deadlines: the marker compares against time.time(), not a monotonic clock.
_FUTURE = int(time.time()) + 86_400
_PAST = int(time.time()) - 86_400


@pytest.fixture
def controller(tmp_path):
    r = load_router(tmp_path)
    proton = tmp_path / "proton-a.conf"
    cloudflare = tmp_path / "cloudflare-a.conf"
    r._providers = {"warp": {"fallback_providers": ["proton", "cloudflare"]},
                    "proton": {}, "cloudflare": {}}
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda profile: None
    files = {"proton": [proton], "cloudflare": [cloudflare]}
    r.provider_files = lambda name: files.get(name, [])
    return r, files


def _mark_exhausted(r, name, profile, *, until=None):
    path = r.egress_record_path(name, profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"exhausted": True}
    if until is not None:
        record["exhausted_until"] = r._iso_ts(until)
    path.write_text(json.dumps(record))


def test_exhausted_provider_is_skipped_for_the_next_candidate(controller):
    r, files = controller
    _mark_exhausted(r, "proton", files["proton"][0], until=_FUTURE)

    assert r.activate_fallback("warp") == 0
    assert r.active_fallback("warp") == "cloudflare"


def test_exhausted_provider_is_rejected_when_only_candidate(controller):
    r, files = controller
    _mark_exhausted(r, "proton", files["proton"][0], until=_FUTURE)

    assert r.activate_fallback("warp", target="proton") != 0
    assert r.active_fallback("warp") is None
    r.engine_reload.assert_not_called()


def test_expired_quota_marker_does_not_block_activation(controller):
    r, files = controller
    _mark_exhausted(r, "proton", files["proton"][0], until=_PAST)

    assert r.activate_fallback("warp", target="proton") == 0
    assert r.active_fallback("warp") == "proton"


def test_provider_without_egress_records_is_not_blocked(controller):
    r, _files = controller
    assert not r.provider_quota_exhausted("proton")
    assert r.activate_fallback("warp", target="proton") == 0


def test_one_unexhausted_profile_keeps_a_wireguard_pool_eligible(controller, tmp_path):
    r, files = controller
    second = tmp_path / "proton-b.conf"
    files["proton"] = [files["proton"][0], second]
    _mark_exhausted(r, "proton", files["proton"][0], until=_FUTURE)

    assert not r.provider_quota_exhausted("proton")
    assert r.activate_fallback("warp", target="proton") == 0


def test_every_profile_exhausted_blocks_a_wireguard_pool(controller, tmp_path):
    r, files = controller
    second = tmp_path / "proton-b.conf"
    files["proton"] = [files["proton"][0], second]
    _mark_exhausted(r, "proton", files["proton"][0], until=_FUTURE)
    _mark_exhausted(r, "proton", second, until=_FUTURE)

    assert r.provider_quota_exhausted("proton")
    assert r.activate_fallback("warp") == 0
    assert r.active_fallback("warp") == "cloudflare"


def test_direct_candidate_is_never_quota_gated(controller):
    r, _files = controller
    r._providers["warp"]["fail_open_direct"] = True
    for name in ("proton", "cloudflare"):
        r.provider_files = lambda n: _files.get(n, [])
    _mark_exhausted(r, "proton", _files["proton"][0], until=_FUTURE)
    _mark_exhausted(r, "cloudflare", _files["cloudflare"][0], until=_FUTURE)

    assert r.activate_fallback("warp") == 0
    assert r.active_fallback("warp") == "direct"
