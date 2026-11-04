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


# ---------------------------------------------------------------------------
# Proxy-backed providers: the scenario in #219 itself
#
# These deliberately do NOT stub provider_files(). A SOCKS5 provider has no
# *.conf profiles; its health records key off proxy_profile_key(), and the
# earlier version of this fix reported "not exhausted" for every proxy
# provider because provider_files() raised on the provider directory.
# ---------------------------------------------------------------------------

@pytest.fixture
def proxy_controller(tmp_path):
    r = load_router(tmp_path)
    r._providers = {
        "warp": {"fallback_providers": ["cloudflare", "proton"]},
        "cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}},
        "proton": {},
    }
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda profile: None
    return r


def _mark_proxy_exhausted(r, name, *, until=None):
    del r._providers[name]["socks5"]  # keep the provider looking proxy-backed
    _mark_exhausted(r, name, r.proxy_profile_key(name), until=until)
    r._providers[name]["socks5"] = {"host": "127.0.0.1", "port": 2181}


def test_proxy_provider_has_no_real_conf_profiles(proxy_controller):
    """Pin the premise the fix depends on.

    A SOCKS5 provider carries no *.conf. Depending on whether ROOT and the
    provider directory resolve consistently, provider_files() returns [] or
    raises; both are "no enumerable profiles", and both previously read as
    "not quota-exhausted" for the provider #219 is about.
    """
    r = proxy_controller
    assert r.is_proxy_provider("cloudflare")
    assert r.proxy_profile_key("cloudflare").stem == "socks"
    try:
        assert r.provider_files("cloudflare") == []
    except ValueError:
        pass  # the other shape of "no enumerable profiles"


def test_exhausted_proxy_provider_is_skipped(proxy_controller):
    r = proxy_controller
    _mark_exhausted(r, "cloudflare", r.proxy_profile_key("cloudflare"), until=_FUTURE)

    assert r.provider_quota_exhausted("cloudflare")
    # proton has no profiles and no records: eligible, but has no valid exit
    # either, so activation fails cleanly rather than parking on cloudflare.
    assert r.activate_fallback("warp") != 0
    assert r.active_fallback("warp") is None


def test_unexhausted_proxy_provider_activates(proxy_controller):
    r = proxy_controller
    _mark_exhausted(r, "cloudflare", r.proxy_profile_key("cloudflare"), until=_PAST)

    assert not r.provider_quota_exhausted("cloudflare")
    assert r.activate_fallback("warp", target="cloudflare") == 0
    assert r.active_fallback("warp") == "cloudflare"


def test_proxy_provider_with_no_egress_record_is_eligible(proxy_controller):
    r = proxy_controller
    assert not r.provider_quota_exhausted("cloudflare")
    assert r.activate_fallback("warp", target="cloudflare") == 0


def test_proxy_marker_without_deadline_stays_blocking(proxy_controller):
    """Fail closed: a malformed marker must not hand a dead exit back."""
    r = proxy_controller
    _mark_exhausted(r, "cloudflare", r.proxy_profile_key("cloudflare"), until=None)

    assert r.provider_quota_exhausted("cloudflare")
    assert r.activate_fallback("warp") != 0
    assert r.active_fallback("warp") is None
