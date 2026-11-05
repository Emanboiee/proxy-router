"""Fallback activation must weigh live quota, not only static profile validity.

Issue #219: ``activate_fallback`` called ``provider_has_valid_exit`` only. For a
proxy-backed provider that is a static ``proxy_upstream()`` parse, so a provider
whose egress record was quota-exhausted still counted as a viable candidate. The
route then parked on an exit that could not serve traffic.
"""
import contextlib
import io
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


def _mark_exhausted(r, name, profile, *, until=None, checked_at=None):
    path = r.egress_record_path(name, profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"exhausted": True,
              "checked_at": int(time.time()) if checked_at is None else checked_at}
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
    # Register "direct" WITH an exhausted record: without the != "direct"
    # exclusion this would activate nothing instead of going direct.
    r._providers["direct"] = {}
    direct_profile = _files["proton"][0].parent / "direct.conf"
    r.provider_files = lambda n: _files.get(n, [direct_profile] if n == "direct" else [])
    _mark_exhausted(r, "direct", direct_profile, until=_FUTURE)
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


def test_exhausted_only_candidate_reports_quota_not_bad_profile(proxy_controller):
    """The failure message must name the real reason.

    A candidate with a valid socks5 upstream that was rejected for quota is not
    a "no valid profile" case; reporting it as one sends operators to the wrong
    config.
    """
    r = proxy_controller
    r._providers["warp"]["fallback_providers"] = ["cloudflare"]
    _mark_exhausted(r, "cloudflare", r.proxy_profile_key("cloudflare"), until=_FUTURE)

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert r.activate_fallback("warp") != 0
    assert "no fallback candidate has a valid profile" not in err.getvalue()
    assert "quota-exhausted" in err.getvalue()


def test_unparseable_profile_does_not_disable_the_gate(controller):
    """One malformed *.conf must not make an exhausted provider look eligible.

    provider_has_valid_exit() uses any() over parseable profiles, so the
    provider still has a valid exit. If all() also counted the bad profile
    (which has no egress record), the whole gate would be skipped.
    """
    r, files = controller
    bad = files["proton"][0].parent / "proton-b.conf"
    files["proton"] = [files["proton"][0], bad]
    r._profile_error = lambda p: "bad config" if p == bad else None
    _mark_exhausted(r, "proton", files["proton"][0], until=_FUTURE)

    assert r.provider_has_valid_exit("proton")
    assert r.provider_quota_exhausted("proton")
    assert r.activate_fallback("warp") == 0
    assert r.active_fallback("warp") == "cloudflare"


def test_invalid_stem_does_not_raise_from_activation(controller):
    """A *.conf whose stem cannot form a record path must not crash recovery.

    WireGuard exports are commonly named "US East.conf"; README:124 tells
    users to drop *.conf files into the provider directory. This worked before
    the gate was added.
    """
    r, files = controller
    weird = files["proton"][0].parent / "bad name.conf"
    files["proton"] = [weird]
    r._profile_error = lambda p: None

    assert r.provider_quota_exhausted("proton") is False
    assert r.activate_fallback("warp", target="proton") == 0


def test_nested_chain_is_gated_by_its_effective_leaf(tmp_path):
    """warp -> proton -> proton2: the exhausted leaf must reject activation."""
    r = load_router(tmp_path)
    conf = tmp_path / "proton.conf"
    conf.write_text("x")
    r._providers = {
        "warp": {"fallback_providers": ["proton"]},
        "proton": {"fallback_providers": ["proton2"]},
        "proton2": {"socks5": {"host": "127.0.0.1", "port": 2181}},
    }
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda p: None
    r.provider_files = lambda n: [conf] if n == "proton" else []
    assert r.activate_fallback("proton", target="proton2") == 0
    assert r._effective_route_provider("proton") == "proton2"

    _mark_exhausted(r, "proton2", r.proxy_profile_key("proton2"), until=_FUTURE)
    assert r.activate_fallback("warp") != 0
    assert r.active_fallback("warp") is None


def test_restore_reinstates_fallback_without_being_quota_gated(tmp_path):
    """restore_fallback() deactivates before probing, then re-activates the
    SAME serving fallback. That reinstatement is not a fresh candidate choice;
    gating it would strand the route on a dead primary with the marker gone.
    """
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.probe_egress = mock.Mock(return_value={"status": 200})
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda p: None
    r.RESTORE_COOLDOWN_SECONDS = 0

    assert r.activate_fallback("warp", target="proton", reason="confirmed-stall") == 0
    assert r.active_fallback("warp") == "proton"
    _mark_exhausted(r, "proton", profile, until=_FUTURE)

    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    assert r.active_fallback("warp") == "proton"


def test_proxy_gate_works_without_stubbing_profile_error(tmp_path):
    """Regression for the round-3 fix that reintroduced the round-1 blocker.

    proxy_profile_key() is a synthetic Path("socks.conf") with no file on
    disk, so the real _profile_error() rejects it. Filtering proxy keys
    through _profile_error made the gate a no-op for EVERY proxy provider.
    Every other proxy test stubs _profile_error, which is what hid this.
    """
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["cloudflare"]},
                    "cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    # Deliberately no r._profile_error stub: use the real implementation.
    key = r.proxy_profile_key("cloudflare")
    assert r._profile_error(key) is not None  # synthetic key has no file
    _mark_exhausted(r, "cloudflare", key, until=_FUTURE)

    assert r.provider_quota_exhausted("cloudflare") is True
    assert r.activate_fallback("warp") != 0
    assert r.active_fallback("warp") is None


def test_nested_chain_ending_in_direct_is_not_quota_gated(tmp_path):
    """A leaf resolving to "direct" has no egress record to exhaust.

    "direct" is a sentinel, not a provider with quota. A config may also
    legitimately name a provider "direct"; either way the leaf must not be
    gated, or a healthy chain can never fail over.
    """
    r = load_router(tmp_path)
    conf = tmp_path / "proton.conf"
    conf.write_text("x")
    direct_conf = tmp_path / "direct.conf"
    r._providers = {
        "warp": {"fallback_providers": ["proton"]},
        "proton": {"fallback_providers": ["direct"]},
        "direct": {},
    }
    r.current_mode = lambda: "proxy"
    r.engine_reload = mock.Mock(return_value=0)
    r._profile_error = lambda p: None
    r.provider_files = lambda n: ([conf] if n == "proton" else
                                  [direct_conf] if n == "direct" else [])
    assert r.activate_fallback("proton", target="direct") == 0
    assert r._effective_route_provider("proton") == "direct"

    _mark_exhausted(r, "direct", direct_conf, until=_FUTURE)
    assert r.provider_quota_exhausted("direct") is True
    assert r.activate_fallback("warp", target="proton") == 0
    assert r.active_fallback("warp") == "proton"


def test_stale_clean_record_does_not_certify_a_fallback(proxy_controller):
    """#219's incident: exhausted=false, ok=true, checked_at weeks old.

    quota_active() returns False for this shape, so the original gate could
    not reject it. A record outside ok_window is unknown, not healthy.
    """
    r = proxy_controller
    key = r.proxy_profile_key("cloudflare")
    path = r.egress_record_path("cloudflare", key)
    path.parent.mkdir(parents=True, exist_ok=True)
    stale = int(time.time()) - 29 * 86400
    path.write_text(json.dumps({
        "ok": True, "exhausted": False, "checked_at": stale,
        "last_ok_at": stale, "status": 200, "fails": 0,
    }))
    assert not r.egress_is_exhausted("cloudflare", key)  # clean, but stale
    assert r.provider_quota_exhausted("cloudflare") is True
    assert r.activate_fallback("warp") != 0
    assert r.active_fallback("warp") is None


def test_fresh_clean_record_stays_eligible(proxy_controller):
    """A current clean probe is real evidence and must still allow failover."""
    r = proxy_controller
    key = r.proxy_profile_key("cloudflare")
    path = r.egress_record_path("cloudflare", key)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    path.write_text(json.dumps({
        "ok": True, "exhausted": False, "checked_at": now,
        "last_ok_at": now, "status": 200,
    }))
    assert r.provider_quota_exhausted("cloudflare") is False
    assert r.activate_fallback("warp", target="cloudflare") == 0
