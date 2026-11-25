"""Fallback restoration must target the provider whose fallback is active.

Two independent defects kept a stalled lane from ever recovering:

* the controller's ``restore_fallback`` refused anything that was not a *direct*
  fallback, so a deliberate ``proton -> cloudflare`` fallback could never be
  undone -- every attempt was rejected by the ``!= "direct"`` guard before a
  single probe ran;
* the watcher asked the controller to restore ``last_provider``, the last
  outbound tag seen in the log. A fallback hop logs its OWN name, so the watcher
  named the fallback (the thing that already worked) instead of the route's
  provider (the thing that was stalled).

Both are pinned here, plus the compatibility case that ``direct`` still
restores exactly as before.

The attributed probe path (Option C) adds two more contracts: with a probe
inbound present for the parked provider, the fallback is NEVER removed to
measure -- the probe rides the parked provider's own inbound -- and an
automatic caller no longer defers. The legacy deferral/destructive cases stay
pinned for engines without that path (tun mode, pre-reload config).
"""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import route_watcher
from tests.test_proxy_provider import WG_ENDPOINT, write_conf
from tests.test_router_regressions import load_router


@pytest.fixture
def controller(tmp_path):
    """`warp` routes discord.com and falls back to the `proton` provider."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    r.probe_egress = mock.Mock(return_value={"status": None})
    r.egress_dns_probe = mock.Mock(return_value=True)
    r.engine_reload = mock.Mock(return_value=0)
    profile = tmp_path / "test.conf"
    r.provider_files = lambda name: [profile]
    r._profile_error = lambda profile: None
    return r


def _restore_marker(r):
    return r.ROOT / "state" / "recovery" / "warp-restore.json"


def _fallback_state(r):
    return (r.ROOT / "state" / "fallback" / "warp.json").read_bytes()


# --- the controller: any configured fallback is restorable ------------------

def test_nothing_to_restore_when_no_fallback_is_active(controller):
    r = controller
    assert r.active_fallback("warp") is None
    assert r.restore_fallback("warp", "discord.com") == 3
    r.probe_egress.assert_not_called()


def test_vpn_fallback_can_be_undone(controller):
    """The production shape: `warp -> proton` is active and the primary is
    healthy. Restoration must COMMIT back to `warp`; before the fix this
    returned 3 without probing anything."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com") == 1     # pending, still on proton
    assert r.probe_egress.call_count == 1
    assert r.active_fallback("warp") == "proton"
    marker = _restore_marker(r)
    marker.write_text(json.dumps({"attempted_at": 0, "successes": 1}))
    assert r.restore_fallback("warp", "discord.com") == 0     # committed
    assert r.active_fallback("warp") is None
    assert not marker.exists()


def test_unhealthy_primary_reinstates_the_same_vpn_fallback(controller):
    """A failed check must restore the fallback that was actually serving --
    never downgrade a deliberate VPN -> VPN fallback to direct."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "proton"
    assert json.loads(_restore_marker(r).read_text())["successes"] == 0


def test_direct_fallback_still_restores_exactly_as_before(controller):
    """Compatibility: the direct case is the previous-target-is-direct case."""
    r = controller
    assert r.activate_fallback("warp", target="direct") == 0
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"
    _restore_marker(r).write_text(json.dumps({"attempted_at": 0, "successes": 1}))
    assert r.restore_fallback("warp", "discord.com") == 0
    assert r.active_fallback("warp") is None


def test_direct_still_retained_when_the_primary_is_dead(controller):
    r = controller
    assert r.activate_fallback("warp", target="direct") == 0
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "direct"


# --- automatic restoration defers; only a deliberate call measures ----------

def test_automatic_restore_defers_and_touches_nothing(controller):
    """The primary is unmeasurable while a fallback serves.

    ``_effective_route_provider`` rewrites the provider wholesale, so every host
    of that provider resolves through the fallback: taking the fallback away is
    the ONLY way to measure the primary, and a supervisor must not do that to a
    working lane. Deferring must therefore leave every trace untouched.
    """
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    before = _fallback_state(r)
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate, \
            mock.patch.object(r, "engine_reload", return_value=0) as reload_engine:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 3
    deactivate.assert_not_called()
    reload_engine.assert_not_called()
    r.probe_egress.assert_not_called()
    assert r.active_fallback("warp") == "proton"
    assert _fallback_state(r) == before
    assert not _restore_marker(r).exists(), \
        "a deferral must not consume the deliberate attempt's cooldown"


def test_a_deferral_does_not_lock_out_a_deliberate_attempt(controller):
    """Deferrals are repeatable and free: the automatic path must never park the
    manual one behind its own cooldown."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    for _ in range(3):
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 3
    assert not _restore_marker(r).exists()
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com") == 1     # deliberate: measured
    r.probe_egress.assert_called_once()


def test_a_deliberate_restore_measures_with_the_fallback_out_of_the_way(controller):
    """The measurement that a deferral refuses to make. The probe must not run
    while the fallback is serving, or it would measure the fallback."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    seen = []

    def probe(**kwargs):
        seen.append((kwargs.get("url"), r.active_fallback("warp")))
        return {"status": 200}

    r.probe_egress.side_effect = probe
    with mock.patch.object(r, "engine_reload", return_value=0):
        assert r.restore_fallback("warp", "discord.com") == 1
    assert seen == [("https://discord.com/", None)], \
        "the deliberate path clears the fallback first and probes after"


def test_a_failed_deliberate_restore_still_reinstates_the_same_fallback(controller):
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    before = json.loads(_fallback_state(r))
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    with mock.patch.object(r, "engine_reload", return_value=0):
        assert r.restore_fallback("warp", "discord.com") == 1
    assert r.active_fallback("warp") == "proton"
    after = json.loads(_fallback_state(r))
    # The marker legitimately records WHY it came back (primary-unhealthy), so
    # this is a target assertion, not a byte one: what must never change is a
    # deliberate VPN -> VPN fallback being downgraded to direct.
    assert after["provider"] == before["provider"] == "proton"


def test_the_watcher_marks_its_restore_call_automatic(tmp_path):
    """The watcher is a supervisor: without the flag its call would measure."""
    argv = []

    def runner(args, **_kwargs):
        argv.append(args)
        return SimpleNamespace(returncode=3, stdout="", stderr="")

    result = route_watcher.restore_provider(tmp_path, "proton", "discord.com",
                                            runner=runner)
    assert result["returncode"] == 3
    assert argv[0][-1] == "--automatic", argv[0]


# --- the watcher: restore the route's provider, not the observed hop --------

def test_watcher_restores_the_route_provider_not_the_observed_fallback():
    """A fallback hop logs its own name. The watcher must still ask the
    controller to restore the ROUTE's provider, otherwise it names the fallback
    -- which is the thing already working -- and the stall never clears."""
    root = Path(tempfile.mkdtemp())
    try:
        w = route_watcher
        w.state_dir(root).mkdir(parents=True)
        (root / "router.json").write_text(json.dumps({
            "routes": [{"id": "discord", "domains": ["discord.com"],
                        "provider": "proton"}],
            "providers": {"proton": {"fallback_providers": ["cloudflare"]},
                          "cloudflare": {}},
            "routing": {"mode": "vpn-list", "vpn_domains": ["discord.com"]},
        }))
        # The outbound tag is the FALLBACK (cloudflare); the route provider is
        # proton, which is what a restore has to address.
        lines = [
            "ERROR using outbound/wireguard[cloudflare]: open connection to discord.com:443: connection reset\n",
        ]
        reads = [0]

        def fake_read(_path, offset):
            if reads[0] == 0:
                reads[0] += 1
                return offset, lines
            return offset, []

        def stop_after_tick(_seconds):
            w.enabled_file(root).unlink(missing_ok=True)

        with mock.patch.object(w, "engine_pid_alive", return_value=True), \
                mock.patch.object(w, "_read_new_lines", side_effect=fake_read), \
                mock.patch.object(w, "client_snapshot", return_value=[]), \
                mock.patch.object(w, "_network_check_hop"), \
                mock.patch.object(w, "probe_target", return_value={"ok": True}), \
                mock.patch.object(w, "restore_provider",
                                  return_value={"returncode": 3, "restored": False}) as restore:
            assert w.worker(root, interval=0.05, sleep=stop_after_tick) == 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
    restore.assert_called_once()
    assert restore.call_args.args[1] == "proton", \
        "restoration must target the route's provider, not the observed fallback hop"
    assert restore.call_args.args[2] == "discord.com"


# --- Option C: the attributed probe path -----------------------------------
#
# With a probe inbound for the parked provider present in the generated config,
# measurement runs THROUGH that inbound: the serving fallback is never removed,
# a failed check changes no routing bytes, and an automatic caller no longer
# defers. The legacy pins above still hold for engines without the path.

def _enable_attributed(r):
    """Give `warp` a probe inbound + matching endpoint in the config.

    Option C's P1 contract: a win may only be banked against an object that
    can be attributed to a profile, so the loaded probe endpoint must parse
    back to the fixture's single fake profile."""
    port = r.probe_port("warp")
    assert port is not None
    r.parse_wireguard = lambda path: copy.deepcopy(_PROBE_ENDPOINT)
    r.SING_BOX_CONFIG.write_text(json.dumps({
        "endpoints": [{"tag": "probe-warp", **copy.deepcopy(_PROBE_ENDPOINT)}],
        "inbounds": [{"type": "mixed", "tag": "probe-warp",
                      "listen": "127.0.0.1", "listen_port": port}],
    }))
    return port


# The dial identity the fake probe endpoint carries. The fixture's profile
# list is one fake path, so this parses back to that profile exactly.
_PROBE_ENDPOINT = {
    "type": "wireguard", "address": ["10.0.0.2/32"], "private_key": "x",
    "peers": [{"address": "192.0.2.1", "port": 51820,
               "public_key": "y", "allowed_ips": ["0.0.0.0/0"]}],
    "mtu": 1380,
}


def test_attributed_probe_measures_the_primary_while_the_fallback_serves(controller):
    """The whole point of Option C: the probe must ride the parked provider's
    own inbound, NOT the fallback, and the fallback must stay serving."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    port = _enable_attributed(r)
    seen = []

    def probe(**kwargs):
        seen.append((kwargs.get("url"), kwargs.get("port"), r.active_fallback("warp")))
        return {"status": 200}

    r.probe_egress.side_effect = probe
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    assert seen == [("https://discord.com/", port, "proton")], \
        "the probe must enter through the parked provider's inbound while the fallback serves"
    assert not deactivate.called, "a single win must never unpark the lane"


def test_attributed_restore_commits_after_two_wins_without_early_unpark(controller):
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed(r)
    before = _fallback_state(r)
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r, "engine_reload", return_value=0):
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
        assert r.active_fallback("warp") == "proton"       # still serving
        assert _fallback_state(r) == before                # bytes untouched
        payload = json.loads(_restore_marker(r).read_text())
        payload["attempted_at"] = 0
        _restore_marker(r).write_text(json.dumps(payload))
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 0
    assert r.active_fallback("warp") is None
    assert not _restore_marker(r).exists()


def test_attributed_failed_check_leaves_routing_bytes_untouched(controller):
    """A failed check must not clear OR re-arm anything: the fallback keeps
    serving and only the cooldown/evidence marker records the attempt."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    port = _enable_attributed(r)
    before = _fallback_state(r)
    r.probe_egress.return_value = {"status": None, "error": "timeout"}
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate, \
            mock.patch.object(r, "activate_fallback", return_value=0) as activate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
        # The attempt consumed the cooldown: a second call is a no-op.
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 3
    assert not deactivate.called
    assert not activate.called
    assert r.probe_egress.call_count == 1
    assert r.active_fallback("warp") == "proton"
    assert _fallback_state(r) == before
    assert r.probe_egress.call_args.kwargs.get("port") == port


def test_automatic_restore_without_a_named_host_resolves_one(controller):
    """The keepalive cannot know a domain; the controller resolves the
    provider's first routed host for the probe."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed(r)
    seen = []

    def probe(**kwargs):
        seen.append(kwargs.get("url"))
        return {"status": 200}

    r.probe_egress.side_effect = probe
    with mock.patch.object(r, "engine_reload", return_value=0):
        assert r.restore_fallback("warp", None, automatic=True) == 1
    assert seen == ["https://discord.com/"], \
        "routes name the host; the caller must not have to"


def test_legacy_automatic_deferral_still_holds_without_the_attributed_path(controller):
    """No probe inbound (tun mode / stale engine): the old contract stands --
    automatic callers defer and touch nothing."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    before = _fallback_state(r)
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 3
    assert not deactivate.called
    r.probe_egress.assert_not_called()
    assert _fallback_state(r) == before
    assert not _restore_marker(r).exists()


def test_restore_promotes_the_profile_the_probe_measured(tmp_path):
    """P1 (reviewer reproduction): a cooldown expiring between probe
    generation and the commit must NOT promote the freshly-warmed, unmeasured
    profile. The loaded probe endpoint belongs to `b`; the commit must
    explicitly promote `b` even though a fresh selection would now pick `a`."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    write_conf(tmp_path / "providers" / "warp", "a")
    write_conf(tmp_path / "providers" / "warp", "b")
    write_conf(tmp_path / "providers" / "proton", "p")
    r.provider_files = lambda name: sorted(
        (tmp_path / "providers" / name).glob("*.conf"))

    def parse(path):
        endpoint = copy.deepcopy(WG_ENDPOINT)
        endpoint["peers"][0]["address"] = ("192.0.2.10" if path.stem == "a"
                                           else "192.0.2.20")
        return endpoint

    r.parse_wireguard = parse
    # `a` is the persisted selection but is cooling down: build + probe must
    # fall through to `b`.
    state_dir = tmp_path / "state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "warp.active").write_text("a")
    cooldown_dir = state_dir / "cooldowns" / "warp"
    cooldown_dir.mkdir(parents=True, exist_ok=True)
    cooldown = cooldown_dir / "a.until"
    cooldown.write_text(str(int(time.time()) + 3600))
    r.engine_reload = mock.Mock(return_value=0)
    fallback_dir = state_dir / "fallback"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    (fallback_dir / "warp.json").write_text(
        json.dumps({"provider": "proton", "reason": "confirmed-stall"}))

    config, _selected = r.build_singbox_config()
    probe_endpoint = next(e for e in config["endpoints"] if e["tag"] == "probe-warp")
    assert probe_endpoint["peers"][0]["address"] == "192.0.2.20", \
        "with `a` cooled, the loaded probe must be `b`"
    r.SING_BOX_CONFIG.write_text(json.dumps(config))

    promoted = []

    def reload():
        fresh, chosen = r.build_singbox_config()
        promoted.append((chosen["warp"].stem,
                         next(e for e in fresh["endpoints"] if e["tag"] == "warp")
                         ["peers"][0]["address"]))
        return 0

    r.engine_reload = reload
    r.probe_egress = mock.Mock(return_value={"status": 200})

    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    marker = _restore_marker(r)
    assert json.loads(marker.read_text())["successes"] == 1
    # `a`'s cooldown expires while the SAME probe-only endpoint stays loaded.
    cooldown.unlink()
    payload = json.loads(marker.read_text())
    payload["attempted_at"] = 0
    marker.write_text(json.dumps(payload))

    assert r.restore_fallback("warp", "discord.com", automatic=True) == 0
    assert promoted == [("b", "192.0.2.20")], \
        "the promoted profile must be the one the probe measured, not the " \
        "freshly-warmed `a`"
    assert (state_dir / "warp.active").read_text() == "b", \
        "the measured profile must be persisted as the active selection"
    assert r.active_fallback("warp") is None


# --- evidence binding: never promote an object the probe did not measure ----

def test_attributed_restore_defers_when_the_probe_object_cannot_be_matched(controller):
    """A live check still banks a win, but the commit line refuses to act on
    evidence that cannot be mapped to a promotable profile: reset and keep the
    fallback serving (reviewer P1 fix)."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed(r)
    # The loaded endpoint parses back to NO profile (e.g. the file was
    # regenerated under the probe): nothing promotable can be bound to it.
    r.parse_wireguard = lambda path: {
        "type": "wireguard", "address": ["10.9.9.9/32"], "private_key": "z",
        "peers": [{"address": "203.0.113.9", "port": 1, "public_key": "z",
                   "allowed_ips": ["0.0.0.0/0"]}], "mtu": 1380}
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
        payload = json.loads(_restore_marker(r).read_text())
        assert payload["successes"] == 1          # the live check banked a win
        payload["attempted_at"] = 0
        _restore_marker(r).write_text(json.dumps(payload))
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    deactivate.assert_not_called()
    assert r.active_fallback("warp") == "proton"
    assert json.loads(_restore_marker(r).read_text())["successes"] == 0


def test_attributed_restore_resets_evidence_when_the_config_changes_mid_probe(controller):
    """A reload racing the check invalidates the verdict: the object measured
    is no longer the object loaded, so no win may be banked against it."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed(r)

    def probe(**kwargs):
        payload = json.loads(r.SING_BOX_CONFIG.read_text())
        payload["endpoints"][0]["peers"][0]["address"] = "192.0.2.99"
        r.SING_BOX_CONFIG.write_text(json.dumps(payload))
        return {"status": 200}

    r.probe_egress = mock.Mock(side_effect=probe)
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    deactivate.assert_not_called()
    assert r.active_fallback("warp") == "proton"
    assert json.loads(_restore_marker(r).read_text())["successes"] == 0


def test_attributed_restore_defers_when_the_measured_profile_disappears_mid_probe(controller):
    """P1 (reviewer round-5.1 reproduction): the loaded endpoint's source
    profile can vanish while the generated fingerprint stays unchanged. The
    post-probe check must revalidate the profile MAPPING too -- a vanished
    handle must never fall through to another selection, so no win may be
    banked and the fallback must keep serving."""
    r = controller
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed(r)
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    marker = _restore_marker(r)
    assert json.loads(marker.read_text())["successes"] == 1
    payload = json.loads(marker.read_text())
    payload["attempted_at"] = 0
    marker.write_text(json.dumps(payload))

    def probe(**kwargs):
        # The loaded tunnel still answers, but its source profile is gone: the
        # endpoint fingerprint cannot move, only the promotion handle can.
        r.provider_files = lambda name: []
        return {"status": 200}

    r.probe_egress = mock.Mock(side_effect=probe)
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate, \
            mock.patch.object(r, "engine_reload", return_value=0) as reload_engine:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    deactivate.assert_not_called()
    reload_engine.assert_not_called()
    assert r.active_fallback("warp") == "proton"
    assert json.loads(_restore_marker(r).read_text())["successes"] == 0


def test_attributed_restore_defers_when_the_promotion_build_cannot_use_the_measured_profile(tmp_path):
    """P1 (fail-closed promotion): even when the mapping and availability
    checks pass, the promoted configuration is built once more and must carry
    the measured dial identity BEFORE anything is unparked. Here `b` vanishes
    exactly when the commit pins it: the build skips `b` and would otherwise
    promote `a`, so the restore must defer and put the persisted selection
    back."""
    r = load_router(tmp_path)
    r._providers = {"warp": {"fallback_providers": ["proton"], "fail_open_direct": True},
                    "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {}
    r._vpn = {}
    r._port = 2080
    r.current_mode = lambda: "proxy"
    r._automatic_proxy_mode = lambda: True
    write_conf(tmp_path / "providers" / "warp", "a")
    write_conf(tmp_path / "providers" / "warp", "b")
    write_conf(tmp_path / "providers" / "proton", "p")
    r.provider_files = lambda name: sorted(
        (tmp_path / "providers" / name).glob("*.conf"))
    vanished = {"b": False}

    def parse(path):
        if path.stem == "b" and vanished["b"]:
            raise SystemExit("profile disappeared")
        endpoint = copy.deepcopy(WG_ENDPOINT)
        endpoint["peers"][0]["address"] = ("192.0.2.10" if path.stem == "a"
                                           else "192.0.2.20")
        return endpoint

    r.parse_wireguard = parse
    # `a` is the persisted selection but is cooling down: build + probe must
    # fall through to `b`.
    state_dir = tmp_path / "state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "warp.active").write_text("a")
    cooldown_dir = state_dir / "cooldowns" / "warp"
    cooldown_dir.mkdir(parents=True, exist_ok=True)
    cooldown = cooldown_dir / "a.until"
    cooldown.write_text(str(int(time.time()) + 3600))
    fallback_dir = state_dir / "fallback"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    fallback_bytes = json.dumps({"provider": "proton", "reason": "confirmed-stall"})
    (fallback_dir / "warp.json").write_text(fallback_bytes)

    config, _selected = r.build_singbox_config()
    assert next(e for e in config["endpoints"] if e["tag"] == "probe-warp") \
        ["peers"][0]["address"] == "192.0.2.20", \
        "with `a` cooled, the loaded probe must be `b`"
    r.SING_BOX_CONFIG.write_text(json.dumps(config))
    r.probe_egress = mock.Mock(return_value={"status": 200})
    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    marker = _restore_marker(r)
    assert json.loads(marker.read_text())["successes"] == 1
    # `a`'s cooldown expires while the SAME probe-only endpoint stays loaded.
    cooldown.unlink()
    payload = json.loads(marker.read_text())
    payload["attempted_at"] = 0
    marker.write_text(json.dumps(payload))
    # `b` disappears at the exact moment the commit pins it: availability was
    # checked against the still-listed file, but the promotion build can no
    # longer produce `b`'s endpoint.
    original_set_active = r.set_active

    def pin_then_vanish(name, profile):
        original_set_active(name, profile)
        if profile.stem == "b":
            vanished["b"] = True

    r.set_active = pin_then_vanish
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate, \
            mock.patch.object(r, "engine_reload", return_value=0) as reload_engine:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    deactivate.assert_not_called()
    reload_engine.assert_not_called()
    assert (state_dir / "warp.active").read_text() == "a", \
        "the failed promotion must restore the previous persisted selection"
    assert (fallback_dir / "warp.json").read_text() == fallback_bytes, \
        "the serving fallback must stay exactly as it was"
    assert json.loads(marker.read_text())["successes"] == 0


def _enable_attributed_proxy(r, port=2181):
    """Probe inbound + matching SOCKS outbound for a proxy-backed provider."""
    probe = r.probe_port("warp")
    assert probe is not None
    r.parse_wireguard = lambda path: copy.deepcopy(_PROBE_ENDPOINT)
    r.SING_BOX_CONFIG.write_text(json.dumps({
        "outbounds": [{"type": "socks", "tag": "probe-warp", "server": "127.0.0.1",
                       "server_port": port, "version": "5"}],
        "inbounds": [{"type": "mixed", "tag": "probe-warp",
                      "listen": "127.0.0.1", "listen_port": probe}],
    }))
    return probe


def test_attributed_restore_commits_when_the_proxy_upstream_is_unchanged(controller):
    """A parked SOCKS-backed provider: the measured upstream IS the dial
    identity, and an unchanged upstream commits normally."""
    r = controller
    r._providers["warp"] = {"socks5": {"host": "127.0.0.1", "port": 2181},
                            "fallback_providers": ["proton"], "fail_open_direct": True}
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed_proxy(r)
    r.probe_egress.return_value = {"status": 200}
    with mock.patch.object(r, "engine_reload", return_value=0):
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
        payload = json.loads(_restore_marker(r).read_text())
        assert payload["successes"] == 1
        payload["attempted_at"] = 0
        _restore_marker(r).write_text(json.dumps(payload))
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 0
    assert r.active_fallback("warp") is None


def test_attributed_restore_defers_when_the_proxy_upstream_changed(controller):
    """The config was generated with port 2181; a router.json edit since then
    means the next reload would dial an upstream the probe never measured."""
    r = controller
    r._providers["warp"] = {"socks5": {"host": "127.0.0.1", "port": 2181},
                            "fallback_providers": ["proton"], "fail_open_direct": True}
    assert r.activate_fallback("warp", target="proton") == 0
    _enable_attributed_proxy(r)
    r.probe_egress.return_value = {"status": 200}
    assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    payload = json.loads(_restore_marker(r).read_text())
    payload["attempted_at"] = 0
    _restore_marker(r).write_text(json.dumps(payload))
    r._providers["warp"]["socks5"]["port"] = 2182
    with mock.patch.object(r, "deactivate_fallback", return_value=0) as deactivate:
        assert r.restore_fallback("warp", "discord.com", automatic=True) == 1
    deactivate.assert_not_called()
    assert r.active_fallback("warp") == "proton"
    assert json.loads(_restore_marker(r).read_text())["successes"] == 0
