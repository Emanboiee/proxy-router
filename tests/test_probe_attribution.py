"""Option C: the attributed probe path for fallback-parked providers.

While a provider is parked under an active fallback, every domain rule routes
through the fallback, so the primary is unmeasurable through the shared
listener -- and the parked primary's own outbound used to be dropped from the
build entirely. The attributed path is the fix: the parked provider keeps a
PROBE-ONLY outbound (tag ``probe-<name>``) plus a loopback mixed inbound pinned
to it by a highest-priority inbound rule. ``restore_fallback`` probes through
that inbound, so the serving fallback is never removed to measure.

Invariants pinned here:

* a parked provider is emitted ONLY under its probe tag -- no domain rule can
  reach it, and the probe rule comes first;
* an unparked provider emits no probe objects at all;
* probe ports are deterministic, distinct per provider, and skipped (not
  fatal) when they would collide with the proxy listener;
* a TUN build carries no probe path (fallback restore is proxy-mode only).
"""
from __future__ import annotations

import json

from tests.test_proxy_provider import load_router, mock_wireguard, write_conf


def _park(router, provider: str, target: str) -> None:
    directory = router.ROOT / "state" / "fallback"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{provider}.json").write_text(
        json.dumps({"provider": target, "reason": "connection"}))


def _wireguard_pair(tmp_path):
    """`warp` (parked on `proton`) and `proton` (serving)."""
    router = load_router(tmp_path)
    router._providers = {"warp": {"fallback_providers": ["proton"]},
                         "proton": {}}
    router._routes = [{"id": "school", "domains": ["school.example"],
                       "provider": "warp"}]
    router._routing = {}
    router._vpn = {}
    router._port = 2180
    mock_wireguard(router, {"warp": write_conf(tmp_path / "providers" / "warp"),
                            "proton": write_conf(tmp_path / "providers" / "proton")})
    return router


def test_parked_wireguard_provider_is_probe_only_and_never_a_route_target(tmp_path):
    router = _wireguard_pair(tmp_path)
    _park(router, "warp", "proton")
    # warp->proton PARKED, so warp is the probe-only side and proton serves.
    config, _selected = router.build_singbox_config()

    assert [e["tag"] for e in config["endpoints"]] == ["proton", "probe-warp"]
    assert router.probe_port("warp") == router.PROBE_PORT_BASE + 1

    rules = config["route"]["rules"]
    assert rules[0] == {"inbound": ["probe-warp"], "outbound": "probe-warp"}, \
        "the probe pin must be the FIRST rule: attribution cannot depend on later matches"
    assert {"outbound": "proton", "domain_suffix": ["school.example"]} in rules
    # No domain rule may ever select the probe tag: probe traffic only.
    assert not any(rule.get("domain_suffix") and rule.get("outbound") == "probe-warp"
                   for rule in rules)
    assert {"type": "mixed", "tag": "probe-warp", "listen": "127.0.0.1",
            "listen_port": router.probe_port("warp")} in config["inbounds"]


def test_unparked_provider_has_no_probe_path(tmp_path):
    router = _wireguard_pair(tmp_path)
    config, _selected = router.build_singbox_config()

    assert [e["tag"] for e in config["endpoints"]] == ["warp", "proton"]
    assert not any(inbound.get("tag", "").startswith("probe-")
                   for inbound in config["inbounds"])
    assert not any(rule.get("inbound", [""])[0].startswith("probe-")
                   for rule in config["route"]["rules"])


def test_parked_proxy_provider_gets_a_probe_outbound_and_inbound(tmp_path):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {},
        "warp-proxy": {"socks5": {"host": "127.0.0.1", "port": 2181},
                       "fallback_providers": ["proton"]},
    }
    router._routes = [{"id": "school", "domains": ["school.example"],
                       "provider": "warp-proxy"}]
    router._routing = {}
    router._vpn = {}
    router._port = 2180
    mock_wireguard(router, {"proton": write_conf(tmp_path / "providers" / "proton")})
    _park(router, "warp-proxy", "proton")

    config, _selected = router.build_singbox_config()

    assert [o.get("tag") for o in config["outbounds"]] == ["direct", "probe-warp-proxy"]
    probe = next(o for o in config["outbounds"] if o["tag"] == "probe-warp-proxy")
    assert probe == {"type": "socks", "tag": "probe-warp-proxy",
                     "server": "127.0.0.1", "server_port": 2181, "version": "5"}
    assert config["route"]["rules"][0] == {"inbound": ["probe-warp-proxy"],
                                           "outbound": "probe-warp-proxy"}
    assert not any(rule.get("domain_suffix") and rule.get("outbound") == "warp-proxy"
                   for rule in config["route"]["rules"])


def test_probe_port_collision_with_the_listener_is_skipped_not_fatal(tmp_path):
    router = _wireguard_pair(tmp_path)
    _park(router, "warp", "proton")
    router._port = router.PROBE_PORT_BASE + 1  # the parked provider's would-be port
    config, _selected = router.build_singbox_config()

    assert not any(inbound.get("tag", "").startswith("probe-")
                   for inbound in config["inbounds"])
    assert not any(rule.get("inbound", [""])[0].startswith("probe-")
                   for rule in config["route"]["rules"])
    assert [e["tag"] for e in config["endpoints"]] == ["proton"]


def test_tun_build_carries_no_probe_path(tmp_path):
    router = _wireguard_pair(tmp_path)
    _park(router, "warp", "proton")
    router.current_mode = lambda: "tun"  # after mock_wireguard's proxy stub
    router.MODE_FILE.write_text("tun")

    config, _selected = router.build_singbox_config()

    assert not any(inbound.get("tag", "").startswith("probe-")
                   for inbound in config["inbounds"])
    assert not any(rule.get("inbound", [""])[0].startswith("probe-")
                   for rule in config["route"]["rules"])
    assert [e["tag"] for e in config["endpoints"]] == ["proton"]
