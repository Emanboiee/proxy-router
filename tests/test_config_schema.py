"""Contract tests for the first issue #66 schema extraction step."""

from pathlib import Path

import config_schema


ROOT = Path(__file__).resolve().parents[1]


def test_schema_leaf_has_no_controller_or_platform_dependency():
    source = (ROOT / "config_schema.py").read_text(encoding="utf-8")
    assert "import router" not in source
    assert "import proxy_tray" not in source
    assert "import subprocess" not in source


def test_migration_is_copying_and_sets_current_version():
    original = {"port": 2080, "providers": {"proton": {}}, "schema_version": 0}
    migrated = config_schema.migrate(original)

    assert migrated["schema_version"] == config_schema.SCHEMA_VERSION == 1
    assert original["schema_version"] == 0
    assert migrated is not original
    migrated["providers"]["proton"]["new"] = True
    assert "new" not in original["providers"]["proton"]


def test_migration_rejects_unknown_versions():
    try:
        config_schema.migrate({"schema_version": 99})
    except ValueError as exc:
        assert "unsupported config schema version" in str(exc)
    else:
        raise AssertionError("unknown schema versions must fail closed")


def test_router_status_exposes_schema_version_without_redefining_defaults(tmp_path, monkeypatch):
    from tests.test_proxy_provider import load_router

    router = load_router(tmp_path)
    monkeypatch.setattr(router, "_status_report", lambda *, fast=False: (0, "running"))
    monkeypatch.setattr(router, "_system_proxy_status_readonly", lambda: ("skipped", {}))
    monkeypatch.setattr(router, "_cached_network_diagnostic", lambda: None)
    monkeypatch.setattr(router, "_legacy_launch_agents", lambda: [])
    monkeypatch.setattr(router, "resolve_sing_box", lambda: "/fixture/sing-box")
    assert router.status_json(fast=True)["schema_version"] == config_schema.SCHEMA_VERSION
    router_source = (ROOT / "router.py").read_text(encoding="utf-8")
    assert "from config_schema import" in router_source
    assert "DEFAULT_EGRESS_SETTINGS = {" not in router_source


def make_config(providers=None, bypass=None):
    """Build a Config directly via its constructor (all sections required)."""
    return config_schema.Config(
        port=2080,
        providers=providers if providers is not None else {"p": {"directory": "providers/p"}},
        routes=[{"id": "r", "provider": "p", "domains": ["a.example"]}],
        vpn={"prefer_ipv6_peers": True},
        routing={"mode": "default"},
        autodetect={"enabled": False},
        egress_settings={"probe_timeout": 8.0},
        rotation={"policy": "latency"},
        error_policy={"default": {"action": "cooldown", "seconds": 300}},
        proxy_bypass_domains=bypass if bypass is not None else ["localhost"],
    )


def test_config_is_frozen():
    cfg = make_config()
    try:
        cfg.port = 9999
    except Exception as exc:
        assert type(exc).__name__ in ("FrozenInstanceError", "AttributeError")
    else:
        raise AssertionError("Config must be immutable")


def test_two_configs_never_share_mutable_state():
    a = make_config(providers={"p": {"v": [1]}}, bypass=[" x "])
    b = config_schema.Config.from_loaded(
        port=a.port, providers=a.providers, routes=a.routes, vpn=a.vpn,
        routing=a.routing, autodetect=a.autodetect,
        egress_settings=a.egress_settings, rotation=a.rotation,
        error_policy=a.error_policy, proxy_bypass_domains=a.proxy_bypass_domains,
    )
    a.providers["p"]["v"].append(2)
    a.routes[0]["domains"].append("b.example")
    assert b.providers["p"]["v"] == [1]
    assert b.routes[0]["domains"] == ["a.example"]


def test_config_to_dict_returns_fresh_copy():
    cfg = make_config()
    out = cfg.to_dict()
    out["providers"]["p"]["directory"] = "MUTATED"
    out["routes"].append({})
    assert cfg.providers["p"]["directory"] == "providers/p"
    assert len(cfg.routes) == 1


def test_parse_egress_settings_is_pure_and_bounded():
    supplied = {"probe_timeout": 999, "block_seconds": -5, "probe_url": "bad"}
    out = config_schema.parse_egress_settings({"egress": supplied})
    assert out["probe_timeout"] == 60.0
    assert out["block_seconds"] == 0
    assert out["probe_url"] == config_schema.DEFAULT_PROBE_URL
    assert "egress" not in supplied  # input untouched: pure


def test_config_runtime_view_is_isolated_from_snapshot():
    cfg = make_config(providers={"p": {"v": [1]}})
    (port, providers, routes, vpn, routing, autodetect, bypass) = cfg.runtime_view()
    providers["p"]["v"].append(2)
    routes[0]["domains"].append("b.example")
    assert cfg.providers["p"]["v"] == [1]
    assert cfg.routes[0]["domains"] == ["a.example"]


def test_config_runtime_view_deep_copies_nested_routing():
    cfg = make_config()
    cfg.routing["direct_domains"] = ["a.example"]
    (port, providers, routes, vpn, routing, autodetect, bypass) = cfg.runtime_view()
    routing["direct_domains"].append("b.example")
    assert cfg.routing["direct_domains"] == ["a.example"]


def test_public_dns_error_exact_strings():
    fn = config_schema.public_dns_error
    assert fn(None) is None
    assert fn("x") == "vpn.public_dns must be an object"
    assert fn({"server": "bad"}) == "vpn.public_dns.server must be an IP address (no bootstrap DNS)"
    assert fn({"server": "0.0.0.0"}) == "vpn.public_dns.server must be a unicast address"
    assert fn({"server": "1.1.1.1", "transport": "x"}) == "vpn.public_dns.transport must be 'https', 'udp', 'tcp', or 'tls'"
    assert fn({"server": "1.1.1.1", "private_domains": ["bad domain"]}) == "vpn.public_dns.private_domains must be a list of domain suffixes"
    assert fn({"server": "1.1.1.1"}) is None


def test_config_schema_has_no_upward_import_after_dns_move():
    source = (ROOT / "config_schema.py").read_text(encoding="utf-8")
    for mod in ("import router", "import proxy_tray", "import monitor", "import route_watcher"):
        assert mod not in source
