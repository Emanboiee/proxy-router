from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path):
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("proxy_router_under_test", ROOT / "router.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.CONFIG_FILE = tmp_path / "router.json"
    module.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    module.LAST_GOOD_FILE = tmp_path / "sing-box.json.last-good"
    module.PID_FILE = tmp_path / "sing-box.pid"
    module.LOG_FILE = tmp_path / "sing-box.log"
    module.LOCK_FILE = tmp_path / "state" / "engine.lock"
    module.MODE_FILE = tmp_path / "state" / "mode"
    return module


def test_vpn_list_filters_provider_routes_to_vpn_domains(tmp_path):
    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    router._providers = {"proton": {}}
    router._routes = [{
        "id": "mixed",
        "provider": "proton",
        "domains": ["blocked.example", "ordinary.example"],
    }]
    router._routing = {"mode": "vpn-list", "vpn_domains": ["blocked.example"]}
    router._port = 2080
    router.current_mode = lambda: "proxy"
    router._usable_profile = lambda name, preferred=None: profile
    router.parse_wireguard = lambda path: {
        "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
        "private_key": "secret", "peers": [{"address": "192.0.2.1", "port": 1,
        "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
    }
    router.dns_server_for = lambda path: "1.1.1.1"

    config, _active = router.build_singbox_config()

    provider_rules = [r for r in config["route"]["rules"] if r.get("outbound") == "proton"]
    assert provider_rules == [{"outbound": "proton", "domain_suffix": ["blocked.example"]}]
    assert config["route"]["final"] == "direct"


def test_primary_routes_use_runtime_fallback_provider(tmp_path):
    router = load_router(tmp_path)
    proton = tmp_path / "proton.conf"
    cloudflare = tmp_path / "cloudflare.conf"
    router._providers = {
        "proton": {"fallback_provider": "cloudflare"},
        "cloudflare": {},
    }
    router._routes = [{
        "id": "opencode", "domains": ["opencode.ai"], "provider": "proton",
    }]
    router._routing = {}
    router._port = 2081
    router.current_mode = lambda: "proxy"
    router._usable_profile = lambda name, preferred=None: {
        "proton": proton, "cloudflare": cloudflare,
    }.get(name)
    router.parse_wireguard = lambda path: {
        "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
        "private_key": "secret", "peers": [{"address": "192.0.2.1", "port": 1,
        "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
    }
    router.dns_server_for = lambda path: "1.1.1.1"
    fallback_dir = tmp_path / "state" / "fallback"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))

    config, _active = router.build_singbox_config()

    assert {endpoint["tag"] for endpoint in config["endpoints"]} == {"cloudflare"}
    assert {rule["outbound"] for rule in config["route"]["rules"] if rule.get("domain_suffix")} == {"cloudflare"}
    assert config["dns"]["rules"] == [{
        "domain_suffix": ["opencode.ai"], "server": "dns-cloudflare",
    }]


def test_activate_fallback_writes_marker_and_reloads_once(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    for provider in ("proton", "cloudflare"):
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        (directory / "active.conf").write_text("profile")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    reloads = []
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: reloads.append(True) or 0)

    assert router.activate_fallback("proton", reason="tls") == 0
    marker = json.loads((tmp_path / "state" / "fallback" / "proton.json").read_text())
    assert marker["provider"] == "cloudflare"
    assert marker["reason"] == "tls"
    assert reloads == [True]

    assert router.deactivate_fallback("proton") == 0
    assert not (tmp_path / "state" / "fallback" / "proton.json").exists()
    assert reloads == [True, True]


def test_activate_fallback_restores_marker_when_reload_fails(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    for provider in ("proton", "cloudflare"):
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        (directory / "active.conf").write_text("profile")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: 1)

    assert router.activate_fallback("proton", reason="tls") == 1
    assert not (tmp_path / "state" / "fallback" / "proton.json").exists()


def test_rotate_refuses_primary_while_fallback_is_active(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    for provider in ("proton", "cloudflare"):
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        (directory / "active.conf").write_text("profile")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    marker = tmp_path / "state" / "fallback"
    marker.mkdir(parents=True)
    (marker / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))

    assert router.rotate("proton") == 1
    assert "fallback active" in capsys.readouterr().err


def test_load_config_rejects_unknown_fallback_provider(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {
            "proton": {
                "directory": "providers/proton",
                "fallback_provider": "warp",
            },
        },
        "routes": [],
    }))

    assert router.load_config() == 1


def test_load_config_accepts_fallback_chain_list(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {
            "proton": {"directory": "providers/proton",
                       "fallback_provider": ["cloudflare", "mullvad"]},
            "cloudflare": {"directory": "providers/cloudflare"},
            "mullvad": {"directory": "providers/mullvad"},
        },
        "routes": [],
    }))

    assert router.load_config() == 0
    assert router.fallback_chain("proton") == ["cloudflare", "mullvad"]


def test_load_config_rejects_self_in_fallback_chain(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {
            "proton": {"directory": "providers/proton",
                       "fallback_provider": ["proton", "cloudflare"]},
            "cloudflare": {"directory": "providers/cloudflare"},
        },
        "routes": [],
    }))

    assert router.load_config() == 1


def test_load_config_rejects_duplicate_fallback_chain_entries(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {
            "proton": {"directory": "providers/proton",
                       "fallback_provider": ["cloudflare", "cloudflare"]},
            "cloudflare": {"directory": "providers/cloudflare"},
        },
        "routes": [],
    }))

    assert router.load_config() == 1


def test_load_config_rejects_bad_default_mode(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [],
        "vpn": {"default_mode": "banana"},
    }))

    assert router.load_config() == 1


def test_load_config_accepts_default_mode_tun(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2081,
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [],
        "vpn": {"default_mode": "tun"},
    }))

    assert router.load_config() == 0


def test_fallback_chain_drops_invalid_entries(tmp_path):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {"fallback_provider": ["cloudflare", "proton", "warp", "cloudflare"]},
        "cloudflare": {},
    }

    assert router.fallback_chain("proton") == ["cloudflare"]
    assert router.configured_fallback("proton") == "cloudflare"


def test_activate_fallback_walks_chain_to_first_valid_provider(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    for provider in ("proton", "cloudflare", "mullvad"):
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        (directory / "active.conf").write_text("profile")
    router._providers = {
        "proton": {"directory": "providers/proton",
                   "fallback_provider": ["cloudflare", "mullvad"]},
        "cloudflare": {"directory": "providers/cloudflare"},
        "mullvad": {"directory": "providers/mullvad"},
    }
    monkeypatch.setattr(router, "_profile_error",
                        lambda profile: None if "mullvad" in str(profile) else "bad")
    reloads = []
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: reloads.append(True) or 0)

    assert router.activate_fallback("proton", reason="tls") == 0
    marker = json.loads((tmp_path / "state" / "fallback" / "proton.json").read_text())
    assert marker["provider"] == "mullvad"
    assert reloads == [True]


def test_activate_fallback_rejects_target_outside_chain(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    for provider in ("proton", "cloudflare", "mullvad"):
        directory = tmp_path / "providers" / provider
        directory.mkdir(parents=True)
        (directory / "active.conf").write_text("profile")
    router._providers = {
        "proton": {"directory": "providers/proton",
                   "fallback_provider": ["cloudflare", "mullvad"]},
        "cloudflare": {"directory": "providers/cloudflare"},
        "mullvad": {"directory": "providers/mullvad"},
    }
    monkeypatch.setattr(router, "_profile_error", lambda profile: None)
    monkeypatch.setattr(router, "engine_reload", lambda *a, **k: 0)

    assert router.activate_fallback("proton", target="mullvad") == 0
    marker = json.loads((tmp_path / "state" / "fallback" / "proton.json").read_text())
    assert marker["provider"] == "mullvad"
    assert router.activate_fallback("proton", target="warp") == 1


def test_active_fallback_validates_marker_against_chain(tmp_path):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {"fallback_provider": ["cloudflare", "mullvad"]},
        "cloudflare": {},
        "mullvad": {},
    }
    fallback_dir = tmp_path / "state" / "fallback"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "proton.json").write_text(json.dumps({"provider": "mullvad"}))

    assert router.active_fallback("proton") == "mullvad"
    (fallback_dir / "proton.json").write_text(json.dumps({"provider": "warp"}))
    assert router.active_fallback("proton") is None


def test_fallback_status_reports_configured_chain(tmp_path):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {"fallback_provider": ["cloudflare", "mullvad"]},
        "cloudflare": {},
        "mullvad": {},
    }
    fallback_dir = tmp_path / "state" / "fallback"
    fallback_dir.mkdir(parents=True)
    (fallback_dir / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))

    assert router.fallback_status("proton") == {
        "configured": ["cloudflare", "mullvad"],
        "active": "cloudflare",
    }


def test_egress_sweep_skips_primary_when_fallback_is_active(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    marker = tmp_path / "state" / "fallback"
    marker.mkdir(parents=True)
    (marker / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))
    # the sweep reports the parked primary via one fallback probe
    monkeypatch.setattr(router, "_check_active_fallback",
                        lambda provider, fallback: (None, "alive", None))

    assert router.egress_sweep("proton", as_json=True) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dead"] == []
    assert data["results"]["proton"] == {
        "status": "fallback", "fallback_provider": "cloudflare",
        "fallback_profile": None, "ok": True,
    }


def test_tun_exclude_cidr_pins_destinations_outside_engine(tmp_path):
    # route_exclude_address keeps these CIDRs on the physical path so they
    # never transit (or blip on) the engine (#38 escape hatch)
    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    router._providers = {"proton": {}}
    router._routes = [{"id": "zen", "domains": ["opencode.ai"], "provider": "proton"}]
    router._vpn = {"capture": "routes", "exclude_cidr": ["203.0.113.0/24"]}
    router._routing = {}
    router._port = 2080
    router.current_mode = lambda: "tun"
    router._usable_profile = lambda name, preferred=None: profile
    router.parse_wireguard = lambda path: {}
    config, _ = router.build_singbox_config()
    tun = next(i for i in config["inbounds"] if i.get("type") == "tun")
    assert tun["route_exclude_address"] == ["203.0.113.0/24"]


def test_load_config_rejects_malformed_exclude_cidr(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2080,
        "providers": {"proton": {"directory": "providers/proton"}},
        "routes": [],
        "vpn": {"exclude_cidr": "203.0.113.0/24"},
    }))
    assert router.load_config() == 1


def test_selective_tun_uses_address_set_and_keeps_auto_route(tmp_path):
    router = load_router(tmp_path)
    rulesets = tmp_path / "rulesets"
    rulesets.mkdir()
    (rulesets / "roblox.json").write_text(json.dumps({
        "provider": "cloudflare",
        "ip_cidr": ["128.116.0.0/17", "2620:135:6000::/40"],
    }))
    profile = tmp_path / "cloudflare.conf"
    router._providers = {"cloudflare": {}}
    router._routes = []
    router._vpn = {"selective": "roblox", "selective_provider": "cloudflare"}
    router._routing = {}
    router._port = 2080
    router.current_mode = lambda: "tun"
    router._usable_profile = lambda name, preferred=None: profile
    router.parse_wireguard = lambda path: {
        "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
        "private_key": "secret", "peers": [{"address": "192.0.2.1", "port": 1,
        "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
    }
    router.dns_server_for = lambda path: "1.1.1.1"

    config, _active = router.build_singbox_config()
    tun = config["inbounds"][0]

    assert tun["auto_route"] is True
    assert tun["route_address_set"] == ["ruleset-roblox"]
    assert config["route"]["rule_set"] == [{
        "type": "inline", "tag": "ruleset-roblox",
        "rules": [{"ip_cidr": ["128.116.0.0/17", "2620:135:6000::/40"]}],
    }]
    assert config["route"]["rules"][1] == {
        "rule_set": ["ruleset-roblox"], "outbound": "cloudflare",
    }


def test_tun_mode_keeps_mixed_proxy_listener(tmp_path):
    # ROOT CAUSE:
    #
    # The tun-mode build replaced the mixed proxy inbound with [tun], so
    # 127.0.0.1:PORT stopped listening while TUN was active. Apps pinned
    # to the proxy (hermes gateway, with-proxy, keepalive egress probes)
    # then died with ClientProxyConnectionError / dead-pool rotation
    # storms even though the tunnel itself was healthy.
    #
    # We fixed this by keeping the mixed inbound ALONGSIDE the tun inbound;
    # TUN captures everything else at the IP layer and both inbound types
    # share one route table.
    router = load_router(tmp_path)
    profile = tmp_path / "proton.conf"
    router._providers = {"proton": {}}
    router._routes = []
    router._vpn = {"mtu": 1280}
    router._routing = {}
    router._port = 2080
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "state" / "mode").write_text("tun")
    router.current_mode = lambda: (tmp_path / "state" / "mode").read_text().strip()
    router._usable_profile = lambda name, preferred=None: profile
    router.parse_wireguard = lambda path: {
        "type": "wireguard", "tag": "", "address": ["10.0.0.2/32"],
        "private_key": "secret", "peers": [{"address": "192.0.2.1", "port": 1,
        "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
    }
    router.dns_server_for = lambda path: "1.1.1.1"

    config, _active = router.build_singbox_config()
    types = [i["type"] for i in config["inbounds"]]
    assert types == ["tun", "mixed"]
    mixed = config["inbounds"][1]
    assert mixed["listen"] == "127.0.0.1"
    assert mixed["listen_port"] == 2080

    # engine_mode_consistent must still tell modes apart: tun-mode builds
    # carry both inbounds, proxy-mode builds carry only the mixed listener.
    def _write(state_mode, inbounds):
        (tmp_path / "state").mkdir(exist_ok=True)
        (tmp_path / "state" / "mode").write_text(state_mode)
        router.SING_BOX_CONFIG.write_text(json.dumps({"inbounds": inbounds}))

    _write("tun", config["inbounds"])
    assert router.engine_mode_consistent() is True
    _write("proxy", [{"type": "mixed", "tag": "local-proxy"}])
    assert router.engine_mode_consistent() is True
    _write("proxy", config["inbounds"])  # tun+mixed while mode says proxy
    assert router.engine_mode_consistent() is False


def test_configured_profile_matches_live_endpoint_without_using_marker(tmp_path):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    profile = provider_dir / "01-NL-FREE-140.conf"
    profile.write_text("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = secret\n\n[Peer]\nEndpoint = 192.0.2.55:51820\nPublicKey = public\nAllowedIPs = 0.0.0.0/0\n")
    router._providers = {"proton": {"directory": "providers/proton"}}
    router.SING_BOX_CONFIG.write_text(json.dumps({"endpoints": [{
        "type": "wireguard", "tag": "proton", "address": ["10.0.0.2/32"],
        "private_key": "secret", "peers": [{"address": "192.0.2.55", "port": 51820,
        "public_key": "public", "allowed_ips": ["0.0.0.0/0"]}],
        "domain_resolver": "dns-proton",
    }]}))
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "proton.active").write_text("00-US-FREE-108")

    assert router.configured_profile("proton") == profile


def test_rotate_to_current_profile_is_noop_does_not_cooldown(tmp_path, monkeypatch):
    """Re-selecting the already-active exit must succeed and must NOT mark
    the current profile cooling; the old code cooled it then refused the
    pick with a nonsense 'exit is cooling down' error."""
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    profile = provider_dir / "00-US-FREE-108.conf"
    profile.write_text("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = secret\n\n[Peer]\nEndpoint = 192.0.2.55:51820\nPublicKey = public\nAllowedIPs = 0.0.0.0/0\n")
    router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
    router.persisted_active = lambda name: profile
    router.is_cooled_down = lambda name, p: False
    marked = {}
    router.mark_cooldown = lambda name, p, seconds: marked.setdefault(name, p)
    router.egress_is_blocked = lambda name, p: False
    router.engine_reload = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not reload"))
    router.set_active = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not set_active"))
    router.record_rotation = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not record_rotation"))

    rc = router.rotate("proton", to="00-US-FREE-108")

    assert rc == 0
    assert "proton" not in marked


# ---------------------------------------------------------------------------
# tray UX regressions (proxy_tray.py)
# ---------------------------------------------------------------------------

import types  # noqa: E402


def load_tray(tmp_path):
    """Load the tray module with deterministic pystray/PIL stubs.

    Stubs are injected into ``sys.modules`` BEFORE the module body runs, so
    ``import pystray`` inside the tray resolves to the stub regardless of
    whether a real pystray is installed in the test interpreter. The stub
    mirrors pystray's Menu-as-second-argument-is-a-submenu behaviour.
    """
    stub_pystray = types.ModuleType("pystray")

    class _StubMenu:
        SEPARATOR = None

        def __init__(self, *items):
            self.items = items
            self._items = items

    class _StubMenuItem:
        def __init__(self, text, action=None, enabled=True, checked=None, submenu=None,
                     default=False):
            if isinstance(action, _StubMenu):
                submenu, action = action, None
            self.text = text
            self.action = action
            self.enabled = enabled
            self.default = default
            self._checked = checked
            self._submenu = submenu

        @property
        def submenu(self):
            if callable(self._submenu) and not isinstance(self._submenu, _StubMenu):
                return self._submenu()
            return self._submenu

        def is_checked(self):
            return bool(self._checked and self._checked(_StubMenuItem("probe")))

    stub_pystray.Menu = _StubMenu
    stub_pystray.MenuItem = _StubMenuItem

    stub_pil = types.ModuleType("PIL")
    stub_pil.Image = object
    stub_pil.ImageDraw = object

    saved = {}
    for name in ("pystray", "PIL"):
        saved[name] = sys.modules.get(name)
        sys.modules[name] = {"pystray": stub_pystray, "PIL": stub_pil}[name]
    try:
        spec = importlib.util.spec_from_file_location(
            "proxy_tray_under_test", ROOT / "proxy_tray.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        # Register before exec: the module uses `from __future__ import
        # annotations`, and dataclasses resolves the string annotations via
        # sys.modules[cls.__module__] — an unregistered module crashes there.
        sys.modules["proxy_tray_under_test"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name in ("pystray", "PIL"):
            if saved[name] is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved[name]


def _tray_app(module, root, *, up=False, providers=None, preset=None, error=None,
              routing="default", action=None, mode="proxy"):
    client = module.RouterClient(str(root))
    app = module.TrayApp.__new__(module.TrayApp)
    app.client = client
    app.latest = module.RouterStatus(
        up=up, mode=mode, providers=providers or {}, routing_mode=routing,
        preset=preset, error=error, active_providers={})
    app.last_action_result = action
    app.lock = __import__("threading").Lock()
    app.tray = None
    return app


def _flatten(menu_items, depth=0):
    """Flatten a stub menu tree into (depth, text, enabled, checked) tuples."""
    out = []
    for item in menu_items:
        if item is None:
            out.append((depth, "---", True, False))
            continue
        sub = item.submenu
        out.append((depth, item.text, item.enabled, item.is_checked() if sub is None else False))
        if sub:
            out.extend(_flatten(sub.items, depth + 1))
    return out


def test_tray_down_status_is_disconnected_not_error(tmp_path):
    """ROOT CAUSE: `RouterStatus.from_cli` short-circuited on rc != 0, so a
    plain disconnect (status --json exits 1 with a valid payload) rendered as
    "! Error" in the tray header. The JSON payload carries the real state.

    Before: error='status exit 1' on any down state.
    After: the payload is parsed and up=False is reported; error stays None.
    """
    module = load_tray(tmp_path)
    down = json.dumps({
        "up": False, "state": "down (proxy mode; run 'vpn on' for tun, 'start' for proxy)",
        "mode": "proxy", "port": 2080, "pid": None,
        "providers": {"proton": {"profiles": ["01-NL-FREE-140"], "active": "01-NL-FREE-140",
                                 "egress": {}}},
        "routing": {"mode": "default", "direct_domains": [], "vpn_domains": [],
                    "default_provider": None},
        "watcher": {"enabled": True, "running": False}, "preset": "opencode",
    })
    st = module.RouterStatus.from_cli(1, down)
    assert st.up is False
    assert st.error is None
    assert st.preset == "opencode"
    assert st.providers["proton"]["active"] == "01-NL-FREE-140"


def test_tray_fresh_install_is_not_error_and_shows_setup_banner(tmp_path):
    """A fresh install (no router.json) must NOT show "! Error status exit 1";
    the menu should point the user at Setup and leave Connect disabled."""
    module = load_tray(tmp_path)
    fresh = json.dumps({
        "up": False, "state": "down (unusable config; see error above)", "mode": None,
        "port": None, "providers": {}, "routes": [],
        "routing": {"mode": None, "direct_domains": [], "vpn_domains": [],
                    "default_provider": None},
    })
    st = module.RouterStatus.from_cli(1, fresh)
    assert st.error is None
    assert st.up is False
    assert st.providers == {}

    app = _tray_app(module, tmp_path)
    rows = _flatten(app.build_menu().items)
    labels = [text for _, text, _, _ in rows]
    assert "● No VPN set up yet" in labels
    assert "Start here: Setup → Add a profile (.conf)" in labels
    # Connect must be disabled until at least one provider exists
    connect_row = next(r for r in rows if r[1] in ("Connect", "Reconnect"))
    assert connect_row[2] is False


def test_tray_unparseable_status_is_error(tmp_path):
    """A status payload that fails to parse is the only thing that should
    surface as an error in the tray."""
    module = load_tray(tmp_path)
    st = module.RouterStatus.from_cli(1, "router: boom")
    assert st.error is not None
    assert st.up is False


def test_tray_presets_menu_includes_custom_presets(tmp_path):
    """Custom presets created in the setup TUI (presets/<name>.json) must
    appear in the tray Presets menu, checked when active."""
    module = load_tray(tmp_path)
    (tmp_path / "presets").mkdir()
    (tmp_path / "presets" / "banana.json").write_text(json.dumps({
        "routes": [{"id": "banana", "domains": ["opencode.ai"], "provider": "proton"}],
        "routing": {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]},
    }))
    app = _tray_app(module, tmp_path, up=True, preset="banana",
                    providers={"proton": {"active": "01-NL-FREE-140",
                                          "profiles": ["01-NL-FREE-140"], "egress": {}}})
    rows = _flatten(app.build_menu().items)
    preset_rows = [(d, t, c) for d, t, e, c in rows if t.startswith("banana")]
    assert preset_rows, "custom preset missing from tray Presets menu"
    depth, label, checked = preset_rows[0]
    assert "opencode.ai via proton" in label
    assert checked is True  # active preset shows the checkmark


def test_tray_humanize_cli_output(tmp_path):
    """Raw CLI success/failure lines become user-facing text in the menu."""
    module = load_tray(tmp_path)
    assert module._humanize(
        "setup: run `proxy-router ensure` (or reload) to apply; the engine is untouched."
    ) == "saved — Connect to apply"
    assert module._humanize(
        "config saved; the engine was NOT reloaded - run 'router.py ensure' to apply"
    ) == "saved — Connect to apply"
    assert module._humanize(
        "router: no sing-box binary found at /usr/local/bin/sing-box"
    ) == "VPN engine not found — run Setup, then Connect"
    assert module._humanize(
        "routing mode 'safe-list' needs 'default_provider'"
    ) == "pick a default provider first: Routing mode → home (safe list)"
    assert module._humanize(
        "router: provider 'cloudflare': all profiles cooling down"
    ) == "no servers available right now — try again in a minute"


def test_tray_friendly_egress_error_mapping(tmp_path):
    """Raw probe error tails must become plain-language labels in the exit
    picker — an SSL URLError tail is operator jargon, not a menu item."""
    module = load_tray(tmp_path)
    f = module._friendly_egress_error
    assert f("URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING, "
             "EOF occurred in violation of protocol (_ssl.c:983)]>") == "throttled (SSL)"
    assert f("URLError: timed out") == "timed out"
    assert f("URLError: connection refused") == "offline"
    assert f("URLError: [Errno -5] No address associated with hostname") == "no route (DNS)"
    assert f("429") == "rate-limited"
    assert f("HTTP 403") == "blocked"
    # unknown but short tails still truncate, not explode
    assert len(f("weird exotic failure mode")) <= 28


def test_tray_exit_picker_humanizes_raw_error(tmp_path):
    """profile_health keeps transport-only probe failures quiet (commonly
    transient), but an HTTP-level degradation must render a friendly tag —
    never the raw Python error tail (the screenshot bug)."""
    module = load_tray(tmp_path)
    transport_dead = {"ok": False, "status": None, "latency_ms": None,
                      "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
                      "blocked": False, "exhausted": False}
    http_degraded = {"ok": False, "status": 503, "latency_ms": None,
                     "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
                     "blocked": False, "exhausted": False}
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "01-NL-FREE-140",
                        "profiles": ["01-NL-FREE-140", "02-NL-FREE-149"],
                        "egress": {"01-NL-FREE-140": transport_dead,
                                   "02-NL-FREE-149": http_degraded}}})
    assert app.latest.profile_health("proton", "01-NL-FREE-140") == ""
    health = app.latest.profile_health("proton", "02-NL-FREE-149")
    assert health.startswith(" ! "), f"HTTP degradation needs a warning: {health!r}"
    assert "urlopen" not in health.lower(), f"Python error leaked: {health!r}"


def test_tray_provider_row_no_manual_checkmark_duplication(tmp_path):
    """The active provider row gets ONE checkmark from pystray's `checked=`;
    the old code ALSO appended '  ✓' to the label, rendering two checkmarks
    ('✓ cloudflare ● warp · 593ms ✓')."""
    module = load_tray(tmp_path)
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "01-NL-FREE-140",
                        "profiles": ["01-NL-FREE-140"],
                        "egress": {"01-NL-FREE-140": {
                            "ok": True, "status": 200,
                            "latency_ms": 164.0, "error": None}}}})
    rows = _flatten(app.build_menu().items)
    provider_rows = [t for _, t, _, _ in rows if t.startswith("proton")]
    assert provider_rows, "provider row missing"
    label = provider_rows[0]
    assert label.count("✓") == 0, f"manual checkmark duplicated in label: {label!r}"
    # the footer must be plain language, not the 'exit' jargon
    footer = [t for _, t, _, _ in rows if "Click a" in t]
    assert footer and "location" in footer[0], f"footer jargon: {footer!r}"


def test_tray_upstream_error_shows_warning_not_green(tmp_path):
    """F1: a probe can ride the tunnel (ok=true) while the exit is actually
    rate-limited upstream (429 from rotate --reason). The tray must NOT show
    a healthy green dot — it should warn, but the exit stays CLICKABLE (a
    stale upstream_error is recoverable, not dead)."""
    module = load_tray(tmp_path)
    egress_ok_but_429 = {"ok": True, "status": 200, "latency_ms": 1203.26,
                         "error": None, "upstream_error": "429",
                         "exhausted": False}
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "01-NL-FREE-140",
                        "profiles": ["01-NL-FREE-140"],
                        "egress": {"01-NL-FREE-140": egress_ok_but_429}}})
    # provider_label: warning marker (▲), never the green ●
    label = app.latest.provider_label("proton")
    assert "▲" in label, f"expected warning marker in {label!r}"
    assert "●" not in label, f"rate-limited exit shown as healthy: {label!r}"
    # profile_health: the 429 must surface in the exit picker as plain
    # language (raw "429" would be fine too, but "rate-limited" reads better)
    health = app.latest.profile_health("proton", "01-NL-FREE-140")
    assert "!" in health, f"upstream 429 not surfaced: {health!r}"
    assert "rate-limited" in health, f"429 not humanized: {health!r}"
    # but the exit stays clickable — recoverable warning ≠ dead
    assert not app._exit_disabled(app.latest, "proton", "01-NL-FREE-140"), \
        "recoverable 429 warning must not disable the exit"
    # a genuinely healthy lane keeps the green dot
    healthy = _tray_app(module, tmp_path, up=True,
                        providers={"proton": {
                            "active": "01-NL-FREE-140",
                            "profiles": ["01-NL-FREE-140"],
                            "egress": {"01-NL-FREE-140": {
                                "ok": True, "status": 200,
                                "latency_ms": 164.0, "error": None}}}})
    healthy_label = healthy.latest.provider_label("proton")
    assert "●" in healthy_label, f"healthy lane lost green dot: {healthy_label!r}"


def test_tray_transport_dead_exit_is_clickable_try_anyway(tmp_path):
    """A transport-dead exit (offline/SSL) stays CLICKABLE so a manual switch
    can try the server and confirm liveness — the router probes the new exit
    and rolls back if it is really dead. Only hard block/exhaust markers
    disable an exit."""
    module = load_tray(tmp_path)
    dead = {"ok": False, "status": None, "latency_ms": None,
            "error": "URLError: connection refused", "blocked": False,
            "exhausted": False}
    blocked = {**dead, "blocked": True}
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "01-NL-FREE-140",
                        "profiles": ["01-NL-FREE-140", "02-NL-FREE-149"],
                        "egress": {"01-NL-FREE-140": dead,
                                   "02-NL-FREE-149": blocked}}})
    # transport-dead: clickable, flagged try-anyway
    assert not app._exit_disabled(app.latest, "proton", "01-NL-FREE-140")
    assert app._exit_try_anyway(app.latest, "proton", "01-NL-FREE-140")
    # hard block marker: disabled, not try-anyway
    assert app._exit_disabled(app.latest, "proton", "02-NL-FREE-149")
    assert not app._exit_try_anyway(app.latest, "proton", "02-NL-FREE-149")


def test_tray_menu_offers_dashboard_default_action(tmp_path):
    """One click on the tray opens the full dashboard TUI: the bold default
    menu entry spawns setup_tui in a terminal window."""
    module = load_tray(tmp_path)
    app = _tray_app(module, tmp_path, up=True)
    items = app.build_menu()
    rows = _flatten(items.items)
    texts = [t for _d, t, _e, _extra in rows]
    assert any("Open Dashboard" in t for t in texts)
    # the bold default action is the first actionable top-level entry:
    # before Connect/Reconnect in the raw item order
    raw = [getattr(i, "text", None) for i in items.items]
    actionable = [t for t in raw if t and not t.startswith(("●", "○", "!"))]
    first_action = actionable[0] if actionable else None
    assert first_action and "Open Dashboard" in first_action, f"first action: {first_action!r}"
    assert "onnect" in actionable[1], actionable[:4]  # Reconnect when up


def test_tray_exit_picker_sorts_healthy_first(tmp_path):
    """Dead exits sink to the bottom of the provider picker but stay
    CLICKABLE (labeled 'try anyway'); only hard block/exhaust markers
    gray the row out."""
    module = load_tray(tmp_path)
    dead = {"ok": False, "status": None, "latency_ms": None,
            "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
            "blocked": False, "exhausted": False}
    blocked = {**dead, "blocked": True}
    healthy = {"ok": True, "status": 200, "latency_ms": 164.0, "error": None}
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "02-NL-FREE-149",
                        "profiles": ["00-US-FREE-108", "01-NL-FREE-140",
                                     "02-NL-FREE-149", "03-CH-FREE-50"],
                        "egress": {"00-US-FREE-108": dead,
                                   "01-NL-FREE-140": dead,
                                   "02-NL-FREE-149": healthy,
                                   "03-CH-FREE-50": blocked}}})
    rows = _flatten(app.build_menu().items)
    # Provider submenu rows are at depth 2; grab the exit entries under proton
    exit_rows = [t for d, t, e, _ in rows if d == 2 and "FREE" in t]
    assert exit_rows[0].startswith("02-NL-FREE-149"), \
        f"healthy exit should sort first: {exit_rows}"
    # both dead exits sink below healthy (alphabetical among themselves)
    assert all(not r.startswith("02-NL-FREE-149") for r in exit_rows[1:]), \
        f"dead exits should all sort after healthy: {exit_rows}"
    # blocked exit sinks last of all
    assert exit_rows[-1].startswith("03-CH-FREE-50"), \
        f"blocked exit should sink last: {exit_rows}"
    # transport-dead rows stay clickable and quiet (no warning text)
    assert "!" not in exit_rows[1] and "!" not in exit_rows[2]
    # disabled flags still correct after sorting
    enabled = [e for d, t, e, _ in rows if d == 2 and "FREE" in t]
    assert enabled[0] is True and enabled[-1] is False
    assert enabled[1] is True and enabled[2] is True


def test_tray_rotate_to_passes_force_for_try_anyway(tmp_path, monkeypatch):
    """A manual pick of an offline/SSL exit must reach the router as
    `rotate --to <profile> --force` so the cooldown from the failed probe
    cannot refuse the attempt; the post-switch probe/rollback still guards."""
    module = load_tray(tmp_path)
    client = module.RouterClient(str(tmp_path))
    calls = []

    class _P:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(module.subprocess, "run",
                        lambda c, **k: calls.append(c) or _P())
    client.rotate_to("proton", "01-NL-FREE-140", force=True)
    assert calls[0][2:] == ["rotate", "proton", "--to", "01-NL-FREE-140", "--force"]
    client.rotate_to("proton", "01-NL-FREE-140")
    assert calls[1][2:] == ["rotate", "proton", "--to", "01-NL-FREE-140"]


def test_record_egress_heals_stale_upstream_error(tmp_path):
    """A passing probe must clear a stale upstream_error marker (e.g. 429
    from `rotate --reason` hours ago). Without this, the tray keeps showing
    a warning/disable on an exit that already recovered."""
    router = load_router(tmp_path)
    (tmp_path / "state" / "egress" / "proton").mkdir(parents=True)
    profile = Path("01-NL-FREE-140.conf")
    router.record_egress("proton", profile, ok=False, status=None,
                         error="URLError: timeout")
    router.record_egress("proton", profile, ok=True, status=200,
                         latency_ms=120.0, error=None)
    rec = router.read_egress("proton", profile)
    assert rec["ok"] is True
    assert rec["upstream_error"] is None
    assert rec["upstream_error_at"] is None
    assert rec["error"] is None


def test_probe_429_does_not_heal_exhausted_marker(tmp_path, monkeypatch):
    """ROOT CAUSE: a probe that gets HTTP 429 from the probe target was
    classified as healthy (ok=True), so the sweep would CLEAR the exhausted
    marker on an exit that is still rate-limited, letting rotation switch
    back into a 429'd server. A 429 probe must be a failure and must leave
    the marker intact."""
    router = load_router(tmp_path)
    (tmp_path / "state" / "egress" / "proton").mkdir(parents=True)
    profile = Path("01-NL-FREE-140.conf")
    router._providers = {"proton": {}}
    router._routes = [{
        "id": "probe", "provider": "proton",
        "domains": ["probe.example.com"],
    }]
    router._routing = {"mode": "proxy"}
    router._port = 2080
    router._apply_upstream_failure("proton", profile, "429", 60)
    rec = router.read_egress("proton", profile)
    assert rec["exhausted"] is True

    monkeypatch.setattr(router, "probe_egress", lambda **k: {
        "ok": False, "latency_ms": None, "status": 429,
        "error": "rate-limit-429", "block_reason": None})
    ok, _ = router.probe_profile("proton", profile)
    rec = router.read_egress("proton", profile)

    assert ok is False
    assert rec["exhausted"] is True
    assert rec["upstream_error"] == "429"
    assert router.is_cooled_down("proton", profile)


class _UnreadableModeFile:
    def is_file(self):
        return True

    def read_text(self):
        raise PermissionError(1, "operation not permitted")


def test_vpn_on_disables_system_proxy_after_tun_start(tmp_path, monkeypatch):
    """ROOT CAUSE: `vpn on` switched the engine to tun mode (no
    127.0.0.1:2080 listener) but left the macOS system proxy enabled, so
    browsers sent traffic to a dead port and every site failed with a
    connection reset. A successful tun start must disable the system proxy."""
    router = load_router(tmp_path)
    router.current_mode = lambda: "proxy"
    router.set_mode = lambda m: None
    router.resolve_sing_box = lambda: Path("/bin/true")
    router.sing_box_at_least = lambda v: True
    router.build_singbox_config = lambda: ({"inbounds": [{"type": "tun"}]}, {"proton": Path("p")})
    router.write_sing_box = lambda c: None
    router.validate_config = lambda: True
    router.vpn_note = lambda: None
    router.engine_start = lambda: 0
    calls = []
    router.system_proxy_off = lambda: calls.append("off") or 0
    monkeypatch.setattr("sys.platform", "darwin")

    assert router.vpn_on() == 0
    assert calls == ["off"]


def test_vpn_on_already_up_still_disables_system_proxy(tmp_path, monkeypatch):
    """Re-entering `vpn on` while tun is already up must be idempotent:
    a stale system proxy (left on by an older version) must be cleared
    even when the engine is not restarted."""
    router = load_router(tmp_path)
    router.current_mode = lambda: "tun"
    router.engine_alive = lambda: True
    router.engine_mode_consistent = lambda: True
    calls = []
    watcher_calls = []
    router.route_watcher_start = lambda: watcher_calls.append("start") or 0
    router.system_proxy_off = lambda: calls.append("off") or 0
    monkeypatch.setattr("sys.platform", "darwin")

    assert router.vpn_on() == 0
    assert watcher_calls == ["start"]
    assert calls == ["off"]


def test_vpn_off_reenables_system_proxy_in_proxy_mode(tmp_path, monkeypatch):
    """Returning to proxy mode restores the listener-based system proxy,
    mirroring the tun-mode disable; without it the browser stays broken
    after `vpn off`."""
    router = load_router(tmp_path)
    router.set_mode = lambda m: None
    router.engine_stop = lambda: 0
    router.engine_start = lambda: 0
    calls = []
    router.system_proxy_on = lambda: calls.append("on") or 0
    monkeypatch.setattr("sys.platform", "darwin")

    assert router.vpn_off() == 0
    assert calls == ["on"]


def test_engine_alive_permission_error_means_our_engine(tmp_path, monkeypatch):
    """ROOT CAUSE: an engine started via `sudo vpn on` runs as root; the
    regular-user liveness probe os.kill(pid, 0) raises PermissionError,
    which was swallowed by the generic OSError catch and misread as
    "process gone", so the keepalive kept restarting a live engine and
    deleted its pid file. PermissionError means the process EXISTS and our
    pid file names it -> it is alive and ours."""
    router = load_router(tmp_path)
    router.PID_FILE.write_text("4242")
    router._pid_matches = lambda pid: True

    def deny_kill(pid, sig):
        raise PermissionError(1, "operation not permitted")

    monkeypatch.setattr(router.os, "kill", deny_kill)
    assert router.engine_alive() is True


def test_engine_stop_permission_error_keeps_pid_file(tmp_path, monkeypatch):
    """A regular-user engine_stop on a sudo-started (root) engine cannot
    signal it: it must fail loudly and keep the pid file (the engine IS
    alive), not delete the pid file and pretend it stopped."""
    router = load_router(tmp_path)
    router.PID_FILE.write_text("4242")
    router._pid_matches = lambda pid: True

    def deny_kill(pid, sig):
        raise PermissionError(1, "operation not permitted")

    monkeypatch.setattr(router.os, "kill", deny_kill)
    assert router.engine_stop() == 1
    assert router.PID_FILE.is_file()


def test_current_mode_unreadable_mode_file_defaults_to_proxy(tmp_path, monkeypatch):
    """A root-owned mode file (from a sudo run) must not crash the
    regular-user CLI/keepalive; unreadable state defaults to proxy mode."""
    router = load_router(tmp_path)
    router.MODE_FILE = _UnreadableModeFile()
    assert router.current_mode() == "proxy"


def test_current_mode_missing_file_falls_back_to_default_mode(tmp_path):
    """Fresh installs have no state/mode; the configured vpn.default_mode
    decides which mode ensure boots (tun for a WARP-style always-on box)."""
    router = load_router(tmp_path)
    router._vpn = {"default_mode": "tun"}
    assert not router.MODE_FILE.exists()
    assert router.current_mode() == "tun"


def test_current_mode_unreadable_file_falls_back_to_default_mode(tmp_path):
    """An unreadable mode file falls back to the configured default_mode
    too, so a sudo-run mode file never silently flips a TUN box to proxy."""
    router = load_router(tmp_path)
    router._vpn = {"default_mode": "tun"}
    router.MODE_FILE = _UnreadableModeFile()
    assert router.current_mode() == "tun"


def test_hand_back_ownership_chowns_when_sudo_invoked(tmp_path, monkeypatch):
    """When running as root under sudo, state files must be handed back to
    the invoking user (SUDO_UID/SUDO_GID) so the regular-user keepalive/CLI
    can read them."""
    router = load_router(tmp_path)
    target = tmp_path / "state-file"
    target.write_text("x")
    monkeypatch.setattr(router.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    chowned = []
    monkeypatch.setattr(router.os, "chown", lambda path, uid, gid: chowned.append((str(path), uid, gid)))

    router._hand_back_ownership(target)
    assert chowned == [(str(target), 501, 20)]


def test_hand_back_ownership_noop_for_regular_user(tmp_path, monkeypatch):
    """A non-root run must never chown state files."""
    router = load_router(tmp_path)
    target = tmp_path / "state-file"
    target.write_text("x")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    chowned = []
    monkeypatch.setattr(router.os, "chown", lambda *args: chowned.append(args))

    router._hand_back_ownership(target)
    assert chowned == []


class _TTY:
    """Stands in for sys.stdin so elevation TTY checks can be controlled."""

    def __init__(self, isatty):
        self._isatty = isatty

    def isatty(self):
        return self._isatty


def test_needs_elevation_vpn_on_interactive_darwin_nonroot(tmp_path, monkeypatch):
    """`vpn on` as a regular user on macOS must re-run elevated so the
    standard admin-password dialog asks permission instead of a manual sudo."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    args = type("A", (), {"cmd": "vpn", "action": "on"})()
    assert router._needs_elevation(args) is True


def test_needs_elevation_vpn_off_only_in_tun_mode(tmp_path, monkeypatch):
    """`vpn off` needs root only while TUN is active (engine runs as root);
    in proxy mode the engine is user-owned so no elevation is needed."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    args = type("A", (), {"cmd": "vpn", "action": "off"})()
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    assert router._needs_elevation(args) is True
    router.MODE_FILE.write_text("proxy")
    assert router._needs_elevation(args) is False


def test_needs_elevation_engine_commands_only_in_tun_mode(tmp_path, monkeypatch):
    """start/stop/ensure/reload/rotate/add/remove touch the engine, which in
    tun mode runs as root -> elevate; in proxy mode they stay user-level."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    for cmd in ("start", "stop", "ensure", "reload", "rotate", "add", "remove"):
        args = type("A", (), {"cmd": cmd})()
        assert router._needs_elevation(args) is True, cmd
    router.MODE_FILE.write_text("proxy")
    for cmd in ("start", "stop", "ensure", "reload", "rotate", "add", "remove"):
        args = type("A", (), {"cmd": cmd})()
        assert router._needs_elevation(args) is False, cmd


def test_needs_elevation_skips_readonly_and_status_commands(tmp_path, monkeypatch):
    """Read-only commands (status, routes, vpn status) never elevate."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    for cmd, action in (("status", None), ("routes", None), ("vpn", "status")):
        args = type("A", (), {"cmd": cmd, "action": action})()
        assert router._needs_elevation(args) is False, cmd


def test_needs_elevation_skips_noninteractive_keepalive(tmp_path, monkeypatch):
    """keepalive/launchd ticks run without a TTY and must never pop the
    admin-password dialog on every 15s interval (until `elevate install`
    granted silent passwordless sudo — covered by the companion test)."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(False))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    monkeypatch.setattr(router, "_sudoers_installed", lambda: False)
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    args = type("A", (), {"cmd": "vpn", "action": "on"})()
    assert router._needs_elevation(args) is False


def test_needs_elevation_noninteractive_lifts_when_sudoers_installed(tmp_path, monkeypatch):
    """With the one-time sudoers grant in place, background ticks may elevate
    silently (no dialog), so the TTY gate lifts."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(False))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    monkeypatch.setattr(router, "_sudoers_installed", lambda: True)
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    args = type("A", (), {"cmd": "vpn", "action": "on"})()
    assert router._needs_elevation(args) is True


def test_sudoers_rules_render_all_command_shapes():
    router = load_router(Path("/tmp/pr-test"))
    rules = router._sudoers_rules("alice", "/usr/bin/python3", "/opt/pr/router.py")
    lines = rules.strip().splitlines()
    assert lines[0].startswith("# Managed by `proxy-router elevate install`")
    cmds = [line.split("NOPASSWD: ", 1)[1] for line in lines[1:]]
    assert "/usr/bin/python3 /opt/pr/router.py vpn *" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py reload" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py ensure" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py rotate *" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py rotate * --reason *" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py rotate" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py add" in cmds
    assert "/usr/bin/python3 /opt/pr/router.py remove" in cmds
    assert all(" ALL=(root) NOPASSWD: " in line for line in lines[1:])


def test_sudoers_installed_probes_by_executing_not_listing(tmp_path, monkeypatch):
    """ROOT CAUSE:
    If sudoers grants the user `ALL=(ALL) ALL` (password required, no
    NOPASSWD marker), `sudo -n -line <cmd>` exits 0 and prints the rule, but
    `sudo -n <cmd>` fails with "a password is required" — the old list-based
    probe reported "passwordless sudo active" when running engine commands
    still prompts/fails. We fixed this by EXECUTING the read-only
    `vpn status` command with `-n`: it exits 0 only when the NOPASSWD rule
    actually fires, which is exactly the property `_elevate` relies on."""
    router = load_router(tmp_path)
    calls = []
    monkeypatch.setattr(router.shutil, "which", lambda name: "/usr/bin/sudo")

    class _R:
        returncode = 0

    monkeypatch.setattr(router.subprocess, "run",
                        lambda *a, **k: calls.append(a) or _R())
    assert router._sudoers_installed() is True
    assert calls[0][0][:2] == ["sudo", "-n"]
    assert calls[0][0][2:] == [sys.executable, str(Path(router.__file__).resolve()), "vpn", "status"]


def test_sudoers_installed_survives_engine_down_exit_1(tmp_path, monkeypatch):
    """ROOT CAUSE:
    If the engine is down, `vpn status` exits 1 by design (rc 0 only when
    the engine is up and matches the persisted mode), so the old
    `returncode == 0` probe reported "grant missing" whenever the engine
    was stopped — background keepalive ticks and `elevate status` then
    refused passwordless sudo that was actually installed. We fixed this
    by treating a nonzero exit as "grant present" unless sudo itself
    reports a denial on stderr ("a password is required" / "not in the
    sudoers file" / requiretty), which is the only way `sudo -n` fails
    without running the command."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.shutil, "which", lambda name: "/usr/bin/sudo")

    class _EngineDown:
        returncode = 1
        stdout = "vpn: down (mode set to tun; run 'vpn on')"
        stderr = ""

    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: _EngineDown())
    assert router._sudoers_installed() is True

    class _Denied:
        returncode = 1
        stdout = ""
        stderr = "sudo: a password is required"

    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: _Denied())
    assert router._sudoers_installed() is False


def test_elevate_prefers_sudo_n_when_granted(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    monkeypatch.setattr(router, "_sudoers_installed", lambda: True)
    calls = []

    class _R:
        returncode = 0

    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: calls.append(a) or _R())
    monkeypatch.setattr(router.sys, "argv", ["router.py", "vpn", "off"])
    assert router._elevate() == 0
    assert calls[0][0][0] == "sudo" and calls[0][0][1] == "-n"
    assert calls[0][0][2].endswith("python3") or calls[0][0][2].endswith("python")
    assert calls[0][0][3].endswith("router.py")
    assert calls[0][0][4:] == ["vpn", "off"]


def test_elevate_falls_back_to_admin_dialog(tmp_path, monkeypatch):
    """Without the sudoers grant, an interactive (TTY) macOS run falls back
    to the admin dialog; a TTY-less run refuses up front (TTY gate)."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.setattr(router, "_sudoers_installed", lambda: False)
    monkeypatch.setattr(router, "_elevate_macos", lambda: 99)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    assert router._elevate() == 99


def test_cmd_elevate_status_reports_grant(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    monkeypatch.setattr(router, "_sudoers_installed", lambda: True)
    assert router.cmd_elevate("status") == 0
    monkeypatch.setattr(router, "_sudoers_installed", lambda: False)
    assert router.cmd_elevate("status") == 1


def test_needs_elevation_skips_root_and_elevated_child(tmp_path, monkeypatch):
    """Already-root runs (sudo, or the elevated child) never re-elevate."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    args = type("A", (), {"cmd": "vpn", "action": "on"})()
    monkeypatch.setattr(router.os, "geteuid", lambda: 0)
    assert router._needs_elevation(args) is False
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setenv("PROXY_ROUTER_ELEVATED", "1")
    assert router._needs_elevation(args) is False


def test_elevate_macos_runs_osascript_with_admin_privileges(tmp_path, monkeypatch):
    """The elevated child must be the same CLI, with SUDO_UID/SUDO_GID and
    PATH injected so ownership hand-back and sing-box resolution work."""
    router = load_router(tmp_path)
    calls = []
    monkeypatch.setattr(router.os, "getuid", lambda: 501)
    monkeypatch.setattr(router.os, "getgid", lambda: 20)
    monkeypatch.setattr(router.os, "environ", {"PATH": "/usr/bin:/bin"}, raising=False)
    monkeypatch.setattr(router.sys, "argv", ["router.py", "vpn", "on"])
    monkeypatch.setattr(router.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(router.subprocess, "run",
                        lambda *a, **k: calls.append((a, k)) or type("P", (), {"returncode": 0})())

    router._elevate_macos()
    assert calls, "osascript was never invoked"
    (pos, kwargs), = calls
    argv = pos[0]
    assert argv[:2] == ["osascript", "-e"]
    script = argv[2]
    assert "with administrator privileges" in script
    assert "SUDO_UID=501" in script
    assert "SUDO_GID=20" in script
    assert "PROXY_ROUTER_ELEVATED=1" in script
    assert "PATH=/usr/bin:/bin" in script
    assert "vpn" in script and "on" in script


def test_elevate_macos_escapes_applescript_specials(tmp_path, monkeypatch):
    r"""Quotes/backslashes in args must survive the AppleScript string literal
    (e.g. an --id with quotes): content `\"`/`\\` escapes, literal delimiters
    stay unescaped (a `\` at expression position is a -2741 syntax error)."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.os, "getuid", lambda: 501)
    monkeypatch.setattr(router.os, "getgid", lambda: 20)
    monkeypatch.setattr(router.os, "environ", {"PATH": "/usr/bin"}, raising=False)
    monkeypatch.setattr(router.sys, "argv", ["router.py", "add", "--id", 'we"ird\\id', "--domain", "x.example"])
    monkeypatch.setattr(router.sys, "executable", "/usr/bin/python3")
    captured = []
    monkeypatch.setattr(router.subprocess, "run",
                        lambda *a, **k: captured.append(a[0]) or type("P", (), {"returncode": 0})())

    router._elevate_macos()
    script = captured[0][2]
    assert script.startswith('do shell script "')
    assert 'we\\"ird\\\\id' in script
    assert script.endswith('" with administrator privileges')


def test_needs_elevation_vpn_restart_always(tmp_path, monkeypatch):
    """`vpn restart` stops the engine and re-enters tun; it always needs root
    so the whole cycle gets ONE admin prompt instead of two."""
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    monkeypatch.setattr(router.sys, "stdin", _TTY(True))
    monkeypatch.delenv("PROXY_ROUTER_ELEVATED", raising=False)
    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("proxy")
    args = type("A", (), {"cmd": "vpn", "action": "restart"})()
    assert router._needs_elevation(args) is True


def test_vpn_restart_stops_then_brings_tun_up(tmp_path, monkeypatch):
    """vpn_restart = engine_stop then vpn_on; a failed stop short-circuits."""
    router = load_router(tmp_path)
    calls = []
    monkeypatch.setattr(router, "engine_stop", lambda: calls.append("stop") or 0)
    monkeypatch.setattr(router, "vpn_on", lambda: calls.append("on") or 0)
    assert router.vpn_restart() == 0
    assert calls == ["stop", "on"]
    calls.clear()
    monkeypatch.setattr(router, "engine_stop", lambda: calls.append("stop") or 1)
    assert router.vpn_restart() == 1
    assert calls == ["stop"]


class _UnreadablePidFile:
    """Pid file a regular user cannot read (root-owned, mode 0600 after a
    `sudo vpn on` batch)."""

    def __init__(self):
        self.unlink_calls = 0

    def is_file(self):
        return True

    def read_text(self):
        raise PermissionError(1, "operation not permitted")

    def unlink(self, missing_ok=False):
        self.unlink_calls += 1


def test_engine_start_aborts_when_engine_stop_fails(tmp_path, monkeypatch):
    """ROOT CAUSE: engine_start ignored engine_stop()'s failure and started
    a second engine on top of a live root-owned one. The doomed Popen then
    failed (no utun access), wait_engine failed, engine_stop unlinked the
    pid file, and the root engine was left running untracked. A failed stop
    must abort the start."""
    router = load_router(tmp_path)
    router.resolve_sing_box = lambda: Path("/bin/true")
    router.sing_box_at_least = lambda v: True
    router.build_singbox_config = lambda overrides=None: ({"inbounds": []}, {"proton": Path("p")})
    router.write_sing_box = lambda c: None
    router.validate_config = lambda: True
    router.engine_stop = lambda: 1
    popen_calls = []
    monkeypatch.setattr(router.subprocess, "Popen", lambda *a, **k: popen_calls.append(a) or object())
    assert router.engine_start() == 1
    assert popen_calls == []


def test_engine_stop_unreadable_pid_keeps_pid_file(tmp_path, monkeypatch):
    """ROOT CAUSE: engine_stop's garbage branch caught PermissionError
    (an OSError subclass) on the pid-file read and unlinked the file, which
    for a root-owned live engine destroys the only ownership record. An
    unreadable pid file must fail loudly and stay in place."""
    router = load_router(tmp_path)
    pid_file = _UnreadablePidFile()
    router.PID_FILE = pid_file
    assert router.engine_stop() == 1
    assert pid_file.unlink_calls == 0


def test_engine_alive_unreadable_pid_uses_ps_scan_fallback(tmp_path, monkeypatch):
    """ROOT CAUSE: engine_alive read PermissionError as "process gone", so
    the keepalive kept restarting a live root-owned engine and deleted its
    pid file. An unreadable pid file must fall back to a process-table scan
    instead of declaring the engine dead."""
    router = load_router(tmp_path)
    router.PID_FILE = _UnreadablePidFile()
    monkeypatch.setattr(router, "_any_our_engine_running", lambda: True)
    assert router.engine_alive() is True
    monkeypatch.setattr(router, "_any_our_engine_running", lambda: False)
    assert router.engine_alive() is False


def test_any_our_engine_running_scans_posix_process_table(tmp_path, monkeypatch):
    """_any_our_engine_running matches a live sing-box by our generated
    config path in its command line, so a foreign/unrelated process can
    never claim liveness."""
    router = load_router(tmp_path)

    class _RunResult:
        def __init__(self, stdout):
            self.stdout = stdout

    router.os = type("_Os", (), {"name": "posix"})()
    dead_cmd = "some other process -c /etc/sing-box/config.json"
    live_cmd = f"sing-box run -c {router.SING_BOX_CONFIG}"
    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: _RunResult(live_cmd))
    assert router._any_our_engine_running() is True
    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: _RunResult(dead_cmd))
    assert router._any_our_engine_running() is False


def test_engine_reload_permission_error_on_sighup_only(tmp_path, monkeypatch):
    """ROOT CAUSE: engine_reload caught only ProcessLookupError around the
    SIGHUP, so a regular-user reload of a root-owned engine crashed with an
    unhandled PermissionError traceback. It must fail with the sudo hint
    and leave the pid file alone."""
    router = load_router(tmp_path)
    router.resolve_sing_box = lambda: Path("/bin/true")
    router.sing_box_at_least = lambda v: True
    router.build_singbox_config = lambda overrides=None: ({"inbounds": []}, {"proton": Path("p")})
    router.write_sing_box = lambda c: None
    router.validate_config = lambda: True
    router.PID_FILE.write_text("4242")
    router._pid_matches = lambda pid: True
    start_calls = []
    monkeypatch.setattr(router, "engine_start", lambda **k: start_calls.append(k) or 0)

    def deny_sighup(pid, sig):
        raise PermissionError(1, "operation not permitted")

    monkeypatch.setattr(router.os, "kill", deny_sighup)
    monkeypatch.setattr(router.os, "geteuid", lambda: 501)
    reloads = []
    monkeypatch.setattr(router.subprocess, "run",
                        lambda *a, **k: reloads.append(a) or SimpleNamespace(returncode=0))
    # a regular user now hands the reload to the granted sudo shape
    # instead of failing; the pid file is untouched either way
    assert router.engine_reload() == 0
    assert start_calls == []
    assert router.PID_FILE.read_text() == "4242"
    assert reloads and reloads[0][0][0] == "sudo"


def test_restore_last_good_permission_error_on_sighup_only(tmp_path, monkeypatch):
    """restore_last_good must not crash on a root-owned engine either: a
    SIGHUP PermissionError fails the restore (rc 1) without touching the
    pid file or attempting a doomed regular-user start."""
    router = load_router(tmp_path)
    router.LAST_GOOD_FILE.write_text("{}")
    router.validate_config = lambda: True
    router.PID_FILE.write_text("4242")
    router._pid_matches = lambda pid: True
    start_calls = []
    monkeypatch.setattr(router, "engine_start", lambda **k: start_calls.append(k) or 0)

    def deny_sighup(pid, sig):
        raise PermissionError(1, "operation not permitted")

    monkeypatch.setattr(router.os, "kill", deny_sighup)
    assert router.restore_last_good() == 1
    assert start_calls == []
    assert router.PID_FILE.read_text() == "4242"


def test_tray_full_tunnel_toggle_checked_when_tun(tmp_path):
    """The tray must expose the full-tunnel (TUN) state as a checked menu
    item so the user can see "on" and click to turn it off from the menu."""
    module = load_tray(tmp_path)
    app = _tray_app(module, tmp_path, up=True, mode="tun")
    rows = _flatten(app.build_menu().items)
    labels = [text for _, text, _, _ in rows]
    assert "Full tunnel (WARP): on" in labels
    toggle = next(r for r in rows if r[1].startswith("Full tunnel (WARP)"))
    assert toggle[3] is True  # checked


def test_tray_full_tunnel_toggle_unchecked_when_proxy(tmp_path):
    """In proxy mode the toggle renders off/unchecked; clicking it turns
    the full tunnel back on."""
    module = load_tray(tmp_path)
    app = _tray_app(module, tmp_path, up=True, mode="proxy")
    rows = _flatten(app.build_menu().items)
    toggle = next(r for r in rows if r[1].startswith("Full tunnel (WARP)"))
    assert toggle[1] == "Full tunnel (WARP): off"
    assert toggle[3] is False


def test_tray_full_tunnel_toggle_invokes_vpn_action(tmp_path, monkeypatch):
    """The toggle's action must route through the router CLI (`vpn off` when
    tun is on, `vpn on` when it isn't) — the tray never mutates engine
    state directly."""
    module = load_tray(tmp_path)
    app = _tray_app(module, tmp_path, up=True, mode="tun")
    calls = []
    monkeypatch.setattr(app.client, "vpn", lambda a: calls.append(a) or (0, ""))
    monkeypatch.setattr(app, "_do", lambda action, _label: action())
    app.action_toggle_vpn()
    assert calls == ["off"]

    app2 = _tray_app(module, tmp_path, up=True, mode="proxy")
    calls2 = []
    monkeypatch.setattr(app2.client, "vpn", lambda a: calls2.append(a) or (0, ""))
    monkeypatch.setattr(app2, "_do", lambda action, _label: action())
    app2.action_toggle_vpn()
    assert calls2 == ["on"]


def test_tray_vpn_off_elevates_via_osascript_on_darwin(tmp_path, monkeypatch):
    """ROOT CAUSE: the tray runs under launchd with no TTY, so router.py's
    isatty-gated `_elevate_macos` never fires from it; a plain `vpn off`
    subprocess would hit the new PermissionError guard and fail with the
    "run with sudo" hint instead of doing anything useful. The tray must
    drive the osascript admin dialog itself, with the same SUDO_UID/SUDO_GID
    hand-back env the CLI injects."""
    module = load_tray(tmp_path)
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "getuid", lambda: 501)
    monkeypatch.setattr(module.os, "getgid", lambda: 20)
    monkeypatch.setattr(module.os, "environ", {"PATH": "/usr/bin:/bin"}, raising=False)
    # No sudoers grant: the tray must fall back to the admin dialog.
    monkeypatch.setattr(module, "_sudoers_ok", lambda *a, **k: False)
    calls = []
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *a, **k: calls.append((a, k)) or type("P", (), {
                            "returncode": 0, "stdout": "", "stderr": ""})())

    client = module.RouterClient(str(tmp_path))
    rc, out = client.vpn("off")
    assert rc == 0
    (pos, kwargs), = calls
    argv = pos[0]
    assert argv[:2] == ["osascript", "-e"]
    script = argv[2]
    assert "with administrator privileges" in script
    assert "SUDO_UID=501" in script
    assert "SUDO_GID=20" in script
    assert "PROXY_ROUTER_ELEVATED=1" in script
    assert "router.py" in script and "vpn off" in script
    assert kwargs.get("timeout") == module.ELEVATED_COMMAND_TIMEOUT


def test_tray_vpn_uses_plain_cli_off_macos(tmp_path, monkeypatch):
    """Non-macOS has no osascript dialog; the toggle falls back to the plain
    CLI, whose clear error tells the user to run it with sudo."""
    module = load_tray(tmp_path)
    monkeypatch.setattr(module.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *a, **k: calls.append(a) or type("P", (), {
                            "returncode": 0, "stdout": "", "stderr": ""})())

    client = module.RouterClient(str(tmp_path))
    rc, out = client.vpn("off")
    assert rc == 0
    assert calls and calls[0][0][-2:] == ["vpn", "off"]
    assert not any(c[0][0] == "osascript" for c in calls)


def test_tray_sudoers_ok_survives_engine_down_exit_1(tmp_path, monkeypatch):
    """ROOT CAUSE:
    Mirrors the router probe: `sudo -n <python> <router> vpn status` exits 1
    while the engine is down, so the old `returncode == 0` check made the
    tray believe the passwordless grant was missing and always fell back to
    the admin-password dialog (which blocks under launchd with no TTY). We
    fixed this the same way as router.py: a nonzero exit only counts as
    "grant missing" when sudo reports a denial on stderr."""
    module = load_tray(tmp_path)
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/sudo")

    class _EngineDown:
        returncode = 1
        stdout = "vpn: down (mode set to tun; run 'vpn on')"
        stderr = ""

    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: _EngineDown())
    assert module._sudoers_ok("/usr/bin/python3", "/opt/pr/router.py") is True

    class _Denied:
        returncode = 1
        stdout = ""
        stderr = "sudo: a password is required"

    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: _Denied())
    assert module._sudoers_ok("/usr/bin/python3", "/opt/pr/router.py") is False
