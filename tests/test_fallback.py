from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("router_fallback_test", ROOT / "router.py")
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


def fake_endpoint(_path: Path) -> dict:
    return {
        "type": "wireguard",
        "tag": "",
        "address": ["10.0.0.2/32"],
        "private_key": "secret",
        "peers": [{
            "address": "192.0.2.1",
            "port": 51820,
            "public_key": "public",
            "allowed_ips": ["0.0.0.0/0"],
        }],
    }


def configure_build(router, tmp_path: Path, fallback_active: bool) -> None:
    proton = tmp_path / "proton.conf"
    cloudflare = tmp_path / "cloudflare.conf"
    proton.write_text("fake")
    cloudflare.write_text("fake")
    router._providers = {
        "proton": {"fallback_provider": "cloudflare"},
        "cloudflare": {},
    }
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    router._routing = {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]}
    router._port = 62080
    router.current_mode = lambda: "proxy"
    router._usable_profile = lambda name, preferred=None: {
        "proton": proton, "cloudflare": cloudflare,
    }.get(name)
    router.parse_wireguard = fake_endpoint
    router.dns_server_for = lambda _path: "1.1.1.1"
    if fallback_active:
        marker = tmp_path / "state" / "fallback"
        marker.mkdir(parents=True)
        (marker / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))


def test_engine_switch_replaces_running_server(tmp_path, monkeypatch):
    fake_bin = tmp_path / "sing-box"
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, signal, socket, sys, time\n"
        "if sys.argv[1] == 'check':\n"
        "    raise SystemExit(0)\n"
        "config = json.loads(open(sys.argv[sys.argv.index('-c') + 1]).read())\n"
        "tag = config['endpoints'][0]['tag']\n"
        "marker = os.environ['FAKE_SINGBOX_MARKER']\n"
        "with open(marker, 'a') as handle:\n"
        "    handle.write(config['endpoints'][0]['peers'][0]['address'] + '\\n')\n"
        "sock = socket.socket()\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "sock.bind(('127.0.0.1', config['inbounds'][0]['listen_port']))\n"
        "sock.listen()\n"
        "signal.signal(signal.SIGTERM, lambda *_args: sys.exit(0))\n"
        "while True:\n"
        "    time.sleep(1)\n"
    )
    fake_bin.chmod(0o755)
    marker = tmp_path / "servers.log"
    monkeypatch.setenv("FAKE_SINGBOX_MARKER", str(marker))
    router = load_router(tmp_path)
    router._sing_box_cache = str(fake_bin)
    router._sing_box_resolved = True
    router._sing_box_version_cache = (1, 13, 16)
    router._sing_box_version_resolved = True
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton"}}
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    router._routing = {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]}
    router._port = 62081
    router.current_mode = lambda: "proxy"
    router._usable_profile = lambda _name, preferred=None: (
        provider_dir / ((preferred or router.persisted_active("proton") or provider_dir / "a.conf").stem + ".conf")
    )
    router.parse_wireguard = lambda path: {
        **fake_endpoint(path),
        "peers": [{**fake_endpoint(path)["peers"][0], "address": path.stem}],
    }
    router.dns_server_for = lambda _path: "1.1.1.1"

    try:
        router.set_active("proton", provider_dir / "a.conf")
        assert router.engine_start() == 0
        router.set_active("proton", provider_dir / "b.conf")
        assert router.engine_switch() == 0
        assert marker.read_text().splitlines() == ["a", "b"]
        assert router.engine_alive()
    finally:
        router.engine_stop()


def test_engine_switch_stops_before_starting_new_config(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    router._providers = {"proton": {}}
    router._usable_profile = lambda _name, preferred=None: tmp_path / "proton.conf"
    events = []
    monkeypatch.setattr(router, "resolve_sing_box", lambda: "/fake/sing-box")
    monkeypatch.setattr(router, "sing_box_at_least", lambda _minimum: True)
    monkeypatch.setattr(router, "build_singbox_config", lambda active_overrides=None: ({"route": {}}, {"proton"}))
    monkeypatch.setattr(router, "write_sing_box", lambda _config: events.append("write"))
    monkeypatch.setattr(router, "validate_config", lambda: events.append("validate") or True)
    monkeypatch.setattr(router, "engine_stop", lambda: events.append("stop") or 0)
    monkeypatch.setattr(
        router, "engine_start",
        lambda use_existing_config=False: events.append(("start", use_existing_config)) or 0,
    )
    monkeypatch.setattr(router, "write_last_good", lambda: events.append("last-good"))

    assert router.engine_switch() == 0
    assert events == ["write", "validate", "stop", ("start", True), "last-good"]


def test_rotate_uses_hard_switch_for_selection_and_rollback(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    events = []
    monkeypatch.setattr(router, "engine_switch", lambda: events.append("switch") or 0)
    router.set_active("proton", provider_dir / "a.conf")
    monkeypatch.setattr(router, "probe_profile", lambda *_args: (False, {"ok": False}))

    assert router.rotate("proton") == 1
    assert events == ["switch", "switch"]
    assert (tmp_path / "state" / "proton.active").read_text() == "a"


def test_rotate_probes_through_mixed_listener_in_tun_mode(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    router.current_mode = lambda: "tun"
    router.listener_up = lambda: True
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "engine_switch", lambda: 0)
    router.set_active("proton", provider_dir / "a.conf")
    probes = []
    monkeypatch.setattr(router, "probe_profile", lambda *args: probes.append(args) or (True, {"ok": True}))

    assert router.rotate("proton") == 0
    assert len(probes) == 1


def test_rotate_restores_active_marker_when_switch_fails(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}}
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "engine_switch", lambda: 1)
    router.set_active("proton", provider_dir / "a.conf")

    assert router.rotate("proton") == 1
    assert (tmp_path / "state" / "proton.active").read_text() == "a"


def test_fallback_remaps_routes_dns_and_removes_primary_endpoint(tmp_path):
    router = load_router(tmp_path)
    configure_build(router, tmp_path, fallback_active=True)

    config, _ = router.build_singbox_config()

    assert [endpoint["tag"] for endpoint in config["endpoints"]] == ["cloudflare"]
    assert {rule["outbound"] for rule in config["route"]["rules"] if rule.get("domain_suffix")} == {"cloudflare"}
    assert config["dns"]["rules"] == [{
        "domain_suffix": ["opencode.ai"], "server": "dns-cloudflare",
    }]


def test_fallback_remaps_safe_list_default_provider(tmp_path):
    router = load_router(tmp_path)
    configure_build(router, tmp_path, fallback_active=True)
    router._routing = {
        "mode": "safe-list",
        "direct_domains": [],
        "default_provider": "proton",
    }

    config, _ = router.build_singbox_config()

    assert config["route"]["final"] == "cloudflare"


def test_fallback_safe_list_default_has_a_routed_probe_target(tmp_path):
    router = load_router(tmp_path)
    configure_build(router, tmp_path, fallback_active=True)
    router._routes = []
    router._routing = {
        "mode": "safe-list",
        "direct_domains": [],
        "default_provider": "proton",
    }
    router._egress_settings = {"probe_url": "https://health.example"}

    assert router.probe_url_for("cloudflare") == "https://health.example"


def test_fallback_activation_and_recovery_are_atomic(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    proton_dir = tmp_path / "providers" / "proton"
    warp_dir = tmp_path / "providers" / "cloudflare"
    proton_dir.mkdir(parents=True)
    warp_dir.mkdir(parents=True)
    (proton_dir / "primary.conf").write_text("fake")
    (warp_dir / "warp.conf").write_text("fake")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    reloads = []
    monkeypatch.setattr(router, "engine_switch", lambda: reloads.append(True) or 0)

    assert router.activate_fallback("proton", reason="tls") == 0
    assert router.active_fallback("proton") == "cloudflare"
    assert len(reloads) == 1
    assert router.deactivate_fallback("proton") == 0
    assert router.active_fallback("proton") is None
    assert len(reloads) == 2


def test_egress_sweep_marks_provider_dead_when_no_valid_profiles(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    (provider_dir / "broken.conf").write_text("not a wireguard profile")
    router._providers = {"proton": {"directory": "providers/proton"}}
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    monkeypatch.setattr(router, "_profile_error", lambda _profile: "malformed")

    assert router.egress_sweep("proton", as_json=True) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["dead"] == ["proton"]
    assert payload["results"]["proton"]["error"] == "no valid profiles"


def test_egress_sweep_marks_unknown_provider_dead(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    router._providers = {"proton": {}}
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True

    assert router.egress_sweep("missing", as_json=True) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["dead"] == ["missing"]
    assert payload["results"]["missing"]["error"] == "unknown provider"


def test_egress_sweep_probes_active_fallback(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    router._providers = {
        "proton": {"fallback_provider": "cloudflare"},
        "cloudflare": {},
    }
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    marker = tmp_path / "state" / "fallback"
    marker.mkdir(parents=True)
    (marker / "proton.json").write_text(json.dumps({"provider": "cloudflare"}))
    monkeypatch.setattr(
        router,
        "_check_active_fallback",
        lambda _primary, _fallback: (tmp_path / "warp.conf", "dead", {"dns_ok": False}),
    )

    assert router.egress_sweep("proton", as_json=True) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["dead"] == ["proton"]
    assert payload["results"]["proton"] == {
        "dns_ok": False,
        "fallback_profile": "warp",
        "fallback_provider": "cloudflare",
        "ok": False,
        "status": "fallback",
    }


def test_egress_sweep_deduplicates_dead_provider_on_switch_failure(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton"}}
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    router.set_active("proton", provider_dir / "a.conf")
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "probe_profile", lambda *_args: (False, {"ok": False}))
    monkeypatch.setattr(router, "engine_switch", lambda: 1)

    assert router.egress_sweep("proton", as_json=True) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["dead"] == ["proton"]


def test_fallback_marker_rolls_back_when_reload_fails(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    warp_dir = tmp_path / "providers" / "cloudflare"
    warp_dir.mkdir(parents=True)
    (warp_dir / "warp.conf").write_text("fake")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "engine_switch", lambda: 1)

    assert router.activate_fallback("proton", reason="tls") == 1
    assert not (tmp_path / "state" / "fallback" / "proton.json").exists()


def test_tls_eof_causes_wrapper_to_activate_fallback_and_retry(tmp_path):
    script = tmp_path / "hermes-opencode.sh"
    shutil.copy2(ROOT / "examples" / "hermes-opencode.sh", script)
    script.chmod(0o755)
    calls = tmp_path / "calls"
    router = tmp_path / "router.py"
    router.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        f"state = pathlib.Path({str(calls)!r})\n"
        "args = sys.argv[1:]\n"
        "if args[:1] == ['ensure']:\n"
        "    raise SystemExit(0)\n"
        "elif args[:2] == ['with-proxy', '--check']:\n"
        "    print('http://127.0.0.1:62080')\n"
        "elif args[:1] == ['provider-count']:\n"
        "    print('2')\n"
        "elif args[:1] == ['rotate']:\n"
        "    raise SystemExit(1)\n"
        "elif args[:1] == ['failover']:\n"
        "    state.with_suffix('.fallback').write_text('cloudflare')\n"
        "    raise SystemExit(0)\n"
        "else:\n"
        "    raise SystemExit(2)\n"
    )
    router.chmod(0o755)
    hermes = tmp_path / "fake-hermes.py"
    hermes.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib\n"
        f"state = pathlib.Path({str(calls)!r})\n"
        "count = int(state.read_text()) if state.exists() else 0\n"
        "state.write_text(str(count + 1))\n"
        "if count == 0:\n"
        "    print('SSL_ERROR_SYSCALL: unexpected EOF while reading')\n"
        "    raise SystemExit(1)\n"
        "print('success')\n"
    )
    hermes.chmod(0o755)
    env = dict(os.environ)
    env.update({
        "HERMES_BIN": str(hermes),
        "OPENCODE_MAX_ATTEMPTS": "2",
        "OPENCODE_RETRY_DELAY_SECONDS": "0",
        "TMPDIR": str(tmp_path),
    })

    result = subprocess.run(
        [str(script), "--version"], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert (calls.with_suffix(".fallback")).read_text() == "cloudflare"


def test_proxy_manager_activates_fallback_when_rotation_fails(tmp_path):
    examples = tmp_path / "examples"
    examples.mkdir()
    script = examples / "proxy-manager.sh"
    shutil.copy2(ROOT / "examples" / "proxy-manager.sh", script)
    script.chmod(0o755)
    marker = tmp_path / "fallback-called"
    router = examples / "router.py"
    router.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "if sys.argv[1] == 'rotate':\n"
        "    raise SystemExit(1)\n"
        "if sys.argv[1] == 'failover':\n"
        f"    pathlib.Path({str(marker)!r}).write_text(' '.join(sys.argv[1:]))\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n"
    )
    router.chmod(0o755)
    env = dict(os.environ)
    env["OPENCODE_PROVIDER"] = "proton"

    result = subprocess.run(
        [str(script), "rotate"], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "failover proton on --reason transport"


def _configure_sweep(router, tmp_path: Path, monkeypatch):
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b", "c"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton"}}
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    router._routing = {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]}
    router._port = 62082
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router.time, "sleep", lambda _seconds: None)
    router.set_active("proton", provider_dir / "a.conf")
    events = []

    def switch():
        events.append(router.persisted_active("proton").stem)
        return 0

    monkeypatch.setattr(router, "engine_switch", switch)
    return provider_dir, events


def test_egress_sweep_hard_switches_to_best_profile(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    _provider_dir, events = _configure_sweep(router, tmp_path, monkeypatch)
    results = {
        "a": (True, {"latency_ms": 10, "status": 200}),
        "b": (True, {"latency_ms": 20, "status": 200}),
        "c": (False, {"latency_ms": None, "status": None}),
    }

    def probe(_name, profile):
        assert router.persisted_active("proton") == profile
        return results[profile.stem]

    monkeypatch.setattr(router, "probe_profile", probe)

    assert router.egress_sweep("proton") == 0
    assert events == ["b", "c", "a"]
    assert (tmp_path / "state" / "proton.active").read_text() == "a"


def test_egress_sweep_restores_original_when_all_profiles_are_dead(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    _provider_dir, events = _configure_sweep(router, tmp_path, monkeypatch)
    monkeypatch.setattr(
        router,
        "probe_profile",
        lambda _name, profile: (False, {"latency_ms": None, "status": None}),
    )

    assert router.egress_sweep("proton") == 1
    assert events == ["b", "c", "a"]
    assert (tmp_path / "state" / "proton.active").read_text() == "a"


def test_egress_sweep_restores_original_after_partial_switch_failure(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir, events = _configure_sweep(router, tmp_path, monkeypatch)

    def switch():
        stem = router.persisted_active("proton").stem
        events.append(stem)
        return 1 if stem == "c" else 0

    monkeypatch.setattr(router, "engine_switch", switch)
    monkeypatch.setattr(
        router,
        "probe_profile",
        lambda _name, _profile: (False, {"latency_ms": None, "status": None}),
    )

    assert router.egress_sweep("proton") == 1
    assert events == ["b", "c", "a"]
    assert router.persisted_active("proton") == provider_dir / "a.conf"


def test_force_rotation_is_blocked_while_fallback_is_active(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("fake")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {},
    }
    router.set_active("proton", provider_dir / "a.conf")
    marker = tmp_path / "state" / "fallback" / "proton.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({"provider": "cloudflare"}))
    monkeypatch.setattr(router, "engine_switch", lambda: 0)

    assert router.rotate("proton", force=True, probe=False) == 1
    assert (tmp_path / "state" / "proton.active").read_text() == "a"


def test_fallback_egress_check_probes_fallback_provider(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    proton_dir = tmp_path / "providers" / "proton"
    warp_dir = tmp_path / "providers" / "cloudflare"
    proton_dir.mkdir(parents=True)
    warp_dir.mkdir(parents=True)
    (proton_dir / "primary.conf").write_text("fake")
    (warp_dir / "warp.conf").write_text("fake")
    router._providers = {
        "proton": {"directory": "providers/proton", "fallback_provider": "cloudflare"},
        "cloudflare": {"directory": "providers/cloudflare"},
    }
    router._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    router._routing = {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]}
    router.current_mode = lambda: "proxy"
    router.listener_up = lambda: True
    router.set_active("proton", proton_dir / "primary.conf")
    router.set_active("cloudflare", warp_dir / "warp.conf")
    marker = tmp_path / "state" / "fallback" / "proton.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({"provider": "cloudflare"}))
    calls = []

    def check(name, profile, *, port=None, url=None):
        calls.append((name, profile.stem, port, url))
        return "dead", {"dns_ok": False}

    monkeypatch.setattr(router, "check_egress_live", check)

    assert router.egress_check("proton", as_json=True) == 1
    assert calls == [("cloudflare", "warp", None, "https://opencode.ai")]


def test_config_rejects_fallback_cycles(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2080,
        "providers": {
            "proton": {"fallback_provider": "cloudflare"},
            "cloudflare": {"fallback_provider": "proton"},
        },
        "routes": [],
        "vpn": {},
    }))

    assert router.load_config() == 1


def test_config_accepts_ordered_fallback_chain_and_legacy_alias(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2080,
        "providers": {
            "proton": {"fallback_providers": ["cloudflare", "mullvad"]},
            "cloudflare": {},
            "mullvad": {},
        },
        "routes": [],
        "vpn": {},
    }))

    assert router.load_config() == 0
    assert router.configured_fallbacks("proton") == ["cloudflare", "mullvad"]

    router._providers = {
        "proton": {"fallback_provider": "cloudflare"},
        "cloudflare": {},
    }
    assert router.configured_fallbacks("proton") == ["cloudflare"]


def test_config_rejects_fallback_chain_cycles(tmp_path):
    router = load_router(tmp_path)
    router.CONFIG_FILE.write_text(json.dumps({
        "port": 2080,
        "providers": {
            "proton": {"fallback_providers": ["cloudflare"]},
            "cloudflare": {"fallback_providers": ["mullvad"]},
            "mullvad": {"fallback_providers": ["proton"]},
        },
        "routes": [],
        "vpn": {},
    }))

    assert router.load_config() == 1


def test_activate_fallback_tries_next_valid_candidate(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    (tmp_path / "providers" / "mullvad").mkdir(parents=True)
    (tmp_path / "providers" / "mullvad" / "mullvad.conf").write_text("fake")
    router._providers = {
        "proton": {
            "directory": "providers/proton",
            "fallback_providers": ["cloudflare", "mullvad"],
        },
        "cloudflare": {"directory": "providers/cloudflare"},
        "mullvad": {"directory": "providers/mullvad"},
    }
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "engine_switch", lambda: 0)

    assert router.activate_fallback("proton") == 0
    assert router.active_fallback("proton") == "mullvad"


def test_rotation_reports_failure_when_probe_fails_without_rollback(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    (provider_dir / "a.conf").write_text("fake")
    router._providers = {"proton": {"directory": "providers/proton"}}
    monkeypatch.setattr(router, "_profile_error", lambda _profile: None)
    monkeypatch.setattr(router, "engine_switch", lambda: 0)
    monkeypatch.setattr(router, "probe_profile", lambda *_args: (False, {"ok": False}))

    assert router.rotate("proton", force=True) == 1
