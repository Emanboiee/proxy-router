from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path


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
# tray UX regressions (examples/proxy_tray.py)
# ---------------------------------------------------------------------------



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
        def __init__(self, text, action=None, enabled=True, checked=None, submenu=None):
            if isinstance(action, _StubMenu):
                submenu, action = action, None
            self.text = text
            self.action = action
            self.enabled = enabled
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
            "proxy_tray_under_test", ROOT / "examples" / "proxy_tray.py")
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
             "EOF occurred in violation of protocol (_ssl.c:983)]>") == "offline (SSL)"
    assert f("URLError: timed out") == "timed out"
    assert f("URLError: connection refused") == "offline"
    assert f("URLError: [Errno -5] No address associated with hostname") == "no route (DNS)"
    assert f("429") == "rate-limited"
    assert f("HTTP 403") == "blocked"
    # unknown but short tails still truncate, not explode
    assert len(f("weird exotic failure mode")) <= 28


def test_tray_exit_picker_humanizes_raw_error(tmp_path):
    """profile_health must render a raw SSL/URLError as '! offline (SSL)',
    not the Python error tail (the screenshot bug)."""
    module = load_tray(tmp_path)
    bad = {"ok": False, "status": None, "latency_ms": None,
           "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING, "
                    "EOF occurred in violation of protocol (_ssl.c:983)]>",
           "blocked": False, "exhausted": False}
    app = _tray_app(module, tmp_path, up=True,
                    providers={"proton": {
                        "active": "01-NL-FREE-140",
                        "profiles": ["01-NL-FREE-140"],
                        "egress": {"01-NL-FREE-140": bad}}})
    health = app.latest.profile_health("proton", "01-NL-FREE-140")
    assert "offline (SSL)" in health, f"raw error tail leaked: {health!r}"
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
    # dead rows carry the "try anyway" affordance label
    assert "try anyway" in exit_rows[1] and "try anyway" in exit_rows[2]
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
    router.system_proxy_off = lambda: calls.append("off") or 0
    monkeypatch.setattr("sys.platform", "darwin")

    assert router.vpn_on() == 0
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

