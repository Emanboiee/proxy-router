from __future__ import annotations

import getpass
import importlib.util
import json
import sys
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
    rules = router._sudoers_rules("kyson", "/usr/bin/python3", "/opt/pr/router.py")
    lines = rules.strip().splitlines()
    assert lines[0].startswith("# Managed by `proxy-router elevate install`")
    cmds = [l.split("NOPASSWD: ", 1)[1] for l in lines[1:]]
    # Every command `_needs_elevation` may elevate in tun mode must be
    # executable passwordless after `elevate install` (start/stop/add/
    # remove were missing and fell back to prompting).
    for shape in ("vpn *", "start", "stop", "ensure", "reload",
                  "add *", "remove *", "rotate *", "rotate * --reason *"):
        assert f"/usr/bin/python3 /opt/pr/router.py {shape}" in cmds, shape
    assert all(" ALL=(root) NOPASSWD: " in l for l in lines[1:])


def test_elevation_user_resolves_sudo_uid_over_root_env(tmp_path, monkeypatch):
    """The elevated child runs as root, where getpass.getuser() reads the
    root environment (LOGNAME=root) and would grant rules to 'root'
    instead of the invoking user; SUDO_UID carries the real uid."""
    router = load_router(tmp_path)
    fake_pwd = type("Pwd", (), {"getpwuid": staticmethod(lambda uid: type("E", (), {"pw_name": "kyson"})())})()
    monkeypatch.setattr(router, "_pwd", fake_pwd)
    monkeypatch.setenv("SUDO_UID", "501")
    assert router._elevation_user() == "kyson"


def test_elevation_user_falls_back_to_login_user(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    monkeypatch.delenv("SUDO_UID", raising=False)
    assert router._elevation_user() == getpass.getuser()


def test_elevation_user_ignores_invalid_sudo_uid(tmp_path, monkeypatch):
    """A non-numeric SUDO_UID (spoofed env) must not crash or resolve to a
    fabricated user; fall back to the login user."""
    router = load_router(tmp_path)
    fake_pwd = type("Pwd", (), {"getpwuid": staticmethod(lambda uid: (_ for _ in ()).throw(KeyError(uid)))})()
    monkeypatch.setattr(router, "_pwd", fake_pwd)
    monkeypatch.setenv("SUDO_UID", "not-a-number")
    assert router._elevation_user() == getpass.getuser()


def test_cmd_elevate_install_as_root_grants_invoking_user(tmp_path, monkeypatch):
    """ROOT CAUSE: `cmd_elevate('install')` computed rules with
    getpass.getuser(); when re-run in the root child (osascript/sudo -n)
    that returns 'root', so the installed sudoers file granted NOPASSWD to
    root — the requesting user got nothing and every engine command kept
    prompting. The rules must target the SUDO_UID user."""
    router = load_router(tmp_path)
    router.SUDOERS_FILE = tmp_path / "91-proxy-router"
    fake_pwd = type("Pwd", (), {"getpwuid": staticmethod(lambda uid: type("E", (), {"pw_name": "kyson"})())})()
    monkeypatch.setattr(router, "_pwd", fake_pwd)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setattr(router.os, "geteuid", lambda: 0)
    monkeypatch.setattr(router.os, "chmod", lambda *a, **k: None)

    class _VisudoOk:
        returncode = 0

    monkeypatch.setattr(router.subprocess, "run", lambda *a, **k: _VisudoOk())

    assert router.cmd_elevate("install") == 0
    installed = router.SUDOERS_FILE.read_text()
    assert "kyson ALL=(root) NOPASSWD: " in installed
    assert "\nroot ALL=(root) NOPASSWD: " not in installed


def test_sudoers_installed_probes_by_executing_not_listing(tmp_path, monkeypatch):
    """ROOT CAUSE:
    If sudoers grants the user `ALL=(ALL) ALL` (password required, no
    NOPASSWD marker), `sudo -n -l <cmd>` exits 0 and prints the rule, but
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
    router = load_router(tmp_path)
    monkeypatch.setattr(router, "_sudoers_installed", lambda: False)
    monkeypatch.setattr(router, "_elevate_macos", lambda: 99)
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
    """Quotes/backslashes in args must survive the AppleScript string literal
    (e.g. an --id with quotes): content `\"`/`\\` escapes stay inside the
    literal, while a literal delimiter quote ends the string (a stray
    backslash at expression position is a -2741 syntax error)."""
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