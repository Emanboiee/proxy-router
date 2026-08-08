#!/usr/bin/env python3
"""Proxy router: domain/IP -> provider (WireGuard) selective routing.

Reads ``router.json`` (routes + providers), generates a sing-box config with one
WireGuard endpoint per provider, and hot-reloads it via SIGHUP so route changes
do not drop existing connections. Providers are pools of ``*.conf`` WireGuard
profiles (Proton, Cloudflare WARP, ...) with per-profile cooldown and rotation.

The generated ``sing-box.json`` contains the private keys of every active
profile, so it is written mode 0600 alongside the input profiles.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
CONFIG_FILE = ROOT / "router.json"
SING_BOX_CONFIG = ROOT / "sing-box.json"
PID_FILE = ROOT / "sing-box.pid"
LOG_FILE = ROOT / "sing-box.log"
LOCK_FILE = ROOT / "state" / "engine.lock"
MODE_FILE = ROOT / "state" / "mode"
DEFAULT_PORT = 2080
DEFAULT_TUN_ADDRESS = ["172.19.0.1/30"]
DEFAULT_TUN_MTU = 1500
DEFAULT_TUN_STACK = "system"

_sing_box_cache: str | None = None
_sing_box_resolved = False


def resolve_sing_box() -> str | None:
    """Resolve the sing-box executable, cached.

    Priority: ``SING_BOX`` env var, then ``<root>/bin/sing-box(.exe)`` (bundled
    releases), then ``sing-box`` on ``PATH``. Returns None when not found.
    """
    global _sing_box_cache, _sing_box_resolved
    if _sing_box_resolved:
        return _sing_box_cache
    bundled = ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    for candidate in (os.environ.get("SING_BOX"), str(bundled)):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _sing_box_cache = candidate
            _sing_box_resolved = True
            return candidate
    _sing_box_cache = shutil.which("sing-box")
    _sing_box_resolved = True
    return _sing_box_cache


def _sing_box_missing_message() -> str:
    """One-line message naming every location the resolver checks."""
    bundled = ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    return f"sing-box not found; set SING_BOX, bundle it at {bundled}, or install it on PATH"

_providers: dict = {}
_routes: list = []
_port: int = DEFAULT_PORT
_vpn: dict = {}


def fail(message: str) -> int:
    print(f"router: {message}", file=sys.stderr)
    return 1


def current_mode() -> str:
    """'proxy' (default) or 'tun'. Persisted in state/mode so ensure/reload
    keep running whatever the user last selected."""
    if MODE_FILE.is_file():
        return MODE_FILE.read_text().strip()
    return "proxy"


def set_mode(mode: str) -> None:
    MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    MODE_FILE.write_text(mode)
    os.chmod(MODE_FILE, 0o600)


def load_config() -> int:
    global _providers, _routes, _port, _vpn
    if not CONFIG_FILE.is_file():
        return fail(f"missing {CONFIG_FILE.name}; run 'router.py init' first")
    try:
        data = json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return fail(f"bad {CONFIG_FILE.name}: {exc}")
    _port = int(data.get("port", DEFAULT_PORT))
    _providers = data.get("providers", {})
    _routes = data.get("routes", [])
    _vpn = data.get("vpn", {})
    if not _providers:
        return fail("no providers configured")
    return 0


def write_default_config() -> None:
    example = ROOT / "router.example.json"
    if example.is_file():
        data = json.loads(example.read_text())
    else:
        data = {
            "port": DEFAULT_PORT,
            "providers": {
                "proton": {"directory": "providers/proton", "cooldown_seconds": 60},
                "cloudflare": {"directory": "providers/cloudflare", "cooldown_seconds": 60},
            },
            "routes": [
                {"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"},
                {
                    "id": "roblox",
                    "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"],
                    "provider": "cloudflare",
                },
            ],
            "vpn": {
                "address": DEFAULT_TUN_ADDRESS,
                "mtu": DEFAULT_TUN_MTU,
                "stack": DEFAULT_TUN_STACK,
            },
        }
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(CONFIG_FILE, 0o600)
    print(f"wrote {CONFIG_FILE}")


# ---------------------------------------------------------------------------
# provider pools
# ---------------------------------------------------------------------------

def provider_dir(name: str) -> Path:
    entry = _providers.get(name, {})
    return (ROOT / entry.get("directory", f"providers/{name}")).resolve()


def provider_files(name: str) -> list[Path]:
    return sorted(provider_dir(name).glob("*.conf"))


def is_cooled_down(name: str, profile: Path) -> bool:
    path = ROOT / "state" / "cooldowns" / name / f"{profile.stem}.until"
    if not path.is_file():
        return False
    try:
        return int(path.read_text().strip()) > int(time.time())
    except ValueError:
        return False


def mark_cooldown(name: str, profile: Path, seconds: int) -> None:
    path = ROOT / "state" / "cooldowns" / name / f"{profile.stem}.until"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(int(time.time()) + seconds))
    os.chmod(path, 0o600)


def resolve_active(name: str) -> Path | None:
    profiles = provider_files(name)
    if not profiles:
        return None
    state = ROOT / "state" / f"{name}.active"
    if state.is_file():
        stem = state.read_text().strip()
        match = next((p for p in profiles if p.stem == stem), None)
        if match is not None and not is_cooled_down(name, match):
            return match
    return next((p for p in profiles if not is_cooled_down(name, p)), None)


def set_active(name: str, profile: Path) -> None:
    state = ROOT / "state" / f"{name}.active"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(profile.stem)
    os.chmod(state, 0o600)


# ---------------------------------------------------------------------------
# sing-box config generation
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> str:
    """Resolve a WireGuard peer host to an IP literal.

    sing-box 1.12+ requires an explicit domain resolver when dialing a peer
    by domain; resolving at build time (like Proton's IP endpoints) avoids
    that and any DNS loop through the provider tunnel itself. Prefer IPv6:
    the network this machine runs on silently drops the WARP IPv4 endpoint
    (handshake never completes) while the IPv6 endpoint answers.
    """
    try:
        socket.inet_aton(host)
        return host  # already an IPv4 literal
    except OSError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
    for info in infos:
        if info[0] == socket.AF_INET6:
            return info[4][0]
    return infos[0][4][0]


def parse_wireguard(profile: Path) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profile)
    interface, peer = parser["Interface"], parser["Peer"]
    host, port = peer["Endpoint"].strip().rsplit(":", 1)
    host = resolve_host(host)
    allowed_ips = [a.strip() for a in re.split(r"[,\s]+", peer.get("AllowedIPs", "").strip()) if a]
    if not allowed_ips:
        raise SystemExit(f"missing AllowedIPs in {profile.name}")
    endpoint = {
        "type": "wireguard",
        "tag": "",  # set by caller to the provider name
        "address": [a.strip() for a in re.split(r"[,\s]+", interface["Address"].strip()) if a],
        "private_key": interface["PrivateKey"].strip(),
        "peers": [{"address": host.strip(), "port": int(port), "public_key": peer["PublicKey"].strip(), "allowed_ips": allowed_ips}],
    }
    if peer.get("PresharedKey", "").strip():
        endpoint["peers"][0]["pre_shared_key"] = peer["PresharedKey"].strip()
    if peer.get("PersistentKeepalive", "").strip():
        endpoint["peers"][0]["persistent_keepalive_interval"] = int(peer["PersistentKeepalive"].strip())
    if interface.get("MTU", "").strip():
        endpoint["mtu"] = int(interface["MTU"].strip())
    return endpoint


def dns_server_for(profile: Path) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profile)
    dns = parser.get("Interface", "DNS", fallback="").strip()
    if dns:
        dns = re.split(r"[,\s]+", dns)[0]
    return dns or "1.1.1.1"


def build_singbox_config() -> tuple[dict, set[str]]:
    active: dict[str, dict] = {}
    dns_map: dict[str, str] = {}
    for name in _providers:
        profile = resolve_active(name)
        if profile is None:
            continue
        endpoint = parse_wireguard(profile)
        endpoint["tag"] = name
        # sing-box 1.12+: domain destinations routed through this endpoint are
        # resolved with an explicit per-endpoint resolver instead of the
        # deprecated implicit DNS rule path. DialerOptions is embedded flat.
        endpoint["domain_resolver"] = f"dns-{name}"
        active[name] = endpoint
        dns_map[name] = dns_server_for(profile)

    dns_servers = [
        {"type": "udp", "tag": f"dns-{name}", "server": dns_map[name], "detour": name}
        for name in active
    ]
    # sing-box 1.12+: any dial without an explicit resolver needs
    # route.default_domain_resolver; the system (local) transport keeps
    # non-routed domains away from the tunnels and silences the deprecated
    # implicit fallback. Route DNS rules still pin tunneled domains to the
    # provider's own server.
    dns_servers.append({"type": "local", "tag": "dns-local"})
    dns_rules = []
    for route in _routes:
        if route["provider"] in active and route.get("domains"):
            dns_rules.append({"domain_suffix": route["domains"], "server": f"dns-{route['provider']}"})

    rules = []
    for route in _routes:
        if route["provider"] not in active:
            continue
        rule = {"outbound": route["provider"]}
        if route.get("domains"):
            rule["domain_suffix"] = route["domains"]
        if route.get("ip_cidr"):
            rule["ip_cidr"] = route["ip_cidr"]
        rules.append(rule)
    rules.extend([
        {"domain": ["localhost"], "outbound": "direct"},
        {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
    ])

    mode = current_mode()
    if mode == "tun":
        inbounds = [{
            "type": "tun",
            "tag": "tun-in",
            "address": _vpn.get("address", DEFAULT_TUN_ADDRESS),
            "mtu": int(_vpn.get("mtu", DEFAULT_TUN_MTU)),
            "stack": _vpn.get("stack", DEFAULT_TUN_STACK),
            "auto_route": True,
            "strict_route": False,
        }]
        route_final = "direct"
    else:
        inbounds = [{"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": _port}]
        route_final = "direct"

    config = {
        "log": {"level": "info"},
        "inbounds": inbounds,
        "endpoints": list(active.values()),
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "dns": {"servers": dns_servers, "rules": dns_rules, "strategy": "ipv4_only"},
        "route": {"auto_detect_interface": True, "default_domain_resolver": "dns-local", "rules": rules, "final": route_final},
    }
    return config, set(active)


def write_sing_box(config: dict) -> None:
    SING_BOX_CONFIG.write_text(json.dumps(config, indent=2) + "\n")
    os.chmod(SING_BOX_CONFIG, 0o600)


def validate_config() -> bool:
    sing_box = resolve_sing_box()
    if sing_box is None:
        print(_sing_box_missing_message(), file=sys.stderr)
        return False
    result = subprocess.run([sing_box, "check", "-c", str(SING_BOX_CONFIG)], capture_output=True, text=True)
    if result.returncode == 0:
        return True
    print(result.stderr, file=sys.stderr)
    return False


def listener_up() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", _port)) == 0


def engine_alive() -> bool:
    """True when a sing-box started by us is still running (tun mode has no
    TCP listener to probe, so process liveness is the health check)."""
    if not PID_FILE.is_file():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        if os.name == "nt":
            result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
            return str(pid) in result.stdout
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, ValueError):
        return False


def wait_engine(timeout: float = 8.0) -> bool:
    """Mode-aware readiness: proxy mode waits for the mixed listener, tun mode
    waits for a live process (interface setup has no socket to poll)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if current_mode() == "tun":
            if engine_alive():
                return True
        else:
            if listener_up():
                return True
        time.sleep(0.2)
    return False


def wait_listener(timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if listener_up():
            return True
        time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# engine lifecycle
# ---------------------------------------------------------------------------

def engine_start() -> int:
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    config, active = build_singbox_config()
    if not active:
        return fail("no provider profile available (drop *.conf into providers/<name>/)")
    write_sing_box(config)
    if not validate_config():
        return fail("sing-box config check failed")
    engine_stop()
    popen_kwargs = {"stdout": LOG_FILE.open("ab"), "stderr": subprocess.STDOUT, "cwd": ROOT}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen([sing_box, "run", "-c", str(SING_BOX_CONFIG)], **popen_kwargs)
    PID_FILE.write_text(str(process.pid))
    os.chmod(PID_FILE, 0o600)
    if not wait_engine():
        engine_stop()
        return fail("sing-box failed to come up")
    return 0


def engine_ensure() -> int:
    if current_mode() == "tun":
        if engine_alive():
            return 0
        return engine_start()
    if listener_up():
        return 0
    return engine_start()


def engine_stop() -> int:
    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text().strip())
            if os.name == "nt":
                # taskkill /T /F is a hard kill (TerminateProcess on the whole
                # tree); the process may already be gone, so ignore its exit code.
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.4)
                os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass
        PID_FILE.unlink(missing_ok=True)
    return 0


def engine_reload() -> int:
    sing_box = resolve_sing_box()
    if sing_box is None:
        return fail(_sing_box_missing_message())
    config, active = build_singbox_config()
    if not active:
        return fail("no provider endpoint available")
    write_sing_box(config)
    if not validate_config():
        return fail("sing-box config check failed")
    if not PID_FILE.is_file():
        return engine_start()
    pid = int(PID_FILE.read_text().strip())
    if os.name == "nt":
        # Windows has no SIGHUP; stop+start applies the fresh config.
        if engine_stop() != 0:
            return fail("engine stop failed during reload")
        return engine_start()
    try:
        os.kill(pid, signal.SIGHUP)  # SIGHUP: sing-box hot-reloads the config in place
    except ProcessLookupError:
        return engine_start()
    if wait_engine(2.0):
        return 0
    return engine_start()


def rotate(name: str) -> int:
    profiles = provider_files(name)
    if not profiles:
        return fail(f"provider '{name}' has no profiles")
    seconds = int(_providers.get(name, {}).get("cooldown_seconds", 60))
    current = resolve_active(name)
    if current is not None and not is_cooled_down(name, current):
        mark_cooldown(name, current, seconds)
    for profile in profiles:
        if not is_cooled_down(name, profile):
            set_active(name, profile)
            print(f"switched {name} -> {profile.stem}")
            return engine_reload()
    return fail(f"provider '{name}': all profiles cooling down")


def provider_count(name: str) -> int:
    """Number of rotation candidates for a provider (used as a retry budget by
    hermes-opencode.sh); at least 1 so callers always attempt once."""
    return max(1, len(provider_files(name)))


# ---------------------------------------------------------------------------
# route table management
# ---------------------------------------------------------------------------

def save_config() -> int:
    data = json.loads(CONFIG_FILE.read_text())
    data["routes"] = _routes
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")
    return 0


def routes_list() -> int:
    for route in _routes:
        targets = ",".join(route.get("domains", []) + route.get("ip_cidr", []))
        print(f"  {route['id']:<16} {targets:<52} -> {route['provider']}")
    return 0


def _routes_add_entry(target: str, key: str, id_: str | None, provider: str) -> tuple[str, str] | None:
    """Add or update a route in the in-memory table.

    Returns (key, id) on success, or None when the target is empty or the
    provider is unknown.
    """
    if not target or provider not in _providers:
        return None
    id_ = id_ or re.sub(r"[^a-z0-9-]", "-", target.lower())
    existing = next((r for r in _routes if r.get("id") == id_), None)
    if existing is None:
        existing = {"id": id_, "provider": provider}
        _routes.append(existing)
    existing[key] = [target]
    existing["provider"] = provider
    return key, id_


def routes_add(args) -> int:
    target = args.domain or args.ip or ""
    key = "domains" if args.domain else "ip_cidr"
    if _routes_add_entry(target, key, args.id, args.provider) is None:
        if not target:
            return fail("need --domain or --ip")
        return fail(f"unknown provider '{args.provider}' (have {', '.join(_providers)})")
    save_config()
    if engine_reload() != 0:
        return fail("route saved but engine reload failed")
    routes_list()
    return 0


def _routes_remove_entry(id_: str) -> bool:
    """Remove the route with the given id from the in-memory table."""
    before = len(_routes)
    _routes[:] = [r for r in _routes if r.get("id") != id_]
    return len(_routes) != before


def routes_remove(id_: str) -> int:
    if not _routes_remove_entry(id_):
        return fail(f"no route with id '{id_}'")
    save_config()
    if engine_reload() != 0:
        return fail("route removed but engine reload failed")
    return 0


# ---------------------------------------------------------------------------
# VPN (TUN) toggle
# ---------------------------------------------------------------------------

def vpn_note() -> None:
    """Per-OS caveats when switching to tun mode; prints to stderr, not an error."""
    if current_mode() != "tun":
        return
    if sys.platform == "darwin":
        print("router: tun mode on macOS needs root (create utun interface); run with sudo", file=sys.stderr)
        print("router: tun mode on macOS is NOT a System Settings VPN entry (requires a signed NE app); it is a utun interface", file=sys.stderr)
    elif os.name == "nt":
        print("router: tun mode on Windows needs an elevated shell (admin) and wintun.dll next to sing-box.exe", file=sys.stderr)


def vpn_on() -> int:
    if current_mode() == "tun":
        if engine_alive():
            print("vpn: tun already up")
            return 0
    set_mode("tun")
    vpn_note()
    return engine_start()


def vpn_off() -> int:
    set_mode("proxy")
    return engine_stop()


def vpn_status() -> int:
    mode = current_mode()
    if mode == "tun":
        if engine_alive():
            print("vpn: up (tun mode)")
            return 0
        print("vpn: down (mode set to tun; run 'vpn on')")
        return 1
    if listener_up():
        print("vpn: proxy up (127.0.0.1:{})".format(_port))
        return 0
    print("vpn: down (proxy mode; run 'vpn on' for tun, 'start' for proxy)")
    return 1


# ---------------------------------------------------------------------------
# macOS system proxy toggle
# ---------------------------------------------------------------------------

def active_service_name() -> str | None:
    iface = None
    out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "interface:" in line:
            iface = line.split()[-1]
    if not iface:
        return None
    service = None
    out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            service = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and line.split()[-1] == iface:
            return service
    return None


def system_proxy_on() -> int:
    service = active_service_name()
    if not service:
        return fail("could not determine the active network service")
    commands = [
        ["networksetup", "-setwebproxy", service, "127.0.0.1", str(_port)],
        ["networksetup", "-setsecurewebproxy", service, "127.0.0.1", str(_port)],
        ["networksetup", "-setwebproxystate", service, "on"],
        ["networksetup", "-setsecurewebproxystate", service, "on"],
        ["networksetup", "-setproxybypassdomains", service, "*.local", "localhost", "127.0.0.1", "::1"],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True)
    print(f"system proxy enabled on '{service}' -> 127.0.0.1:{_port}")
    return 0


def system_proxy_off() -> int:
    service = active_service_name()
    if not service:
        return fail("could not determine the active network service")
    subprocess.run(["networksetup", "-setwebproxystate", service, "off"], capture_output=True)
    subprocess.run(["networksetup", "-setsecurewebproxystate", service, "off"], capture_output=True)
    print(f"system proxy disabled ({service})")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(prog="router", description="selective WireGuard proxy router")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init")
    sub.add_parser("ensure")
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("status")
    sub.add_parser("reload")
    sub.add_parser("routes")
    sub.add_parser("up")
    sub.add_parser("down")

    vpn = sub.add_parser("vpn", help="toggle TUN mode (vpn on|off|status)")
    vpn.add_argument("action", choices=["on", "off", "status"])

    r_add = sub.add_parser("add")
    r_add.add_argument("--id")
    r_add.add_argument("--domain")
    r_add.add_argument("--ip")
    r_add.add_argument("--provider", required=True)

    r_rm = sub.add_parser("remove")
    r_rm.add_argument("id")

    r_rot = sub.add_parser("rotate")
    r_rot.add_argument("provider")

    r_count = sub.add_parser("provider-count")
    r_count.add_argument("provider")

    args = parser.parse_args()
    if args.cmd == "init":
        write_default_config()
        return 0
    if args.cmd is None:
        parser.print_help()
        return 2

    if args.cmd == "up":
        if sys.platform != "darwin":
            return fail("up requires macOS (v1 scope)")
        rc = load_config()
        if rc == 0 and engine_start() == 0:
            return system_proxy_on()
        return rc
    if args.cmd == "down" and sys.platform != "darwin":
        return fail("down requires macOS (v1 scope)")

    rc = load_config()
    if rc and args.cmd != "status":
        return rc

    if args.cmd == "ensure":
        return _with_lock(engine_ensure)
    if args.cmd == "start":
        return _with_lock(engine_start)
    if args.cmd == "stop":
        return _with_lock(engine_stop)
    if args.cmd == "status":
        if resolve_sing_box() is None:
            print(f"router: {_sing_box_missing_message()}", file=sys.stderr)
        if current_mode() == "tun":
            print("up (tun)" if engine_alive() else "down")
        else:
            print("up" if listener_up() else "down")
        return 0
    if args.cmd == "reload":
        return _with_lock(engine_reload)
    if args.cmd == "rotate":
        return _with_lock(lambda: rotate(args.provider))
    if args.cmd == "provider-count":
        print(provider_count(args.provider))
        return 0
    if args.cmd == "routes":
        return routes_list()
    if args.cmd == "vpn":
        if args.action == "on":
            return _with_lock(vpn_on)
        if args.action == "off":
            return _with_lock(vpn_off)
        return vpn_status()
    if args.cmd == "add":
        return _with_lock(lambda: routes_add(args))
    if args.cmd == "remove":
        return _with_lock(lambda: routes_remove(args.id))
    if args.cmd == "down":
        if sys.platform != "darwin":
            return fail("down requires macOS (v1 scope)")
        return system_proxy_off()
    parser.print_help()
    return 2


class _EngineLock:
    """Exclusive lock on ``state/engine.lock``.

    Uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows so the
    same CLI surface works on macOS, Linux, and Windows.
    """

    def __init__(self) -> None:
        self._path = LOCK_FILE
        self._file = None

    def __enter__(self) -> "_EngineLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("w")
        if os.name == "nt":
            import msvcrt

            # msvcrt.locking cannot lock an empty file, so seed one byte.
            self._file.write("0")
            self._file.flush()
            self._file.seek(0)
            msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self._file is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
        return False


def _with_lock(action) -> int:
    with _EngineLock():
        return action()


if __name__ == "__main__":
    raise SystemExit(main())