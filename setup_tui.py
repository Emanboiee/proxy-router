#!/usr/bin/env python3
"""Setup wizard for proxy-router: guides, profile imports, route presets, checks.

Stdlib only. Owns the non-engine half of ``proxy-router setup``:

- ``guide_text``      - bundled provider guides (Proton VPN Free, Cloudflare WARP)
- ``import_profiles`` - validates/dedupes/copies WireGuard ``.conf`` files
- ``apply_presets``   - idempotent safe route presets (opencode.ai, Roblox)
- ``check``           - reports provider profile availability (no network)
- ``bridge``          - installs/verifies the Hermes OpenCode auto-rotation
  bridge (``proxy-manager.sh``) at the path the Hermes plugin expects
- ``main`` / ``wizard`` - non-interactive CLI flags and a full-screen TUI
  (alternate screen, arrow-key navigation; plain line menu when not a TTY)

This module never starts sing-box, enables TUN, or touches networking on its
own. The only engine lifecycle call (menu item 8) shells out to the existing
``router.py ensure`` command, and only when the user explicitly selects it.
"""
from __future__ import annotations

import argparse
import configparser
import contextlib
import copy
import dataclasses
import glob
import io
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None
    tty = None

_HAVE_TERMIOS = termios is not None and tty is not None

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()

# Default Hermes config path for the bridge check (resolved via env at call
# time so tests can override; defaults to this module-level value).
_HERMES_CONFIG_DEFAULT = "~/.hermes/config.yaml"

# Guides live next to this module in the checkout/installed prefix. They are
# resolved from the module location (not ROOT) because the test harness
# relocates ROOT per-suite while the bundled guides are fixed files.
_GUIDES = {
    "proton": "proton-vpn-free.md",
    "warp": "cloudflare-warp.md",
}

# Idempotent safe presets: only ever added when their route id is absent,
# never merged into or replacing unrelated routes/providers.
_PRESET_ROUTES = {
    "opencode-zen": {
        "id": "opencode-zen",
        "domains": ["opencode.ai"],
        "provider": "proton",
    },
    "roblox": {
        "id": "roblox",
        "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"],
        "provider": "cloudflare",
    },
}

ANSI = sys.stdout.isatty() and sys.stdin.isatty() and os.environ.get("NO_COLOR") is None


class _Ansi:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"
    MAGENTA = "\x1b[35m"
    REVERSE = "\x1b[7m"
    # 256-color: true orange/purple (brand-ish, readable on light+dark).
    PURPLE = "\x1b[38;5;141m"
    ORANGE = "\x1b[38;5;208m"


def _style(text: str, *codes: str) -> str:
    return "".join(codes) + text + _Ansi.RESET if ANSI else text


_PROVIDER_RE = re.compile(r"\b(proton|cloudflare|warp)\b", re.IGNORECASE)


def _tint_provider(text: str) -> str:
    """Color provider names: Proton/WARP = purple, Cloudflare = orange.

    Applies AFTER width fitting so ANSI bytes never affect layout math.
    No-op when ANSI is disabled (NO_COLOR / non-TTY).
    """
    if not ANSI:
        return text

    def _repl(match: re.Match) -> str:
        word = match.group(0)
        color = _Ansi.PURPLE if word.lower() in ("proton", "warp") else _Ansi.ORANGE
        return color + word + _Ansi.RESET

    return _PROVIDER_RE.sub(_repl, text)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _valid_endpoint(endpoint: str) -> bool:
    """Basic host:port endpoint shape (bracketed IPv6 allowed, no DNS lookups)."""
    endpoint = endpoint.strip()
    if not endpoint:
        return False
    if endpoint.startswith("["):
        return re.fullmatch(r"\[[0-9a-fA-F:.%]+\]:\d+", endpoint) is not None
    host, sep, port = endpoint.rpartition(":")
    return bool(sep) and bool(host) and port.isdigit()


def inspect_profile(conf_path: Path) -> tuple[bool, str]:
    """Validate the minimum WireGuard structure of a ``.conf`` file.

    Returns (ok, reason). Checks ``[Interface]`` Address/PrivateKey,
    ``[Peer]`` PublicKey/Endpoint/AllowedIPs, and a parseable Endpoint -
    the same surface the engine's parser needs. Never returns file contents.
    """
    try:
        parser = configparser.ConfigParser(interpolation=None)
        if not parser.read(conf_path):
            return False, "unreadable file"
        if not parser.has_section("Interface"):
            return False, "missing [Interface] section"
        interface = parser["Interface"]
        for key in ("Address", "PrivateKey"):
            if not str(interface.get(key, "")).strip():
                return False, f"missing Interface.{key}"
        if not parser.has_section("Peer"):
            return False, "missing [Peer] section"
        peer = parser["Peer"]
        for key in ("PublicKey", "Endpoint", "AllowedIPs"):
            if not str(peer.get(key, "")).strip():
                return False, f"missing Peer.{key}"
        if not _valid_endpoint(str(peer["Endpoint"])):
            return False, "bad Peer.Endpoint (expected host:port or [v6]:port)"
        return True, "ok"
    except configparser.Error as exc:
        return False, f"not a parseable config: {exc}"
    except OSError as exc:
        return False, f"cannot read file: {exc}"


def validate_profile(conf_path: Path) -> bool:
    """Default single-file validator: True for a structurally valid profile."""
    ok, _ = inspect_profile(conf_path)
    return ok


def sanitize_name(name: str) -> str:
    """Lowercase, safe filename preserving a trailing ``.conf`` extension."""
    name = name.strip()
    stem = name[:-5] if name.lower().endswith(".conf") else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem)
    stem = stem.strip("._-").lower()
    if not stem:
        stem = "profile"
    return stem + ".conf"


def _unique_target(destination: Path, name: str) -> Path:
    target = destination / name
    if not target.exists():
        return target
    stem = name[:-5] if name.lower().endswith(".conf") else Path(name).stem
    for index in range(2, 10_000):
        candidate = destination / f"{stem}-{index}.conf"
        if not candidate.exists():
            return candidate
    raise OSError(f"could not find a unique destination name for {name}")


def import_profiles(source, destination, validator=None) -> dict:
    """Copy valid WireGuard ``.conf`` profiles from ``source`` into ``destination``.

    ``source`` is a single ``.conf`` file or a directory of ``.conf`` files.
    Each profile is validated, given a sanitized, collision-free name, and
    written with mode 0600. Nothing about the contents is printed.

    Returns::

        {"imported": n, "rejected": n, "files": [names],
         "rejected_files": [{"name": ..., "reason": ...}]}
    """
    source = Path(source)
    destination = Path(destination)
    if source.is_dir():
        candidates = sorted(
            p for p in source.iterdir() if p.is_file() and p.suffix.lower() == ".conf"
        )
    else:
        candidates = [source]
    destination.mkdir(parents=True, exist_ok=True)

    files: list[str] = []
    rejected_files: list[dict] = []
    for candidate in candidates:
        name = candidate.name
        if not candidate.is_file():
            rejected_files.append({"name": name, "reason": "no such file"})
            continue
        if validator is None or validator is validate_profile:
            ok, reason = inspect_profile(candidate)
        else:
            try:
                ok = bool(validator(candidate))
            except Exception as exc:  # noqa: BLE001 - a broken custom validator
                ok, reason = False, f"validator error: {exc}"
            else:
                reason = "" if ok else "rejected by custom validator"
        if not ok:
            rejected_files.append({"name": name, "reason": reason or "invalid WireGuard profile"})
            continue
        try:
            target = _unique_target(destination, sanitize_name(name))
            shutil.copyfile(candidate, target)
            os.chmod(target, 0o600)
        except OSError as exc:
            rejected_files.append({"name": name, "reason": f"copy failed: {exc}"})
            continue
        files.append(target.name)

    return {
        "imported": len(files),
        "rejected": len(rejected_files),
        "files": files,
        "rejected_files": rejected_files,
    }


# ---------------------------------------------------------------------------
# guides
# ---------------------------------------------------------------------------

def guide_text(provider: str) -> str:
    """Return the bundled markdown guide; ``all`` combines them; unknown -> ""."""
    if provider == "all":
        return "\n\n".join(part for part in (guide_text("proton"), guide_text("warp")) if part)
    if provider not in _GUIDES:
        return ""
    try:
        return (Path(__file__).resolve().parent / "guides" / _GUIDES[provider]).read_text()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------

def _default_config() -> dict:
    example = Path(__file__).resolve().parent / "router.example.json"
    if example.is_file():
        return json.loads(example.read_text())
    return {
        "port": 2080,
        "providers": {},
        "routes": [],
        "vpn": {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"},
    }


def apply_presets(config_path, opencode=True, warp_roblox=True) -> dict:
    """Add the safe route presets to ``router.json`` (idempotent, lossless).

    Adds providers ``proton``/``cloudflare`` and routes ``opencode-zen``
    (opencode.ai -> proton) and ``roblox`` (Roblox domains -> cloudflare) when
    missing, leaving every other key, provider, route, and value untouched.
    Returns ``{"added": [route ids created this call]}``.
    """
    config_path = Path(config_path)
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    providers = data.setdefault("providers", {})
    routes = data.setdefault("routes", [])

    added: list[str] = []
    if opencode:
        providers.setdefault("proton", {"directory": "providers/proton", "cooldown_seconds": 60})
        if not any(r.get("id") == "opencode-zen" for r in routes):
            routes.append(dict(_PRESET_ROUTES["opencode-zen"]))
            added.append("opencode-zen")
    if warp_roblox:
        providers.setdefault(
            "cloudflare", {"directory": "providers/cloudflare", "cooldown_seconds": 60}
        )
        if not any(r.get("id") == "roblox" for r in routes):
            routes.append(dict(_PRESET_ROUTES["roblox"]))
            added.append("roblox")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(config_path, 0o600)
    return {"added": added}


# ---------------------------------------------------------------------------
# non-interactive commands
# ---------------------------------------------------------------------------

def check(root) -> dict:
    """Report provider profile availability from ``root/router.json``.

    Network-free: every configured provider needs at least one valid
    ``*.conf`` profile in its directory. Returns ``{"ok": bool, "issues": []}``.
    """
    root = Path(root)
    config_file = root / "router.json"
    if not config_file.is_file():
        return {"ok": False, "issues": [f"missing {config_file}"]}
    try:
        data = json.loads(config_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "issues": [f"bad {config_file.name}: {exc}"]}
    providers = data.get("providers") or {}
    if not providers:
        return {"ok": False, "issues": ["no providers configured in router.json"]}
    issues: list[str] = []
    for name, entry in providers.items():
        directory = root / (entry or {}).get("directory", f"providers/{name}")
        if not directory.is_dir():
            issues.append(f"provider '{name}': missing directory {directory}")
            continue
        if not any(validate_profile(p) for p in directory.glob("*.conf")):
            issues.append(f"provider '{name}': no valid .conf profile in {directory}")
    return {"ok": not issues, "issues": issues}


def _expand_paths(paths) -> list[Path]:
    """Expand ~ and glob patterns into a de-duplicated list of paths."""
    expanded: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        raw = os.path.expanduser(raw)
        if any(ch in raw for ch in "*?["):
            matches = sorted(glob.glob(raw))
            candidates = matches or [raw]
        else:
            candidates = [raw]
        for candidate in candidates:
            key = os.path.abspath(candidate)
            if key not in seen:
                seen.add(key)
                expanded.append(Path(candidate))
    return expanded


def _merge_results(results: list[dict]) -> dict:
    return {
        "imported": sum(r["imported"] for r in results),
        "rejected": sum(r["rejected"] for r in results),
        "files": [f for r in results for f in r["files"]],
        "rejected_files": [f for r in results for f in r["rejected_files"]],
    }


def _cmd_guide(provider: str) -> int:
    text = guide_text(provider)
    if not text:
        print(f"setup: no guide available for '{provider}'", file=sys.stderr)
        return 1
    print(_style(f"--- {_tint_provider(provider)} setup guide ---", _Ansi.BOLD, _Ansi.CYAN))
    print(text)
    return 0


def _cmd_check(root: Path) -> int:
    result = check(root)
    if result["ok"]:
        print(_style("setup: ok - every provider has at least one valid profile", _Ansi.GREEN))
        return 0
    for issue in result["issues"]:
        print(_style(f"setup: {issue}", _Ansi.RED), file=sys.stderr)
    print(_style("setup: check failed", _Ansi.RED), file=sys.stderr)
    return 1


def _cmd_import(root: Path, provider: str, paths) -> int:
    destination = root / "providers" / provider
    sources = _expand_paths(paths) or [Path(paths[0])]
    merged = _merge_results([import_profiles(src, destination) for src in sources])
    if merged["imported"]:
        print(_style(
            f"setup: imported {merged['imported']} profile(s) into providers/{provider}",
            _Ansi.GREEN,
        ))
        for name in merged["files"]:
            print(_style(f"  + {name}", _Ansi.DIM))
    for entry in merged["rejected_files"]:
        print(_style(f"  - {entry['name']}: {entry['reason']}", _Ansi.YELLOW))
    if merged["rejected"]:
        print(_style(f"setup: rejected {merged['rejected']} file(s)", _Ansi.YELLOW))
    return 0 if merged["imported"] else 1


def _cmd_preset(root: Path) -> int:
    config_path = root / "router.json"
    try:
        result = apply_presets(config_path)
    except (json.JSONDecodeError, OSError) as exc:
        print(_style(f"setup: preset failed: {exc}", _Ansi.RED), file=sys.stderr)
        return 1
    if result["added"]:
        print(_style(_tint_provider("setup: added route preset(s): " + ", ".join(result["added"])), _Ansi.GREEN))
    else:
        print(_style(_tint_provider("setup: route presets already applied (nothing to add)"), _Ansi.GREEN))
    print(f"setup: wrote {config_path}")
    return 0


# ---------------------------------------------------------------------------
# Hermes OpenCode auto-rotation bridge
# ---------------------------------------------------------------------------

def bridge_root() -> Path:
    """Machine-level VPN root that the Hermes rotation plugin expects.

    Mirrors the plugin's lookup exactly: ``OPENCODE_ZEN_VPN_ROOT`` env
    override, else the plugin's compiled-in default (hardcoded here only).
    ``expanduser`` so ``~`` prefixes work in the env value.
    """
    return Path(
        os.environ.get("OPENCODE_ZEN_VPN_ROOT", "/Users/kyson/airi/tools/opencode-zen-vpn")
    ).expanduser()


def _hermes_config_path() -> Path:
    """Hermes config path, resolved from env at call time (default module global)."""
    return Path(os.environ.get("HERMES_CONFIG", _HERMES_CONFIG_DEFAULT)).expanduser()


def _hermes_plugin_enabled() -> bool:
    """Best-effort: is ``opencode-server-rotation`` listed under a plugins: block?

    Read-only and never fatal: an unreadable/missing config reports not
    enabled. A simple scan of parsed lines keeps this dependency-free.
    """
    try:
        lines = _hermes_config_path().read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    section = ""
    for line in lines:
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
        if section == "plugins" and "opencode-server-rotation" in line:
            return True
    return False


def _cmd_bridge_check(root: Path | None = None) -> int:
    """Verify the Hermes rotation bridge; no side effects, one line per check.

    ``root`` is accepted for CLI symmetry but placement always comes from
    ``OPENCODE_ZEN_VPN_ROOT`` (this is a machine-level Hermes integration,
    not a repo file). The Hermes plugin-enabled line is informational only
    and does not affect the exit code.
    """
    manager = bridge_root() / "proxy-manager.sh"
    ok = True

    if manager.is_file():
        print(_style(f"bridge: manager present ({manager})", _Ansi.GREEN))
    else:
        print(_style(f"bridge: manager missing ({manager})", _Ansi.RED))
        ok = False

    if os.access(manager, os.X_OK):
        print(_style("bridge: executable", _Ansi.GREEN))
    else:
        print(_style("bridge: not executable", _Ansi.RED))
        ok = False

    if manager.is_file():
        try:
            result = subprocess.run(["bash", "-n", str(manager)], capture_output=True, text=True)
        except OSError as exc:
            print(_style(f"bridge: syntax check skipped (bash unavailable: {exc})", _Ansi.YELLOW))
        else:
            if result.returncode == 0:
                print(_style("bridge: syntax ok", _Ansi.GREEN))
            else:
                print(_style(f"bridge: syntax error: {result.stderr.strip() or result.stdout.strip()}", _Ansi.RED))
                ok = False
    else:
        print(_style("bridge: syntax check skipped (manager missing)", _Ansi.YELLOW))

    vpn_root = bridge_root()
    if os.environ.get("OPENCODE_ZEN_VPN_ROOT"):
        print(f"bridge: vpn root {vpn_root} (env OPENCODE_ZEN_VPN_ROOT)")
    else:
        print(f"bridge: vpn root {vpn_root} (default)")

    if _hermes_plugin_enabled():
        print(_style("bridge: hermes plugin enabled (opencode-server-rotation)", _Ansi.GREEN))
    else:
        print(_style("bridge: hermes plugin NOT enabled (add plugins: - opencode-server-rotation)", _Ansi.YELLOW))
    return 0 if ok else 1


def _cmd_bridge_install(root: Path, force: bool = False) -> int:
    """Install the Hermes OpenCode auto-rotation bridge and validate it.

    Copies ``examples/proxy-manager.sh`` to ``OPENCODE_ZEN_VPN_ROOT/
    proxy-manager.sh`` (a machine-level Hermes integration, not a repo
    config file), chmod 0755, then runs ``bash -n`` and removes the file
    on failure. Idempotent when content is already identical; refuses to
    overwrite a differing existing file unless ``force`` is set.
    """
    source = Path(__file__).resolve().parent / "examples" / "proxy-manager.sh"
    target_dir = bridge_root()
    target = target_dir / "proxy-manager.sh"

    try:
        payload = source.read_bytes()
    except OSError as exc:
        print(f"bridge: cannot read source {source}: {exc}", file=sys.stderr)
        return 1

    if target.is_file():
        try:
            if target.read_bytes() == payload:
                print(_style(f"bridge: already up to date ({target})", _Ansi.GREEN))
                return 0
        except OSError as exc:
            if not force:
                print(_style(f"bridge: existing {target} not readable ({exc})", _Ansi.RED), file=sys.stderr)
                return 1
        if not force:
            print(
                _style(
                    f"bridge: refusing to overwrite existing {target} "
                    "(use --bridge-force-install)",
                    _Ansi.YELLOW,
                ),
                file=sys.stderr,
            )
            return 1
    elif target.exists():
        if not force:
            print(_style(f"bridge: refusing to replace non-file path {target}", _Ansi.YELLOW), file=sys.stderr)
            return 1

    created_dir = not target_dir.is_dir()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if created_dir:
            os.chmod(target_dir, 0o700)
        shutil.copy2(source, target)
        os.chmod(target, 0o755)
    except OSError as exc:
        print(f"bridge: install failed: {exc}", file=sys.stderr)
        return 1

    try:
        result = subprocess.run(["bash", "-n", str(target)], capture_output=True, text=True)
    except OSError as exc:
        print(f"bridge: bash unavailable after install ({exc})", file=sys.stderr)
        return 1
    if result.returncode != 0:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        print(
            f"bridge: syntax check failed, removed {target}: "
            f"{result.stderr.strip() or result.stdout.strip()}",
            file=sys.stderr,
        )
        return 1
    print(_style(f"bridge: installed -> {target}", _Ansi.GREEN))
    return 0


def _router_command(root: Path, *args: str) -> int:
    """Run the existing router CLI against ``root`` (never enabled implicitly)."""
    script = Path(__file__).resolve().parent / "router.py"
    env = dict(os.environ, PROXY_ROUTER_ROOT=str(root))
    try:
        return subprocess.call([sys.executable, str(script), *args], env=env)
    except OSError as exc:
        print(f"setup: could not run {script}: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# interactive wizard
# ---------------------------------------------------------------------------

_BANNER = """
  proxy-router setup wizard
  -------------------------
  Guides, profile imports, route presets and health checks.
  The engine is never started unless you explicitly pick item 8.
"""

_MENU = [
    ("1", "Show Proton VPN guide"),
    ("2", "Show Cloudflare WARP guide"),
    ("3", "Show both guides"),
    ("4", "Import Proton VPN profiles (.conf file or directory)"),
    ("5", "Import Cloudflare WARP profiles (.conf file or directory)"),
    ("6", "Apply route presets (opencode.ai -> proton, roblox -> cloudflare)"),
    ("7", "Check provider health"),
    ("8", "Start / reload the proxy engine (explicit action)"),
    ("9", "Install / verify OpenCode auto-rotation bridge (Hermes)"),
    ("q", "Quit"),
]


def _print_menu() -> None:
    print(_style(_BANNER, _Ansi.CYAN))
    for key, label in _MENU:
        print(f"  {_style(key, _Ansi.BOLD)}  {_tint_provider(label)}")
    print()


def _prompt_import(root: Path, provider: str) -> None:
    label = "Proton VPN" if provider == "proton" else "Cloudflare WARP"
    try:
        answer = input(f"  path to .conf file or directory ({_tint_provider(label)}): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not answer:
        return
    _cmd_import(root, provider, [answer])


def _line_wizard(root: Path) -> int:
    """Line-based fallback: used whenever either stream is not a real TTY."""
    while True:
        _print_menu()
        try:
            choice = input(_style("setup> ", _Ansi.BOLD)).strip().lower()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 130
        if choice in ("q", "quit"):
            return 0
        if choice == "1":
            _cmd_guide("proton")
        elif choice == "2":
            _cmd_guide("warp")
        elif choice == "3":
            _cmd_guide("all")
        elif choice == "4":
            _prompt_import(root, "proton")
        elif choice == "5":
            _prompt_import(root, "cloudflare")
        elif choice == "6":
            _cmd_preset(root)
        elif choice == "7":
            _cmd_check(root)
        elif choice == "8":
            print(_style("  starting/reloading the proxy engine (router ensure)...", _Ansi.YELLOW))
            rc = _router_command(root, "ensure")
            if rc == 0:
                print(_style("  engine up", _Ansi.GREEN))
            else:
                print(_style("  engine failed to start (see router output above)", _Ansi.RED))
        elif choice == "9":
            _cmd_bridge_install(root)
        else:
            print(f"  unknown choice '{choice}' (enter a number or 'q')")


# ---------------------------------------------------------------------------
# full-screen TUI: state, pure key handling and frame rendering
# ---------------------------------------------------------------------------

# TUI menu keeps the same actions plus Quit (digit 0; q/Q/ESC also quit).
TUI_MENU = [
    ("1", "Show Proton guide"),
    ("2", "Show Cloudflare guide"),
    ("3", "Show both guides"),
    ("4", "Import Proton profiles"),
    ("5", "Import Cloudflare profiles"),
    ("6", "Apply route presets (opencode.ai -> proton, roblox -> cloudflare)"),
    ("7", "Check provider health"),
    ("8", "Start/reload the proxy engine"),
    ("9", "Install / verify OpenCode auto-rotation bridge (Hermes)"),
    ("0", "Quit"),
]
TUI_MENU_INDEX = {key: index for index, (key, _) in enumerate(TUI_MENU)}

UP = "\x1b[A"
DOWN = "\x1b[B"
ESC = "\x1b"
ENTER = "\r"
BACKSPACE = "\x7f"

_ANSI_ESC_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI SGR sequences so captured action output stays box-safe."""
    return _ANSI_ESC_RE.sub("", text)


@dataclasses.dataclass
class TuiState:
    """Pure TUI state; view is one of "menu" | "guide" | "import"."""

    view: str = "menu"
    cursor: int = 0
    guide_provider: str = "proton"
    guide_lines: list = dataclasses.field(default_factory=list)
    guide_scroll: int = 0
    import_provider: str = "proton"
    import_text: str = ""
    status: str = ""
    status_ok: bool = True
    action: tuple | None = None  # recorded machine action for the wizard loop
    quit: bool = False
    cols: int = 80
    rows: int = 24


def _initial_state() -> TuiState:
    size = shutil.get_terminal_size((80, 24))
    return TuiState(cols=max(size.columns, 40), rows=max(size.lines, 18))


def _fit(text: str, width: int) -> str:
    """Truncate/pad ``text`` to exactly ``width`` columns."""
    if len(text) > width:
        if width <= 1:
            return text[:width]
        return text[: width - 1] + "\u2026"  # horizontal ellipsis
    return text + " " * (width - len(text))


def _wrap_guide(text: str, width: int) -> list[str]:
    """Split guide markdown into screen lines wrapped to ``width``."""
    width = max(width, 10)
    lines: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            lines.append("")
        else:
            lines.extend(textwrap.wrap(line, width) or [""])
    return lines


def _render_menu(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    header = _style(_fit(" proxy-router setup ", inner), _Ansi.BOLD, _Ansi.CYAN)
    lines.append("\u2502" + header + "\u2502")
    lines.append("\u2502" + _fit(" Guides \u00b7 imports \u00b7 presets \u00b7 health checks ", inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for index, (key, label) in enumerate(TUI_MENU):
        right = f" {key} "
        prefix = f"  {key}  "
        fitted = _fit(prefix + label, inner - len(right))
        label_plain = fitted[len(prefix):]
        label_tint = _tint_provider(label_plain)
        if index == state.cursor:
            row = "\u2502" + prefix + label_tint + right + "\u2502"
            lines.append(_style(row, _Ansi.REVERSE))
        else:
            lines.append("\u2502" + _style(prefix, _Ansi.CYAN) + label_tint + right + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    status_lines = [ln for ln in state.status.splitlines() if ln.strip()] or ["Ready \u2014 pick an item."]
    for ln in status_lines[-2:]:
        plain = _strip_ansi(ln)
        if plain.strip() == "Ready \u2014 pick an item.":
            styled = _style(_fit(" " + plain, inner), _Ansi.DIM)
        elif state.status_ok:
            styled = _style(_fit(" " + plain, inner), _Ansi.GREEN)
        else:
            styled = _style(_fit(" " + plain, inner), _Ansi.RED)
        lines.append("\u2502" + styled + "\u2502")
    lines.append("\u2502" + _style(_fit(" \u2191\u2193 navigate \u00b7 Enter select \u00b7 q/ESC quit ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_guide(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    titles = {
        "proton": "Show Proton VPN guide",
        "warp": "Show Cloudflare WARP guide",
        "all": "Show both guides",
    }
    title = titles.get(state.guide_provider, "Guide")
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(f" {_tint_provider(title)} ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    visible = max(state.rows - 5, 1)
    scroll = min(state.guide_scroll, max(0, len(state.guide_lines) - visible))
    for index in range(visible):
        src = state.guide_lines[scroll + index] if scroll + index < len(state.guide_lines) else ""
        lines.append("\u2502" + _fit(src, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    total = len(state.guide_lines)
    shown = min(scroll + 1, total) if total else 0
    lines.append("\u2502" + _style(_fit(f" line {shown}/{total} \u00b7 \u2191\u2193 scroll \u00b7 q back ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_import(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    title = (
        "Import Proton VPN profiles"
        if state.import_provider == "proton"
        else "Import Cloudflare WARP profiles"
    )
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(f" {_tint_provider(title)} ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    path_display = state.import_text or "no path yet"
    lines.append("\u2502" + _fit(" path: " + path_display, inner) + "\u2502")
    lines.append("\u2502" + _style(_fit(" Enter submits \u00b7 ESC cancels \u00b7 backspace edits ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def render_frame(state: TuiState) -> list[str]:
    """Build the full frame (header, body, footer) as a list of screen lines."""
    if state.view == "guide":
        return _render_guide(state)
    if state.view == "import":
        return _render_import(state)
    return _render_menu(state)


def _open_guide(state: TuiState, provider: str) -> None:
    text = guide_text(provider)
    if not text:
        state.status = f"no {provider} guide available"
        state.status_ok = False
        return
    state.view = "guide"
    state.guide_provider = provider
    state.guide_lines = _wrap_guide(text, max(state.cols - 4, 20))
    state.guide_scroll = 0


def _select_item(state: TuiState, index: int) -> TuiState:
    """Enter/digit selection: switch view or record a machine action."""
    key, _ = TUI_MENU[index]
    if key == "0":
        state.quit = True
    elif key == "1":
        _open_guide(state, "proton")
    elif key == "2":
        _open_guide(state, "warp")
    elif key == "3":
        _open_guide(state, "all")
    elif key == "4":
        state.view, state.import_provider, state.import_text = "import", "proton", ""
    elif key == "5":
        state.view, state.import_provider, state.import_text = "import", "cloudflare", ""
    elif key == "6":
        state.action = ("preset",)
    elif key == "7":
        state.action = ("check",)
    elif key == "8":
        state.action = ("engine",)
    elif key == "9":
        state.action = ("bridge_install",)
    return state


def apply_key(state: TuiState, key: str) -> TuiState:
    """Advance the TUI by one key event; returns a new state.

    Pure with respect to the terminal: never writes to the screen and never
    runs machine actions directly. Imports/presets/check/engine record
    ``state.action`` for the wizard loop to execute through the existing
    ``_cmd_*`` helpers, keeping business logic identical to today.
    """
    state = copy.copy(state)
    state.action = None

    if state.view == "guide":
        if key in ("q", "Q", ESC, ENTER, "\n"):
            state.view = "menu"
        elif key in (UP, "k", "K"):
            state.guide_scroll = max(0, state.guide_scroll - 1)
        elif key in (DOWN, "j", "J"):
            visible = max(1, state.rows - 5)
            max_scroll = max(0, len(state.guide_lines) - visible)
            state.guide_scroll = min(state.guide_scroll + 1, max_scroll)
        return state

    if state.view == "import":
        if key == ESC:
            state.view = "menu"
        elif key in (ENTER, "\n"):
            path = state.import_text.strip()
            state.view = "menu"
            if not path:
                state.status = "import cancelled: empty path"
                state.status_ok = False
            else:
                state.action = ("import", state.import_provider, path)
        elif key in (BACKSPACE, "\x08"):
            state.import_text = state.import_text[:-1]
        elif key and len(key) == 1 and ord(key) >= 32:
            if len(state.import_text) < max(state.cols * 4, 256):
                state.import_text += key
        return state

    # menu view
    if key in (UP, "k", "K"):
        state.cursor = (state.cursor - 1) % len(TUI_MENU)
    elif key in (DOWN, "j", "J"):
        state.cursor = (state.cursor + 1) % len(TUI_MENU)
    elif key in ("q", "Q", ESC, "\x03", "\x04"):
        state.quit = True
    elif key in (ENTER, "\n"):
        return _select_item(state, state.cursor)
    elif key in "0123456789" and key in TUI_MENU_INDEX:
        state.cursor = TUI_MENU_INDEX[key]
        return _select_item(state, state.cursor)
    return state


@contextlib.contextmanager
def _capture_output():
    """Capture parent prints and child-process fd output into one buffer."""
    buf = io.StringIO()
    saved_out = saved_err = None
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        saved_out, saved_err = os.dup(1), os.dup(2)
        with tempfile.TemporaryFile() as tmp:
            os.dup2(tmp.fileno(), 1)
            os.dup2(tmp.fileno(), 2)
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                yield buf
            tmp.seek(0)
            buf.write(tmp.read().decode("utf-8", errors="replace"))
    finally:
        if saved_out is not None:
            os.dup2(saved_out, 1)
            os.close(saved_out)
        if saved_err is not None:
            os.dup2(saved_err, 2)
            os.close(saved_err)


def _execute_action(action: tuple, root: Path) -> tuple[str, int]:
    """Run a recorded action through the existing helpers, capturing output.

    Exactly the same helpers and call shapes as the non-interactive CLI and
    the line wizard use; the screen simply stays up and the result lands in
    the status area instead of the terminal scrollback.
    """
    kind = action[0]
    with _capture_output() as buf:
        if kind == "import":
            rc = _cmd_import(root, action[1], [action[2]])
        elif kind == "preset":
            rc = _cmd_preset(root)
        elif kind == "check":
            rc = _cmd_check(root)
        elif kind == "engine":
            rc = _router_command(root, "ensure")
            if rc == 0:
                buf.write("engine up")
            else:
                buf.write("engine failed to start (see output above)")
        elif kind == "bridge_install":
            rc = _cmd_bridge_install(root)
        else:  # pragma: no cover - defensive
            rc = 0
    return _strip_ansi(buf.getvalue()).strip(), rc


def _paint(state: TuiState) -> None:
    """Paint one full frame: home + lines + home, single write burst."""
    out = sys.stdout
    frame = render_frame(state)
    if len(frame) < state.rows:
        frame = frame + [""] * (state.rows - len(frame))
    out.write("\x1b[H")
    out.write("\r\n".join(frame))
    out.write("\x1b[H")
    if state.view == "import":
        row = 4  # 1-based line of the " path: " input row (frame index 3)
        col = min(1 + len(" path: ") + len(state.import_text), state.cols - 1)
        out.write(f"\x1b[{row};{col}H\x1b[?25h")
    else:
        out.write("\x1b[?25l")
    out.flush()


def _read_key(timeout: float = 0.05) -> str:
    """Read one key event from raw stdin; resolves ESC-prefixed sequences."""
    fd = sys.stdin.fileno()

    def _read1() -> str:
        try:
            data = os.read(fd, 1)
        except OSError:
            return ""
        if not data:
            return "\x04"  # EOF behaves like quit
        return data.decode("utf-8", errors="replace")

    ch = _read1()
    if ch != ESC:
        return ch
    # ESC: possibly the start of an arrow/function sequence; peek for more.
    try:
        ready, _, _ = select.select([fd], [], [], timeout)
    except (OSError, ValueError):
        ready = []
    if not ready:
        return ESC
    seq = _read1()
    if seq in ("[", "O"):
        try:
            ready, _, _ = select.select([fd], [], [], timeout)
        except (OSError, ValueError):
            ready = []
        if ready:
            seq += _read1()
    return ESC + seq


def _tui_wizard(root: Path) -> int:
    """Full-screen alternate-screen wizard (both streams must be TTYs)."""
    state = _initial_state()
    fd = sys.stdin.fileno()
    try:
        saved = termios.tcgetattr(fd)
    except (termios.error, OSError, ValueError):
        saved = None
    interrupted = False
    try:
        try:
            tty.setraw(fd)
        except Exception:
            return _line_wizard(root)
        sys.stdout.write("\x1b[?1049h\x1b[?25l\x1b[2J")
        sys.stdout.flush()
        while not state.quit:
            _paint(state)
            key = _read_key()
            state = apply_key(state, key)
            if state.action is not None:
                text, rc = _execute_action(state.action, root)
                state.action = None
                state.view = "menu"
                state.status = text or ("command finished" if rc == 0 else "command failed")
                state.status_ok = rc == 0
    except KeyboardInterrupt:
        interrupted = True
    finally:
        # Always restore the terminal, even on errors or Ctrl-C.
        try:
            sys.stdout.write("\x1b[?25h\x1b[?1049l\n\n")
            sys.stdout.flush()
        except Exception:
            pass
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            except Exception:
                pass
    return 130 if interrupted else 0


def wizard(root=None) -> int:
    """Interactive setup: full-screen TUI on a real TTY, line fallback otherwise.

    Falls back to the plain line menu when stdin or stdout is not a TTY
    (pipes, CI, tests) or when POSIX raw mode (termios/tty) is unavailable.
    """
    root = Path(root) if root is not None else ROOT
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return _line_wizard(root)
    if not _HAVE_TERMIOS:
        return _line_wizard(root)
    return _tui_wizard(root)


def main(argv=None, root=None) -> int:
    """CLI entry point: non-interactive flags, or the wizard when run bare.

    ``root`` is the repository root to operate on (tests and the router CLI
    pass it explicitly); it redirects every path this module resolves.
    """
    global ROOT
    if root is not None:
        ROOT = Path(root).resolve()
    if argv and argv[0] == "setup":
        argv = argv[1:]

    parser = argparse.ArgumentParser(
        prog="proxy-router setup",
        description="setup wizard: guides, profile import, presets, health check",
    )
    parser.add_argument("--guide", choices=["proton", "warp", "all"], metavar="PROVIDER",
                        help="print a setup guide (proton, warp, or all)")
    parser.add_argument("--check", action="store_true",
                        help="verify router.json and provider profiles")
    parser.add_argument("--import-proton", nargs="+", metavar="PATH",
                        help="import WireGuard .conf file(s)/directory into providers/proton")
    parser.add_argument("--import-warp", nargs="+", metavar="PATH",
                        help="import WireGuard .conf file(s)/directory into providers/cloudflare")
    parser.add_argument("--preset", action="store_true",
                        help="apply safe route presets to router.json (idempotent)")
    parser.add_argument("--bridge-install", action="store_true",
                        help="install the Hermes OpenCode auto-rotation bridge")
    parser.add_argument("--bridge-force-install", action="store_true",
                        help="install the bridge, overwriting an existing file")
    parser.add_argument("--bridge-check", action="store_true",
                        help="verify the installed OpenCode auto-rotation bridge")
    args = parser.parse_args(argv)

    rc = 0
    if args.guide:
        rc = max(rc, _cmd_guide(args.guide))
    if args.check:
        rc = max(rc, _cmd_check(ROOT))
    if args.import_proton:
        rc = max(rc, _cmd_import(ROOT, "proton", args.import_proton))
    if args.import_warp:
        rc = max(rc, _cmd_import(ROOT, "cloudflare", args.import_warp))
    if args.preset:
        rc = max(rc, _cmd_preset(ROOT))
    if args.bridge_install:
        rc = max(rc, _cmd_bridge_install(ROOT))
    if args.bridge_force_install:
        rc = max(rc, _cmd_bridge_install(ROOT, force=True))
    if args.bridge_check:
        rc = max(rc, _cmd_bridge_check(ROOT))
    if not (args.guide or args.check or args.import_proton or args.import_warp or args.preset
            or args.bridge_install or args.bridge_force_install or args.bridge_check):
        rc = wizard(ROOT)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
