#!/usr/bin/env python3
"""Setup wizard for proxy-router: guides, profile imports, route presets, checks.

Stdlib only. Owns the non-engine half of ``proxy-router setup``:

- ``guide_text``      - bundled provider guides (Proton VPN Free, Cloudflare WARP)
- ``import_profiles`` - validates/dedupes/copies WireGuard ``.conf`` files
- ``apply_presets``   - idempotent safe route presets (opencode.ai, Roblox)
- ``check``           - reports provider profile availability (no network)
- ``main`` / ``wizard`` - non-interactive CLI flags and an ANSI line-input menu

This module never starts sing-box, enables TUN, or touches networking on its
own. The only engine lifecycle call (menu item 8) shells out to the existing
``router.py ensure`` command, and only when the user explicitly selects it.
"""
from __future__ import annotations

import argparse
import configparser
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()

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


def _style(text: str, *codes: str) -> str:
    return "".join(codes) + text + _Ansi.RESET if ANSI else text


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
    print(_style(f"--- {provider} setup guide ---", _Ansi.BOLD, _Ansi.CYAN))
    print(text)
    return 0


def _cmd_check(root: Path) -> int:
    result = check(root)
    if result["ok"]:
        print("setup: ok - every provider has at least one valid profile")
        return 0
    for issue in result["issues"]:
        print(f"setup: {issue}", file=sys.stderr)
    print("setup: check failed", file=sys.stderr)
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
            print(f"  + {name}")
    for entry in merged["rejected_files"]:
        print(f"  - {entry['name']}: {entry['reason']}")
    if merged["rejected"]:
        print(_style(f"setup: rejected {merged['rejected']} file(s)", _Ansi.YELLOW))
    return 0 if merged["imported"] else 1


def _cmd_preset(root: Path) -> int:
    config_path = root / "router.json"
    try:
        result = apply_presets(config_path)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"setup: preset failed: {exc}", file=sys.stderr)
        return 1
    if result["added"]:
        print(_style("setup: added route preset(s): " + ", ".join(result["added"]), _Ansi.GREEN))
    else:
        print("setup: route presets already applied (nothing to add)")
    print(f"setup: wrote {config_path}")
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
    ("q", "Quit"),
]


def _print_menu() -> None:
    print(_style(_BANNER, _Ansi.CYAN))
    for key, label in _MENU:
        print(f"  {_style(key, _Ansi.BOLD)}  {label}")
    print()


def _prompt_import(root: Path, provider: str) -> None:
    label = "Proton VPN" if provider == "proton" else "Cloudflare WARP"
    try:
        answer = input(f"  path to .conf file or directory ({label}): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not answer:
        return
    _cmd_import(root, provider, [answer])


def wizard(root=None) -> int:
    """Bare ``setup`` menu: ANSI when both streams are TTYs, line-input always."""
    root = Path(root) if root is not None else ROOT
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
        else:
            print(f"  unknown choice '{choice}' (enter a number or 'q')")


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
    if not (args.guide or args.check or args.import_proton or args.import_warp or args.preset):
        rc = wizard(ROOT)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
